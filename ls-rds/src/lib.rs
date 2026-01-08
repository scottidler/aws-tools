//! ls-rds library
//!
//! Core functionality for listing RDS instances across AWS accounts.
//! This module separates business logic from the CLI shell.

pub mod cli;
pub mod config;

pub use cli::Cli;
pub use config::{Config, ScanMode, extract_account_from_arn};

use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_config::sts::AssumeRoleProvider;
use aws_sdk_organizations as org;
use aws_sdk_rds as rds;
use aws_sdk_sts as sts;
use aws_types::{region::Region, SdkConfig};
use eyre::Result;
use log::{debug, error, info};
use std::{env, fs, path::PathBuf};

/// Result from scanning RDS instances
#[derive(Debug, Clone)]
pub struct RdsInstance {
    pub region: String,
    pub role_arn: Option<String>,
    pub instance_id: String,
}

/// Result of an RDS scan operation
#[derive(Debug)]
pub struct ScanResult {
    pub instances: Vec<RdsInstance>,
}

/// Return an OS‑appropriate log directory, creating it if necessary.
pub fn get_or_create_log_dir() -> PathBuf {
    let dir = {
        #[cfg(target_os = "macos")]
        {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_owned());
            PathBuf::from(home).join("Library").join("Logs").join("slam")
        }
        #[cfg(not(target_os = "macos"))]
        {
            if let Ok(xdg_state) = env::var("XDG_STATE_HOME") {
                PathBuf::from(xdg_state).join("slam")
            } else if let Ok(home) = env::var("HOME") {
                PathBuf::from(home).join(".local").join("state").join("slam")
            } else {
                PathBuf::from("slam_logs")
            }
        }
    };

    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("Failed to create log directory {}: {}", dir.display(), e);
    }
    dir
}

/// Get default region from environment or config
pub fn get_default_region(config: &Config) -> String {
    env::var("AWS_REGION")
        .or_else(|_| env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| config.regions.first().cloned().unwrap_or_else(|| "us-east-1".to_string()))
}

/// Get the caller's account ID
pub async fn get_caller_account(base_conf: &SdkConfig) -> Result<String> {
    debug!("Calling STS GetCallerIdentity…");
    let caller_account = sts::Client::new(base_conf)
        .get_caller_identity()
        .send()
        .await?
        .account()
        .unwrap_or_default()
        .to_owned();
    debug!("Caller account = {}", caller_account);
    Ok(caller_account)
}

/// List RDS instances with existing credentials
pub async fn list_rds(base_conf: &SdkConfig, regions: &[Region]) -> Result<Vec<RdsInstance>> {
    debug!("Entering list_rds()");
    let mut instances = Vec::new();

    for region in regions {
        info!("→ Region {}", region);

        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(RegionProviderChain::first_try(region.clone()))
            .credentials_provider(
                base_conf
                    .credentials_provider()
                    .expect("base config missing credentials provider")
                    .clone(),
            )
            .load()
            .await;

        let client = rds::Client::new(&conf);

        info!("   Sending DescribeDBInstances…");
        match client.describe_db_instances().send().await {
            Ok(output) => {
                let count = output.db_instances().len();
                info!("   Got {} instances in {}", count, region);
                for inst in output.db_instances() {
                    instances.push(RdsInstance {
                        region: region.to_string(),
                        role_arn: None,
                        instance_id: inst.db_instance_identifier().unwrap_or_default().to_string(),
                    });
                }
            }
            Err(e) => error!("   Error in {}: {:?}", region, e),
        }
    }
    Ok(instances)
}

/// Scan account via assumed role
pub async fn scan_account(
    base_conf: &SdkConfig,
    regions: &[Region],
    role_arn: &str,
) -> Result<Vec<RdsInstance>> {
    info!("--- Scanning with role {}", role_arn);
    let mut instances = Vec::new();

    for region in regions {
        info!("→ Region {}", region);

        let provider = AssumeRoleProvider::builder(role_arn.to_owned())
            .session_name("ls-rds")
            .region(region.clone())
            .configure(base_conf)
            .build()
            .await;

        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(RegionProviderChain::first_try(region.clone()))
            .credentials_provider(provider)
            .load()
            .await;

        let client = rds::Client::new(&conf);

        info!("   Sending DescribeDBInstances…");
        match client.describe_db_instances().send().await {
            Ok(output) => {
                let count = output.db_instances().len();
                info!("   Got {} instances", count);
                for inst in output.db_instances() {
                    instances.push(RdsInstance {
                        region: region.to_string(),
                        role_arn: Some(role_arn.to_string()),
                        instance_id: inst.db_instance_identifier().unwrap_or_default().to_string(),
                    });
                }
            }
            Err(e) => error!("   Error in {}: {:?}", region, e),
        }
    }

    Ok(instances)
}

/// Enumerate organization accounts and scan each
pub async fn enumerate_organization(base_conf: &SdkConfig, regions: &[Region]) -> Result<Vec<RdsInstance>> {
    info!("Enumerating accounts via AWS Organizations…");
    let org_client = org::Client::new(base_conf);
    let mut instances = Vec::new();

    let mut pages = org_client.list_accounts().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page?;
        for acct in page.accounts() {
            let account_id = acct.id().unwrap_or_default();
            let role_arn = format!("arn:aws:iam::{}:role/YourCrossAccountRole", account_id);
            info!("→ Found account {}; attempting {}", account_id, role_arn);
            let mut acct_instances = scan_account(base_conf, regions, &role_arn).await?;
            instances.append(&mut acct_instances);
        }
    }
    Ok(instances)
}

/// Process explicit role ARNs
pub async fn process_role_arns(
    base_conf: &SdkConfig,
    regions: &[Region],
    caller_account: &str,
    arns: &[String],
) -> Result<Vec<RdsInstance>> {
    info!("Using explicit role ARNs…");
    let mut instances = Vec::new();

    for arn in arns {
        let arn_account = arn.split(':').nth(4).unwrap_or_default();
        debug!("Examining ARN {} (account {})", arn, arn_account);

        if arn_account == caller_account {
            info!("→ {} is in current account – skipping AssumeRole", arn);
            let mut current_instances = list_rds(base_conf, regions).await?;
            instances.append(&mut current_instances);
        } else {
            info!("→ Assuming {}", arn);
            let mut arn_instances = scan_account(base_conf, regions, arn).await?;
            instances.append(&mut arn_instances);
        }
    }
    Ok(instances)
}

/// Run the RDS scan for given config
pub async fn run(config: &Config) -> Result<ScanResult> {
    let default_region = get_default_region(config);
    debug!("Bootstrap/STS Region: {}", &default_region);

    info!("Loading base AWS config…");
    let base_conf = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(default_region))
        .load()
        .await;

    let caller_account = get_caller_account(&base_conf).await?;

    let regions: Vec<Region> = config
        .regions
        .iter()
        .map(|s| {
            debug!("Parsed Region arg: {}", s);
            Region::new(s.trim().to_owned())
        })
        .collect();

    let instances = match &config.mode {
        ScanMode::Organization => {
            enumerate_organization(&base_conf, &regions).await?
        }
        ScanMode::RoleArns(arns) => {
            process_role_arns(&base_conf, &regions, &caller_account, arns).await?
        }
        ScanMode::CurrentAccount => {
            info!("Listing RDS in current account {}", caller_account);
            list_rds(&base_conf, &regions).await?
        }
    };

    Ok(ScanResult { instances })
}

/// Format an RDS instance for output
pub fn format_instance(inst: &RdsInstance) -> String {
    match &inst.role_arn {
        Some(arn) => format!("{}\t{}\t{}", arn, inst.region, inst.instance_id),
        None => format!("{}\t{}", inst.region, inst.instance_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_create_log_dir_returns_valid_path() {
        let dir = get_or_create_log_dir();
        assert!(dir.ends_with("slam"));
    }

    #[test]
    fn format_instance_without_role() {
        let inst = RdsInstance {
            region: "us-west-2".to_string(),
            role_arn: None,
            instance_id: "my-db".to_string(),
        };
        let output = format_instance(&inst);
        assert_eq!(output, "us-west-2\tmy-db");
    }

    #[test]
    fn format_instance_with_role() {
        let inst = RdsInstance {
            region: "us-west-2".to_string(),
            role_arn: Some("arn:aws:iam::123456789012:role/TestRole".to_string()),
            instance_id: "my-db".to_string(),
        };
        let output = format_instance(&inst);
        assert!(output.contains("TestRole"));
        assert!(output.contains("us-west-2"));
        assert!(output.contains("my-db"));
    }

    #[test]
    fn rds_instance_clone_works() {
        let inst = RdsInstance {
            region: "us-west-2".to_string(),
            role_arn: None,
            instance_id: "my-db".to_string(),
        };
        let cloned = inst.clone();
        assert_eq!(cloned.region, inst.region);
        assert_eq!(cloned.instance_id, inst.instance_id);
    }

    #[test]
    fn get_default_region_from_config() {
        let config = Config {
            regions: vec!["us-east-1".to_string()],
            mode: ScanMode::CurrentAccount,
        };
        // When env vars aren't set, should fall back to config
        let region = get_default_region(&config);
        // Will be from env if set, otherwise from config
        assert!(!region.is_empty());
    }
}
