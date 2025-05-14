// src/main.rs

//! List every RDS DB instance in the current account (and, optionally, across
//! other accounts or explicit role ARNs). All log output is written to a file
//! whose location is chosen by `get_or_create_log_dir()`; nothing is printed to
//! the terminal unless you explicitly `tail -f` the file.

use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_config::sts::AssumeRoleProvider;
use aws_sdk_organizations as org;
use aws_sdk_rds as rds;
use aws_sdk_sts as sts;
use aws_types::{region::Region, SdkConfig};
use clap::Parser;
use eyre::Result;
use log::{debug, error, info};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::Instant,
};

#[derive(Parser, Debug)]
struct Opt {
    /// Enumerate *all* accounts via AWS Organizations
    #[clap(long)]
    use_org: bool,

    /// One or more specific role ARNs (mutually exclusive with --use-org)
    #[clap(long, conflicts_with = "use_org")]
    role_arns: Vec<String>,

    /// Comma‑separated AWS Regions to scan
    #[clap(long, default_value = "us-east-1,us-west-2")]
    regions: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ───────────── setup file logging ─────────────
    let log_dir = get_or_create_log_dir();
    let log_file_path = log_dir.join("ls-rds.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)?;
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            let ts = buf.timestamp_millis();
            writeln!(
                buf,
                "{} {:<5} [{}] {}",
                ts,
                record.level(),
                record.target(),
                record.args()
            )
        })
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .filter_level(log::LevelFilter::Trace)
        .init();

    info!("Logging to {}", log_file_path.display());

    let overall_start = Instant::now();
    let opt = Opt::parse();
    debug!("CLI options parsed: {:?}", opt);

    // ───── choose a bootstrap Region ─────
    let default_region = env::var("AWS_REGION")
        .or_else(|_| env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| {
            opt.regions
                .split(',')
                .next()
                .unwrap_or("us-east-1")
                .trim()
                .to_owned()
        });
    debug!("Default Region for bootstrap/STSes: {}", default_region);

    // ───── build base config ─────
    info!("Loading base AWS config…");
    let base_conf = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(default_region.clone()))
        .load()
        .await;
    debug!(
        "Loaded base config in {:.2?} (Region = {:?})",
        overall_start.elapsed(),
        base_conf.region().map(|r| r.as_ref())
    );

    // ───── figure out current account ─────
    debug!("Calling STS GetCallerIdentity…");
    let caller_account = sts::Client::new(&base_conf)
        .get_caller_identity()
        .send()
        .await?
        .account()
        .unwrap_or_default()
        .to_owned();
    debug!("Caller account = {}", caller_account);

    // ───── parse Regions argument ─────
    let regions: Vec<Region> = opt
        .regions
        .split(',')
        .map(|s| Region::new(s.trim().to_owned()))
        .collect();
    debug!("Regions to scan: {:?}", regions);

    // ───── choose execution path ─────
    if opt.use_org {
        enumerate_organization(&base_conf, &regions).await?;
    } else if !opt.role_arns.is_empty() {
        process_role_arns(&base_conf, &regions, &caller_account, &opt.role_arns).await?;
    } else {
        info!("Listing RDS in current account {}", caller_account);
        list_rds(&base_conf, &regions).await?;
    }

    info!("Total runtime: {:.2?}", overall_start.elapsed());
    Ok(())
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

// ------------- helper: enumerate Organization -------------
async fn enumerate_organization(base_conf: &SdkConfig, regions: &[Region]) -> Result<()> {
    info!("Enumerating accounts via AWS Organizations…");
    let org_client = org::Client::new(base_conf);
    let mut pages = org_client.list_accounts().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page?;
        for acct in page.accounts() {
            let account_id = acct.id().unwrap_or_default();
            let role_arn = format!("arn:aws:iam::{}:role/YourCrossAccountRole", account_id);
            info!("→ Found account {}; attempting {}", account_id, role_arn);
            scan_account(base_conf, regions, &role_arn).await?;
        }
    }
    Ok(())
}

// ------------- helper: process --role-arns -------------
async fn process_role_arns(
    base_conf: &SdkConfig,
    regions: &[Region],
    caller_account: &str,
    arns: &[String],
) -> Result<()> {
    info!("Using explicit role ARNs…");
    for arn in arns {
        let arn_account = arn.split(':').nth(4).unwrap_or_default();
        debug!("Examining ARN {} (account {})", arn, arn_account);

        if arn_account == caller_account {
            info!("→ {} is in current account – skipping AssumeRole", arn);
            list_rds(base_conf, regions).await?;
        } else {
            info!("→ Assuming {}", arn);
            scan_account(base_conf, regions, arn).await?;
        }
    }
    Ok(())
}

// ------------- helper: list RDS with existing creds -------------
async fn list_rds(base_conf: &SdkConfig, regions: &[Region]) -> Result<()> {
    debug!("Entering list_rds()");
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
                    println!(
                        "{}\t{}",
                        region,
                        inst.db_instance_identifier().unwrap_or_default()
                    );
                }
            }
            Err(e) => error!("   Error in {}: {:?}", region, e),
        }
    }
    Ok(())
}

// ------------- helper: AssumeRole then list RDS -------------
async fn scan_account(
    base_conf: &SdkConfig,
    regions: &[Region],
    role_arn: &str,
) -> Result<()> {
    info!("--- Scanning with role {}", role_arn);
    let scan_start = Instant::now();

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
                    println!(
                        "{}\t{}\t{}",
                        role_arn,
                        region,
                        inst.db_instance_identifier().unwrap_or_default()
                    );
                }
            }
            Err(e) => error!("   Error in {}: {:?}", region, e),
        }
    }

    info!(
        "Finished scanning {} in {:.2?}",
        role_arn,
        scan_start.elapsed()
    );
    Ok(())
}
