// src/main.rs

//! List every RDS DB instance in the current account (and, optionally, in other
//! accounts/roles).  Uses very chatty logging so you can see *every* decision
//! and AWS call that happens.

use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_config::sts::AssumeRoleProvider;
use aws_sdk_organizations as org;
use aws_sdk_rds as rds;
use aws_sdk_sts as sts;
use aws_types::{region::Region, SdkConfig};
use clap::Parser;
use eyre::Result;
use log::{debug, error, info};
use std::{env, time::Instant};

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
    // ─────────────── logger ───────────────
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Trace) // show EVERYthing
        .init();

    let overall_start = Instant::now();
    let opt = Opt::parse();
    debug!("CLI options parsed: {:?}", opt);

    // ─────── determine a default Region for STS/bootstrap ──────
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
    debug!("Chosen default Region for bootstrap/STSes: {}", default_region);

    // ─────────── base config (with a Region) ───────────
    info!("Loading base AWS config…");
    let base_conf = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(default_region.clone()))
        .load()
        .await;
    debug!(
        "Loaded base config in {:.2?}  (Region = {:?})",
        overall_start.elapsed(),
        base_conf.region().map(|r| r.as_ref())
    );

    // ─── discover which account these credentials belong to ───
    debug!("Calling STS GetCallerIdentity…");
    let caller_identity_start = Instant::now();
    let caller_account = sts::Client::new(&base_conf)
        .get_caller_identity()
        .send()
        .await?
        .account()
        .unwrap_or_default()
        .to_owned();
    debug!(
        "STS GetCallerIdentity returned account {} in {:.2?}",
        caller_account,
        caller_identity_start.elapsed()
    );

    // ───────── parse requested Regions ─────────
    let regions: Vec<Region> = opt
        .regions
        .split(',')
        .map(|s| {
            let s = s.trim();
            debug!("Parsed Region argument: {}", s);
            Region::new(s.to_owned())
        })
        .collect();
    debug!("Final list of Regions to scan: {:?}", regions);

    // ───────────────── execution paths ─────────────────
    if opt.use_org {
        // A) Enumerate every account in the Organization
        enumerate_organization(&base_conf, &regions).await?;
    } else if !opt.role_arns.is_empty() {
        // B) Use explicit role ARNs
        process_role_arns(&base_conf, &regions, &caller_account, &opt.role_arns).await?;
    } else {
        // C) No role ARNs → just use current creds
        info!("Listing RDS in *current* account {}", caller_account);
        list_rds(&base_conf, &regions).await?;
    }

    info!("Total runtime: {:.2?}", overall_start.elapsed());
    Ok(())
}

// ───────────────── helper: enumerate Organization ─────────────────
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

// ───────────────── helper: process --role-arns ────────────────────
async fn process_role_arns(
    base_conf: &SdkConfig,
    regions: &[Region],
    caller_account: &str,
    arns: &[String],
) -> Result<()> {
    info!("Using explicit role ARNs…");
    for arn in arns {
        let arn_account = arn.split(':').nth(4).unwrap_or_default();
        debug!(
            "Examining ARN {}  (account = {}, caller_account = {})",
            arn, arn_account, caller_account
        );

        if arn_account == caller_account {
            info!("→ {} is the *current* account – skipping AssumeRole", arn);
            list_rds(base_conf, regions).await?;
        } else {
            info!("→ Assuming {}", arn);
            scan_account(base_conf, regions, arn).await?;
        }
    }
    Ok(())
}

// ───────────────── helper: list with existing creds ───────────────
async fn list_rds(base_conf: &SdkConfig, regions: &[Region]) -> Result<()> {
    debug!("Entering list_rds()");
    for region in regions {
        info!("→ Region {}", region);

        debug!("  Building per‑Region config (no assume) …");
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
        debug!("  Config for {} built", region);

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

// ─────────── helper: AssumeRole then list RDS ────────────
async fn scan_account(base_conf: &SdkConfig, regions: &[Region], role_arn: &str) -> Result<()> {
    info!("--- Scanning with role {}", role_arn);
    let scan_start = Instant::now();

    for region in regions {
        info!("→ Region {}", region);
        debug!("  Building AssumeRoleProvider for {}", region);
        let provider = AssumeRoleProvider::builder(role_arn.to_owned())
            .session_name("ls-rds")
            .region(region.clone())
            .configure(base_conf)
            .build()
            .await;

        debug!("  Building per‑Region config with assumed creds…");
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
