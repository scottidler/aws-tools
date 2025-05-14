//! ls-vpc v0.3.3
//! ---------------------------------------------------------------------------
//! • Scan one or many VPCs in the Regions you list (`--regions` is required).
//! • If you pass no VPC IDs (positional), every VPC in those Regions is scanned.
//! • Prints whether each VPC is public (IGW attached) and/or peered.
//! • Writes full TRACE logs to:
//!       macOS   ~/Library/Logs/slam/ls-vpc.log
//!       Linux   ~/.local/state/slam/ls-vpc/ls-vpc.log   (or  $XDG_STATE_HOME)

// std ───────────────────────────────────────────────────────────────
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::Instant,
};

// deps ──────────────────────────────────────────────────────────────
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_docdb as docdb;
use aws_sdk_ec2 as ec2;
use aws_sdk_elasticloadbalancingv2 as elbv2;
use aws_sdk_rds as rds;
use aws_types::{region::Region, SdkConfig};
use clap::{Parser, ValueHint};
use eyre::{eyre, Result};
use log::{error, info, trace};
use env_logger::Target;

/*──────────────────────── data structures ─────────────────────────*/

#[derive(Debug)]
struct ResourceRecord {
    arn: String,
    rtype: &'static str,
    name: String,
}

#[derive(Debug)]
struct VpcSummary {
    name: Option<String>,
    public: bool,
    peered: bool,
    resources: Vec<ResourceRecord>,
}

/*──────────────────────── CLI definition ──────────────────────────*/

#[derive(Parser, Debug)]
#[command(name = "ls-vpc", author, version, about)]
struct Opt {
    /// Comma- or space-separated list of Regions (required)
    #[clap(
        long,
        value_delimiter = ',',
        num_args = 1..,
        value_hint = ValueHint::Other
    )]
    regions: Vec<String>,

    /// Zero or more VPC IDs.  If none given, all VPCs are scanned.
    #[clap(value_name = "VPC_ID", value_hint = ValueHint::Other)]
    vpc_ids: Vec<String>,
}

/*──────────────────────── scanner trait ───────────────────────────*/

#[async_trait]
trait ServiceScanner: Send + Sync {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>>;
}

/*──────────────────────── EC2 scanner ─────────────────────────────*/

struct Ec2Scanner;
#[async_trait]
impl ServiceScanner for Ec2Scanner {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>> {
        let client = ec2::Client::new(sdk);
        let mut recs = Vec::new();

        // Instances
        let mut pages = client
            .describe_instances()
            .filters(
                ec2::types::Filter::builder()
                    .name("vpc-id")
                    .values(vpc_id)
                    .build(),
            )
            .into_paginator()
            .items()
            .send();
        while let Some(res) = pages.next().await {
            for inst in res?.instances() {
                recs.push(ResourceRecord {
                    arn: inst.instance_id().unwrap_or_default().to_owned(),
                    rtype: "ec2.instance",
                    name: inst
                        .tags()
                        .iter()
                        .find(|t| t.key() == Some("Name"))
                        .and_then(|t| t.value())
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
        }

        // ENIs
        for eni in client
            .describe_network_interfaces()
            .filters(
                ec2::types::Filter::builder()
                    .name("vpc-id")
                    .values(vpc_id)
                    .build(),
            )
            .send()
            .await?
            .network_interfaces()
        {
            recs.push(ResourceRecord {
                arn: eni.network_interface_id().unwrap_or_default().to_owned(),
                rtype: "ec2.eni",
                name: eni.description().unwrap_or_default().to_owned(),
            });
        }

        // NAT Gateways
        for ngw in client
            .describe_nat_gateways()
            .filter(
                ec2::types::Filter::builder()
                    .name("vpc-id")
                    .values(vpc_id)
                    .build(),
            )
            .send()
            .await?
            .nat_gateways()
        {
            recs.push(ResourceRecord {
                arn: ngw.nat_gateway_id().unwrap_or_default().to_owned(),
                rtype: "ec2.nat-gateway",
                name: ngw.nat_gateway_id().unwrap_or_default().to_owned(),
            });
        }

        // Flow Logs
        for fl in client
            .describe_flow_logs()
            .filter(
                ec2::types::Filter::builder()
                    .name("resource-id")
                    .values(vpc_id)
                    .build(),
            )
            .send()
            .await?
            .flow_logs()
        {
            recs.push(ResourceRecord {
                arn: fl.flow_log_id().unwrap_or_default().to_owned(),
                rtype: "ec2.flow-log",
                name: fl.log_group_name().unwrap_or_default().to_owned(),
            });
        }

        Ok(recs)
    }
}

/*──────────────────────── ELBv2 scanner ───────────────────────────*/

struct ElbScanner;
#[async_trait]
impl ServiceScanner for ElbScanner {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>> {
        let client = elbv2::Client::new(sdk);
        let mut recs = Vec::new();

        for lb in client.describe_load_balancers().send().await?.load_balancers() {
            if lb.vpc_id() == Some(vpc_id) {
                recs.push(ResourceRecord {
                    arn: lb.load_balancer_arn().unwrap_or_default().to_owned(),
                    rtype: "elbv2.load-balancer",
                    name: lb.load_balancer_name().unwrap_or_default().to_owned(),
                });
            }
        }

        for tg in client.describe_target_groups().send().await?.target_groups() {
            if tg.vpc_id() == Some(vpc_id) {
                recs.push(ResourceRecord {
                    arn: tg.target_group_arn().unwrap_or_default().to_owned(),
                    rtype: "elbv2.target-group",
                    name: tg.target_group_name().unwrap_or_default().to_owned(),
                });
            }
        }
        Ok(recs)
    }
}

/*────────────────── RDS / DocDB scanner ──────────────────────────*/

struct RdsScanner;
#[async_trait]
impl ServiceScanner for RdsScanner {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>> {
        let client = rds::Client::new(sdk);
        let mut recs = Vec::new();

        for db in client.describe_db_instances().send().await?.db_instances() {
            if db
                .db_subnet_group()
                .and_then(|g| g.vpc_id())
                == Some(vpc_id)
            {
                recs.push(ResourceRecord {
                    arn: db.db_instance_arn().unwrap_or_default().to_owned(),
                    rtype: "rds.instance",
                    name: db.db_instance_identifier().unwrap_or_default().to_owned(),
                });
            }
        }

        for cl in client.describe_db_clusters().send().await?.db_clusters() {
            recs.push(ResourceRecord {
                arn: cl.db_cluster_arn().unwrap_or_default().to_owned(),
                rtype: "rds.cluster",
                name: cl.db_cluster_identifier().unwrap_or_default().to_owned(),
            });
        }

        let dclient = docdb::Client::new(sdk);
        for cl in dclient.describe_db_clusters().send().await?.db_clusters() {
            recs.push(ResourceRecord {
                arn: cl.db_cluster_arn().unwrap_or_default().to_owned(),
                rtype: "docdb.cluster",
                name: cl.db_cluster_identifier().unwrap_or_default().to_owned(),
            });
        }
        Ok(recs)
    }
}

/*────────────────── VPC helpers ──────────────────────────*/

async fn discover_vpcs(
    conf: &SdkConfig,
    filter_ids: &[String],
) -> Result<Vec<(String, Option<String>)>> {
    let client = ec2::Client::new(conf);
    let mut req = client.describe_vpcs();
    for id in filter_ids {
        req = req.vpc_ids(id);
    }
    let resp = req.send().await?;
    Ok(resp
        .vpcs()
        .iter()
        .map(|v| {
            let name = v
                .tags()
                .iter()
                .find(|t| t.key() == Some("Name"))
                .and_then(|t| t.value())
                .map(|s| s.to_owned());
            (v.vpc_id().unwrap_or_default().to_owned(), name)
        })
        .collect())
}

async fn classify_vpc(conf: &SdkConfig, vpc_id: &str) -> Result<(bool, bool)> {
    let ec2c = ec2::Client::new(conf);

    let public = !ec2c
        .describe_internet_gateways()
        .filters(
            ec2::types::Filter::builder()
                .name("attachment.vpc-id")
                .values(vpc_id)
                .build(),
        )
        .send()
        .await?
        .internet_gateways()
        .is_empty();

    let peered = ec2c
        .describe_vpc_peering_connections()
        .filters(
            ec2::types::Filter::builder()
                .name("requester-vpc-info.vpc-id")
                .values(vpc_id)
                .build(),
        )
        .send()
        .await?
        .vpc_peering_connections()
        .iter()
        .any(|pc| {
            matches!(
                pc.status().and_then(|s| s.code()),
                Some(ec2::types::VpcPeeringConnectionStateReasonCode::Active)
            )
        });

    Ok((public, peered))
}

/*────────────────────────── main ──────────────────────────*/

#[tokio::main]
async fn main() -> Result<()> {
    /* ───── CLI and logging ───── */
    let opt = Opt::parse();
    if opt.regions.is_empty() {
        return Err(eyre!("--regions is required"));
    }

    let log_file = get_or_create_log_dir().join("ls-vpc.log");
    let fh = OpenOptions::new().create(true).append(true).open(&log_file)?;
    env_logger::Builder::from_default_env()
        .format(|buf, rec| {
            let ts = buf.timestamp_millis();
            writeln!(
                buf,
                "{} {:<5} [{:<15}] {}",
                ts,
                rec.level(),
                rec.target(),
                rec.args()
            )
        })
        .target(Target::Pipe(Box::new(fh)))
        .filter_level(log::LevelFilter::Trace)
        .init();
    info!("Logging to {}", log_file.display());

    /* ───── scanner registry ───── */
    let scanners: Vec<Box<dyn ServiceScanner>> =
        vec![Box::new(Ec2Scanner), Box::new(ElbScanner), Box::new(RdsScanner)];

    let mut vpcs: std::collections::BTreeMap<(String, String), VpcSummary> = Default::default();
    let start = Instant::now();

    for region_name in &opt.regions {
        info!("Region {}", region_name);
        let region = Region::new(region_name.clone());
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(region.clone())
            .load()
            .await;

        // discover vpcs
        let discovered = discover_vpcs(&conf, &opt.vpc_ids).await?;
        trace!("found {} VPCs", discovered.len());

        for (vpc_id, vpc_name) in discovered {
            let (public, peered) = classify_vpc(&conf, &vpc_id).await?;
            trace!("{} {} public={} peered={}", region_name, vpc_id, public, peered);

            let mut summary = VpcSummary {
                name: vpc_name,
                public,
                peered,
                resources: Vec::new(),
            };

            for s in &scanners {
                match s.scan(&conf, &vpc_id).await {
                    Ok(mut r) => summary.resources.append(&mut r),
                    Err(e) => error!("scan error {} {}: {:?}", region_name, vpc_id, e),
                }
            }

            vpcs.insert((region_name.clone(), vpc_id), summary);
        }
    }

    /* ───── output ───── */
    println!(
        "{:<10} {:<15} {:<25} {:<10} {:<6}",
        "REGION", "VPC-ID", "NAME", "VISIBILITY", "PEERED"
    );
    println!("{}", "-".repeat(95));

    for ((region, vpc_id), summary) in &vpcs {
        println!(
            "{:<10} {:<15} {:<25} {:<10} {:<6}",
            region,
            vpc_id,
            summary.name.as_deref().unwrap_or(""),
            if summary.public { "public" } else { "private" },
            if summary.peered { "true" } else { "false" }
        );
        for r in &summary.resources {
            println!("  {:<22} {:<28} {}", r.rtype, r.name, r.arn);
        }
        println!();
    }

    println!(
        "Scanned {} VPC(s) across {} Region(s) in {:.2?}",
        vpcs.len(),
        opt.regions.len(),
        start.elapsed()
    );
    Ok(())
}

/*──────────── log directory helper ───────────*/

fn get_or_create_log_dir() -> PathBuf {
    let dir = if cfg!(target_os = "macos") {
        env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("Library")
            .join("Logs")
            .join("slam")
    } else if let Ok(x) = env::var("XDG_STATE_HOME") {
        PathBuf::from(x).join("slam")
    } else if let Ok(h) = env::var("HOME") {
        PathBuf::from(h).join(".local").join("state").join("slam")
    } else {
        PathBuf::from("slam_logs")
    };
    fs::create_dir_all(&dir).ok();
    dir
}
