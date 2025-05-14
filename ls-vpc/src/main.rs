//! ls-vpc – v0.1.1
//! Lists resources that live inside a given VPC ID.
//! Implemented scanners (thread-safe via async-trait + boxed dyn):
//!   • EC2 instances / ENIs / NAT gateways / FlowLogs
//!   • ELBv2 load balancers & target groups
//!   • RDS instances & clusters
//!   • DocumentDB clusters
//! The table now prints the Region, removing the dead-code warning.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::Instant,
};

use async_trait::async_trait;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_sdk_docdb as docdb;
use aws_sdk_ec2 as ec2;
use aws_sdk_elasticloadbalancingv2 as elbv2;
use aws_sdk_rds as rds;
use aws_types::{region::Region, SdkConfig};
use clap::Parser;
use eyre::Result;
use futures::{stream, StreamExt};
use log::{error, info, trace};

/*──────────────────────────── data ───────────────────────────*/

#[derive(Debug)]
struct ResourceRecord {
    arn:    String,
    rtype:  &'static str,
    name:   String,
    region: String,
}

/*──────────────────────────── CLI ────────────────────────────*/

#[derive(Parser, Debug)]
#[command(name = "ls-vpc", author, version, about)]
struct Opt {
    #[clap(long, required = true)]
    vpc_id: String,

    /// Regions, comma- or space-separated
    #[clap(
        long,
        value_delimiter = ',',
        num_args = 1..,
        default_values = ["us-east-1", "us-west-2"]
    )]
    regions: Vec<String>,
}

/*────────────────── Scanner trait (dyn boxed) ─────────────────*/

#[async_trait]
trait ServiceScanner: Send + Sync {
    async fn scan(
        &self,
        sdk: &SdkConfig,
        region: &Region,
        vpc_id: &str,
    ) -> Result<Vec<ResourceRecord>>;
}

/*───────────────── EC2-family scanner ─────────────────────────*/

struct Ec2Scanner;
#[async_trait]
impl ServiceScanner for Ec2Scanner {
    async fn scan(
        &self,
        sdk: &SdkConfig,
        region: &Region,
        vpc_id: &str,
    ) -> Result<Vec<ResourceRecord>> {
        let client = ec2::Client::new(sdk);
        let mut recs = Vec::new();

        // instances
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
                    arn: format!(
                        "arn:aws:ec2:{}::instance/{}",
                        region.as_ref(),
                        inst.instance_id().unwrap_or_default()
                    ),
                    rtype: "ec2.instance",
                    name: inst
                        .tags()
                        .iter()
                        .find(|t| t.key() == Some("Name"))
                        .and_then(|t| t.value())
                        .unwrap_or_default()
                        .to_owned(),
                    region: region.as_ref().into(),
                });
            }
        }

        // enis
        let enis = client
            .describe_network_interfaces()
            .filters(
                ec2::types::Filter::builder()
                    .name("vpc-id")
                    .values(vpc_id)
                    .build(),
            )
            .send()
            .await?;
        for eni in enis.network_interfaces() {
            recs.push(ResourceRecord {
                arn: format!(
                    "arn:aws:ec2:{}::network-interface/{}",
                    region.as_ref(),
                    eni.network_interface_id().unwrap_or_default()
                ),
                rtype: "ec2.eni",
                name: eni.description().unwrap_or_default().to_owned(),
                region: region.as_ref().into(),
            });
        }

        // NAT gateways
        let nat_gws = client
            .describe_nat_gateways()
            .filter(
                ec2::types::Filter::builder()
                    .name("vpc-id")
                    .values(vpc_id)
                    .build(),
            )
            .send()
            .await?;
        for ngw in nat_gws.nat_gateways() {
            recs.push(ResourceRecord {
                arn: format!(
                    "arn:aws:ec2:{}::natgateway/{}",
                    region.as_ref(),
                    ngw.nat_gateway_id().unwrap_or_default()
                ),
                rtype: "ec2.nat-gateway",
                name: ngw.nat_gateway_id().unwrap_or_default().to_owned(),
                region: region.as_ref().into(),
            });
        }

        // flow logs
        let flow_logs = client
            .describe_flow_logs()
            .filter(
                ec2::types::Filter::builder()
                    .name("resource-id")
                    .values(vpc_id)
                    .build(),
            )
            .send()
            .await?;
        for fl in flow_logs.flow_logs() {
            recs.push(ResourceRecord {
                arn: fl.flow_log_id().unwrap_or_default().to_owned(),
                rtype: "ec2.flow-log",
                name: fl.log_group_name().unwrap_or_default().to_owned(),
                region: region.as_ref().into(),
            });
        }

        Ok(recs)
    }
}

/*───────────────── ELBv2 scanner ─────────────────────────────*/

struct ElbScanner;
#[async_trait]
impl ServiceScanner for ElbScanner {
    async fn scan(
        &self,
        sdk: &SdkConfig,
        region: &Region,
        vpc_id: &str,
    ) -> Result<Vec<ResourceRecord>> {
        let client = elbv2::Client::new(sdk);
        let mut recs = Vec::new();

        for lb in client.describe_load_balancers().send().await?.load_balancers() {
            if lb.vpc_id() == Some(vpc_id) {
                recs.push(ResourceRecord {
                    arn: lb.load_balancer_arn().unwrap_or_default().to_owned(),
                    rtype: "elbv2.load-balancer",
                    name: lb.load_balancer_name().unwrap_or_default().to_owned(),
                    region: region.as_ref().into(),
                });
            }
        }

        for tg in client.describe_target_groups().send().await?.target_groups() {
            if tg.vpc_id() == Some(vpc_id) {
                recs.push(ResourceRecord {
                    arn: tg.target_group_arn().unwrap_or_default().to_owned(),
                    rtype: "elbv2.target-group",
                    name: tg.target_group_name().unwrap_or_default().to_owned(),
                    region: region.as_ref().into(),
                });
            }
        }
        Ok(recs)
    }
}

/*────────────── RDS / Aurora / DocDB scanner ───────────────*/

struct RdsScanner;
#[async_trait]
impl ServiceScanner for RdsScanner {
    async fn scan(
        &self,
        sdk: &SdkConfig,
        region: &Region,
        vpc_id: &str,
    ) -> Result<Vec<ResourceRecord>> {
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
                    region: region.as_ref().into(),
                });
            }
        }

        for cl in client.describe_db_clusters().send().await?.db_clusters() {
            recs.push(ResourceRecord {
                arn: cl.db_cluster_arn().unwrap_or_default().to_owned(),
                rtype: "rds.cluster",
                name: cl.db_cluster_identifier().unwrap_or_default().to_owned(),
                region: region.as_ref().into(),
            });
        }

        let dclient = docdb::Client::new(sdk);
        for cl in dclient.describe_db_clusters().send().await?.db_clusters() {
            recs.push(ResourceRecord {
                arn: cl.db_cluster_arn().unwrap_or_default().to_owned(),
                rtype: "docdb.cluster",
                name: cl.db_cluster_identifier().unwrap_or_default().to_owned(),
                region: region.as_ref().into(),
            });
        }
        Ok(recs)
    }
}

/*────────────────────────── main ──────────────────────────*/

#[tokio::main]
async fn main() -> Result<()> {
    // logging
    let log_dir = get_or_create_log_dir();
    let log_file = log_dir.join("ls-vpc.log");
    let fh = OpenOptions::new().create(true).append(true).open(&log_file)?;
    env_logger::Builder::from_default_env()
        .format(|buf, rec| {
            let ts = buf.timestamp_millis();
            writeln!(buf, "{} {:<5} [{}] {}", ts, rec.level(), rec.target(), rec.args())
        })
        .target(env_logger::Target::Pipe(Box::new(fh)))
        .filter_level(log::LevelFilter::Trace)
        .init();
    info!("Log → {}", log_file.display());

    // CLI / AWS bootstrap
    let opt = Opt::parse();
    info!("VPC   : {}", opt.vpc_id);
    info!("Regions: {:?}", opt.regions);

    let bootstrap_region = &opt.regions[0];
    let base_conf = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(bootstrap_region.clone()))
        .load()
        .await;

    let regions: Vec<Region> = opt
        .regions
        .iter()
        .map(|s| Region::new(s.to_owned()))
        .collect();

    let registry: Vec<(&str, Box<dyn ServiceScanner>)> = vec![
        ("ec2", Box::new(Ec2Scanner)),
        ("elbv2", Box::new(ElbScanner)),
        ("rds", Box::new(RdsScanner)),
    ];

    let start = Instant::now();
    let mut all: Vec<ResourceRecord> = Vec::new();

    for region in &regions {
        info!("Scanning {}", region.as_ref());

        let tasks = registry.iter().map(|(name, scanner)| {
            let vpc_id = opt.vpc_id.clone();
            let region = region.clone();
            let creds = base_conf.credentials_provider().unwrap().clone();
            let name = *name;
            async move {
                let conf = aws_config::defaults(BehaviorVersion::latest())
                    .region(RegionProviderChain::first_try(region.clone()))
                    .credentials_provider(creds)
                    .load()
                    .await;
                trace!("{name} scanner in {}", region.as_ref());
                scanner.scan(&conf, &region, &vpc_id).await.map_err(|e| {
                    error!("{name} error in {}: {:?}", region.as_ref(), e);
                    e
                })
            }
        });

        let region_recs: Vec<Vec<ResourceRecord>> = stream::iter(tasks)
            .buffer_unordered(6)
            .filter_map(|r| async { r.ok() })
            .collect()
            .await;

        for mut recs in region_recs {
            all.append(&mut recs);
        }
    }

    // output
    info!("Finished in {:.2?}", start.elapsed());
    println!("{:<10} {:<22} {:<28} {}", "REGION", "TYPE", "NAME", "ARN");
    println!("{}", "-".repeat(100));
    for rec in &all {
        println!(
            "{:<10} {:<22} {:<28} {}",
            rec.region, rec.rtype, rec.name, rec.arn
        );
    }
    println!("Total: {}", all.len());
    Ok(())
}

/*──────────────── helper: log directory ─────────────────*/

fn get_or_create_log_dir() -> PathBuf {
    let dir = {
        #[cfg(target_os = "macos")]
        {
            env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("Library")
                .join("Logs")
                .join("slam")
        }
        #[cfg(not(target_os = "macos"))]
        {
            if let Ok(x) = env::var("XDG_STATE_HOME") {
                PathBuf::from(x).join("slam")
            } else if let Ok(h) = env::var("HOME") {
                PathBuf::from(h).join(".local").join("state").join("slam")
            } else {
                PathBuf::from("slam_logs")
            }
        }
    };
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("‼️  couldn't create {}: {}", dir.display(), e);
    }
    dir
}
