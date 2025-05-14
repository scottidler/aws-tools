//! ls-vpc v0.2
//! ---------------------------------------------------------------------------
//!   • Lists every AWS resource that lives in the VPC you specify
//!   • Classifies that VPC per-Region as “public” (has an IGW) and/or “peered”
//!   • Implemented resource scanners
//!       – EC2: instances, ENIs, NAT Gateways, VPC Flow Logs
//!       – ELBv2: load balancers & target groups
//!       – RDS/Aurora: instances & clusters
//!       – DocumentDB clusters
//!
//! Usage example
//!   aws-vault exec prod -- ./target/release/ls-vpc \
//!       --vpc-id vpc-0abc123def456 \
//!       --regions us-west-2,us-east-1

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

/*──────────────────────── data models ───────────────────────*/

#[derive(Debug)]
struct ResourceRecord {
    arn:    String,
    rtype:  &'static str,
    name:   String,
    region: String,
}

#[derive(Debug)]
struct VpcClass {
    region: String,
    public: bool,
    peered: bool,
}

/*──────────────────────── CLI options ──────────────────────*/

#[derive(Parser, Debug)]
#[command(name = "ls-vpc", author, version, about)]
struct Opt {
    /// VPC ID like vpc-0123abcd
    #[clap(long, required = true)]
    vpc_id: String,

    /// Regions list, space- or comma-separated
    #[clap(
        long,
        value_delimiter = ',',
        num_args = 1..,
        default_values = ["us-east-1", "us-west-2"]
    )]
    regions: Vec<String>,
}

/*────────────────── generic scanner trait ──────────────────*/

#[async_trait]
trait ServiceScanner: Send + Sync {
    async fn scan(
        &self,
        sdk: &SdkConfig,
        region: &Region,
        vpc_id: &str,
    ) -> Result<Vec<ResourceRecord>>;
}

/*────────────────── EC2-family scanner ─────────────────────*/

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

        /* instances */
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

        /* ENIs */
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

        /* NAT Gateways */
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

        /* VPC Flow Logs */
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

/*────────────────── ELBv2 scanner ─────────────────────────*/

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

/*────────────── RDS / Aurora / DocDB scanner ──────────────*/

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

        /* RDS instances */
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

        /* RDS/Aurora clusters (no direct VPC field in SDK) */
        for cl in client.describe_db_clusters().send().await?.db_clusters() {
            recs.push(ResourceRecord {
                arn: cl.db_cluster_arn().unwrap_or_default().to_owned(),
                rtype: "rds.cluster",
                name: cl.db_cluster_identifier().unwrap_or_default().to_owned(),
                region: region.as_ref().into(),
            });
        }

        /* DocumentDB clusters */
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

/*────────────────── classify VPC helper ───────────────────*/

async fn classify_vpc(conf: &SdkConfig, region: &Region, vpc_id: &str) -> Result<VpcClass> {
    let ec2c = ec2::Client::new(conf);

    /* public? — any IGW attached */
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

    /* peered? — any ACTIVE VPC peering connection */
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
                pc.status()
                    .and_then(|s| s.code()),
                Some(ec2::types::VpcPeeringConnectionStateReasonCode::Active)
            )
        });

    Ok(VpcClass {
        region: region.as_ref().into(),
        public,
        peered,
    })
}

/*────────────────────────── main ──────────────────────────*/

#[tokio::main]
async fn main() -> Result<()> {
    /* logging setup */
    let log_dir = get_or_create_log_dir();
    let log_path = log_dir.join("ls-vpc.log");
    let fh = OpenOptions::new().create(true).append(true).open(&log_path)?;
    env_logger::Builder::from_default_env()
        .format(|buf, rec| {
            let ts = buf.timestamp_millis();
            writeln!(buf, "{} {:<5} [{}] {}", ts, rec.level(), rec.target(), rec.args())
        })
        .target(env_logger::Target::Pipe(Box::new(fh)))
        .filter_level(log::LevelFilter::Trace)
        .init();
    info!("Logs → {}", log_path.display());

    /* CLI + bootstrap config */
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
        .map(|s| Region::new(s.clone()))
        .collect();

    let registry: Vec<(&str, Box<dyn ServiceScanner>)> = vec![
        ("ec2", Box::new(Ec2Scanner)),
        ("elbv2", Box::new(ElbScanner)),
        ("rds", Box::new(RdsScanner)),
    ];

    /* scan + classify */
    let start = Instant::now();
    let mut classes: Vec<VpcClass> = Vec::new();
    let mut all_recs: Vec<ResourceRecord> = Vec::new();

    for region in &regions {
        info!("--- {}", region.as_ref());

        /* per-region SDK config reusing creds */
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(RegionProviderChain::first_try(region.clone()))
            .credentials_provider(base_conf.credentials_provider().unwrap().clone())
            .load()
            .await;

        /* classify */
        match classify_vpc(&conf, region, &opt.vpc_id).await {
            Ok(cls) => classes.push(cls),
            Err(e) => error!("classification error {}: {:?}", region.as_ref(), e),
        }

        /* scanners */
        let tasks = registry.iter().map(|(name, scanner)| {
            let vpc_id = opt.vpc_id.clone();
            let region = region.clone();
            let conf = conf.clone();
            let name = *name;
            async move {
                trace!("{name} scanner start {}", region.as_ref());
                scanner.scan(&conf, &region, &vpc_id).await.map_err(|e| {
                    error!("{name} error in {}: {:?}", region.as_ref(), e);
                    e
                })
            }
        });

        for mut vecs in stream::iter(tasks)
            .buffer_unordered(6)
            .filter_map(|r| async { r.ok() })
            .collect::<Vec<_>>()
            .await
        {
            all_recs.append(&mut vecs);
        }
    }

    /* output */
    info!("Finished in {:.2?}", start.elapsed());

    println!("\nVPC CLASSIFICATION");
    println!("{:<10} {:<6} {:<6}", "REGION", "PUBLIC", "PEERED");
    for cls in &classes {
        println!(
            "{:<10} {:<6} {:<6}",
            cls.region,
            if cls.public { "yes" } else { "no" },
            if cls.peered { "yes" } else { "no" }
        );
    }

    println!(
        "\n{:<10} {:<22} {:<28} {}",
        "REGION", "TYPE", "NAME", "ARN"
    );
    println!("{}", "-".repeat(100));
    for rec in &all_recs {
        println!(
            "{:<10} {:<22} {:<28} {}",
            rec.region, rec.rtype, rec.name, rec.arn
        );
    }
    println!("Total resources: {}", all_recs.len());
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
    fs::create_dir_all(&dir).unwrap_or_else(|e| {
        eprintln!("‼️  could not create {}: {}", dir.display(), e);
    });
    dir
}
