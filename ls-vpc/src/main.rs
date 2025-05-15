//! ls-vpc 0.6.1
//! ---------------------------------------------------------------------------
//! Summary  (no VPC IDs) → Comfy-table output
//! Detail   (with IDs)   → Custom ASCII output with “infra:” section
//! Any InvalidVpcID.NotFound error is **silently skipped** without panicking.

use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::Instant,
};

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_docdb as docdb;
use aws_sdk_ec2 as ec2;
use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_elasticloadbalancingv2 as elbv2;
use aws_sdk_rds as rds;
use aws_types::{region::Region, SdkConfig};
use clap::{Parser, ValueHint};
use comfy_table::{Table, presets::ASCII_FULL};
use env_logger::Target;
use eyre::{eyre, Result};
use log::trace;

/*──────── domain types ───────*/
#[derive(Debug, Copy, Clone)]
enum Peering {
    Peered,
    Unpeered,
}

#[derive(Debug)]
struct ResourceRecord {
    arn:  String,
    rtype: &'static str,
    name: String,
}

#[derive(Debug)]
struct VpcSummary {
    name: Option<String>,
    public: bool,
    peering: Peering,
    cidrs: Vec<String>,
    resources: Vec<ResourceRecord>,
}

/*──────── CLI ───────*/
#[derive(Parser, Debug)]
#[command(name = "ls-vpc", author, version, about)]
struct Opt {
    #[clap(long, value_delimiter = ',', num_args = 1..)]
    regions: Vec<String>,

    #[clap(value_name = "VPC_ID", value_hint = ValueHint::Other)]
    vpc_ids: Vec<String>,
}

/*──────── ServiceScanner trait ─────*/
#[async_trait]
trait ServiceScanner: Send + Sync {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>>;
}

/*──────── EC2 scanner ─────*/
struct Ec2Scanner;
#[async_trait]
impl ServiceScanner for Ec2Scanner {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>> {
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

        /* ENIs */
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

        /* NAT Gateways */
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

        /* Flow logs */
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

/*──────── ELBv2 scanner ─────*/
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

/*──────── RDS / DocDB scanner ─────*/
struct RdsScanner;
#[async_trait]
impl ServiceScanner for RdsScanner {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>> {
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
                });
            }
        }

        /* RDS clusters */
        for cl in client.describe_db_clusters().send().await?.db_clusters() {
            recs.push(ResourceRecord {
                arn: cl.db_cluster_arn().unwrap_or_default().to_owned(),
                rtype: "rds.cluster",
                name: cl.db_cluster_identifier().unwrap_or_default().to_owned(),
            });
        }

        /* DocDB clusters */
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

/*──────── helper: list_vpcs ─────*/

async fn list_vpcs(
    conf: &SdkConfig,
    filter: &[String],
) -> Result<Vec<(String, Option<String>)>> {
    let client = ec2::Client::new(conf);

    if filter.is_empty() {
        let resp = client.describe_vpcs().send().await?;
        return Ok(resp
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
            .collect());
    }

    let mut out = Vec::new();
    for id in filter {
        match client.describe_vpcs().vpc_ids(id).send().await {
            Ok(resp) => {
                for v in resp.vpcs() {
                    let name = v
                        .tags()
                        .iter()
                        .find(|t| t.key() == Some("Name"))
                        .and_then(|t| t.value())
                        .map(|s| s.to_owned());
                    out.push((v.vpc_id().unwrap_or_default().to_owned(), name));
                }
            }
            Err(e) if e.code() == Some("InvalidVpcID.NotFound") => {
                trace!("{id} absent in this region – skipped");
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

async fn peering_status(conf: &SdkConfig, vpc_id: &str) -> Result<Peering> {
    let client = ec2::Client::new(conf);
    let active = client
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
    Ok(if active { Peering::Peered } else { Peering::Unpeered })
}

async fn is_public(conf: &SdkConfig, vpc_id: &str) -> Result<bool> {
    let client = ec2::Client::new(conf);
    Ok(!client
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
        .is_empty())
}

/*──────── helper: get_cidrs ─────*/

async fn get_cidrs(conf: &SdkConfig, vpc_id: &str) -> Result<Vec<String>> {
    let client = ec2::Client::new(conf);
    let mut cidrs = Vec::new();

    let resp = client.describe_vpcs().vpc_ids(vpc_id).send().await?;
    if let Some(vpc) = resp.vpcs().first() {
        if let Some(primary) = vpc.cidr_block() {
            cidrs.push(primary.to_owned());
        }
        for assoc in vpc.cidr_block_association_set() {
            if let Some(cidr) = assoc.cidr_block() {
                cidrs.push(cidr.to_owned());
            }
        }
        for ipv6 in vpc.ipv6_cidr_block_association_set() {
            if let Some(cidr) = ipv6.ipv6_cidr_block() {
                cidrs.push(cidr.to_owned());
            }
        }
    }

    cidrs.sort();
    cidrs.dedup();
    Ok(cidrs)
}

/*──────── helper: column widths for detail view ─────*/

fn column_widths(
    vpcs: &BTreeMap<(String, String), VpcSummary>,
) -> (usize, usize, usize, usize, usize) {
    let mut region_w = "REGION".len();
    let mut vis_w = "VIS".len();
    let mut peer_w = "PEERING".len();
    let mut vpc_w = "VPC-ID".len();
    let mut cidr_w = "CIDR".len();

    for ((region, vpc_id), summary) in vpcs {
        region_w = region_w.max(region.len());
        vis_w = vis_w.max(if summary.public { 6 } else { 7 });
        peer_w = peer_w.max(match summary.peering {
            Peering::Peered => 6,
            Peering::Unpeered => 8,
        });
        vpc_w = vpc_w.max(vpc_id.len());
        cidr_w = cidr_w.max(summary.cidrs.join(",").len());
    }

    (region_w, vis_w, peer_w, vpc_w, cidr_w)
}

/*──────── summary report (Comfy-table) ─────*/

fn print_summary_table(vpcs: &BTreeMap<(String, String), VpcSummary>) {
    let mut table = Table::new();
    table.load_preset(ASCII_FULL);
    table.set_header(vec!["REGION", "VIS", "PEERING", "VPC-ID", "CIDR", "NAME"]);

    for ((region, vpc_id), s) in vpcs {
        let vis = if s.public { "public" } else { "private" };
        let peer = match s.peering {
            Peering::Peered => "peered",
            Peering::Unpeered => "unpeered",
        };
        let cidr_col = s.cidrs.join(",");
        table.add_row(vec![
            region.clone(),
            vis.to_owned(),
            peer.to_owned(),
            vpc_id.clone(),
            cidr_col,
            s.name.clone().unwrap_or_default(),
        ]);
    }

    println!("{table}");
}

/*──────── detail report (custom ASCII) ─────*/

fn print_detail_table(vpcs: &BTreeMap<(String, String), VpcSummary>) {
    let (region_w, vis_w, peer_w, vpc_w, cidr_w) = column_widths(vpcs);

    println!(
        "{:<region_w$} {:<vis_w$} {:<peer_w$} {:<vpc_w$} {:<cidr_w$} | {}",
        "REGION",
        "VIS",
        "PEERING",
        "VPC-ID",
        "CIDR",
        "NAME",
        region_w = region_w,
        vis_w = vis_w,
        peer_w = peer_w,
        vpc_w = vpc_w,
        cidr_w = cidr_w
    );

    let dash_len = region_w + 1 + vis_w + 1 + peer_w + 1 + vpc_w + 1 + cidr_w + 3 + 40;
    println!("{}", "-".repeat(dash_len));

    for ((region, vpc_id), s) in vpcs {
        let cidr_col = s.cidrs.join(",");
        println!(
            "{:<region_w$} {:<vis_w$} {:<peer_w$} {:<vpc_w$} {:<cidr_w$} | {}",
            region,
            if s.public { "public" } else { "private" },
            match s.peering {
                Peering::Peered => "peered",
                Peering::Unpeered => "unpeered",
            },
            vpc_id,
            cidr_col,
            s.name.as_deref().unwrap_or(""),
            region_w = region_w,
            vis_w = vis_w,
            peer_w = peer_w,
            vpc_w = vpc_w,
            cidr_w = cidr_w
        );

        if !s.resources.is_empty() {
            println!("infra:");
            for r in &s.resources {
                println!("  {:<22} {:<28} {}", r.rtype, r.name, r.arn);
            }
            println!();
        }
    }
}

/*──────── main ─────*/
#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    if opt.regions.is_empty() {
        return Err(eyre!("--regions is required"));
    }
    let summary_only = opt.vpc_ids.is_empty();

    /* logging */
    let log_file = get_or_create_log_dir().join("ls-vpc.log");
    let fh = OpenOptions::new().create(true).append(true).open(&log_file)?;
    env_logger::Builder::from_default_env()
        .target(Target::Pipe(Box::new(fh)))
        .format(|buf, rec| {
            writeln!(
                buf,
                "{} {:<5} [{}] {}",
                buf.timestamp_millis(),
                rec.level(),
                rec.target(),
                rec.args()
            )
        })
        .filter_level(log::LevelFilter::Trace)
        .init();

    let scanners: Vec<Box<dyn ServiceScanner>> =
        vec![Box::new(Ec2Scanner), Box::new(ElbScanner), Box::new(RdsScanner)];

    let mut vpcs: BTreeMap<(String, String), VpcSummary> = BTreeMap::new();
    let start = Instant::now();

    for region_name in &opt.regions {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region_name.clone()))
            .load()
            .await;

        for (vpc_id, vpc_name) in list_vpcs(&conf, &opt.vpc_ids).await? {
            let mut summary = VpcSummary {
                name: vpc_name,
                public: is_public(&conf, &vpc_id).await?,
                peering: peering_status(&conf, &vpc_id).await?,
                cidrs: get_cidrs(&conf, &vpc_id).await?,
                resources: Vec::new(),
            };
            if !summary_only {
                for s in &scanners {
                    if let Ok(mut res) = s.scan(&conf, &vpc_id).await {
                        summary.resources.append(&mut res);
                    }
                }
            }
            vpcs.insert((region_name.clone(), vpc_id), summary);
        }
    }

    /* output */
    if summary_only {
        print_summary_table(&vpcs);
    } else {
        print_detail_table(&vpcs);
    }

    println!(
        "Finished in {:.2?} – {} VPC(s) across {} Region(s)",
        start.elapsed(),
        vpcs.len(),
        opt.regions.len()
    );
    Ok(())
}

/*──────── log-dir helper ─────*/
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
