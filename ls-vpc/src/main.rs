//! ls-vpc 0.7.0
//! ---------------------------------------------------------------------------
//! Summary view  → Comfy-table output (no VPC-IDs passed).
//! Detail view   → ASCII output with per-resource “infra:” section (when VPC-IDs
//!                 are supplied).
//! Any InvalidVpcID.NotFound error is **silently skipped**.

mod scanner;
mod utils;

use crate::scanner::{Ec2Scanner, ElbScanner, RdsScanner, ServiceScanner};
use crate::utils::get_or_create_log_dir;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    time::Instant,
};

use aws_config::BehaviorVersion;
use aws_sdk_ec2 as ec2;
use aws_types::{region::Region, SdkConfig};
use clap::{Parser, ValueHint};
use comfy_table::Table;
use comfy_table::presets::{ASCII_FULL, ASCII_FULL_CONDENSED};
use env_logger::Target;
use eyre::{eyre, Result};
use log::trace;

use aws_sdk_docdb::error::ProvideErrorMetadata;

/*──────── additional domain types ─────*/

#[derive(Debug)]
struct VpcSummary {
    name:     Option<String>,
    public:   bool,
    cidrs:    Vec<String>,
    peers:    Vec<String>,
    resources: Vec<scanner::ResourceRecord>,
}

/*──────── CLI ───────*/
#[derive(Parser, Debug)]
#[command(name = "ls-vpc", author, version, about)]
struct Opt {
    /// Comma-separated AWS regions, e.g. `us-west-2,us-east-1`
    #[clap(long, value_delimiter = ',', num_args = 1..)]
    regions: Vec<String>,

    /// Optional VPC IDs. If omitted → summary mode.
    #[clap(value_name = "VPC_ID", value_hint = ValueHint::Other)]
    vpc_ids: Vec<String>,
}

/*──────── AWS helpers ─────*/

/// Return `(vpc_id, vpc_name)` for either **all** VPCs in a region
/// or only the ones explicitly requested.
/// Silently skips `InvalidVpcID.NotFound` errors.
async fn list_vpcs(conf: &SdkConfig, filter: &[String]) -> Result<Vec<(String, Option<String>)>> {
    let client = ec2::Client::new(conf);

    // No filter → every VPC in the region
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

    // Filtered lookup
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

/// Is at least one Internet-gateway attached?
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

/*──────── helpers ─────*/

async fn get_peer_vpcs(conf: &SdkConfig, vpc_id: &str) -> Result<Vec<String>> {
    use aws_sdk_ec2::types::VpcPeeringConnectionStateReasonCode as State;

    let client = ec2::Client::new(conf);
    let mut peers = Vec::new();

    /* requester side → accepter is “the other side” */
    let resp = client
        .describe_vpc_peering_connections()
        .filters(
            ec2::types::Filter::builder()
                .name("requester-vpc-info.vpc-id")
                .values(vpc_id)
                .build(),
        )
        .send()
        .await?;

    for pc in resp.vpc_peering_connections() {
        if matches!(pc.status().and_then(|s| s.code()), Some(State::Active)) {
            if let Some(pid) = pc.accepter_vpc_info().and_then(|i| i.vpc_id()) {
                peers.push(pid.to_owned());
            }
        }
    }

    /* accepter side → requester is “the other side” */
    let resp2 = client
        .describe_vpc_peering_connections()
        .filters(
            ec2::types::Filter::builder()
                .name("accepter-vpc-info.vpc-id")
                .values(vpc_id)
                .build(),
        )
        .send()
        .await?;

    for pc in resp2.vpc_peering_connections() {
        if matches!(pc.status().and_then(|s| s.code()), Some(State::Active)) {
            if let Some(pid) = pc.requester_vpc_info().and_then(|i| i.vpc_id()) {
                peers.push(pid.to_owned());
            }
        }
    }

    peers.sort();
    peers.dedup();
    Ok(peers)
}

/// All IPv4/IPv6 CIDR blocks attached to the VPC.
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

fn print_summary_table(vpcs: &BTreeMap<(String, String), VpcSummary>) {
    let mut table = Table::new();
    table.load_preset(ASCII_FULL_CONDENSED);
    table.set_header(vec![
        "REGION", "VIS", "CIDR", "VPC-ID", "PEERS", "NAME",
    ]);

    for ((region, vpc_id), s) in vpcs {
        let vis = if s.public { "public" } else { "private" };

        table.add_row(vec![
            region.clone(),
            vis.to_owned(),
            s.cidrs.join(","),
            vpc_id.clone(),
            s.peers.join(","),
            s.name.clone().unwrap_or_default(),
        ]);
    }

    println!("{table}");
}

fn print_detail_table(vpcs: &BTreeMap<(String, String), VpcSummary>) {
    for ((region, vpc_id), s) in vpcs {
        /* ── one-row summary table ─────────────────────────────────────── */
        let mut summary = Table::new();
        summary.load_preset(ASCII_FULL);
        summary.set_header(vec![
            "REGION", "VIS", "CIDR", "VPC-ID", "PEERS", "NAME",
        ]);

        let vis = if s.public { "public" } else { "private" };

        summary.add_row(vec![
            region.clone(),
            vis.into(),
            s.cidrs.join(","),
            vpc_id.clone(),
            s.peers.join(","),
            s.name.clone().unwrap_or_default(),
        ]);

        println!("{summary}");

        /* ── resources table ───────────────────────────────────────────── */
        if !s.resources.is_empty() {
            let mut detail = Table::new();
            detail.load_preset(ASCII_FULL_CONDENSED);
            detail.set_header(vec!["TYPE", "NAME", "IDENTIFIER / ARN"]);

            for r in &s.resources {
                detail.add_row(vec![
                    r.rtype.to_owned(),
                    r.name.clone(),
                    r.arn.clone(),
                ]);
            }
            println!("{detail}");
        }

        println!(); // blank line between VPC blocks
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

    /* scanners */
    let scanners: Vec<Box<dyn ServiceScanner>> =
        vec![Box::new(Ec2Scanner), Box::new(ElbScanner), Box::new(RdsScanner)];

    /* collect data */
    let mut vpcs: BTreeMap<(String, String), VpcSummary> = BTreeMap::new();
    let start = Instant::now();

    for region_name in &opt.regions {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region_name.clone()))
            .load()
            .await;

        for (vpc_id, vpc_name) in list_vpcs(&conf, &opt.vpc_ids).await? {
            let peers = get_peer_vpcs(&conf, &vpc_id).await?;
            let mut summary = VpcSummary {
                name: vpc_name,
                public: is_public(&conf, &vpc_id).await?,
                cidrs: get_cidrs(&conf, &vpc_id).await?,
                peers,
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
