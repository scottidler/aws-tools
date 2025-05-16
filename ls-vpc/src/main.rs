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
use comfy_table::{presets::ASCII_FULL, Table};
use env_logger::Target;
use eyre::{eyre, Result};
use log::trace;

use aws_sdk_docdb::error::ProvideErrorMetadata;

/*──────── additional domain types ─────*/

#[derive(Debug, Copy, Clone)]
enum Peering {
    Peered,
    Unpeered,
}

#[derive(Debug)]
struct VpcSummary {
    name: Option<String>,
    public: bool,
    peering: Peering,
    cidrs: Vec<String>,
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

/// Any **ACTIVE** peering connection present?
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

/*──────── text-table helpers (detail view only) ─────*/

fn column_widths(vpcs: &BTreeMap<(String, String), VpcSummary>) -> (usize, usize, usize, usize, usize) {
    let mut region_w = "REGION".len();
    let mut vis_w    = "VIS".len();
    let mut peer_w   = "PEERING".len();
    let mut vpc_w    = "VPC-ID".len();
    let mut cidr_w   = "CIDR".len();

    for ((region, vpc_id), s) in vpcs {
        region_w = region_w.max(region.len());
        vis_w    = vis_w.max(if s.public { 6 } else { 7 });
        peer_w   = peer_w.max(match s.peering { Peering::Peered => 6, Peering::Unpeered => 8 });
        vpc_w    = vpc_w.max(vpc_id.len());
        cidr_w   = cidr_w.max(s.cidrs.join(",").len());
    }

    (region_w, vis_w, peer_w, vpc_w, cidr_w)
}

fn print_detail_table(vpcs: &BTreeMap<(String, String), VpcSummary>) {
    let (region_w, vis_w, peer_w, vpc_w, cidr_w) = column_widths(vpcs);

    println!(
        "{:<region_w$} {:<vis_w$} {:<peer_w$} {:<vpc_w$} {:<cidr_w$} | {}",
        "REGION", "VIS", "PEERING", "VPC-ID", "CIDR", "NAME",
        region_w = region_w, vis_w = vis_w, peer_w = peer_w, vpc_w = vpc_w, cidr_w = cidr_w
    );
    let dash_len = region_w + vis_w + peer_w + vpc_w + cidr_w + /*  separators */ 1*4 + 3 + 40;
    println!("{}", "-".repeat(dash_len));

    for ((region, vpc_id), s) in vpcs {
        println!(
            "{:<region_w$} {:<vis_w$} {:<peer_w$} {:<vpc_w$} {:<cidr_w$} | {}",
            region,
            if s.public { "public" } else { "private" },
            match s.peering { Peering::Peered => "peered", Peering::Unpeered => "unpeered" },
            vpc_id,
            s.cidrs.join(","),
            s.name.as_deref().unwrap_or(""),
            region_w = region_w, vis_w = vis_w, peer_w = peer_w, vpc_w = vpc_w, cidr_w = cidr_w
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

/*──────── Comfy-table summary ─────*/

fn print_summary_table(vpcs: &BTreeMap<(String, String), VpcSummary>) {
    let mut table = Table::new();
    table.load_preset(ASCII_FULL);
    table.set_header(vec!["REGION", "VIS", "PEERING", "VPC-ID", "CIDR", "NAME"]);

    for ((region, vpc_id), s) in vpcs {
        let vis  = if s.public { "public" } else { "private" };
        let peer = match s.peering { Peering::Peered => "peered", Peering::Unpeered => "unpeered" };
        table.add_row(vec![
            region.clone(),
            vis.to_owned(),
            peer.to_owned(),
            vpc_id.clone(),
            s.cidrs.join(","),
            s.name.clone().unwrap_or_default(),
        ]);
    }

    println!("{table}");
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
            writeln!(buf, "{} {:<5} [{}] {}", buf.timestamp_millis(), rec.level(), rec.target(), rec.args())
        })
        .filter_level(log::LevelFilter::Trace)
        .init();

    /* assemble scanners */
    let scanners: Vec<Box<dyn ServiceScanner>> = vec![
        Box::new(Ec2Scanner),
        Box::new(ElbScanner),
        Box::new(RdsScanner),
    ];

    /* walk regions */
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
