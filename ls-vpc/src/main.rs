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
use eyre::Result;
use log::trace;

use aws_sdk_docdb::error::ProvideErrorMetadata;

#[derive(Parser, Debug)]
#[command(name = "ls-vpc", author, version, about)]
struct Opt {
    /// AWS Regions to query (pick one or both of `us-east-1`, `us-west-2`).
    ///
    /// Examples:
    ///   ls-vpc                    # uses the default us-east-1 us-west-2
    ///   ls-vpc -r us-east-1       # east only
    ///   ls-vpc -r us-west-2       # west only
    ///   ls-vpc -r us-east-1 -r us-west-2   # both
    #[clap(
        short = 'r',
        long = "regions",
        value_parser = clap::builder::PossibleValuesParser::new(["us-east-1", "us-west-2"]),
        num_args = 0..,
        default_values_t = vec![
            "us-east-1".to_string(),
            "us-west-2".to_string()
        ]
    )]
    regions: Vec<String>,

    /// Optional VPC IDs. If omitted → summary mode.
    #[clap(value_name = "VPC_ID", value_hint = ValueHint::Other)]
    vpc_ids: Vec<String>,
}

#[derive(Debug)]
struct VpcSummary {
    name:     Option<String>,
    public:   bool,
    cidrs:    Vec<String>,
    peers:    Vec<String>,
    resources: Vec<scanner::ResourceRecord>,
}

fn summary_headers() -> Vec<&'static str> {
    vec!["REGION", "VIS", "CIDR", "VPC-ID", "PEERS", "NAME"]
}

fn summary_row(region: &str, vpc_id: &str, s: &VpcSummary) -> Vec<String> {
    let vis = if s.public { "public" } else { "private" };
    vec![
        region.to_owned(),
        vis.to_owned(),
        s.cidrs.join(","),
        vpc_id.to_owned(),
        s.peers.join(","),
        s.name.clone().unwrap_or_default(),
    ]
}

async fn list_filtered_vpcs(
    client: &ec2::Client,
    filter: &[String],
) -> Result<Vec<(String, Option<String>)>> {
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
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

async fn list_vpcs(conf: &SdkConfig, filter: &[String]) -> Result<Vec<(String, Option<String>)>> {
    let client = ec2::Client::new(conf);
    if filter.is_empty() {
        return list_all_vpcs(&client).await;
    }
    list_filtered_vpcs(&client, filter).await
}

async fn list_all_vpcs(client: &ec2::Client) -> Result<Vec<(String, Option<String>)>> {
    Ok(client
        .describe_vpcs()
        .send()
        .await?
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

async fn collect_peers<F>(
    client: &ec2::Client,
    vpc_id: &str,
    filter_name: &str,
    extract_other: F,
) -> Result<Vec<String>>
where
    F: Fn(&aws_sdk_ec2::types::VpcPeeringConnection) -> Option<&str>,
{
    use aws_sdk_ec2::types::VpcPeeringConnectionStateReasonCode as State;

    let resp = client
        .describe_vpc_peering_connections()
        .filters(
            ec2::types::Filter::builder()
                .name(filter_name)
                .values(vpc_id)
                .build(),
        )
        .send()
        .await?;

    let mut peers = Vec::new();
    for pc in resp.vpc_peering_connections() {
        if matches!(pc.status().and_then(|s| s.code()), Some(State::Active)) {
            if let Some(pid) = extract_other(pc) {
                peers.push(pid.to_owned());
            }
        }
    }
    Ok(peers)
}

async fn get_peer_vpcs(conf: &SdkConfig, vpc_id: &str) -> Result<Vec<String>> {
    let client = ec2::Client::new(conf);

    let mut peers = collect_peers(
        &client,
        vpc_id,
        "requester-vpc-info.vpc-id",
        |pc| pc.accepter_vpc_info().and_then(|i| i.vpc_id()),
    )
    .await?;

    peers.extend(
        collect_peers(
            &client,
            vpc_id,
            "accepter-vpc-info.vpc-id",
            |pc| pc.requester_vpc_info().and_then(|i| i.vpc_id()),
        )
        .await?,
    );

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
    table.set_header(summary_headers());
    for ((region, vpc_id), s) in vpcs {
        table.add_row(summary_row(region, vpc_id, s));
    }
    println!("{table}");
}

fn print_detail_table(vpcs: &BTreeMap<(String, String), VpcSummary>) {
    use crate::utils::{terminal_width, wrap_identifier};
    use comfy_table::{
        ColumnConstraint,           // ← constraint enum
        ContentArrangement,         // ← keep dynamic layout
        Width,                      // ← Fixed / Percent variants
    };

    // --------------------------------------------------------------------
    // Work out the terminal width and some hard limits for each column
    // --------------------------------------------------------------------
    let term_w               = terminal_width();      // full TTY width
    let borders_and_padding  = 10usize;               // | … | … | … |
    let min_arn_width        = 20usize;               // never smaller
    let name_soft_cap        = term_w / 3;            // NAME col clamp

    for ((region, vpc_id), s) in vpcs {
        // ----------------------- summary row ----------------------------
        let mut summary = Table::new();
        summary.load_preset(ASCII_FULL);
        summary.set_header(summary_headers());
        summary.add_row(summary_row(region, vpc_id, s));
        println!("{summary}");

        // ---------------- resource-level detail -------------------------
        if !s.resources.is_empty() {
            // Longest strings in TYPE / NAME columns
            let type_col_len = s
                .resources
                .iter()
                .map(|r| r.rtype.len())
                .max()
                .unwrap_or(4)
                .min(25);                 // TYPE never absurdly wide

            let name_col_len = s
                .resources
                .iter()
                .map(|r| r.name.len())
                .max()
                .unwrap_or(4)
                .min(name_soft_cap);      // NAME clamped

            // Whatever is left goes to the ARN column
            let arn_col_len = term_w
                .saturating_sub(type_col_len + name_col_len + borders_and_padding)
                .max(min_arn_width);

            let mut detail = Table::new();
            detail.load_preset(ASCII_FULL_CONDENSED);
            detail.set_header(vec!["TYPE", "NAME", "IDENTIFIER / ARN"]);
            detail.set_content_arrangement(ContentArrangement::DynamicFullWidth);

            // ---------------- per-column constraints --------------------
            detail
                .column_mut(0)
                .expect("TYPE column exists")
                .set_constraint(ColumnConstraint::UpperBoundary(Width::Fixed(
                    type_col_len as u16,
                )));

            detail
                .column_mut(1)
                .expect("NAME column exists")
                .set_constraint(ColumnConstraint::UpperBoundary(Width::Fixed(
                    name_col_len as u16,
                )));

            detail
                .column_mut(2)
                .expect("ARN column exists")
                .set_constraint(ColumnConstraint::UpperBoundary(Width::Fixed(
                    arn_col_len as u16,
                )));

            // ----------------- populate the table -----------------------
            for r in &s.resources {
                detail.add_row(vec![
                    r.rtype.to_owned(),
                    r.name.clone(),
                    wrap_identifier(&r.arn, arn_col_len),
                ]);
            }

            println!("{detail}");
        }
        println!();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
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
