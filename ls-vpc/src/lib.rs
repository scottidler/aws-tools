//! ls-vpc library
//!
//! Core functionality for listing VPCs and their resources.
//! This module separates business logic from the CLI shell.

pub mod cli;
pub mod config;
pub mod scanner;
pub mod utils;

pub use cli::Cli;
pub use config::Config;
pub use scanner::{Ec2Scanner, ElbScanner, RdsScanner, ResourceRecord, ServiceScanner};
pub use utils::{get_or_create_log_dir, terminal_width, wrap_identifier};

use aws_config::BehaviorVersion;
use aws_sdk_docdb::error::ProvideErrorMetadata;
use aws_sdk_ec2 as ec2;
use aws_types::{region::Region, SdkConfig};
use comfy_table::presets::{ASCII_FULL, ASCII_FULL_CONDENSED};
use comfy_table::Table;
use eyre::Result;
use log::trace;
use std::collections::BTreeMap;

/// Summary information about a VPC
#[derive(Debug, Clone)]
pub struct VpcSummary {
    pub name: Option<String>,
    pub public: bool,
    pub cidrs: Vec<String>,
    pub peers: Vec<String>,
    pub resources: Vec<ResourceRecord>,
}

/// Result of a VPC scan operation
#[derive(Debug)]
pub struct ScanResult {
    pub vpcs: BTreeMap<(String, String), VpcSummary>,
    pub regions_scanned: usize,
}

/// Headers for summary table output
pub fn summary_headers() -> Vec<&'static str> {
    vec!["REGION", "VIS", "CIDR", "VPC-ID", "PEERS", "NAME"]
}

/// Create a row for summary table output
pub fn summary_row(region: &str, vpc_id: &str, s: &VpcSummary) -> Vec<String> {
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

/// List VPCs, optionally filtered by ID
pub async fn list_filtered_vpcs(
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

/// List all VPCs in the region
pub async fn list_all_vpcs(client: &ec2::Client) -> Result<Vec<(String, Option<String>)>> {
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

/// List VPCs with optional filtering
pub async fn list_vpcs(conf: &SdkConfig, filter: &[String]) -> Result<Vec<(String, Option<String>)>> {
    let client = ec2::Client::new(conf);
    if filter.is_empty() {
        return list_all_vpcs(&client).await;
    }
    list_filtered_vpcs(&client, filter).await
}

/// Check if a VPC has an internet gateway attached (making it "public")
pub async fn is_public(conf: &SdkConfig, vpc_id: &str) -> Result<bool> {
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

/// Collect peer VPCs using a filter
pub async fn collect_peers<F>(
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

/// Get all peer VPCs for a given VPC
pub async fn get_peer_vpcs(conf: &SdkConfig, vpc_id: &str) -> Result<Vec<String>> {
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

/// Get all CIDR blocks for a VPC
pub async fn get_cidrs(conf: &SdkConfig, vpc_id: &str) -> Result<Vec<String>> {
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

/// Format summary table for terminal output
pub fn format_summary_table(vpcs: &BTreeMap<(String, String), VpcSummary>) -> String {
    let mut table = Table::new();
    table.load_preset(ASCII_FULL_CONDENSED);
    table.set_header(summary_headers());
    for ((region, vpc_id), s) in vpcs {
        table.add_row(summary_row(region, vpc_id, s));
    }
    table.to_string()
}

/// Format detail table for terminal output
pub fn format_detail_table(vpcs: &BTreeMap<(String, String), VpcSummary>) -> String {
    use comfy_table::{ColumnConstraint, ContentArrangement, Width};

    let term_w = terminal_width();
    let borders_and_padding = 10usize;
    let min_arn_width = 20usize;
    let name_soft_cap = term_w / 3;

    let mut output = String::new();

    for ((region, vpc_id), s) in vpcs {
        let mut summary = Table::new();
        summary.load_preset(ASCII_FULL);
        summary.set_header(summary_headers());
        summary.add_row(summary_row(region, vpc_id, s));
        output.push_str(&summary.to_string());
        output.push('\n');

        if !s.resources.is_empty() {
            let type_col_len = s
                .resources
                .iter()
                .map(|r| r.rtype.len())
                .max()
                .unwrap_or(4)
                .min(25);

            let name_col_len = s
                .resources
                .iter()
                .map(|r| r.name.len())
                .max()
                .unwrap_or(4)
                .min(name_soft_cap);

            let arn_col_len = term_w
                .saturating_sub(type_col_len + name_col_len + borders_and_padding)
                .max(min_arn_width);

            let mut detail = Table::new();
            detail.load_preset(ASCII_FULL_CONDENSED);
            detail.set_header(vec!["TYPE", "NAME", "IDENTIFIER / ARN"]);
            detail.set_content_arrangement(ContentArrangement::DynamicFullWidth);

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

            for r in &s.resources {
                detail.add_row(vec![
                    r.rtype.to_owned(),
                    r.name.clone(),
                    wrap_identifier(&r.arn, arn_col_len),
                ]);
            }

            output.push_str(&detail.to_string());
            output.push('\n');
        }
        output.push('\n');
    }

    output
}

/// Run the VPC scan for given config
pub async fn run(config: &Config) -> Result<ScanResult> {
    let scanners: Vec<Box<dyn ServiceScanner>> =
        vec![Box::new(Ec2Scanner), Box::new(ElbScanner), Box::new(RdsScanner)];

    let mut vpcs: BTreeMap<(String, String), VpcSummary> = BTreeMap::new();

    for region in &config.regions {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .load()
            .await;

        for (vpc_id, vpc_name) in list_vpcs(&conf, &config.vpc_ids).await? {
            let peers = get_peer_vpcs(&conf, &vpc_id).await?;
            let mut summary = VpcSummary {
                name: vpc_name,
                public: is_public(&conf, &vpc_id).await?,
                cidrs: get_cidrs(&conf, &vpc_id).await?,
                peers,
                resources: Vec::new(),
            };

            if !config.summary_only {
                for s in &scanners {
                    if let Ok(mut res) = s.scan(&conf, &vpc_id).await {
                        summary.resources.append(&mut res);
                    }
                }
            }

            vpcs.insert((region.clone(), vpc_id), summary);
        }
    }

    Ok(ScanResult {
        regions_scanned: config.regions.len(),
        vpcs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_headers_has_six_columns() {
        assert_eq!(summary_headers().len(), 6);
    }

    #[test]
    fn summary_row_formats_public_vpc() {
        let summary = VpcSummary {
            name: Some("my-vpc".to_string()),
            public: true,
            cidrs: vec!["10.0.0.0/16".to_string()],
            peers: vec!["vpc-peer1".to_string()],
            resources: vec![],
        };
        let row = summary_row("us-west-2", "vpc-123", &summary);
        assert_eq!(row[0], "us-west-2");
        assert_eq!(row[1], "public");
        assert_eq!(row[2], "10.0.0.0/16");
        assert_eq!(row[3], "vpc-123");
        assert_eq!(row[4], "vpc-peer1");
        assert_eq!(row[5], "my-vpc");
    }

    #[test]
    fn summary_row_formats_private_vpc() {
        let summary = VpcSummary {
            name: None,
            public: false,
            cidrs: vec!["10.0.0.0/16".to_string(), "10.1.0.0/16".to_string()],
            peers: vec![],
            resources: vec![],
        };
        let row = summary_row("us-east-1", "vpc-456", &summary);
        assert_eq!(row[1], "private");
        assert_eq!(row[2], "10.0.0.0/16,10.1.0.0/16");
        assert_eq!(row[5], "");
    }

    #[test]
    fn format_summary_table_creates_valid_table() {
        let mut vpcs = BTreeMap::new();
        vpcs.insert(
            ("us-west-2".to_string(), "vpc-123".to_string()),
            VpcSummary {
                name: Some("test-vpc".to_string()),
                public: true,
                cidrs: vec!["10.0.0.0/16".to_string()],
                peers: vec![],
                resources: vec![],
            },
        );
        let table = format_summary_table(&vpcs);
        assert!(table.contains("us-west-2"));
        assert!(table.contains("vpc-123"));
        assert!(table.contains("test-vpc"));
        assert!(table.contains("public"));
    }

    #[test]
    fn format_detail_table_includes_resources() {
        let mut vpcs = BTreeMap::new();
        vpcs.insert(
            ("us-west-2".to_string(), "vpc-123".to_string()),
            VpcSummary {
                name: Some("test-vpc".to_string()),
                public: true,
                cidrs: vec!["10.0.0.0/16".to_string()],
                peers: vec![],
                resources: vec![ResourceRecord {
                    arn: "i-1234567890abcdef0".to_string(),
                    rtype: "ec2.instance",
                    name: "my-instance".to_string(),
                }],
            },
        );
        let table = format_detail_table(&vpcs);
        assert!(table.contains("ec2.instance"));
        assert!(table.contains("my-instance"));
    }

    #[test]
    fn vpc_summary_clone_works() {
        let summary = VpcSummary {
            name: Some("test".to_string()),
            public: true,
            cidrs: vec!["10.0.0.0/16".to_string()],
            peers: vec![],
            resources: vec![],
        };
        let cloned = summary.clone();
        assert_eq!(cloned.name, summary.name);
        assert_eq!(cloned.public, summary.public);
    }
}
