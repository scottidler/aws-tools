//! scanner.rs
//! ---------------------------------------------------------------------------
//! All service-specific scanner implementations live here.  Each scanner
//! implements the [`ServiceScanner`] trait and returns a list of
//! [`ResourceRecord`] items discovered inside a single VPC.

use async_trait::async_trait;
use aws_sdk_docdb as docdb;
use aws_sdk_ec2 as ec2;
use aws_sdk_elasticloadbalancingv2 as elbv2;
use aws_sdk_rds as rds;
use aws_types::SdkConfig;
use eyre::Result;

/// A single AWS resource that lives inside a VPC (instance, ENI, DB cluster…).
#[derive(Debug)]
pub struct ResourceRecord {
    pub arn:  String,
    pub rtype: &'static str,
    pub name: String,
}

#[async_trait]
pub trait ServiceScanner: Send + Sync {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>>;
}

pub struct Ec2Scanner;

#[async_trait]
impl ServiceScanner for Ec2Scanner {
    async fn scan(&self, sdk: &SdkConfig, vpc_id: &str) -> Result<Vec<ResourceRecord>> {
        let client = ec2::Client::new(sdk);
        let mut recs = Vec::new();

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

pub struct ElbScanner;

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

pub struct RdsScanner;

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
