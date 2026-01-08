//! Configuration for ls-vpc
//!
//! This module validates CLI arguments and provides defaults.

use crate::cli::Cli;
use eyre::{Result, bail};

/// Validated configuration for ls-vpc
#[derive(Debug, Clone)]
pub struct Config {
    /// AWS regions to scan
    pub regions: Vec<String>,
    /// VPC IDs to filter (empty = all VPCs)
    pub vpc_ids: Vec<String>,
    /// Whether to show summary only (no resources)
    pub summary_only: bool,
}

impl TryFrom<Cli> for Config {
    type Error = eyre::Error;

    fn try_from(cli: Cli) -> Result<Self> {
        // Validate regions
        if cli.regions.is_empty() {
            bail!("At least one region must be specified");
        }

        // Validate VPC IDs format if provided
        for vpc_id in &cli.vpc_ids {
            if !vpc_id.starts_with("vpc-") {
                bail!("Invalid VPC ID format: '{}'. VPC IDs must start with 'vpc-'", vpc_id);
            }
        }

        Ok(Config {
            regions: cli.regions,
            summary_only: cli.vpc_ids.is_empty(),
            vpc_ids: cli.vpc_ids,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
            vpc_ids: vec![],
            summary_only: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_with_regions(regions: Vec<String>) -> Cli {
        Cli {
            regions,
            vpc_ids: vec![],
        }
    }

    fn cli_with_vpc_ids(vpc_ids: Vec<String>) -> Cli {
        Cli {
            regions: vec!["us-west-2".to_string()],
            vpc_ids,
        }
    }

    #[test]
    fn config_from_cli_with_defaults() {
        let cli = Cli {
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
            vpc_ids: vec![],
        };
        let config = Config::try_from(cli).unwrap();
        assert_eq!(config.regions.len(), 2);
        assert!(config.summary_only);
        assert!(config.vpc_ids.is_empty());
    }

    #[test]
    fn config_from_cli_with_vpc_ids() {
        let cli = Cli {
            regions: vec!["us-west-2".to_string()],
            vpc_ids: vec!["vpc-123".to_string(), "vpc-456".to_string()],
        };
        let config = Config::try_from(cli).unwrap();
        assert!(!config.summary_only);
        assert_eq!(config.vpc_ids.len(), 2);
    }

    #[test]
    fn config_rejects_empty_regions() {
        let cli = cli_with_regions(vec![]);
        let result = Config::try_from(cli);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("region"));
    }

    #[test]
    fn config_rejects_invalid_vpc_id_format() {
        let cli = cli_with_vpc_ids(vec!["invalid-vpc-id".to_string()]);
        let result = Config::try_from(cli);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("vpc-"));
    }

    #[test]
    fn config_accepts_valid_vpc_ids() {
        let cli = cli_with_vpc_ids(vec!["vpc-12345678".to_string(), "vpc-abcdef01".to_string()]);
        let config = Config::try_from(cli).unwrap();
        assert_eq!(config.vpc_ids.len(), 2);
    }

    #[test]
    fn config_default_has_both_regions() {
        let config = Config::default();
        assert!(config.regions.contains(&"us-east-1".to_string()));
        assert!(config.regions.contains(&"us-west-2".to_string()));
    }

    #[test]
    fn config_default_is_summary_only() {
        let config = Config::default();
        assert!(config.summary_only);
    }

    #[test]
    fn config_clone_works() {
        let config = Config::default();
        let cloned = config.clone();
        assert_eq!(cloned.regions, config.regions);
    }
}
