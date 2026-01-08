//! CLI argument parsing for ls-vpc
//!
//! This module contains only the clap derive structs.
//! Validation happens in config.rs.

use clap::{Parser, ValueHint};

#[derive(Parser, Debug, Clone)]
#[command(name = "ls-vpc", author, version = env!("GIT_DESCRIBE"), about)]
pub struct Cli {
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
    pub regions: Vec<String>,

    /// Optional VPC IDs. If omitted → summary mode.
    #[clap(value_name = "VPC_ID", value_hint = ValueHint::Other)]
    pub vpc_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_parses_default_regions() {
        let cli = Cli::parse_from(["ls-vpc"]);
        assert_eq!(cli.regions, vec!["us-east-1", "us-west-2"]);
        assert!(cli.vpc_ids.is_empty());
    }

    #[test]
    fn cli_parses_single_region() {
        let cli = Cli::parse_from(["ls-vpc", "-r", "us-west-2"]);
        assert_eq!(cli.regions, vec!["us-west-2"]);
    }

    #[test]
    fn cli_parses_multiple_regions() {
        let cli = Cli::parse_from(["ls-vpc", "-r", "us-east-1", "-r", "us-west-2"]);
        assert_eq!(cli.regions.len(), 2);
    }

    #[test]
    fn cli_parses_vpc_ids() {
        // Use -- to separate options from positional arguments
        let cli = Cli::parse_from(["ls-vpc", "--", "vpc-123", "vpc-456"]);
        assert_eq!(cli.vpc_ids, vec!["vpc-123", "vpc-456"]);
    }

    #[test]
    fn cli_parses_region_and_vpc_ids() {
        // Explicit region followed by VPC IDs
        let cli = Cli::parse_from(["ls-vpc", "-r", "us-west-2", "--", "vpc-123"]);
        assert_eq!(cli.regions, vec!["us-west-2"]);
        assert_eq!(cli.vpc_ids, vec!["vpc-123"]);
    }
}
