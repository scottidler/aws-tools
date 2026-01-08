//! CLI argument parsing for ls-rds
//!
//! This module contains only the clap derive structs.
//! Validation happens in config.rs.

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "ls-rds", author, version = env!("GIT_DESCRIBE"), about)]
pub struct Cli {
    /// Enumerate *all* accounts via AWS Organizations
    #[clap(long)]
    pub use_org: bool,

    /// One or more specific role ARNs (mutually exclusive with --use-org)
    #[clap(long, conflicts_with = "use_org")]
    pub role_arns: Vec<String>,

    /// One or more AWS Regions to scan.  You may supply them as
    ///   --regions us-west-2 us-east-1
    /// or as a single comma‑separated string:
    ///   --regions us-west-2,us-east-1
    #[clap(
        long,
        value_delimiter = ',',
        num_args = 1..,
        default_values = ["us-east-1", "us-west-2"]
    )]
    pub regions: Vec<String>,
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
        let cli = Cli::parse_from(["ls-rds"]);
        assert_eq!(cli.regions, vec!["us-east-1", "us-west-2"]);
        assert!(!cli.use_org);
        assert!(cli.role_arns.is_empty());
    }

    #[test]
    fn cli_parses_single_region() {
        let cli = Cli::parse_from(["ls-rds", "--regions", "us-west-2"]);
        assert_eq!(cli.regions, vec!["us-west-2"]);
    }

    #[test]
    fn cli_parses_comma_separated_regions() {
        let cli = Cli::parse_from(["ls-rds", "--regions", "us-west-2,us-east-1"]);
        assert_eq!(cli.regions, vec!["us-west-2", "us-east-1"]);
    }

    #[test]
    fn cli_parses_multiple_region_flags() {
        let cli = Cli::parse_from(["ls-rds", "--regions", "us-west-2", "us-east-1"]);
        assert_eq!(cli.regions.len(), 2);
    }

    #[test]
    fn cli_parses_use_org() {
        let cli = Cli::parse_from(["ls-rds", "--use-org"]);
        assert!(cli.use_org);
    }

    #[test]
    fn cli_parses_role_arns() {
        let cli = Cli::parse_from([
            "ls-rds",
            "--role-arns",
            "arn:aws:iam::123456789012:role/TestRole",
        ]);
        assert_eq!(cli.role_arns.len(), 1);
        assert!(cli.role_arns[0].contains("TestRole"));
    }

    #[test]
    fn cli_parses_multiple_role_arns() {
        let cli = Cli::parse_from([
            "ls-rds",
            "--role-arns",
            "arn:aws:iam::111111111111:role/Role1",
            "--role-arns",
            "arn:aws:iam::222222222222:role/Role2",
        ]);
        assert_eq!(cli.role_arns.len(), 2);
    }
}
