//! Configuration for ls-rds
//!
//! This module validates CLI arguments and provides defaults.

use crate::cli::Cli;
use eyre::{Result, bail};

/// Mode of operation for ls-rds
#[derive(Debug, Clone, PartialEq)]
pub enum ScanMode {
    /// Scan current account only
    CurrentAccount,
    /// Scan all accounts via AWS Organizations
    Organization,
    /// Scan specific accounts via role ARNs
    RoleArns(Vec<String>),
}

/// Validated configuration for ls-rds
#[derive(Debug, Clone)]
pub struct Config {
    /// AWS regions to scan
    pub regions: Vec<String>,
    /// Scanning mode
    pub mode: ScanMode,
}

impl TryFrom<Cli> for Config {
    type Error = eyre::Error;

    fn try_from(cli: Cli) -> Result<Self> {
        // Validate regions
        if cli.regions.is_empty() {
            bail!("At least one region must be specified");
        }

        // Validate role ARN format if provided
        for arn in &cli.role_arns {
            if !arn.starts_with("arn:aws:iam::") || !arn.contains(":role/") {
                bail!(
                    "Invalid role ARN format: '{}'. Expected format: arn:aws:iam::<account>:role/<name>",
                    arn
                );
            }
        }

        let mode = if cli.use_org {
            ScanMode::Organization
        } else if !cli.role_arns.is_empty() {
            ScanMode::RoleArns(cli.role_arns)
        } else {
            ScanMode::CurrentAccount
        };

        Ok(Config {
            regions: cli.regions,
            mode,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
            mode: ScanMode::CurrentAccount,
        }
    }
}

/// Extract account ID from a role ARN
pub fn extract_account_from_arn(arn: &str) -> Option<&str> {
    arn.split(':').nth(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_default() -> Cli {
        Cli {
            use_org: false,
            role_arns: vec![],
            regions: vec!["us-east-1".to_string(), "us-west-2".to_string()],
        }
    }

    #[test]
    fn config_from_cli_defaults_to_current_account() {
        let cli = cli_default();
        let config = Config::try_from(cli).unwrap();
        assert_eq!(config.mode, ScanMode::CurrentAccount);
        assert_eq!(config.regions.len(), 2);
    }

    #[test]
    fn config_from_cli_with_use_org() {
        let cli = Cli {
            use_org: true,
            ..cli_default()
        };
        let config = Config::try_from(cli).unwrap();
        assert_eq!(config.mode, ScanMode::Organization);
    }

    #[test]
    fn config_from_cli_with_role_arns() {
        let cli = Cli {
            role_arns: vec!["arn:aws:iam::123456789012:role/TestRole".to_string()],
            ..cli_default()
        };
        let config = Config::try_from(cli).unwrap();
        match config.mode {
            ScanMode::RoleArns(arns) => {
                assert_eq!(arns.len(), 1);
            }
            _ => panic!("Expected RoleArns mode"),
        }
    }

    #[test]
    fn config_rejects_empty_regions() {
        let cli = Cli {
            regions: vec![],
            ..cli_default()
        };
        let result = Config::try_from(cli);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("region"));
    }

    #[test]
    fn config_rejects_invalid_role_arn_format() {
        let cli = Cli {
            role_arns: vec!["invalid-arn".to_string()],
            ..cli_default()
        };
        let result = Config::try_from(cli);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid role ARN"));
    }

    #[test]
    fn config_rejects_role_arn_without_role() {
        let cli = Cli {
            role_arns: vec!["arn:aws:iam::123456789012:user/TestUser".to_string()],
            ..cli_default()
        };
        let result = Config::try_from(cli);
        assert!(result.is_err());
    }

    #[test]
    fn config_accepts_valid_role_arns() {
        let cli = Cli {
            role_arns: vec![
                "arn:aws:iam::123456789012:role/TestRole".to_string(),
                "arn:aws:iam::987654321098:role/AnotherRole".to_string(),
            ],
            ..cli_default()
        };
        let config = Config::try_from(cli).unwrap();
        match config.mode {
            ScanMode::RoleArns(arns) => {
                assert_eq!(arns.len(), 2);
            }
            _ => panic!("Expected RoleArns mode"),
        }
    }

    #[test]
    fn config_default_has_both_regions() {
        let config = Config::default();
        assert!(config.regions.contains(&"us-east-1".to_string()));
        assert!(config.regions.contains(&"us-west-2".to_string()));
    }

    #[test]
    fn config_default_is_current_account_mode() {
        let config = Config::default();
        assert_eq!(config.mode, ScanMode::CurrentAccount);
    }

    #[test]
    fn extract_account_from_arn_valid() {
        let arn = "arn:aws:iam::123456789012:role/TestRole";
        assert_eq!(extract_account_from_arn(arn), Some("123456789012"));
    }

    #[test]
    fn extract_account_from_arn_invalid() {
        let arn = "invalid";
        assert_eq!(extract_account_from_arn(arn), None);
    }

    #[test]
    fn scan_mode_equality() {
        assert_eq!(ScanMode::CurrentAccount, ScanMode::CurrentAccount);
        assert_eq!(ScanMode::Organization, ScanMode::Organization);
        assert_ne!(ScanMode::CurrentAccount, ScanMode::Organization);
    }
}
