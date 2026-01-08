//! ls-vpc 0.7.0
//! ---------------------------------------------------------------------------
//! Summary view  → Comfy-table output (no VPC-IDs passed).
//! Detail view   → ASCII output with per-resource "infra:" section (when VPC-IDs
//!                 are supplied).
//! Any InvalidVpcID.NotFound error is **silently skipped**.

use clap::Parser;
use env_logger::Target;
use eyre::Result;
use ls_vpc::{format_detail_table, format_summary_table, get_or_create_log_dir, run, Cli, Config};
use std::{fs::OpenOptions, io::Write, time::Instant};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::try_from(cli)?;

    // Set up logging
    let log_file = get_or_create_log_dir().join("ls-vpc.log");
    let fh = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)?;
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

    let start = Instant::now();
    let result = run(&config).await?;

    // Output results
    if config.summary_only {
        print!("{}", format_summary_table(&result.vpcs));
    } else {
        print!("{}", format_detail_table(&result.vpcs));
    }

    println!(
        "Finished in {:.2?} – {} VPC(s) across {} Region(s)",
        start.elapsed(),
        result.vpcs.len(),
        result.regions_scanned
    );

    Ok(())
}
