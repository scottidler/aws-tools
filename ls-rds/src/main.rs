//! ls-rds
//!
//! List every RDS DB instance in the current account (and optionally across
//! other accounts or explicit role ARNs). All log output is written to a
//! timestamped file under an OS‑appropriate "slam" log directory.

use clap::Parser;
use eyre::Result;
use log::info;
use ls_rds::{format_instance, get_or_create_log_dir, run, Cli, Config};
use std::{
    fs::OpenOptions,
    io::Write,
    time::Instant,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Set up file logging
    let log_dir = get_or_create_log_dir();
    let log_file_path = log_dir.join("ls-rds.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)?;
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            let ts = buf.timestamp_millis();
            writeln!(
                buf,
                "{} {:<5} [{}] {}",
                ts,
                record.level(),
                record.target(),
                record.args()
            )
        })
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .filter_level(log::LevelFilter::Trace)
        .init();
    info!("Logging to {}", log_file_path.display());

    let overall_start = Instant::now();
    let cli = Cli::parse();
    let config = Config::try_from(cli)?;

    let result = run(&config).await?;

    // Output results
    for inst in &result.instances {
        println!("{}", format_instance(inst));
    }

    info!("Total runtime: {:.2?}", overall_start.elapsed());
    Ok(())
}
