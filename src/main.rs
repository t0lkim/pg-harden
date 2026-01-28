mod checks;
mod cli;
mod config;
mod connection;
mod error;
mod output;

use crate::checks::CheckRegistry;
use crate::cli::{Cli, Commands, OutputFormat, ScanArgs};
use crate::config::ScanConfig;
use crate::output::ScanReport;
use clap::Parser;
use colored::Colorize;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::List => {
            let registry = CheckRegistry::new();
            registry.print_list();
            ExitCode::SUCCESS
        }
        Commands::Scan(args) => match run_scan(args, cli.verbose).await {
            Ok(code) => ExitCode::from(code as u8),
            Err(e) => {
                eprintln!("{}: {}", "Error".red().bold(), e);
                ExitCode::from(3)
            }
        },
    }
}

async fn run_scan(args: ScanArgs, verbose: bool) -> Result<i32, error::AppError> {
    let registry = CheckRegistry::new();

    // Build scan configuration
    let scan_config = ScanConfig {
        hba_file: args.hba_file.clone(),
        config_file: args.config_file.clone(),
        data_directory: None,
        verbose,
        include_checks: args.checks.clone(),
        exclude_checks: args.exclude.clone(),
    };

    // Attempt connection
    let client = if args.connection_host().is_some() {
        match connection::connect(&args, verbose).await {
            Ok(c) => {
                if verbose {
                    eprintln!("{}", "Connected to PostgreSQL".green());
                }
                Some(c)
            }
            Err(e) => {
                if args.offline {
                    eprintln!(
                        "{}: {} (continuing in offline mode)",
                        "Warning".yellow(),
                        e
                    );
                    None
                } else {
                    return Err(e.into());
                }
            }
        }
    } else if args.offline {
        None
    } else {
        eprintln!(
            "{}: No host or socket specified. Use --offline for file-based checks only.",
            "Error".red()
        );
        return Err(error::AppError::Config(
            "No connection target specified".to_string(),
        ));
    };

    // Run checks
    let mut results = Vec::new();

    for check in registry.checks() {
        if !scan_config.should_run_check(check.id()) {
            continue;
        }

        if check.requires_connection() && client.is_none() {
            if verbose {
                eprintln!(
                    "Skipping {} (requires connection)",
                    check.id()
                );
            }
            continue;
        }

        match check.execute(client.as_ref(), &scan_config).await {
            Ok(result) => results.push(result),
            Err(e) => {
                if verbose {
                    eprintln!(
                        "{}: Check {} failed: {}",
                        "Warning".yellow(),
                        check.id(),
                        e
                    );
                }
            }
        }
    }

    // Generate report
    let report = ScanReport::new(results);

    // Output results
    match args.format {
        OutputFormat::Text => report.print(),
        OutputFormat::Json => {
            report.print_json().map_err(|e| {
                error::AppError::Config(format!("JSON serialization failed: {}", e))
            })?;
        }
    }

    Ok(report.exit_code())
}
