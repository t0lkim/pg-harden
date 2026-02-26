mod checks;
mod cli;
mod config;
mod connection;
mod error;
mod output;
mod target;

use crate::checks::CheckRegistry;
use crate::cli::{Cli, Commands, OutputFormat, ScanArgs};
use crate::config::ScanConfig;
use crate::connection::ConnectParams;
use crate::output::{HostReport, ScanReport};
use crate::target::ResolvedTarget;
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

    let scan_config = ScanConfig {
        hba_file: args.hba_file.clone(),
        config_file: args.config_file.clone(),
        data_directory: None,
        verbose,
        include_checks: args.checks.clone(),
        exclude_checks: args.exclude.clone(),
    };

    // Resolve targets
    if !args.has_target() {
        if args.offline {
            // Offline mode with no target — run file-based checks only
            let results = run_checks_on_host(&registry, None, &scan_config, verbose).await;
            let host_report = HostReport::new("localhost (offline)".to_string(), results);
            let report = ScanReport::new(vec![host_report]);
            output_report(&report, &args)?;
            return Ok(report.exit_code());
        }

        eprintln!(
            "{}: No host or socket specified. Use --offline for file-based checks only.",
            "Error".red()
        );
        return Err(error::AppError::Config(
            "No connection target specified".to_string(),
        ));
    }

    // Socket connection — single target, no resolution needed
    if let Some(ref socket) = args.socket {
        let params = ConnectParams::from_socket(&args, socket);
        let client = match connection::connect(&params, verbose).await {
            Ok(c) => {
                if verbose {
                    eprintln!("{}", "Connected via socket".green());
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
        };

        let results = run_checks_on_host(&registry, client.as_ref(), &scan_config, verbose).await;
        let host_report = HostReport::new(format!("socket:{}", socket), results);
        let report = ScanReport::new(vec![host_report]);
        output_report(&report, &args)?;
        return Ok(report.exit_code());
    }

    // TCP targets — resolve hosts, CIDR, hostnames
    let targets = target::resolve_all_targets(&args.hosts)
        .map_err(|e| error::AppError::Config(e))?;

    if targets.is_empty() {
        return Err(error::AppError::Config(
            "No targets resolved from input".to_string(),
        ));
    }

    if verbose {
        eprintln!(
            "Resolved {} target(s) from {} input(s)",
            targets.len(),
            args.hosts.len()
        );
    }

    let mut host_reports = Vec::new();

    for target in &targets {
        if verbose || targets.len() > 1 {
            eprintln!("Scanning {}...", target);
        }

        let host_report = scan_single_target(target, &args, &registry, &scan_config, verbose).await?;
        host_reports.push(host_report);
    }

    let report = ScanReport::new(host_reports);
    output_report(&report, &args)?;
    Ok(report.exit_code())
}

async fn scan_single_target(
    target: &ResolvedTarget,
    args: &ScanArgs,
    registry: &CheckRegistry,
    scan_config: &ScanConfig,
    verbose: bool,
) -> Result<HostReport, error::AppError> {
    let host_str = target.addr.to_string();
    let params = ConnectParams::from_args(args, &host_str);

    let client = match connection::connect(&params, verbose).await {
        Ok(c) => {
            if verbose {
                eprintln!("{}: {}", "Connected".green(), target);
            }
            Some(c)
        }
        Err(e) => {
            if args.offline {
                eprintln!(
                    "{}: {} for {} (continuing in offline mode)",
                    "Warning".yellow(),
                    e,
                    target
                );
                None
            } else {
                return Err(e.into());
            }
        }
    };

    let results = run_checks_on_host(registry, client.as_ref(), scan_config, verbose).await;
    Ok(HostReport::new(target.to_string(), results))
}

async fn run_checks_on_host(
    registry: &CheckRegistry,
    client: Option<&tokio_postgres::Client>,
    scan_config: &ScanConfig,
    verbose: bool,
) -> Vec<output::CheckResult> {
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

        match check.execute(client, scan_config).await {
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

    results
}

fn output_report(report: &ScanReport, args: &ScanArgs) -> Result<(), error::AppError> {
    match args.format {
        OutputFormat::Text => report.print(),
        OutputFormat::Json => {
            report.print_json().map_err(|e| {
                error::AppError::Config(format!("JSON serialisation failed: {}", e))
            })?;
        }
    }
    Ok(())
}
