use clap::{Parser, Subcommand, ValueEnum};

/// PostgreSQL security hardening scanner
#[derive(Parser, Debug)]
#[command(name = "pg-harden")]
#[command(author, version, about, long_about = None)]
#[command(after_help = "\
Use <COMMAND> --help for more information on a specific command.

Examples:
  pg-harden scan -H 192.168.1.100                       Scan a single host
  pg-harden scan -H db.example.com                      Scan by hostname (DNS resolved)
  pg-harden scan -H 10.0.0.0/24                         Scan a subnet via CIDR
  pg-harden scan -H fd00::/120                          Scan an IPv6 CIDR block
  pg-harden scan -H 10.0.0.1 -H 10.0.0.2                Scan multiple targets
  pg-harden scan -H db.local -f json                    Output results as JSON
  pg-harden scan -H db.local -c auth-scram              Run a specific check only
  pg-harden scan --offline --hba-file /etc/pg_hba.conf  File-based checks without a connection
  pg-harden list                                        List all available checks")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan PostgreSQL instance for security issues
    Scan(ScanArgs),

    /// List available security checks
    List,
}

#[derive(Parser, Debug)]
pub struct ScanArgs {
    /// Target host(s): IP address, hostname, or CIDR block. Repeatable.
    #[arg(short = 'H', long = "host", num_args = 1..)]
    pub hosts: Vec<String>,

    /// PostgreSQL port
    #[arg(short = 'p', long, env = "PGPORT", default_value = "5432")]
    pub port: u16,

    /// PostgreSQL user
    #[arg(short = 'U', long, env = "PGUSER", default_value = "postgres")]
    pub user: String,

    /// PostgreSQL password (or use PGPASSWORD env var)
    #[arg(short = 'W', long, env = "PGPASSWORD")]
    pub password: Option<String>,

    /// PostgreSQL database
    #[arg(short = 'd', long, env = "PGDATABASE", default_value = "postgres")]
    pub database: String,

    /// Unix socket directory
    #[arg(short = 's', long, env = "PGHOST")]
    pub socket: Option<String>,

    /// Path to pg_hba.conf (auto-detected if not specified)
    #[arg(long)]
    pub hba_file: Option<String>,

    /// Path to postgresql.conf (auto-detected if not specified)
    #[arg(long)]
    pub config_file: Option<String>,

    /// Output format
    #[arg(short = 'f', long, default_value = "text")]
    pub format: OutputFormat,

    /// Run specific checks only (comma-separated)
    #[arg(short = 'c', long, value_delimiter = ',')]
    pub checks: Option<Vec<String>>,

    /// Exclude specific checks (comma-separated)
    #[arg(short = 'x', long, value_delimiter = ',')]
    pub exclude: Option<Vec<String>>,

    /// Connection timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Continue even if connection fails (file-based checks only)
    #[arg(long)]
    pub offline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

impl ScanArgs {
    /// Whether any connection target is specified (host or socket).
    pub fn has_target(&self) -> bool {
        !self.hosts.is_empty() || self.socket.is_some()
    }
}
