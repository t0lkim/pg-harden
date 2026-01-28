use clap::{Parser, Subcommand, ValueEnum};

/// PostgreSQL security hardening scanner
#[derive(Parser, Debug)]
#[command(name = "pg-harden")]
#[command(author, version, about, long_about = None)]
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
    /// PostgreSQL host
    #[arg(short = 'H', long, env = "PGHOST")]
    pub host: Option<String>,

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
    /// Determine if we should use socket connection
    pub fn use_socket(&self) -> bool {
        self.socket.is_some() && self.host.is_none()
    }

    /// Get the connection host (socket path or TCP host)
    pub fn connection_host(&self) -> Option<&str> {
        if let Some(ref socket) = self.socket {
            Some(socket.as_str())
        } else {
            self.host.as_deref()
        }
    }
}
