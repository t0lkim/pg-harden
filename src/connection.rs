use crate::cli::ScanArgs;
use crate::error::ConnectionError;
use tokio_postgres::{Client, NoTls};

/// Connection parameters for a single target.
pub struct ConnectParams<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub password: Option<&'a str>,
    pub database: &'a str,
    pub timeout: u64,
}

impl<'a> ConnectParams<'a> {
    /// Build params for a specific host from ScanArgs.
    pub fn from_args(args: &'a ScanArgs, host: &'a str) -> Self {
        Self {
            host,
            port: args.port,
            user: &args.user,
            password: args.password.as_deref(),
            database: &args.database,
            timeout: args.timeout,
        }
    }

    /// Build params for a socket connection from ScanArgs.
    pub fn from_socket(args: &'a ScanArgs, socket: &'a str) -> Self {
        Self {
            host: socket,
            port: args.port,
            user: &args.user,
            password: args.password.as_deref(),
            database: &args.database,
            timeout: args.timeout,
        }
    }
}

/// Establish connection to PostgreSQL.
pub async fn connect(params: &ConnectParams<'_>, verbose: bool) -> Result<Client, ConnectionError> {
    let config = build_connection_string(params);

    if verbose {
        eprintln!("Connecting with: {}", redact_password(&config));
    }

    let (client, connection) = tokio_postgres::connect(&config, NoTls)
        .await
        .map_err(|e| ConnectionError::Connection(e.to_string()))?;

    // Spawn connection handler
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    Ok(client)
}

fn build_connection_string(params: &ConnectParams<'_>) -> String {
    let mut parts = Vec::new();

    parts.push(format!("host={}", params.host));
    parts.push(format!("port={}", params.port));
    parts.push(format!("user={}", params.user));
    parts.push(format!("dbname={}", params.database));

    if let Some(password) = params.password {
        parts.push(format!("password={}", password));
    }

    parts.push(format!("connect_timeout={}", params.timeout));

    parts.join(" ")
}

fn redact_password(config: &str) -> String {
    let mut result = String::new();

    for part in config.split_whitespace() {
        if part.starts_with("password=") {
            result.push_str("password=*** ");
        } else {
            result.push_str(part);
            result.push(' ');
        }
    }

    result.trim().to_string()
}

/// Query a single value from PostgreSQL
pub async fn query_setting(client: &Client, setting: &str) -> Result<String, crate::error::CheckError> {
    let query = format!("SHOW {}", setting);
    let row = client
        .query_one(&query, &[])
        .await
        .map_err(|e| crate::error::CheckError::QueryFailed(e.to_string()))?;

    Ok(row.get(0))
}

/// Query the hba_file location from PostgreSQL
pub async fn get_hba_file(client: &Client) -> Result<String, crate::error::CheckError> {
    query_setting(client, "hba_file").await
}
