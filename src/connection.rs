use crate::cli::ScanArgs;
use crate::error::ConnectionError;
use tokio_postgres::{Client, NoTls};

/// Establish connection to PostgreSQL
pub async fn connect(args: &ScanArgs, verbose: bool) -> Result<Client, ConnectionError> {
    let config = build_connection_string(args);

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

fn build_connection_string(args: &ScanArgs) -> String {
    let mut parts = Vec::new();

    if let Some(ref socket) = args.socket {
        parts.push(format!("host={}", socket));
    } else if let Some(ref host) = args.host {
        parts.push(format!("host={}", host));
    }

    parts.push(format!("port={}", args.port));
    parts.push(format!("user={}", args.user));
    parts.push(format!("dbname={}", args.database));

    if let Some(ref password) = args.password {
        parts.push(format!("password={}", password));
    }

    parts.push(format!("connect_timeout={}", args.timeout));

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

/// Query the data directory from PostgreSQL
pub async fn get_data_directory(client: &Client) -> Result<String, crate::error::CheckError> {
    query_setting(client, "data_directory").await
}

/// Query the hba_file location from PostgreSQL
pub async fn get_hba_file(client: &Client) -> Result<String, crate::error::CheckError> {
    query_setting(client, "hba_file").await
}
