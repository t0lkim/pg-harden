use crate::cli::{ScanArgs, SslMode};
use crate::error::ConnectionError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tokio_postgres::config::SslMode as PgSslMode;
use tokio_postgres::{Client, Config, NoTls};

/// Connection parameters for a single target.
pub struct ConnectParams<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub password: Option<&'a str>,
    pub database: &'a str,
    pub timeout: u64,
    pub ssl_mode: SslMode,
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
            ssl_mode: args.ssl_mode,
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
            ssl_mode: args.ssl_mode,
        }
    }
}

/// Establish connection to PostgreSQL.
pub async fn connect(params: &ConnectParams<'_>, verbose: bool) -> Result<Client, ConnectionError> {
    let mut config = Config::new();
    config
        .host(params.host)
        .port(params.port)
        .user(params.user)
        .dbname(params.database)
        .connect_timeout(Duration::from_secs(params.timeout));

    if let Some(password) = params.password {
        config.password(password);
    }

    if verbose {
        eprintln!("Connecting with: {}", redacted_display(params));
    }

    // TLS is meaningless over a Unix socket — always plaintext (psql behaviour).
    let plaintext_only = params.host.starts_with('/') || params.ssl_mode == SslMode::Disable;

    if plaintext_only {
        config.ssl_mode(PgSslMode::Disable);
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|e| ConnectionError::Connection(e.to_string()))?;
        spawn_connection_handler(connection);
        return Ok(client);
    }

    let (pg_mode, verify) = match params.ssl_mode {
        SslMode::Prefer => (PgSslMode::Prefer, false),
        SslMode::Require => (PgSslMode::Require, false),
        SslMode::VerifyFull => (PgSslMode::Require, true),
        SslMode::Disable => unreachable!(),
    };

    config.ssl_mode(pg_mode);
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(make_tls_config(verify));
    let (client, connection) = config
        .connect(tls)
        .await
        .map_err(|e| ConnectionError::Connection(e.to_string()))?;
    spawn_connection_handler(connection);
    Ok(client)
}

fn spawn_connection_handler<S, T>(connection: tokio_postgres::Connection<S, T>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });
}

/// Build a rustls client config. With `verify` enabled the certificate
/// chain and hostname are checked against the Mozilla CA roots; otherwise
/// any certificate is accepted (psql `sslmode=require` semantics).
fn make_tls_config(verify: bool) -> ClientConfig {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS protocol versions");

    if verify {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    }
}

/// Certificate verifier that accepts anything. Used for sslmode=require,
/// where encryption is mandatory but the CA chain is not verified.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn redacted_display(params: &ConnectParams<'_>) -> String {
    let password = if params.password.is_some() {
        " password=***"
    } else {
        ""
    };
    format!(
        "host={} port={} user={} dbname={} connect_timeout={} sslmode={:?}{}",
        params.host,
        params.port,
        params.user,
        params.database,
        params.timeout,
        params.ssl_mode,
        password
    )
}

/// Query a single value from PostgreSQL
pub async fn query_setting(
    client: &Client,
    setting: &str,
) -> Result<String, crate::error::CheckError> {
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
