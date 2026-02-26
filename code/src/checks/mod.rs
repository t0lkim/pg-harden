pub mod auth_pghba;
pub mod auth_scram;
pub mod ssl_enabled;

use crate::config::ScanConfig;
use crate::error::CheckError;
use crate::output::{CheckResult, Severity};
use async_trait::async_trait;
use tokio_postgres::Client;

/// Trait for security checks
#[async_trait]
pub trait SecurityCheck: Send + Sync {
    /// Unique identifier for the check
    fn id(&self) -> &'static str;

    /// Human-readable name
    fn name(&self) -> &'static str;

    /// Severity if check fails
    fn severity(&self) -> Severity;

    /// Description of what this check does
    fn description(&self) -> &'static str;

    /// Whether this check requires a database connection
    fn requires_connection(&self) -> bool {
        true
    }

    /// Execute the check
    async fn execute(
        &self,
        client: Option<&Client>,
        config: &ScanConfig,
    ) -> Result<CheckResult, CheckError>;
}

/// Registry of all available checks
pub struct CheckRegistry {
    checks: Vec<Box<dyn SecurityCheck>>,
}

impl CheckRegistry {
    pub fn new() -> Self {
        let checks: Vec<Box<dyn SecurityCheck>> = vec![
            Box::new(auth_scram::AuthScramCheck),
            Box::new(ssl_enabled::SslEnabledCheck),
            Box::new(auth_pghba::AuthPgHbaCheck),
        ];

        Self { checks }
    }

    pub fn checks(&self) -> &[Box<dyn SecurityCheck>] {
        &self.checks
    }

    pub fn print_list(&self) {
        println!("Available security checks:\n");
        for check in &self.checks {
            println!(
                "  {:20} [{}] {}",
                check.id(),
                check.severity().as_str(),
                check.description()
            );
        }
        println!();
    }
}

impl Default for CheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}
