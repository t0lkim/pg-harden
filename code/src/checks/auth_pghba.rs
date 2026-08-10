use crate::checks::SecurityCheck;
use crate::checks::pghba::{self, DANGEROUS_METHODS};
use crate::config::ScanConfig;
use crate::error::CheckError;
use crate::output::{CheckResult, Severity};
use async_trait::async_trait;
use tokio_postgres::Client;

/// Check pg_hba.conf for dangerous authentication methods
pub struct AuthPgHbaCheck;

#[async_trait]
impl SecurityCheck for AuthPgHbaCheck {
    fn id(&self) -> &'static str {
        "auth-pghba"
    }

    fn name(&self) -> &'static str {
        "pg_hba.conf Security"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn description(&self) -> &'static str {
        "Check for dangerous authentication methods in pg_hba.conf"
    }

    fn requires_connection(&self) -> bool {
        false // Can work with file path directly
    }

    async fn execute(
        &self,
        client: Option<&Client>,
        config: &ScanConfig,
    ) -> Result<CheckResult, CheckError> {
        let hba_path = pghba::resolve_hba_path(client, config).await?;
        let (entries, warnings) = pghba::load_hba_entries(&hba_path).await;

        let issues: Vec<String> = entries
            .iter()
            .filter(|e| DANGEROUS_METHODS.contains(&e.method.as_str()))
            .map(|e| {
                format!(
                    "{}:{}: {} {} {} - '{}' authentication is insecure",
                    e.source, e.line, e.entry_type, e.database, e.user, e.method
                )
            })
            .collect();

        if issues.is_empty() && warnings.is_empty() {
            Ok(CheckResult::pass(
                self.id(),
                self.name(),
                self.severity(),
                "No dangerous authentication methods found",
            ))
        } else if issues.is_empty() {
            Ok(CheckResult::pass(
                self.id(),
                self.name(),
                self.severity(),
                "No dangerous authentication methods found",
            )
            .with_details(warnings))
        } else {
            Ok(CheckResult::fail(
                self.id(),
                self.name(),
                self.severity(),
                format!("Found {} dangerous authentication entries", issues.len()),
            )
            .with_details(issues)
            .with_remediation(
                "Replace 'trust', 'password', 'md5', and 'ident' with 'scram-sha-256' or 'cert'",
            ))
        }
    }
}
