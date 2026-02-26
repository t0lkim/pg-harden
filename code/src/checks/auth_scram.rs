use crate::checks::SecurityCheck;
use crate::config::ScanConfig;
use crate::connection::query_setting;
use crate::error::CheckError;
use crate::output::{CheckResult, Severity};
use async_trait::async_trait;
use tokio_postgres::Client;

/// Check that SCRAM-SHA-256 is enforced for password encryption
pub struct AuthScramCheck;

#[async_trait]
impl SecurityCheck for AuthScramCheck {
    fn id(&self) -> &'static str {
        "auth-scram"
    }

    fn name(&self) -> &'static str {
        "SCRAM-SHA-256 Authentication"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "Verify SCRAM-SHA-256 is used for password encryption"
    }

    async fn execute(
        &self,
        client: Option<&Client>,
        _config: &ScanConfig,
    ) -> Result<CheckResult, CheckError> {
        let client = client.ok_or(CheckError::RequiresConnection)?;

        let password_encryption = query_setting(client, "password_encryption").await?;

        if password_encryption == "scram-sha-256" {
            Ok(CheckResult::pass(
                self.id(),
                self.name(),
                self.severity(),
                "Password encryption uses SCRAM-SHA-256",
            ))
        } else {
            Ok(CheckResult::fail(
                self.id(),
                self.name(),
                self.severity(),
                format!(
                    "Password encryption is '{}', should be 'scram-sha-256'",
                    password_encryption
                ),
            )
            .with_remediation("Set password_encryption = 'scram-sha-256' in postgresql.conf"))
        }
    }
}
