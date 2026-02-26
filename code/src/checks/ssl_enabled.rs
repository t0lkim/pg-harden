use crate::checks::SecurityCheck;
use crate::config::ScanConfig;
use crate::connection::query_setting;
use crate::error::CheckError;
use crate::output::{CheckResult, Severity};
use async_trait::async_trait;
use tokio_postgres::Client;

/// Check that SSL is enabled
pub struct SslEnabledCheck;

#[async_trait]
impl SecurityCheck for SslEnabledCheck {
    fn id(&self) -> &'static str {
        "ssl-enabled"
    }

    fn name(&self) -> &'static str {
        "SSL Enabled"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn description(&self) -> &'static str {
        "Verify SSL is enabled for encrypted connections"
    }

    async fn execute(
        &self,
        client: Option<&Client>,
        _config: &ScanConfig,
    ) -> Result<CheckResult, CheckError> {
        let client = client.ok_or(CheckError::RequiresConnection)?;

        let ssl = query_setting(client, "ssl").await?;

        if ssl == "on" {
            Ok(CheckResult::pass(
                self.id(),
                self.name(),
                self.severity(),
                "SSL is enabled",
            ))
        } else {
            Ok(CheckResult::fail(
                self.id(),
                self.name(),
                self.severity(),
                "SSL is disabled",
            )
            .with_remediation("Set ssl = on in postgresql.conf and configure SSL certificates"))
        }
    }
}
