use crate::checks::SecurityCheck;
use crate::config::ScanConfig;
use crate::connection::get_hba_file;
use crate::error::CheckError;
use crate::output::{CheckResult, Severity};
use async_trait::async_trait;
use tokio::fs;
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
        Severity::High
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
        // Determine hba_file path
        let hba_path = if let Some(ref path) = config.hba_file {
            path.clone()
        } else if let Some(client) = client {
            get_hba_file(client).await?
        } else {
            return Err(CheckError::FileRead(
                "No pg_hba.conf path specified and no database connection".to_string(),
            ));
        };

        // Read and parse the file
        let content = fs::read_to_string(&hba_path)
            .await
            .map_err(|e| CheckError::FileRead(format!("{}: {}", hba_path, e)))?;

        let issues = analyze_hba_content(&content);

        if issues.is_empty() {
            Ok(CheckResult::pass(
                self.id(),
                self.name(),
                self.severity(),
                "No dangerous authentication methods found",
            ))
        } else {
            Ok(CheckResult::fail(
                self.id(),
                self.name(),
                self.severity(),
                format!("Found {} dangerous authentication entries", issues.len()),
            )
            .with_details(issues)
            .with_remediation(
                "Replace 'trust', 'password', and 'md5' with 'scram-sha-256' or 'cert'",
            ))
        }
    }
}

/// Analyze pg_hba.conf content for dangerous entries
fn analyze_hba_content(content: &str) -> Vec<String> {
    let mut issues = Vec::new();
    let dangerous_methods = ["trust", "password", "md5"];

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse the line
        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        // pg_hba.conf format: TYPE DATABASE USER ADDRESS METHOD [OPTIONS]
        // Minimum valid line has at least 4-5 parts
        if parts.len() < 4 {
            continue;
        }

        // Find the method (varies based on line type)
        let method = find_auth_method(&parts);

        if let Some(method) = method {
            if dangerous_methods.contains(&method) {
                let issue = format!(
                    "Line {}: {} ({}) - '{}' authentication is insecure",
                    line_num + 1,
                    parts[0], // TYPE
                    parts.get(1).unwrap_or(&"?"), // DATABASE
                    method
                );
                issues.push(issue);
            }
        }
    }

    issues
}

/// Find the authentication method in a pg_hba.conf line
fn find_auth_method<'a>(parts: &[&'a str]) -> Option<&'a str> {
    if parts.is_empty() {
        return None;
    }

    let entry_type = parts[0];

    match entry_type {
        "local" => {
            // local DATABASE USER METHOD [OPTIONS]
            parts.get(3).copied()
        }
        "host" | "hostssl" | "hostnossl" | "hostgssenc" | "hostnogssenc" => {
            // host DATABASE USER ADDRESS METHOD [OPTIONS]
            // ADDRESS can be CIDR or hostname
            parts.get(4).copied()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_trust_local() {
        let content = "local all all trust";
        let issues = analyze_hba_content(content);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("trust"));
    }

    #[test]
    fn test_detect_md5_host() {
        let content = "host all all 0.0.0.0/0 md5";
        let issues = analyze_hba_content(content);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("md5"));
    }

    #[test]
    fn test_safe_scram() {
        let content = "host all all 0.0.0.0/0 scram-sha-256";
        let issues = analyze_hba_content(content);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_skip_comments() {
        let content = "# This is a comment\n# host all all trust";
        let issues = analyze_hba_content(content);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_multiple_issues() {
        let content = r#"
local all postgres trust
host all all 127.0.0.1/32 md5
host all all ::1/128 password
"#;
        let issues = analyze_hba_content(content);
        assert_eq!(issues.len(), 3);
    }
}
