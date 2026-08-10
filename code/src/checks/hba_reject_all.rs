use crate::checks::SecurityCheck;
use crate::checks::pghba::{self, HbaEntry};
use crate::config::ScanConfig;
use crate::error::CheckError;
use crate::output::{CheckResult, Severity};
use async_trait::async_trait;
use tokio_postgres::Client;

/// Check that pg_hba.conf ends with reject-all rules for IPv4 and IPv6.
///
/// Deny-all posture: after the explicit allow rules, the final host rules
/// must reject everything else. Any host entry after the reject-all rules
/// is unreachable and reported.
pub struct HbaRejectAllCheck;

#[async_trait]
impl SecurityCheck for HbaRejectAllCheck {
    fn id(&self) -> &'static str {
        "hba-reject-all"
    }

    fn name(&self) -> &'static str {
        "pg_hba.conf Reject-All Default"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "Verify pg_hba.conf has reject-all rules (0.0.0.0/0 and ::/0) as the final entries"
    }

    fn requires_connection(&self) -> bool {
        false
    }

    async fn execute(
        &self,
        client: Option<&Client>,
        config: &ScanConfig,
    ) -> Result<CheckResult, CheckError> {
        let hba_path = pghba::resolve_hba_path(client, config).await?;
        let (entries, _) = pghba::load_hba_entries(&hba_path).await;

        let problems = analyze_reject_all(&entries);

        if problems.is_empty() {
            Ok(CheckResult::pass(
                self.id(),
                self.name(),
                self.severity(),
                "pg_hba.conf ends with reject-all rules for IPv4 and IPv6",
            ))
        } else {
            Ok(CheckResult::fail(
                self.id(),
                self.name(),
                self.severity(),
                "pg_hba.conf is missing reject-all default rules".to_string(),
            )
            .with_details(problems)
            .with_remediation(
                "Append 'host all all 0.0.0.0/0 reject' and 'host all all ::/0 reject' as the final pg_hba.conf rules",
            ))
        }
    }
}

/// Assess host-type entries for reject-all coverage. Returns a list of
/// problems; empty means the deny-all posture is in place.
fn analyze_reject_all(entries: &[HbaEntry]) -> Vec<String> {
    let host_entries: Vec<&HbaEntry> = entries.iter().filter(|e| e.is_host_type()).collect();

    let last_v4_reject = host_entries.iter().rposition(|e| {
        e.method == "reject" && e.database == "all" && e.user == "all" && e.is_ipv4_wildcard()
    });
    let last_v6_reject = host_entries.iter().rposition(|e| {
        e.method == "reject" && e.database == "all" && e.user == "all" && e.is_ipv6_wildcard()
    });

    let mut problems = Vec::new();

    if last_v4_reject.is_none() {
        problems.push("No 'host all all 0.0.0.0/0 reject' rule found".to_string());
    }
    if last_v6_reject.is_none() {
        problems.push("No 'host all all ::/0 reject' rule found".to_string());
    }

    // Anything after the last reject-all is unreachable configuration
    let last_reject_idx = [last_v4_reject, last_v6_reject].into_iter().flatten().max();
    if let Some(idx) = last_reject_idx {
        for entry in &host_entries[idx + 1..] {
            problems.push(format!(
                "{}:{}: entry after reject-all is unreachable ({} {} {})",
                entry.source, entry.line, entry.database, entry.user, entry.method
            ));
        }
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::pghba::parse_hba_content;

    fn analyze(content: &str) -> Vec<String> {
        analyze_reject_all(&parse_hba_content("test.conf", content))
    }

    #[test]
    fn pass_with_both_reject_all_rules() {
        let problems = analyze(
            "host netbox netbox 10.0.1.0/24 scram-sha-256\n\
             host all all 0.0.0.0/0 reject\n\
             host all all ::/0 reject\n",
        );
        assert!(problems.is_empty(), "unexpected: {:?}", problems);
    }

    #[test]
    fn fail_without_any_reject_all() {
        let problems = analyze("host all all 10.0.0.0/8 scram-sha-256\n");
        assert_eq!(problems.len(), 2);
        assert!(problems[0].contains("0.0.0.0/0"));
        assert!(problems[1].contains("::/0"));
    }

    #[test]
    fn fail_with_only_ipv4_reject_all() {
        let problems = analyze("host all all 0.0.0.0/0 reject\n");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("::/0"));
    }

    #[test]
    fn reject_all_with_separate_netmask_counts() {
        let problems = analyze(
            "host all all 0.0.0.0 0.0.0.0 reject\n\
             host all all ::/0 reject\n",
        );
        assert!(problems.is_empty(), "unexpected: {:?}", problems);
    }

    #[test]
    fn reject_all_not_matching_all_databases_fails() {
        let problems = analyze("host postgres all 0.0.0.0/0 reject\n");
        assert!(problems.iter().any(|p| p.contains("0.0.0.0/0")));
    }

    #[test]
    fn entries_after_reject_all_flagged_unreachable() {
        let problems = analyze(
            "host all all 0.0.0.0/0 reject\n\
             host all all ::/0 reject\n\
             host late late 10.0.0.5/32 scram-sha-256\n",
        );
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("unreachable"));
    }

    #[test]
    fn local_entries_do_not_count_as_reject_all() {
        let problems = analyze("local all all reject\n");
        assert_eq!(problems.len(), 2);
    }
}
