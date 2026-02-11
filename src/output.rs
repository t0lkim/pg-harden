use colored::Colorize;
use serde::{Deserialize, Serialize};

/// Severity level for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn colored(&self) -> colored::ColoredString {
        match self {
            Severity::Info => self.as_str().blue(),
            Severity::Low => self.as_str().cyan(),
            Severity::Medium => self.as_str().yellow(),
            Severity::High => self.as_str().red(),
            Severity::Critical => self.as_str().red().bold(),
        }
    }
}

/// Result of a security check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: String,
    pub check_name: String,
    pub severity: Severity,
    pub passed: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl CheckResult {
    pub fn pass(id: &str, name: &str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            check_id: id.to_string(),
            check_name: name.to_string(),
            severity,
            passed: true,
            message: message.into(),
            details: None,
            remediation: None,
        }
    }

    pub fn fail(
        id: &str,
        name: &str,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            check_id: id.to_string(),
            check_name: name.to_string(),
            severity,
            passed: false,
            message: message.into(),
            details: None,
            remediation: None,
        }
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn print(&self) {
        let status = if self.passed {
            "✓".green()
        } else {
            "✗".red()
        };

        println!(
            "{} [{}] {}: {}",
            status,
            self.severity.colored(),
            self.check_name.bold(),
            self.message
        );

        if let Some(details) = &self.details {
            for detail in details {
                println!("    → {}", detail);
            }
        }

        if !self.passed {
            if let Some(remediation) = &self.remediation {
                println!("    {} {}", "Fix:".yellow(), remediation);
            }
        }
    }
}

/// Results for a single host
#[derive(Debug, Serialize, Deserialize)]
pub struct HostReport {
    pub host: String,
    pub results: Vec<CheckResult>,
    pub summary: ScanSummary,
}

impl HostReport {
    pub fn new(host: String, results: Vec<CheckResult>) -> Self {
        let summary = ScanSummary::from_results(&results);
        Self {
            host,
            results,
            summary,
        }
    }
}

/// Report containing all check results, optionally across multiple hosts.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub hosts: Vec<HostReport>,
    pub summary: ScanSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub critical: usize,
    pub high: usize,
}

impl ScanSummary {
    pub fn from_results(results: &[CheckResult]) -> Self {
        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = total - passed;
        let critical = results
            .iter()
            .filter(|r| !r.passed && r.severity == Severity::Critical)
            .count();
        let high = results
            .iter()
            .filter(|r| !r.passed && r.severity == Severity::High)
            .count();

        Self {
            total,
            passed,
            failed,
            critical,
            high,
        }
    }

    pub fn aggregate(summaries: &[&ScanSummary]) -> Self {
        Self {
            total: summaries.iter().map(|s| s.total).sum(),
            passed: summaries.iter().map(|s| s.passed).sum(),
            failed: summaries.iter().map(|s| s.failed).sum(),
            critical: summaries.iter().map(|s| s.critical).sum(),
            high: summaries.iter().map(|s| s.high).sum(),
        }
    }
}

impl ScanReport {
    pub fn new(hosts: Vec<HostReport>) -> Self {
        let refs: Vec<&ScanSummary> = hosts.iter().map(|h| &h.summary).collect();
        let summary = ScanSummary::aggregate(&refs);
        Self { hosts, summary }
    }

    pub fn exit_code(&self) -> i32 {
        if self.summary.critical > 0 || self.summary.high > 0 {
            2
        } else if self.summary.failed > 0 {
            1
        } else {
            0
        }
    }

    pub fn print(&self) {
        let multi = self.hosts.len() > 1;

        for host_report in &self.hosts {
            if multi {
                println!();
                println!(
                    "{}",
                    format!("━━━ {} ━━━", host_report.host).bold().cyan()
                );
            }

            println!();
            for result in &host_report.results {
                result.print();
            }

            if multi {
                println!();
                println!(
                    "  {} passed, {} failed ({} critical, {} high)",
                    host_report.summary.passed.to_string().green(),
                    host_report.summary.failed.to_string().red(),
                    host_report.summary.critical,
                    host_report.summary.high
                );
            }
        }

        println!();
        if multi {
            println!(
                "Overall: {} hosts scanned — {} passed, {} failed ({} critical, {} high)",
                self.hosts.len(),
                self.summary.passed.to_string().green(),
                self.summary.failed.to_string().red(),
                self.summary.critical,
                self.summary.high
            );
        } else {
            println!(
                "Summary: {} passed, {} failed ({} critical, {} high)",
                self.summary.passed.to_string().green(),
                self.summary.failed.to_string().red(),
                self.summary.critical,
                self.summary.high
            );
        }
    }

    pub fn print_json(&self) -> Result<(), serde_json::Error> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }
}
