/// Configuration for a scan operation
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Path to pg_hba.conf
    pub hba_file: Option<String>,

    /// Path to postgresql.conf
    pub config_file: Option<String>,

    /// PostgreSQL data directory
    pub data_directory: Option<String>,

    /// Enable verbose output
    pub verbose: bool,

    /// Checks to run (None = all)
    pub include_checks: Option<Vec<String>>,

    /// Checks to exclude
    pub exclude_checks: Option<Vec<String>>,
}

impl ScanConfig {
    pub fn should_run_check(&self, check_id: &str) -> bool {
        // If exclude list contains this check, skip it
        if let Some(ref exclude) = self.exclude_checks
            && exclude.iter().any(|e| e == check_id)
        {
            return false;
        }

        // If include list is specified, only run those
        if let Some(ref include) = self.include_checks {
            return include.iter().any(|i| i == check_id);
        }

        // Default: run all checks
        true
    }
}
