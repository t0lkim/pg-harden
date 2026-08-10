//! Shared pg_hba.conf parsing, including `include` directive expansion.
//!
//! Used by the `auth-pghba` and `hba-reject-all` checks.

use crate::config::ScanConfig;
use crate::connection::get_hba_file;
use crate::error::CheckError;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio_postgres::Client;

/// Maximum depth for nested include directives.
const MAX_INCLUDE_DEPTH: u8 = 3;

/// All pg_hba.conf authentication methods (PostgreSQL 18).
const KNOWN_METHODS: &[&str] = &[
    "trust",
    "reject",
    "scram-sha-256",
    "md5",
    "password",
    "gss",
    "sspi",
    "ident",
    "peer",
    "pam",
    "ldap",
    "radius",
    "cert",
    "bsd",
    "oauth",
];

/// Authentication methods considered dangerous under a deny-all posture.
pub const DANGEROUS_METHODS: &[&str] = &["trust", "password", "md5", "ident"];

/// A parsed pg_hba.conf entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HbaEntry {
    /// File the entry was read from (differs when reached via include)
    pub source: String,
    /// 1-based line number within the source file
    pub line: usize,
    /// local, host, hostssl, hostnossl, hostgssenc, hostnogssenc
    pub entry_type: String,
    pub database: String,
    pub user: String,
    /// CIDR/hostname for host-type entries; None for local
    pub address: Option<String>,
    pub method: String,
}

impl HbaEntry {
    /// True for TCP connection types (host, hostssl, ...).
    pub fn is_host_type(&self) -> bool {
        self.entry_type.starts_with("host")
    }

    /// True when the entry matches all IPv4 hosts.
    pub fn is_ipv4_wildcard(&self) -> bool {
        self.address.as_deref() == Some("0.0.0.0/0")
    }

    /// True when the entry matches all IPv6 hosts.
    pub fn is_ipv6_wildcard(&self) -> bool {
        self.address.as_deref() == Some("::/0")
    }
}

/// Parse the active (non-comment) entries from pg_hba.conf content.
pub fn parse_hba_content(source: &str, content: &str) -> Vec<HbaEntry> {
    let mut entries = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        // Skip include directives — they are expanded by the loader
        let directive = parts[0].trim_start_matches('@');
        if matches!(directive, "include" | "include_if_exists" | "include_dir") {
            continue;
        }

        let entry = match parts[0] {
            "local" => {
                // local DATABASE USER METHOD [OPTIONS]
                let method = find_method(&parts, 3);
                method.map(|(method, _)| HbaEntry {
                    source: source.to_string(),
                    line: line_num + 1,
                    entry_type: "local".to_string(),
                    database: parts[1].to_string(),
                    user: parts[2].to_string(),
                    address: None,
                    method: method.to_string(),
                })
            }
            t if t.starts_with("host") => {
                // host DATABASE USER ADDRESS [MASK] METHOD [OPTIONS]
                let method = find_method(&parts, 4);
                method.map(|(method, method_idx)| {
                    let address = combine_address(&parts, method_idx);
                    HbaEntry {
                        source: source.to_string(),
                        line: line_num + 1,
                        entry_type: t.to_string(),
                        database: parts[1].to_string(),
                        user: parts[2].to_string(),
                        address: Some(address),
                        method: method.to_string(),
                    }
                })
            }
            _ => None,
        };

        if let Some(entry) = entry {
            entries.push(entry);
        }
    }

    entries
}

/// Find the authentication method token starting at `from`, skipping any
/// netmask token in the separate-mask address form.
fn find_method<'a>(parts: &[&'a str], from: usize) -> Option<(&'a str, usize)> {
    (from..parts.len()).find_map(|i| {
        if KNOWN_METHODS.contains(&parts[i]) {
            Some((parts[i], i))
        } else {
            None
        }
    })
}

/// Build the address string, folding the separate-netmask form into CIDR.
fn combine_address(parts: &[&str], method_idx: usize) -> String {
    let addr = parts[3];

    // Separate-netmask form: host db user 10.0.0.0 255.0.0.0 scram-sha-256
    if method_idx == 5
        && let (Ok(ip), Ok(mask)) = (addr.parse::<IpAddr>(), parts[4].parse::<IpAddr>())
    {
        if let Some(prefix) = netmask_prefix_len(mask) {
            return format!("{}/{}", ip, prefix);
        }
        return format!("{} {}", ip, mask);
    }

    addr.to_string()
}

/// Convert a dotted-quad/colon netmask to a prefix length, if contiguous.
fn netmask_prefix_len(mask: IpAddr) -> Option<u8> {
    match mask {
        IpAddr::V4(m) => {
            let bits = u32::from(m);
            if bits == 0 {
                return Some(0);
            }
            let leading = bits.leading_ones();
            // Contiguity check: ones followed by zeros only
            if bits << leading == 0 {
                Some(leading as u8)
            } else {
                None
            }
        }
        IpAddr::V6(m) => {
            let bits = u128::from(m);
            if bits == 0 {
                return Some(0);
            }
            let leading = bits.leading_ones();
            if bits << leading == 0 {
                Some(leading as u8)
            } else {
                None
            }
        }
    }
}

/// Resolve the pg_hba.conf path: explicit flag, else `SHOW hba_file`.
pub async fn resolve_hba_path(
    client: Option<&Client>,
    config: &ScanConfig,
) -> Result<String, CheckError> {
    if let Some(ref path) = config.hba_file {
        return Ok(path.clone());
    }
    if let Some(client) = client {
        return get_hba_file(client).await;
    }
    Err(CheckError::FileRead(
        "No pg_hba.conf path specified and no database connection".to_string(),
    ))
}

/// Load pg_hba.conf entries, expanding include directives.
///
/// Returns the parsed entries plus warnings for includes that could not
/// be read (missing `include` targets, unreadable directories).
///
/// Errors when the main file itself is unreadable — a vacuous result set
/// must never masquerade as a passing configuration (e.g. when scanning
/// remotely, where the server's hba path does not exist locally).
pub async fn load_hba_entries(path: &str) -> Result<(Vec<HbaEntry>, Vec<String>), CheckError> {
    fs::metadata(path)
        .await
        .map_err(|e| CheckError::FileRead(format!("{}: {}", path, e)))?;

    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let mut visited = HashSet::new();

    load_file(
        Path::new(path),
        0,
        &mut visited,
        &mut entries,
        &mut warnings,
    )
    .await;

    Ok((entries, warnings))
}

async fn load_file(
    path: &Path,
    depth: u8,
    visited: &mut HashSet<PathBuf>,
    entries: &mut Vec<HbaEntry>,
    warnings: &mut Vec<String>,
) {
    if depth > MAX_INCLUDE_DEPTH {
        warnings.push(format!("{}: include depth exceeded", path.display()));
        return;
    }

    let canonical = path.to_path_buf();
    if !visited.insert(canonical.clone()) {
        return; // already loaded (include cycle)
    }

    let content = match fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) => {
            warnings.push(format!("{}: {}", path.display(), e));
            return;
        }
    };

    entries.extend(parse_hba_content(&path.display().to_string(), &content));

    // Expand include directives in order
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let directive = parts[0].trim_start_matches('@');
        let target = resolve_include(path, parts[1]);

        match directive {
            "include" => {
                if target.exists() {
                    Box::pin(load_file(&target, depth + 1, visited, entries, warnings)).await;
                } else {
                    warnings.push(format!("{}: include target not found", target.display()));
                }
            }
            "include_if_exists" => {
                if target.exists() {
                    Box::pin(load_file(&target, depth + 1, visited, entries, warnings)).await;
                }
            }
            "include_dir" => {
                load_dir(&target, depth, visited, entries, warnings).await;
            }
            _ => {}
        }
    }
}

async fn load_dir(
    dir: &Path,
    depth: u8,
    visited: &mut HashSet<PathBuf>,
    entries: &mut Vec<HbaEntry>,
    warnings: &mut Vec<String>,
) {
    let mut read_dir = match fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) => {
            warnings.push(format!("{}: {}", dir.display(), e));
            return;
        }
    };

    let mut conf_files = Vec::new();
    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "conf") {
            conf_files.push(path);
        }
    }
    // PostgreSQL processes include_dir files in C locale alphabetical order
    conf_files.sort();

    for file in conf_files {
        Box::pin(load_file(&file, depth + 1, visited, entries, warnings)).await;
    }
}

fn resolve_include(including_file: &Path, target: &str) -> PathBuf {
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        target_path.to_path_buf()
    } else {
        including_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(target_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> Vec<HbaEntry> {
        parse_hba_content("test.conf", content)
    }

    #[test]
    fn local_entry_parsed() {
        let entries = parse("local all all trust");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, "trust");
        assert_eq!(entries[0].entry_type, "local");
        assert!(entries[0].address.is_none());
    }

    #[test]
    fn host_cidr_parsed() {
        let entries = parse("host all all 0.0.0.0/0 md5");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, "md5");
        assert_eq!(entries[0].address.as_deref(), Some("0.0.0.0/0"));
    }

    #[test]
    fn host_separate_netmask_folded_to_cidr() {
        let entries = parse("host all all 10.0.0.0 255.0.0.0 scram-sha-256");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, "scram-sha-256");
        assert_eq!(entries[0].address.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn host_separate_netmask_zero_folded() {
        let entries = parse("host all all 0.0.0.0 0.0.0.0 md5");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address.as_deref(), Some("0.0.0.0/0"));
    }

    #[test]
    fn ident_detected_as_method() {
        let entries = parse("host all all 192.168.1.0/24 ident");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, "ident");
    }

    #[test]
    fn method_found_before_options() {
        // Options after the method must not confuse detection
        let entries = parse("host all all 10.0.0.0/8 scram-sha-256 clientcert=verify-full");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, "scram-sha-256");
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let entries = parse("# host all all trust\n\n   \nlocal all all peer");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, "peer");
    }

    #[test]
    fn include_directives_not_entries() {
        let entries = parse("include other.conf\ninclude_dir conf.d\nlocal all all peer");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn netmask_prefix_lengths() {
        assert_eq!(
            netmask_prefix_len("255.255.255.0".parse().unwrap()),
            Some(24)
        );
        assert_eq!(netmask_prefix_len("0.0.0.0".parse().unwrap()), Some(0));
        // Non-contiguous mask
        assert_eq!(netmask_prefix_len("255.0.255.0".parse().unwrap()), None);
    }

    #[tokio::test]
    async fn include_files_expanded() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("pg_hba.conf");
        let extra = dir.path().join("extra.conf");

        std::fs::write(&main, "local all all peer\ninclude extra.conf\n").unwrap();
        std::fs::write(&extra, "host all all 10.0.0.0/8 md5\n").unwrap();

        let (entries, warnings) = load_hba_entries(main.to_str().unwrap()).await.unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].method, "md5");
        assert!(entries[1].source.contains("extra.conf"));
    }

    #[tokio::test]
    async fn include_dir_expanded_alphabetically() {
        let dir = tempfile::tempdir().unwrap();
        let confd = dir.path().join("conf.d");
        std::fs::create_dir(&confd).unwrap();

        let main = dir.path().join("pg_hba.conf");
        std::fs::write(&main, "include_dir conf.d\n").unwrap();
        std::fs::write(confd.join("02-second.conf"), "host b b 10.0.0.2/32 md5\n").unwrap();
        std::fs::write(confd.join("01-first.conf"), "host a a 10.0.0.1/32 md5\n").unwrap();
        std::fs::write(confd.join("ignored.txt"), "host x x 10.0.0.9/32 md5\n").unwrap();

        let (entries, warnings) = load_hba_entries(main.to_str().unwrap()).await.unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].database, "a");
        assert_eq!(entries[1].database, "b");
    }

    #[tokio::test]
    async fn missing_include_warns_but_does_not_fail() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("pg_hba.conf");
        std::fs::write(&main, "local all all peer\ninclude missing.conf\n").unwrap();

        let (entries, warnings) = load_hba_entries(main.to_str().unwrap()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("missing.conf"));
    }

    #[tokio::test]
    async fn include_cycles_terminate() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.conf");
        let b = dir.path().join("b.conf");
        std::fs::write(&a, "include b.conf\nlocal all all peer\n").unwrap();
        std::fs::write(&b, "include a.conf\n").unwrap();

        let (entries, _) = load_hba_entries(a.to_str().unwrap()).await.unwrap();
        assert_eq!(entries.len(), 1);
    }
}
