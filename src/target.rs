use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;

/// A resolved scan target with display name and IP address.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    /// Human-readable label (original input or hostname)
    pub label: String,
    /// Resolved IP address to connect to
    pub addr: IpAddr,
}

impl std::fmt::Display for ResolvedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.label == self.addr.to_string() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{} ({})", self.label, self.addr)
        }
    }
}

/// Parse a target string into one or more resolved targets.
///
/// Accepts:
/// - IPv4/IPv6 address: `192.168.1.1`, `::1`
/// - CIDR block: `192.168.1.0/24`, `fd00::/120`
/// - Hostname: `db.example.com` (resolved via DNS)
pub fn resolve_target(input: &str) -> Result<Vec<ResolvedTarget>, String> {
    // Try CIDR first
    if input.contains('/') {
        return resolve_cidr(input);
    }

    // Try bare IP address
    if let Ok(addr) = input.parse::<IpAddr>() {
        return Ok(vec![ResolvedTarget {
            label: input.to_string(),
            addr,
        }]);
    }

    // Must be a hostname — resolve via DNS
    resolve_hostname(input)
}

/// Expand a CIDR block into individual host IPs.
fn resolve_cidr(input: &str) -> Result<Vec<ResolvedTarget>, String> {
    let network: IpNet = input
        .parse()
        .map_err(|e| format!("invalid CIDR notation '{}': {}", input, e))?;

    let targets: Vec<ResolvedTarget> = network
        .hosts()
        .map(|addr| ResolvedTarget {
            label: addr.to_string(),
            addr,
        })
        .collect();

    if targets.is_empty() {
        return Err(format!("CIDR block '{}' contains no usable host addresses", input));
    }

    Ok(targets)
}

/// Resolve a hostname to IP addresses via DNS.
fn resolve_hostname(hostname: &str) -> Result<Vec<ResolvedTarget>, String> {
    // ToSocketAddrs requires a port — use dummy port 0
    let socket_addr = format!("{}:0", hostname);
    let addrs: Vec<_> = socket_addr
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for '{}': {}", hostname, e))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("hostname '{}' resolved to no addresses", hostname));
    }

    // Deduplicate IPs (DNS can return duplicates across A/AAAA)
    let mut seen = std::collections::HashSet::new();
    let targets: Vec<ResolvedTarget> = addrs
        .into_iter()
        .filter(|sa| seen.insert(sa.ip()))
        .map(|sa| ResolvedTarget {
            label: hostname.to_string(),
            addr: sa.ip(),
        })
        .collect();

    Ok(targets)
}

/// Resolve all target inputs into a flat list of targets.
pub fn resolve_all_targets(inputs: &[String]) -> Result<Vec<ResolvedTarget>, String> {
    let mut all_targets = Vec::new();

    for input in inputs {
        let targets = resolve_target(input.trim())?;
        all_targets.extend(targets);
    }

    Ok(all_targets)
}
