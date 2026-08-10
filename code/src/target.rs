use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;

/// Maximum hosts a single CIDR block may expand to without --allow-large.
pub const MAX_CIDR_HOSTS: usize = 256;

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
///
/// CIDR blocks larger than [`MAX_CIDR_HOSTS`] are rejected unless
/// `allow_large` is set.
pub fn resolve_target(input: &str, allow_large: bool) -> Result<Vec<ResolvedTarget>, String> {
    // Try CIDR first
    if input.contains('/') {
        return resolve_cidr(input, allow_large);
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
fn resolve_cidr(input: &str, allow_large: bool) -> Result<Vec<ResolvedTarget>, String> {
    let network: IpNet = input
        .parse()
        .map_err(|e| format!("invalid CIDR notation '{}': {}", input, e))?;

    // Take at most MAX_CIDR_HOSTS + 1 so we can detect oversized blocks
    // without materialising millions of addresses (IPv6 /64 etc.).
    let targets: Vec<ResolvedTarget> = network
        .hosts()
        .take(MAX_CIDR_HOSTS + 1)
        .map(|addr| ResolvedTarget {
            label: addr.to_string(),
            addr,
        })
        .collect();

    if targets.len() > MAX_CIDR_HOSTS && !allow_large {
        return Err(format!(
            "CIDR block '{}' expands to more than {} hosts; re-run with --allow-large to scan it anyway",
            input, MAX_CIDR_HOSTS
        ));
    }

    if targets.is_empty() {
        return Err(format!(
            "CIDR block '{}' contains no usable host addresses",
            input
        ));
    }

    // Oversized but allowed: re-expand fully.
    if targets.len() > MAX_CIDR_HOSTS {
        return Ok(network
            .hosts()
            .map(|addr| ResolvedTarget {
                label: addr.to_string(),
                addr,
            })
            .collect());
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
pub fn resolve_all_targets(
    inputs: &[String],
    allow_large: bool,
) -> Result<Vec<ResolvedTarget>, String> {
    let mut all_targets = Vec::new();

    for input in inputs {
        let targets = resolve_target(input.trim(), allow_large)?;
        all_targets.extend(targets);
    }

    Ok(all_targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_ip_resolves() {
        let targets = resolve_target("192.168.1.1", false).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].addr.to_string(), "192.168.1.1");
    }

    #[test]
    fn small_cidr_expands() {
        let targets = resolve_target("10.0.0.0/29", false).unwrap();
        assert_eq!(targets.len(), 6);
    }

    #[test]
    fn cidr_at_limit_allowed() {
        // /24 = 254 hosts, under the 256 cap
        let targets = resolve_target("10.0.0.0/24", false).unwrap();
        assert_eq!(targets.len(), 254);
    }

    #[test]
    fn cidr_over_limit_rejected() {
        // /23 = 510 hosts, over the 256 cap
        let err = resolve_target("10.0.0.0/23", false).unwrap_err();
        assert!(err.contains("--allow-large"));
    }

    #[test]
    fn cidr_over_limit_allowed_with_flag() {
        let targets = resolve_target("10.0.0.0/23", true).unwrap();
        assert_eq!(targets.len(), 510);
    }

    #[test]
    fn huge_ipv6_cidr_rejected_without_hanging() {
        let err = resolve_target("fd00::/64", false).unwrap_err();
        assert!(err.contains("--allow-large"));
    }

    #[test]
    fn invalid_cidr_errors() {
        assert!(resolve_target("10.0.0.0/33", false).is_err());
    }
}
