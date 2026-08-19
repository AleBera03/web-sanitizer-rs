//! Address classification: the pure half of the guard.
//!
//! The table is hand-written because `IpAddr::is_global` is nightly-only
//! and because these rows have to be read line by line anyway. Each row carries
//! the rule id the report must name.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::policy::{ConfigError, SsrfRules};

pub const CATEGORY_SSRF: &str = "ssrf";

// rule ids, one per reason an address is unreachable for us
const UNSPECIFIED: &str = "ssrf.unspecified";
const PRIVATE: &str = "ssrf.private";
const LOOPBACK: &str = "ssrf.loopback";
const LINK_LOCAL: &str = "ssrf.link_local";
const CGNAT: &str = "ssrf.cgnat";
const PROTOCOL: &str = "ssrf.protocol_assignments";
const DOCUMENTATION: &str = "ssrf.documentation";
const BENCHMARKING: &str = "ssrf.benchmarking";
const MULTICAST: &str = "ssrf.multicast";
const RESERVED: &str = "ssrf.reserved";
const DISCARD: &str = "ssrf.discard";
const UNIQUE_LOCAL: &str = "ssrf.unique_local";
const CONFIGURED: &str = "ssrf.deny_extra";

/// IPv4 network in prefix form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr4 {
    base: u32,
    prefix: u8,
}

impl Cidr4 {
    const fn new(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Cidr4 {
        Cidr4 {
            base: u32::from_be_bytes([a, b, c, d]),
            prefix,
        }
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = mask32(self.prefix);
        u32::from(ip) & mask == self.base & mask
    }
}

/// IPv6 network in prefix form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr6 {
    base: u128,
    prefix: u8,
}

impl Cidr6 {
    const fn new(base: u128, prefix: u8) -> Cidr6 {
        Cidr6 { base, prefix }
    }

    fn contains(&self, ip: Ipv6Addr) -> bool {
        let mask = mask128(self.prefix);
        u128::from(ip) & mask == self.base & mask
    }
}

/// A network plus the reason it is forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row<C> {
    cidr: C,
    rule: &'static str,
}

const fn row4(a: u8, b: u8, c: u8, d: u8, prefix: u8, rule: &'static str) -> Row<Cidr4> {
    Row {
        cidr: Cidr4::new(a, b, c, d, prefix),
        rule,
    }
}

const fn row6(base: u128, prefix: u8, rule: &'static str) -> Row<Cidr6> {
    Row {
        cidr: Cidr6::new(base, prefix),
        rule,
    }
}

const BUILTIN_V4: &[Row<Cidr4>] = &[
    row4(0, 0, 0, 0, 8, UNSPECIFIED),
    row4(10, 0, 0, 0, 8, PRIVATE),
    row4(100, 64, 0, 0, 10, CGNAT),
    row4(127, 0, 0, 0, 8, LOOPBACK),
    // includes the cloud metadata endpoint 169.254.169.254
    row4(169, 254, 0, 0, 16, LINK_LOCAL),
    row4(172, 16, 0, 0, 12, PRIVATE),
    row4(192, 0, 0, 0, 24, PROTOCOL),
    row4(192, 0, 2, 0, 24, DOCUMENTATION),
    row4(192, 168, 0, 0, 16, PRIVATE),
    row4(198, 18, 0, 0, 15, BENCHMARKING),
    row4(198, 51, 100, 0, 24, DOCUMENTATION),
    row4(203, 0, 113, 0, 24, DOCUMENTATION),
    row4(224, 0, 0, 0, 4, MULTICAST),
    row4(240, 0, 0, 0, 4, RESERVED),
];

const BUILTIN_V6: &[Row<Cidr6>] = &[
    row6(0, 128, UNSPECIFIED),
    row6(1, 128, LOOPBACK),
    row6(0x0100 << 112, 64, DISCARD),
    row6(0x2001_0db8 << 96, 32, DOCUMENTATION),
    // includes the AWS IPv6 metadata address fd00:ec2::254
    row6(0xfc00 << 112, 7, UNIQUE_LOCAL),
    row6(0xfe80 << 112, 10, LINK_LOCAL),
    row6(0xff00 << 112, 8, MULTICAST),
];

/// Either half of a parsed CIDR, as written in a policy list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4(Cidr4),
    V6(Cidr6),
}

impl Cidr {
    /// Parse `10.0.0.0/8`, `2001:db8::/32`, or a bare address (host route).
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => {
                let bits: u8 = prefix
                    .parse()
                    .map_err(|_| format!("`{prefix}` is not a prefix length"))?;
                (addr, Some(bits))
            }
            None => (text, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{addr}` is not an IP address"))?;
        match addr {
            IpAddr::V4(v4) => {
                let prefix = prefix.unwrap_or(32);
                if prefix > 32 {
                    return Err(format!("prefix /{prefix} is out of range for IPv4"));
                }
                Ok(Cidr::V4(Cidr4 {
                    base: u32::from(v4),
                    prefix,
                }))
            }
            IpAddr::V6(v6) => {
                let prefix = prefix.unwrap_or(128);
                if prefix > 128 {
                    return Err(format!("prefix /{prefix} is out of range for IPv6"));
                }
                Ok(Cidr::V6(Cidr6 {
                    base: u128::from(v6),
                    prefix,
                }))
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4(c), IpAddr::V4(ip)) => c.contains(ip),
            (Cidr::V6(c), IpAddr::V6(ip)) => c.contains(ip),
            _ => false,
        }
    }
}

/// Compiled deny table. The built-in rows plus whatever the policy
/// added. Immutable after `Engine::new`, therefore `Sync` with no lock.
#[derive(Debug, Clone)]
pub struct IpDenyTable {
    v4: Vec<Row<Cidr4>>,
    v6: Vec<Row<Cidr6>>,
}

impl Default for IpDenyTable {
    fn default() -> IpDenyTable {
        IpDenyTable::builtin()
    }
}

impl IpDenyTable {
    pub fn builtin() -> IpDenyTable {
        IpDenyTable {
            v4: BUILTIN_V4.to_vec(),
            v6: BUILTIN_V6.to_vec(),
        }
    }

    /// Built-ins plus `ssrf.deny_extra`. A malformed row is a config error
    /// (exit 2) before any input is touched.
    pub fn compile(rules: &SsrfRules) -> Result<IpDenyTable, ConfigError> {
        let mut table = IpDenyTable::builtin();
        for entry in &rules.deny_extra {
            match Cidr::parse(entry).map_err(|message| ConfigError::Ssrf {
                field: "deny_extra",
                entry: entry.clone(),
                message,
            })? {
                Cidr::V4(cidr) => table.v4.push(Row {
                    cidr,
                    rule: CONFIGURED,
                }),
                Cidr::V6(cidr) => table.v6.push(Row {
                    cidr,
                    rule: CONFIGURED,
                }),
            }
        }
        Ok(table)
    }

    /// The rule that forbids `ip`, or `None` when it is reachable.
    ///
    /// An IPv6 address carrying an IPv4 one is unwrapped first: deciding on the
    /// wrapper would classify by syntax, which is the mistake the whole module
    /// exists to avoid.
    pub fn classify(&self, ip: IpAddr) -> Option<&'static str> {
        match ip {
            IpAddr::V4(v4) => self.classify_v4(v4),
            IpAddr::V6(v6) => match unwrap_embedded_v4(v6) {
                Some(v4) => self.classify_v4(v4),
                None => self
                    .v6
                    .iter()
                    .find(|row| row.cidr.contains(v6))
                    .map(|row| row.rule),
            },
        }
    }

    fn classify_v4(&self, ip: Ipv4Addr) -> Option<&'static str> {
        self.v4
            .iter()
            .find(|row| row.cidr.contains(ip))
            .map(|row| row.rule)
    }
}


#[derive(Debug, Clone, Default)]
pub struct AllowList {
    hosts: Vec<String>,
    cidrs: Vec<Cidr>,
}

impl AllowList {
    pub fn compile(rules: &SsrfRules) -> Result<AllowList, ConfigError> {
        let mut allow = AllowList::default();
        for entry in &rules.allow_hosts {
            match Cidr::parse(entry) {
                Ok(cidr) => allow.cidrs.push(cidr),
                // not an address: a host name, matched literally
                Err(_) => {
                    if entry.trim().is_empty() {
                        return Err(ConfigError::Ssrf {
                            field: "allow_hosts",
                            entry: entry.clone(),
                            message: "empty entry".to_string(),
                        });
                    }
                    allow.hosts.push(entry.trim().to_ascii_lowercase());
                }
            }
        }
        Ok(allow)
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.cidrs.is_empty()
    }

    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        self.hosts.contains(&host)
    }

    pub fn allows_addr(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }
}

/// The IPv4 address carried by an IPv4-mapped (`::ffff:0:0/96`), NAT64
/// (`64:ff9b::/96`) or 6to4 (`2002::/16`) IPv6 address.
fn unwrap_embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let bits = u128::from(ip);
    let segments = ip.segments();
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        return Some(Ipv4Addr::from(bits as u32));
    }
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        return Some(Ipv4Addr::from(bits as u32));
    }
    if segments[0] == 0x2002 {
        return Some(Ipv4Addr::from(((bits >> 80) & 0xffff_ffff) as u32));
    }
    None
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix.min(128))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address parses")
    }

    fn classify(text: &str) -> Option<&'static str> {
        IpDenyTable::builtin().classify(ip(text))
    }

    // the table, row by row

    #[test]
    fn every_ipv4_row_of_the_spec_table_fires() {
        let cases = [
            ("0.0.0.0", UNSPECIFIED),
            ("0.255.255.255", UNSPECIFIED),
            ("10.0.0.5", PRIVATE),
            ("10.255.255.255", PRIVATE),
            ("100.64.0.1", CGNAT),
            ("100.127.255.255", CGNAT),
            ("127.0.0.1", LOOPBACK),
            ("127.255.255.254", LOOPBACK),
            ("169.254.169.254", LINK_LOCAL),
            ("172.16.0.1", PRIVATE),
            ("172.31.255.255", PRIVATE),
            ("192.0.0.1", PROTOCOL),
            ("192.0.2.7", DOCUMENTATION),
            ("192.168.1.1", PRIVATE),
            ("198.18.0.1", BENCHMARKING),
            ("198.19.255.255", BENCHMARKING),
            ("198.51.100.9", DOCUMENTATION),
            ("203.0.113.9", DOCUMENTATION),
            ("224.0.0.1", MULTICAST),
            ("239.255.255.255", MULTICAST),
            ("240.0.0.1", RESERVED),
            ("255.255.255.255", RESERVED),
        ];
        for (addr, rule) in cases {
            assert_eq!(classify(addr), Some(rule), "{addr}");
        }
    }

    #[test]
    fn every_ipv6_row_of_the_spec_table_fires() {
        let cases = [
            ("::", UNSPECIFIED),
            ("::1", LOOPBACK),
            ("100::1", DISCARD),
            ("2001:db8::1", DOCUMENTATION),
            ("fc00::1", UNIQUE_LOCAL),
            ("fd00:ec2::254", UNIQUE_LOCAL),
            ("fdff:ffff::1", UNIQUE_LOCAL),
            ("fe80::1", LINK_LOCAL),
            ("febf::1", LINK_LOCAL),
            ("ff02::1", MULTICAST),
        ];
        for (addr, rule) in cases {
            assert_eq!(classify(addr), Some(rule), "{addr}");
        }
    }

    #[test]
    fn public_addresses_are_reachable() {
        for addr in [
            "93.184.216.34",
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",  // just outside 172.16/12
            "100.128.0.1", // just outside 100.64/10
            "198.20.0.1",  // just outside 198.18/15
            "2606:2800:220:1:248:1893:25c8:1946",
            "2001:db9::1", // just outside 2001:db8::/32
        ] {
            assert_eq!(classify(addr), None, "{addr}");
        }
    }

    #[test]
    fn prefix_boundaries_are_exact() {
        // one address below and one above each edge that is easy to get wrong
        assert_eq!(classify("9.255.255.255"), None);
        assert_eq!(classify("11.0.0.0"), None);
        assert_eq!(classify("172.15.255.255"), None);
        assert_eq!(classify("169.253.255.255"), None);
        assert_eq!(classify("169.255.0.0"), None);
        assert_eq!(classify("223.255.255.255"), None);
        assert_eq!(classify("fbff::1"), None); // fc00::/7 starts at fc00
        assert_eq!(classify("fec0::1"), None); // fe80::/10 ends at febf
    }

    // the evasion encodings: every spelling collapses onto one verdict

    #[test]
    fn obfuscated_spellings_of_loopback_agree_with_the_canonical_one() {
        // decimal, octal and hex are resolved by the network stack, so by the
        // time we classify they are already the same u32
        assert_eq!(Ipv4Addr::from(2130706433u32), ip("127.0.0.1"));
        for addr in [
            "127.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
        ] {
            assert_eq!(classify(addr), Some(LOOPBACK), "{addr}");
        }
    }

    #[test]
    fn embedded_forms_of_metadata_and_private_ranges_are_unwrapped() {
        assert_eq!(classify("::ffff:169.254.169.254"), Some(LINK_LOCAL));
        assert_eq!(classify("64:ff9b::a9fe:a9fe"), Some(LINK_LOCAL));
        assert_eq!(classify("2002:a9fe:a9fe::"), Some(LINK_LOCAL));
        assert_eq!(classify("::ffff:10.0.0.5"), Some(PRIVATE));
        assert_eq!(classify("2002:c0a8:1::"), Some(PRIVATE)); // 192.168.0.1
    }

    #[test]
    fn embedded_public_addresses_stay_reachable() {
        // a NAT64 wrapper around a public address is a public address
        assert_eq!(classify("::ffff:93.184.216.34"), None);
        assert_eq!(classify("64:ff9b::5db8:d822"), None);
        assert_eq!(classify("2002:5db8:d822::"), None);
    }

    // policy extensions

    #[test]
    fn deny_extra_rows_are_compiled_and_named() {
        let rules = SsrfRules {
            deny_extra: vec!["203.0.200.0/24".to_string(), "2001:beef::/32".to_string()],
            ..SsrfRules::default()
        };
        let table = IpDenyTable::compile(&rules).unwrap();
        assert_eq!(table.classify(ip("203.0.200.7")), Some(CONFIGURED));
        assert_eq!(table.classify(ip("2001:beef::1")), Some(CONFIGURED));
        assert_eq!(table.classify(ip("203.0.201.7")), None);
        // built-ins survive the extension
        assert_eq!(table.classify(ip("127.0.0.1")), Some(LOOPBACK));
    }

    #[test]
    fn a_malformed_deny_row_is_a_config_error() {
        for entry in ["not-an-ip", "10.0.0.0/33", "10.0.0.0/x", "::1/200"] {
            let rules = SsrfRules {
                deny_extra: vec![entry.to_string()],
                ..SsrfRules::default()
            };
            assert!(
                matches!(IpDenyTable::compile(&rules), Err(ConfigError::Ssrf { .. })),
                "{entry}"
            );
        }
    }

    #[test]
    fn a_bare_address_is_a_host_route() {
        let cidr = Cidr::parse("10.1.2.3").unwrap();
        assert!(cidr.contains(ip("10.1.2.3")));
        assert!(!cidr.contains(ip("10.1.2.4")));
    }

    #[test]
    fn allow_list_separates_names_from_networks() {
        let rules = SsrfRules {
            allow_hosts: vec![
                "Intranet.Local".to_string(),
                "10.1.0.0/16".to_string(),
                "::1".to_string(),
            ],
            ..SsrfRules::default()
        };
        let allow = AllowList::compile(&rules).unwrap();
        assert!(allow.allows_host("intranet.local"));
        assert!(allow.allows_host("INTRANET.LOCAL"));
        assert!(!allow.allows_host("other.local"));
        assert!(allow.allows_addr(ip("10.1.5.5")));
        assert!(!allow.allows_addr(ip("10.2.5.5")));
        assert!(allow.allows_addr(ip("::1")));
        assert!(
            !AllowList::compile(&SsrfRules::default())
                .unwrap()
                .allows_host("intranet.local")
        );
    }

    #[test]
    fn default_allow_list_is_empty() {
        let allow = AllowList::compile(&SsrfRules::default()).unwrap();
        assert!(allow.is_empty());
        assert!(!allow.allows_addr(ip("127.0.0.1")));
    }
}
