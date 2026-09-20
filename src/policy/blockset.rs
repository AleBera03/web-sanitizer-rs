//! - parse a host-style file. It is compliant to
//!   https://man7.org/linux/man-pages/man5/hosts.5.html

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use url::Host;

use super::ConfigError;

/// Hostnames that appear in every stock hosts file as local mappings.
/// See [an example](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
/// from (https://github.com/StevenBlack/hosts) or `/etc/hosts` in Unix/Linux
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

#[derive(Debug, Default)]
pub struct BlockSet {
    domains: HashSet<String>,
    // ips: HashSet<IpAddr>, TODO: SAVE HERE FOR A POSSIBLE FUTURE DEVELOPMENT
}

impl BlockSet {
    /// Load and merge every configured list. Accepted line forms:
    /// `# comment`, blank, `evil.com`, or hosts-style `0.0.0.0 evil.com [more…]`.
    pub fn from_files(paths: &[PathBuf]) -> Result<BlockSet, ConfigError> {
        let mut set = BlockSet::default();
        for path in paths {
            set.load_file(path)?;
        }
        Ok(set)
    }

    fn load_file(&mut self, path: &Path) -> Result<(), ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        for (idx, raw) in text.lines().enumerate() {
            let line = raw
                .split('#')
                .next()
                .ok_or(ConfigError::Parse {
                    path: Some(PathBuf::from(path)),
                    message: "".to_string(), // TODO: write error message
                })?
                .trim();
            if line.is_empty() {
                continue;
            }
            let tokens = line.split_whitespace();
            let parts: Vec<&str> = tokens.collect();
            if parts.len() < 2 {
                return Err(ConfigError::Blocklist {
                    path: PathBuf::from(path),
                    line: Some(idx),
                    message: "format must be <ip address> <canonical domain> [alias1] [alias2] ..."
                        .to_string(),
                });
            }
            let ip = parts[0];
            if ip.parse::<IpAddr>().is_err() {
                return Err(ConfigError::Blocklist {
                    path: PathBuf::from(path),
                    line: Some(idx),
                    message: "format must be <ip address> <canonical domain> [alias1] [alias2] ..."
                        .to_string(),
                });
            }
            for &host in &parts[1..] {
                if ip.cmp(host) == Ordering::Equal || LOCAL_NAMES.contains(&host) {
                    continue;
                }
                match self
                    .domains
                    .insert(host.to_ascii_lowercase().trim_end_matches('.').to_string())
                {
                    true => continue,
                    false => {
                        return Err(ConfigError::Blocklist {
                            path: PathBuf::from(path),
                            line: Some(idx),
                            message: "impossible to insert the domain".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Exact host and parent-domain suffix match: a list entry `evil.com`
    /// matches `evil.com` and `a.b.evil.com`, but never `notevil.com` —
    /// matching walks label boundaries, not substrings. Case and punycode
    /// folding already happened inside [`Host`], so no normalisation here.
    ///
    /// IP hosts never match: in a hosts-style line the address is the redirect
    /// target of the names beside it, not itself a blocked host.
    pub fn contains(&self, host: Host) -> bool {
        match host {
            Host::Domain(d) => {
                // the URL parser keeps the FQDN root dot, entries are stored without it
                let mut candidate = d.trim_end_matches('.');
                loop {
                    if self.domains.contains(candidate) {
                        return true;
                    }
                    match candidate.split_once('.') {
                        Some((_, parent)) => candidate = parent,
                        None => return false,
                    }
                }
            }
            _ => false,
        }
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_helper::set_from::SetFrom;

    /// Lookups go through `Host`, exactly like `UrlChecker` does: the parser
    /// owns case-folding and punycode, the set only walks labels.
    fn host(s: &str) -> Host {
        Host::parse(s).expect("test host parses")
    }

    #[test]
    fn matches_exact_suffix_and_case() {
        let set = BlockSet::set_from_text("0.0.0.0 evil.com\n");

        assert!(set.contains(host("evil.com")));
        assert!(set.contains(host("EVIL.COM")));
        assert!(set.contains(host("a.b.evil.com")));
        assert!(set.contains(host("evil.com."))); // trailing-dot FQDN form
        assert!(!set.contains(host("notevil.com"))); // label boundary, not substring
        assert!(!set.contains(host("evil.com.attacker.net"))); // suffix walk goes up, not down
        assert!(!set.contains(host("com")));
    }

    #[test]
    fn ip_hosts_never_match() {
        // the address column is the redirect target of the names beside it
        let set = BlockSet::set_from_text("0.0.0.0 evil.com\n::1 ads.example\n");
        assert!(!set.contains(host("0.0.0.0")));
        assert!(!set.contains(host("[::1]")));
        assert!(!set.contains(host("203.0.113.9")));
    }

    #[test]
    fn parses_hosts_style_lines_and_comments() {
        let set = BlockSet::set_from_text(
            "# managed list\n\
             0.0.0.0 ads.example  tracker.example\n\
             127.0.0.1 evil.org # inline comment\n",
        );
        assert!(set.contains(host("ads.example")));
        assert!(set.contains(host("tracker.example")));
        assert!(set.contains(host("evil.org")));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn skips_stock_localhost_mappings() {
        let set =
            BlockSet::set_from_text("127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 evil.net\n");
        assert!(!set.contains(host("localhost")));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn skips_a_name_repeating_its_own_address() {
        let set = BlockSet::set_from_text("89.89.89.89 89.89.89.89\n0.0.0.0 evil.net\n");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn rejects_urls_and_multi_token_garbage() {
        let dir = tempfile::tempdir().unwrap();

        let mut path = dir.path().join("bad1.txt");
        fs::write(&path, "http://evil.com/path\n").unwrap();
        let err = BlockSet::from_files(std::slice::from_ref(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Blocklist { line: Some(0), .. }));

        path = dir.path().join("bad2.txt");
        fs::write(&path, "evil.com other.com\n").unwrap();
        let err = BlockSet::from_files(std::slice::from_ref(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Blocklist { line: Some(0), .. }));
    }

    #[test]
    fn rejects_a_bare_domain_line() {
        // the address column is mandatory: a lone name is not a hosts entry
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bare.txt");
        fs::write(&path, "# managed list\nevil.com\n").unwrap();
        let err = BlockSet::from_files(std::slice::from_ref(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Blocklist { line: Some(1), .. }));
    }

    #[test]
    fn rejects_a_repeated_domain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dup.txt");
        fs::write(&path, "0.0.0.0 evil.com\n127.0.0.1 evil.com\n").unwrap();
        let err = BlockSet::from_files(std::slice::from_ref(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Blocklist { line: Some(1), .. }));
    }

    #[test]
    fn missing_list_file_fails_fast() {
        let err = BlockSet::from_files(&[PathBuf::from("/nonexistent/list.txt")]).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }
}
