//! ## File structure mixes host-style, pure domain style, IP literal
//! ```txt
//! 0.0.0.0 evil.org
//! usa.gov
//! 10.10.10.10 whatis.this
//! 89.89.89.89
//! ```

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::ConfigError;
use super::ParseError;

fn domain_to_ascii(host: &str) -> Result<String, ParseError> {
    idna::domain_to_ascii(host.trim_end_matches('.')).map_err(|e| ParseError::Idna { source: e })
}

/// Hostnames that appear in every stock hosts file as local mappings.
/// See [an example](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
/// from (https://github.com/StevenBlack/hosts)
const HOSTS_FILE_NOISE: &[&str] = &[
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
    exact: HashSet<String>,
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
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut tokens = line.split_whitespace();
            let first = tokens.next().expect("non-empty line has a token");
            let entries: Vec<&str> = if first.parse::<IpAddr>().is_ok() {
                // hosts-style: redirect IP followed by one or more hostnames,
                // or a bare IP entry blocking that literal host.
                let rest: Vec<&str> = tokens.collect();
                if rest.is_empty() { vec![first] } else { rest }
            } else if tokens.next().is_some() {
                return Err(ConfigError::Blocklist {
                    path: path.to_path_buf(),
                    line: Some(idx + 1),
                    message: format!("expected `host` or `ip host...`, got: {line}"),
                });
            } else {
                vec![first]
            };
            for entry in entries {
                self.insert(path, idx + 1, entry)?;
            }
        }
        Ok(())
    }

    fn insert(&mut self, path: &Path, line: usize, entry: &str) -> Result<(), ConfigError> {
        let host = entry.trim_end_matches('.').to_ascii_lowercase();
        if host.contains('/') || host.contains(':') {
            return Err(ConfigError::Blocklist {
                path: path.to_path_buf(),
                line: Some(line),
                message: format!("`{entry}` is not a bare hostname"),
            });
        }
        if HOSTS_FILE_NOISE.contains(&host.as_str()) {
            return Ok(());
        }
        self.exact.insert(host);
        Ok(())
    }

    /// Exact host and parent-domain suffix match, ASCII-case-insensitive:
    /// a list entry `evil.com` matches `evil.com` and `a.b.evil.com`, but
    /// never `notevil.com` — matching walks label boundaries, not substrings.
    pub fn contains(&self, host: &str) -> bool {
        match domain_to_ascii(host) {
            Ok(normalised) => {
                if normalised.parse::<IpAddr>().is_ok() {
                    return self.exact.contains(&normalised); // no suffix-walk for literal IPs
                }
                let mut candidate = normalised.as_str();
                loop {
                    if self.exact.contains(candidate) {
                        return true;
                    }
                    match candidate.split_once('.') {
                        Some((_, parent)) => candidate = parent,
                        None => return false,
                    }
                }
            }
            Err(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_from(text: &str) -> BlockSet {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list.txt");
        std::fs::write(&path, text).unwrap();
        BlockSet::from_files(&[path]).unwrap()
    }

    #[test]
    fn matches_exact_suffix_and_case() {
        let set = set_from("evil.com\n");
        assert!(set.contains("evil.com"));
        assert!(set.contains("EVIL.COM"));
        assert!(set.contains("a.b.evil.com"));
        assert!(set.contains("evil.com.")); // trailing-dot FQDN form
        assert!(!set.contains("notevil.com")); // label boundary, not substring
        assert!(!set.contains("evil.com.attacker.net")); // suffix walk goes up, not down
        assert!(!set.contains("com"));
    }

    #[test]
    fn parses_hosts_style_lines_and_comments() {
        let set = set_from(
            "# managed list\n\
             0.0.0.0 ads.example  tracker.example\n\
             127.0.0.1 evil.org # inline comment\n\
             \n\
             plain.example\n",
        );
        println!("{:?}", set);
        assert!(set.contains("ads.example"));
        assert!(set.contains("tracker.example"));
        assert!(set.contains("evil.org"));
        assert!(set.contains("plain.example"));
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn skips_stock_localhost_mappings() {
        let set = set_from("127.0.0.1 localhost\n::1 ip6-localhost\nip6-loopback\nevil.net\n");
        assert!(!set.contains("localhost"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn bare_ip_entry_blocks_that_literal_host() {
        let set = set_from("203.0.113.9\n");
        assert!(set.contains("203.0.113.9"));
    }

    #[test]
    fn rejects_urls_and_multi_token_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.txt");
        std::fs::write(&path, "http://evil.com/path\n").unwrap();
        let err = BlockSet::from_files(std::slice::from_ref(&path)).unwrap_err();
        assert!(matches!(err, ConfigError::Blocklist { line: Some(1), .. }));

        std::fs::write(&path, "evil.com other.com\n").unwrap();
        assert!(BlockSet::from_files(std::slice::from_ref(&path)).is_err());
    }

    #[test]
    fn missing_list_file_fails_fast() {
        let err = BlockSet::from_files(&[PathBuf::from("/nonexistent/list.txt")]).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }
}
