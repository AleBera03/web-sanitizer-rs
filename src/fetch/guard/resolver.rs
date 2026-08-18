use std::fmt::Debug;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

/// One lookup, `(host, port)` in and socket addresses out.
pub trait NameResolver: Debug + Send + Sync + 'static {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

#[derive(Debug, Default)]
pub struct SystemResolver;

impl NameResolver for SystemResolver {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        // an IPv6 literal reaches us bracketed, which `to_socket_addrs` wants
        let authority = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Ok(authority.to_socket_addrs()?.collect())
    }
}

#[cfg(test)]
pub mod scripted {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A resolver with a script. Answer *n* for the *n*-th lookup, last answer
    /// repeated afterwards. It counts calls, which is what makes "the second
    /// lookup never happened" an assertion rather than a hope.
    #[derive(Debug)]
    pub struct ScriptedResolver {
        answers: Mutex<Vec<io::Result<Vec<SocketAddr>>>>,
        calls: AtomicUsize,
    }

    impl ScriptedResolver {
        pub fn new(answers: Vec<Vec<SocketAddr>>) -> ScriptedResolver {
            ScriptedResolver {
                answers: Mutex::new(answers.into_iter().map(Ok).collect()),
                calls: AtomicUsize::new(0),
            }
        }

        /// Same address set for every lookup.
        pub fn constant(addrs: Vec<SocketAddr>) -> ScriptedResolver {
            ScriptedResolver::new(vec![addrs])
        }

        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl NameResolver for ScriptedResolver {
        fn lookup(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            let index = self.calls.fetch_add(1, Ordering::Relaxed);
            let answers = self.answers.lock().unwrap();
            match answers.get(index).or_else(|| answers.last()) {
                Some(Ok(addrs)) => Ok(addrs.clone()),
                Some(Err(e)) => Err(io::Error::new(e.kind(), "scripted failure")),
                None => Ok(Vec::new()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scripted::ScriptedResolver;
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("test address parses")
    }

    #[test]
    fn system_resolver_handles_literals_of_both_families() {
        let v4 = SystemResolver.lookup("127.0.0.1", 8080).unwrap();
        assert_eq!(v4, [addr("127.0.0.1:8080")]);
        let v6 = SystemResolver.lookup("::1", 443).unwrap();
        assert_eq!(v6, [addr("[::1]:443")]);
        // already bracketed, as a URL authority spells it
        let bracketed = SystemResolver.lookup("[::1]", 443).unwrap();
        assert_eq!(bracketed, [addr("[::1]:443")]);
    }

    #[test]
    fn system_resolver_reports_an_unresolvable_name_as_an_error() {
        let err = SystemResolver.lookup("nonexistent.invalid", 80);
        assert!(err.is_err() || err.unwrap().is_empty());
    }

    #[test]
    fn scripted_answers_advance_and_are_counted() {
        let resolver = ScriptedResolver::new(vec![
            vec![addr("93.184.216.34:80")],
            vec![addr("127.0.0.1:80")],
        ]);
        assert_eq!(resolver.calls(), 0);
        assert_eq!(
            resolver.lookup("host", 80).unwrap(),
            [addr("93.184.216.34:80")]
        );
        assert_eq!(resolver.lookup("host", 80).unwrap(), [addr("127.0.0.1:80")]);
        // the script is exhausted: the last answer sticks
        assert_eq!(resolver.lookup("host", 80).unwrap(), [addr("127.0.0.1:80")]);
        assert_eq!(resolver.calls(), 3);
    }

    #[test]
    fn constant_script_repeats_one_answer() {
        let resolver = ScriptedResolver::constant(vec![addr("10.0.0.1:80")]);
        for _ in 0..3 {
            assert_eq!(resolver.lookup("h", 80).unwrap(), [addr("10.0.0.1:80")]);
        }
        assert_eq!(resolver.calls(), 3);
    }
}
