use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::error::{Result, XtaskError};

pub struct Sentinel {
    port: u16,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Sentinel {
    pub fn start() -> Result<Sentinel> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|source| XtaskError::Read {
            path: std::path::PathBuf::from("127.0.0.1:0"),
            source,
        })?;
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        listener
            .set_nonblocking(true)
            .map_err(|source| XtaskError::Read {
                path: std::path::PathBuf::from("sentinel listener"),
                source,
            })?;

        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::clone(&accepted);
        let halt = Arc::clone(&stop);
        thread::spawn(move || {
            while !halt.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        counter.fetch_add(1, Ordering::Relaxed);
                        drain(stream);
                    }
                    Err(_) => thread::sleep(Duration::from_millis(20)),
                }
            }
        });

        Ok(Sentinel {
            port,
            accepted,
            stop,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }

    pub fn page(&self) -> String {
        format!(
            "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\
             <link rel=\"stylesheet\" href=\"http://localhost:{port}/s.css\"></head>\
             <body><h1>sentinel</h1>\
             <img src=\"http://127.0.0.1:{port}/x.png\" alt=\"\"></body></html>\n",
            port = self.port
        )
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn drain(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 1024];
    let _ = stream.read(&mut sink);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpStream;

    #[test]
    fn a_fresh_sentinel_has_seen_nothing() {
        let sentinel = Sentinel::start().unwrap();
        assert!(sentinel.port() > 0);
        assert_eq!(sentinel.accepted(), 0);
    }

    #[test]
    fn the_page_points_both_references_at_the_listener() {
        let sentinel = Sentinel::start().unwrap();
        let page = sentinel.page();
        assert!(page.contains(&format!("http://localhost:{}/s.css", sentinel.port())));
        assert!(page.contains(&format!("http://127.0.0.1:{}/x.png", sentinel.port())));
    }

    #[test]
    fn a_connection_that_does_arrive_is_counted() {
        let sentinel = Sentinel::start().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", sentinel.port())).unwrap();
        let _ = stream.write_all(b"GET /s.css HTTP/1.0\r\n\r\n");
        for _ in 0..50 {
            if sentinel.accepted() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(sentinel.accepted(), 1);
    }
}
