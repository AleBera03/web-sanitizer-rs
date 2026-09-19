//! A small HTTP server for measurement, not for production traffic. It answers
//! from a routing table so a fetching run is measured against fixtures with a
//! known latency instead of somebody else's server. Used by the throughput
//! benchmark and by the corpus fetching runs in xtask.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Resource {
    pub content_type: String,
    pub body: Vec<u8>,
    pub status: u16,
}

impl Resource {
    pub fn new(content_type: &str, body: Vec<u8>) -> Resource {
        Resource {
            content_type: content_type.to_string(),
            body,
            status: 200,
        }
    }

    pub fn with_status(mut self, status: u16) -> Resource {
        self.status = status;
        self
    }
}

type Fallback = fn(&str) -> Option<Resource>;

struct Shared {
    routes: Mutex<HashMap<String, Resource>>,
    fallback: Mutex<Option<Fallback>>,
    hits: AtomicUsize,
    latency: Duration,
    stop: AtomicBool,
}

impl Shared {
    fn answer(&self, path: &str) -> Option<Resource> {
        if let Some(found) = self.routes.lock().ok()?.get(path) {
            return Some(found.clone());
        }
        let fallback = *self.fallback.lock().ok()?;
        fallback.and_then(|f| f(path))
    }
}

pub struct FixtureServer {
    base: String,
    shared: Arc<Shared>,
}

impl FixtureServer {
    pub fn start(latency: Duration) -> FixtureServer {
        FixtureServer::start_on(latency, "127.0.0.1")
    }

    pub fn start_on(latency: Duration, host: &str) -> FixtureServer {
        let listener = TcpListener::bind((host, 0)).expect("a loopback port is available");
        let port = listener
            .local_addr()
            .expect("the listener has an address")
            .port();
        listener
            .set_nonblocking(true)
            .expect("the listener accepts a non-blocking mode");

        let shared = Arc::new(Shared {
            routes: Mutex::new(HashMap::new()),
            fallback: Mutex::new(None),
            hits: AtomicUsize::new(0),
            latency,
            stop: AtomicBool::new(false),
        });

        let worker = Arc::clone(&shared);
        thread::spawn(move || {
            while !worker.stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let handler = Arc::clone(&worker);
                        thread::spawn(move || serve(stream, handler));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(1)),
                }
            }
        });

        FixtureServer {
            base: format!("http://{host}:{port}"),
            shared,
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn route(&self, path: &str, resource: Resource) {
        if let Ok(mut routes) = self.shared.routes.lock() {
            routes.insert(path.to_string(), resource);
        }
    }

    pub fn fallback(&self, answer: Fallback) {
        if let Ok(mut slot) = self.shared.fallback.lock() {
            *slot = Some(answer);
        }
    }

    pub fn hits(&self) -> usize {
        self.shared.hits.load(Ordering::Relaxed)
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(mut stream: TcpStream, shared: Arc<Shared>) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let Some(path) = request_path(&stream) else {
        return;
    };
    shared.hits.fetch_add(1, Ordering::Relaxed);
    if !shared.latency.is_zero() {
        thread::sleep(shared.latency);
    }
    let answer = shared.answer(&path);
    let response = match answer {
        Some(resource) => head(resource.status, &resource.content_type, resource.body.len())
            .into_bytes()
            .into_iter()
            .chain(resource.body)
            .collect::<Vec<u8>>(),
        None => head(404, "text/plain", 0).into_bytes(),
    };
    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

fn request_path(stream: &TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let path = line.split_whitespace().nth(1)?.to_string();
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) if header.trim().is_empty() => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Some(path)
}

fn head(status: u16, content_type: &str, length: usize) -> String {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn get(server: &FixtureServer, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(server.base().trim_start_matches("http://")).unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: fixture\r\n\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    #[test]
    fn a_routed_path_answers_with_its_own_body_and_type() {
        let server = FixtureServer::start(Duration::ZERO);
        server.route("/a.css", Resource::new("text/css", b"body{}".to_vec()));
        let (status, text) = get(&server, "/a.css");
        assert_eq!(status, 200);
        assert!(text.contains("Content-Type: text/css"), "{text}");
        assert!(text.ends_with("body{}"), "{text}");
    }

    #[test]
    fn an_unrouted_path_is_a_not_found_rather_than_a_hang() {
        let server = FixtureServer::start(Duration::ZERO);
        let (status, _) = get(&server, "/missing");
        assert_eq!(status, 404);
    }

    #[test]
    fn a_fallback_answers_what_no_route_claims() {
        let server = FixtureServer::start(Duration::ZERO);
        server.fallback(|path| match path.ends_with(".png") {
            true => Some(Resource::new("image/png", vec![0x89, b'P', b'N', b'G'])),
            false => None,
        });
        assert_eq!(get(&server, "/x.png").0, 200);
        assert_eq!(get(&server, "/x.txt").0, 404);
    }

    #[test]
    fn a_route_wins_over_the_fallback() {
        let server = FixtureServer::start(Duration::ZERO);
        server.fallback(|_| Some(Resource::new("text/plain", b"fallback".to_vec())));
        server.route("/x", Resource::new("text/plain", b"routed".to_vec()));
        assert!(get(&server, "/x").1.ends_with("routed"));
    }

    #[test]
    fn every_request_is_counted() {
        let server = FixtureServer::start(Duration::ZERO);
        server.route("/x", Resource::new("text/plain", b"ok".to_vec()));
        let _ = get(&server, "/x");
        let _ = get(&server, "/missing");
        assert_eq!(server.hits(), 2);
    }

    #[test]
    fn the_url_helper_hangs_a_path_off_the_base() {
        let server = FixtureServer::start(Duration::ZERO);
        assert!(server.url("/p/1.html").starts_with("http://127.0.0.1:"));
        assert!(server.url("/p/1.html").ends_with("/p/1.html"));
    }

    #[test]
    fn a_declared_latency_delays_the_answer() {
        let server = FixtureServer::start(Duration::from_millis(40));
        server.route("/slow", Resource::new("text/plain", b"ok".to_vec()));
        let started = std::time::Instant::now();
        let _ = get(&server, "/slow");
        assert!(started.elapsed() >= Duration::from_millis(30));
    }
}
