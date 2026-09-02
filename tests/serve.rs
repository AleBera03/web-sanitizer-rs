use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port exists");
    listener.local_addr().unwrap().port()
}

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn start() -> Server {
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_wsrs"))
            .args(["serve", "--port", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("binary runs");
        let server = Server { child, port };
        server.wait_until_listening();
        server
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if agent().get(self.url("/")).call().is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("server never started listening on port {}", self.port);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

fn json_of(mut body: ureq::Body) -> Value {
    let mut text = String::new();
    body.as_reader().read_to_string(&mut text).unwrap();
    serde_json::from_str(&text).expect("the response is JSON")
}

#[test]
fn liveness_and_health_answer_before_any_work() {
    let server = Server::start();

    let mut banner = agent().get(server.url("/")).call().unwrap();
    assert_eq!(banner.status(), 200);
    let mut text = String::new();
    banner
        .body_mut()
        .as_reader()
        .read_to_string(&mut text)
        .unwrap();
    assert!(text.contains("listening"), "{text}");

    let health = agent().get(server.url("/health")).call().unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(json_of(health.into_body())["status"], "ok");
}

#[test]
fn submitted_bytes_answer_200_with_the_report_and_the_sanitised_content() {
    let server = Server::start();

    let response = agent()
        .post(server.url("/v1/resources"))
        .send(&br#"<!DOCTYPE html><a href="javascript:alert(1)">x</a>"#[..])
        .unwrap();

    assert_eq!(response.status(), 200);
    let body = json_of(response.into_body());
    assert_eq!(body["report"]["status"], "sanitised");
    assert!(!body["report"]["actions"].as_array().unwrap().is_empty());
    assert!(body["content"].is_string());
}

#[test]
fn a_json_body_that_is_not_json_answers_400() {
    let server = Server::start();

    let response = agent()
        .post(server.url("/v1/resources"))
        .header("content-type", "application/json")
        .send(&b"{"[..])
        .unwrap();

    assert_eq!(response.status(), 400);
    assert_eq!(json_of(response.into_body())["error"], "bad_request");
}

#[test]
fn a_url_outside_http_answers_400_without_fetching() {
    let server = Server::start();

    let response = agent()
        .post(server.url("/v1/resources"))
        .header("content-type", "application/json")
        .send(&br#"{"url":"file:///etc/passwd"}"#[..])
        .unwrap();

    assert_eq!(response.status(), 400);
    let body = json_of(response.into_body());
    assert_eq!(body["error"], "unsupported_scheme");
    assert_eq!(body["report"]["status"], "unsupported_scheme");
}

#[test]
fn a_url_the_guard_refuses_answers_403_and_opens_no_connection() {
    let sentinel = TcpListener::bind("127.0.0.1:0").unwrap();
    let sentinel_port = sentinel.local_addr().unwrap().port();
    let server = Server::start();

    let response = agent()
        .post(server.url("/v1/resources"))
        .header("content-type", "application/json")
        .send(format!(r#"{{"url":"http://127.0.0.1:{sentinel_port}/"}}"#).as_bytes())
        .unwrap();

    assert_eq!(response.status(), 403);
    let body = json_of(response.into_body());
    assert_eq!(body["error"], "ssrf_blocked");
    assert_eq!(body["report"]["status"], "ssrf_blocked");

    sentinel.set_nonblocking(true).unwrap();
    assert!(
        sentinel.accept().is_err(),
        "the guard let a connection through"
    );
}

#[test]
fn a_body_over_the_input_budget_is_refused_before_the_engine() {
    let server = Server::start();
    let oversized = vec![b'a'; 11 * 1024 * 1024];

    let response = agent()
        .post(server.url("/v1/resources"))
        .send(&oversized[..])
        .unwrap();

    assert_eq!(response.status(), 413);
}

#[test]
fn a_port_already_taken_is_a_configuration_error() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();

    let output = Command::new(env!("CARGO_BIN_EXE_wsrs"))
        .args(["serve", "--port", &port.to_string()])
        .output()
        .expect("binary runs");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot listen"), "{stderr}");
}
