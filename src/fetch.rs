//! The fetch seam. `Fetcher` is right now _optional_ 'cause it implements sub-fetching
//!
//! `HttpFetcher` (ureq-based) actual active fetcher. To be implemented.
//! Until then [`DisabledFetcher`] makes URL inputs report `fetch_error` instead of pretending.

use thiserror::Error;
use url::Url;

use crate::policy::FetchPolicy;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum FetchError {
    /// No fetch client configured in this build.
    #[error("fetching is not available in this build")]
    Disabled,
}

pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &Url, policy: &FetchPolicy) -> Result<Fetched, FetchError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fetched {
    /// URL after redirects — MIME sniffing and reporting use this, not the input URL.
    pub final_url: Url,
    /// `Content-Type` as declared by the server; sniffing may overrule it.
    pub declared_mime: Option<String>,
    pub body: Vec<u8>,
}

/// Fetcher that refuses every request. Placeholder front-end wiring until
/// `HttpFetcher` implementation.
pub struct DisabledFetcher;

impl Fetcher for DisabledFetcher {
    fn fetch(&self, _url: &Url, _policy: &FetchPolicy) -> Result<Fetched, FetchError> {
        Err(FetchError::Disabled)
    }
}
