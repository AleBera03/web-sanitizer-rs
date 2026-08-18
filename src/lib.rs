//! web-sanitizer library crate: all re-exports
//!
//! The binary front-ends (CLI batch mode, HTTP server mode) call
//! [`Engine::process`] and [`Engine::process_batch`]

pub mod engine;
pub mod fetch;
pub mod html;
pub mod input;
pub mod policy;
pub mod report;
pub mod scan;
pub mod sniff;
pub mod tests_helper;
pub mod urlcheck;

pub use engine::subresource::Asset;
pub use engine::{Engine, Outcome};
pub use fetch::guard::{FetchContext, FetchOrigin, Guard};
pub use html::{HtmlOutcome, Reference, sanitize_html};
pub use input::{InputSource, OutputName};
pub use policy::Policy;
pub use report::{InputReport, RunReport};
// pub use scan::{ScanOutcome, scan_content};
pub use scan::active::ScanOutcome;
pub use sniff::{AcquiredInput, SniffOutcome, sniff_input};
