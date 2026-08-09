use std::sync::Arc;

use crate::policy::Policy;
use crate::sniff::{AcquiredInput, SniffOutcome, sniff_input};

pub fn run(input: AcquiredInput, policy: Arc<Policy>, verbose: u8) -> SniffOutcome {
    sniff_input(input, policy, verbose)
}
