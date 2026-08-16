use crate::policy::SubresourcesRules;
use crate::sniff::{AcquiredInput, SniffOutcome, sniff_input};

pub fn run(input: AcquiredInput, rules: &SubresourcesRules, verbose: u8) -> SniffOutcome {
    sniff_input(input, rules, verbose)
}
