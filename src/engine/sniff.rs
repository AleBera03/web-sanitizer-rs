use crate::sniff::{SniffAction, SniffStatus, sniff};

pub fn sniff_input(input: AcquiredInput, verbose: u8) -> SniffOutcome {
    let start = std::time::Instant::now();
    let mut actions = Vec::new();
    let mut bytes_out = 0;
    let status = match sniff::sniff(&input.data, &mut actions) {
        Ok(bytes) => {
            bytes_out = bytes;
            SniffStatus::Success
        }
        Err(e) => SniffStatus::Failure(e.to_string()),
    };
    let duration_ms = start.elapsed().as_millis();
    SniffOutcome {
        source: input.source,
        bytes_in: input.data.len(),
        bytes_out,
        duration_ms,
        status,
        actions,
        error: None,
    }
}
