use std::io::{IsTerminal, Write};
use std::path::Path;

pub struct Progress {
    total: usize,
    done: usize,
    interactive: bool,
}

fn line(done: usize, total: usize, name: &str) -> String {
    format!("  {done}/{total} {name}")
}

// a run of the corpus takes minutes once fetching is on, so it says what it is
// working on rather than leaving the terminal silent
impl Progress {
    pub fn start(label: &str, total: usize) -> Progress {
        println!("\n{label}  ({total} inputs)");
        Progress {
            total,
            done: 0,
            interactive: std::io::stdout().is_terminal(),
        }
    }

    pub fn tick(&mut self, name: &str) {
        self.done += 1;
        if !self.interactive {
            return;
        }
        let mut out = std::io::stdout();
        let _ = write!(out, "\r\u{1b}[K{}", line(self.done, self.total, name));
        let _ = out.flush();
    }

    pub fn finish(self, path: &Path) {
        if self.interactive {
            let mut out = std::io::stdout();
            let _ = write!(out, "\r\u{1b}[K");
            let _ = out.flush();
        }
        println!("  {} inputs written to {}", self.done, path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_progress_line_names_the_position_and_the_input() {
        assert_eq!(line(3, 41, "a.html"), "  3/41 a.html");
    }

    #[test]
    fn ticking_counts_every_input_whether_or_not_a_terminal_is_watching() {
        let mut progress = Progress {
            total: 2,
            done: 0,
            interactive: false,
        };
        progress.tick("a");
        progress.tick("b");
        assert_eq!(progress.done, 2);
    }

    #[test]
    fn a_run_with_no_inputs_still_reports_its_total() {
        let progress = Progress {
            total: 0,
            done: 0,
            interactive: false,
        };
        assert_eq!(progress.total, 0);
        progress.finish(Path::new("/tmp/x.csv"));
    }
}
