//! Input gathering: CLI arguments and `--input-list` files become an ordered
//! list of [`InputSource`]s. Directory walks filter by the
//! policy's extension set and refuse symlinks that resolve outside the tree
//! root — those are surfaced separately so the front-end can report
//! them as `skipped_symlink` without the engine ever touching them.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum InputError {
    #[error("cannot read input {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

/// One unit of work for the engine. Scheme validation for URLs happens in the
/// engine at acquire time. Gathering never does I/O on the
/// input itself.
#[derive(Debug, Clone, PartialEq)]
pub enum InputSource {
    File(PathBuf),
    Url(Url),
    /// Saved a string malformed url in order to properly drive error to engine
    MalformedUrl(String),
    /// In-memory input: server mode and tests.
    Bytes {
        name: String,
        data: Vec<u8>,
    },
}

impl InputSource {
    /// The `source` string used in reports.
    pub fn describe(&self) -> String {
        match self {
            InputSource::File(p) => p.display().to_string(),
            InputSource::Url(u) => u.to_string(),
            InputSource::MalformedUrl(s) => s.to_string(),
            InputSource::Bytes { name, .. } => name.clone(),
        }
    }
}

/// Names the outputs of one input carry under the output directory. The
/// sanitised copy and its sub-resources share a stem, so which assets belong to
/// which file is readable from the layout alone: `3-page.html` sits next to
/// `3-page.html.assets/`.
///
/// The stem joins the input's position in the batch to the last component of its
/// source. The index keeps same-named files from different directories apart and
/// stays stable when completions stop arriving in order, while the name is
/// reduced to ASCII alphanumerics plus `.`, `_` and `-` so no character the
/// input chose reaches a path we write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputName {
    stem: String,
}

impl OutputName {
    /// Stands in for a source with no usable last component, such as a bare `/`
    /// or an unnamed in-memory input.
    const UNNAMED: &'static str = "input";

    pub fn derive(index: usize, source: &str) -> OutputName {
        let base = Path::new(source)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let safe: String = base
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let safe = if safe.is_empty() {
            OutputName::UNNAMED.to_string()
        } else {
            safe
        };
        OutputName {
            stem: format!("{index}-{safe}"),
        }
    }

    /// File name of the sanitised copy.
    pub fn file(&self) -> &str {
        &self.stem
    }

    /// Directory holding the sub-resources of this input, relative to the
    /// output directory.
    pub fn asset_dir(&self) -> String {
        format!("{}.assets", self.stem)
    }
}

#[derive(Debug, Default)]
pub struct GatherResult {
    /// Inputs in argument order; directory contents in sorted walk order.
    pub inputs: Vec<InputSource>,
    /// Symlinks refused by the tree-escape guard, for `skipped_symlink` reports.
    pub skipped_symlinks: Vec<PathBuf>,
}

/// Resolve CLI arguments plus an optional input-list file into engine inputs.
///
/// Each argument or list line is: a URL if it contains `://`, a directory to
/// walk recursively if it names one, otherwise a file path taken as-is (an
/// explicitly named file is user intent — the extension filter only applies
/// to walks). Unreadable directories and list files fail fast (exit 2);
/// unreadable *files* are per-input `io_error`s discovered by the engine.
pub fn gather(
    args: &[String],
    input_list: Option<&Path>,
    extensions: &[String],
) -> Result<GatherResult, InputError> {
    let mut items: Vec<String> = args.to_vec();
    if let Some(list_path) = input_list {
        let text = fs::read_to_string(list_path).map_err(|source| InputError::Io {
            path: list_path.to_path_buf(),
            source,
        })?;
        items.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from),
        );
    }

    let mut result = GatherResult::default();
    for item in items {
        // cli input URLs must respect WHATWG standard
        // in any case urlcheck control would fail
        if item.contains("://") {
            match Url::parse(&item) {
                Ok(url) => result.inputs.push(InputSource::Url(url)),
                // take string as-is. engine will recognize malformed url
                Err(_) => result.inputs.push(InputSource::MalformedUrl(item)),
            }
            continue;
        }
        let path = PathBuf::from(&item);
        if path.is_dir() {
            walk_dir(&path, extensions, &mut result)?;
        } else {
            result.inputs.push(InputSource::File(path));
        }
    }
    Ok(result)
}

/// Recursive walk in sorted order (deterministic reports). Guard invariant:
/// nothing whose canonical path escapes the canonical tree root is emitted.
fn walk_dir(
    root: &Path,
    extensions: &[String],
    result: &mut GatherResult,
) -> Result<(), InputError> {
    let canonical_root = root.canonicalize().map_err(|source| InputError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    // tracks visited directories
    let mut visited = HashSet::new();
    visited.insert(canonical_root.clone());
    walk_into(root, &canonical_root, extensions, &mut visited, result)
}

fn walk_into(
    dir: &Path,
    canonical_root: &Path,
    extensions: &[String],
    visited: &mut HashSet<PathBuf>,
    result: &mut GatherResult,
) -> Result<(), InputError> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|source| InputError::Io {
            path: dir.to_path_buf(),
            source,
        })?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()
        .map_err(|source| InputError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    entries.sort();

    for path in entries {
        let is_symlink = path.symlink_metadata().map_err(|source| InputError::Io {
            path: path.clone(),
            source,
        })?;
        if is_symlink.file_type().is_symlink() {
            match path.canonicalize() {
                Ok(target) if target.starts_with(canonical_root) => {}
                _ => {
                    result.skipped_symlinks.push(path);
                    continue;
                }
            }
        }
        if path.is_dir() {
            let canonical = path.canonicalize().map_err(|source| InputError::Io {
                path: path.clone(),
                source,
            })?;
            if visited.insert(canonical) {
                walk_into(&path, canonical_root, extensions, visited, result)?;
            }
        } else if has_matching_extension(&path, extensions) {
            result.inputs.push(InputSource::File(path));
        }
    }
    Ok(())
}

fn has_matching_extension(path: &Path, extensions: &[String]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            extensions
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs;

    fn exts() -> Vec<String> {
        vec!["html".into(), "htm".into()]
    }

    #[test]
    fn args_become_urls_and_files_in_order() {
        let result = gather(
            &["http://example.com/a".into(), "page.html".into()],
            None,
            &exts(),
        )
        .unwrap();
        assert_eq!(result.inputs.len(), 2);
        assert!(
            matches!(&result.inputs[0], InputSource::Url(u) if u.host_str() == Some("example.com"))
        );
        assert!(matches!(&result.inputs[1], InputSource::File(p) if p == Path::new("page.html")));
    }

    #[test]
    fn non_http_schemes_still_gather_as_urls_for_engine_rejection() {
        let result = gather(&["ftp://example.com/x".into()], None, &exts()).unwrap();
        assert!(matches!(&result.inputs[0], InputSource::Url(u) if u.scheme() == "ftp"));
    }

    #[test]
    fn input_list_lines_append_after_args() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("list.txt");
        fs::write(&list, "# comment\n\nhttp://example.com/one\nlocal.html\n").unwrap();
        let result = gather(&["first.html".into()], Some(&list), &exts()).unwrap();
        let described: Vec<String> = result.inputs.iter().map(|i| i.describe()).collect();
        assert_eq!(
            described,
            ["first.html", "http://example.com/one", "local.html"]
        );
    }

    #[test]
    fn missing_input_list_fails_fast() {
        assert!(gather(&[], Some(Path::new("/nonexistent/list.txt")), &exts()).is_err());
    }

    #[test]
    fn walk_filters_extensions_recursively_in_sorted_order() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("b.html"), "x").unwrap();
        fs::write(dir.path().join("a.HTM"), "x").unwrap(); // case-insensitive match
        fs::write(dir.path().join("notes.txt"), "x").unwrap();
        fs::write(dir.path().join("sub/c.html"), "x").unwrap();

        let result = gather(&[dir.path().display().to_string()], None, &exts()).unwrap();
        let names: Vec<String> = result
            .inputs
            .iter()
            .map(|i| {
                Path::new(&i.describe())
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["a.HTM", "b.html", "c.html"]);
        assert!(result.skipped_symlinks.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn escaping_symlink_is_skipped_inside_link_is_followed() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.html"), "x").unwrap();

        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ok.html"), "x").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.html"),
            dir.path().join("escape.html"),
        )
        .unwrap();
        std::os::unix::fs::symlink(dir.path().join("ok.html"), dir.path().join("alias.html"))
            .unwrap();

        let result = gather(&[dir.path().display().to_string()], None, &exts()).unwrap();
        let names: Vec<String> = result
            .inputs
            .iter()
            .map(|i| {
                Path::new(&i.describe())
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, ["alias.html", "ok.html"]);
        assert_eq!(result.skipped_symlinks.len(), 1);
        assert!(result.skipped_symlinks[0].ends_with("escape.html"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_directory_cycle_terminates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.html"), "x").unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).unwrap();

        let result = gather(&[dir.path().display().to_string()], None, &exts()).unwrap();
        assert_eq!(result.inputs.len(), 1);
    }

    #[test]
    fn output_names_are_indexed_and_sanitised() {
        assert_eq!(
            OutputName::derive(3, "/tmp/dir/page.html").file(),
            "3-page.html"
        );
        assert_eq!(
            OutputName::derive(0, "http://example.com/a/b.html").file(),
            "0-b.html"
        );
        assert_eq!(
            OutputName::derive(1, "we ird$.html").file(),
            "1-we_ird_.html"
        );
        // a bare-host URL falls back to the host as the name
        assert_eq!(
            OutputName::derive(2, "http://example.com/").file(),
            "2-example.com"
        );
    }

    #[test]
    fn a_source_without_a_last_component_still_gets_a_name() {
        assert_eq!(OutputName::derive(0, "/").file(), "0-input");
        assert_eq!(OutputName::derive(4, "").file(), "4-input");
        assert_eq!(OutputName::derive(1, "..").file(), "1-input");
    }

    #[test]
    fn the_asset_directory_shares_the_stem_of_its_parent() {
        let name = OutputName::derive(3, "/tmp/dir/page.html");
        assert_eq!(name.asset_dir(), "3-page.html.assets");
        assert!(name.asset_dir().starts_with(name.file()));
    }

    #[test]
    fn explicit_file_bypasses_extension_filter() {
        let result = gather(&["report.txt".into()], None, &exts()).unwrap();
        assert!(matches!(&result.inputs[0], InputSource::File(p) if p == Path::new("report.txt")));
    }
}
