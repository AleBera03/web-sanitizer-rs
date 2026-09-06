use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum XtaskError {
    #[error("cannot read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },

    #[error("cannot write {path}: {source}")]
    Write { path: PathBuf, source: io::Error },

    #[error("{path} is not valid TOML: {source}")]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("{path} is not valid JSON: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("cannot write the table {path}: {source}")]
    Csv { path: PathBuf, source: csv::Error },

    #[error("policy {path}: {source}")]
    Policy {
        path: PathBuf,
        source: web_sanitizer::policy::ConfigError,
    },

    #[error("the ground truth has no entry for {name}")]
    UnknownSample { name: String },

    #[error("{name} is listed in the ground truth but missing from {dir}")]
    MissingSample { name: String, dir: PathBuf },

    #[error("{0}")]
    Harness(String),

    #[error("cannot render {path}: {source}")]
    Chart {
        path: PathBuf,
        source: charming::EchartsError,
    },

    #[error("{measured} measurement(s) did not meet the documented expectation")]
    Violations { measured: usize },
}

pub type Result<T> = std::result::Result<T, XtaskError>;

pub fn read(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| XtaskError::Read {
        path: path.to_path_buf(),
        source,
    })
}

pub fn read_to_string(path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|source| XtaskError::Read {
        path: path.to_path_buf(),
        source,
    })
}

pub fn write(path: &std::path::Path, bytes: impl AsRef<[u8]>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| XtaskError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(path, bytes).map_err(|source| XtaskError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_names_itself_in_the_error() {
        let error = read(std::path::Path::new("/nonexistent/xtask/file")).unwrap_err();
        assert!(error.to_string().contains("/nonexistent/xtask/file"));
    }

    #[test]
    fn write_creates_the_parent_directory() {
        let dir = std::env::temp_dir().join("xtask-write-test");
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("nested/deeper/file.txt");
        write(&target, "content").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "content");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
