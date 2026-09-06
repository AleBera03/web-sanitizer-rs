use std::path::Path;

use serde::Serialize;

use crate::error::{Result, XtaskError};

pub fn save<T: Serialize>(path: &Path, rows: &[T]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| XtaskError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut writer = csv::Writer::from_path(path).map_err(|source| XtaskError::Csv {
        path: path.to_path_buf(),
        source,
    })?;
    for row in rows {
        writer.serialize(row).map_err(|source| XtaskError::Csv {
            path: path.to_path_buf(),
            source,
        })?;
    }
    writer.flush().map_err(|source| XtaskError::Write {
        path: path.to_path_buf(),
        source,
    })
}

pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let mut reader = csv::Reader::from_path(path).map_err(|source| XtaskError::Csv {
        path: path.to_path_buf(),
        source,
    })?;
    reader
        .deserialize()
        .collect::<std::result::Result<Vec<T>, csv::Error>>()
        .map_err(|source| XtaskError::Csv {
            path: path.to_path_buf(),
            source,
        })
}

pub fn words(values: &[String]) -> String {
    values.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Row {
        name: String,
        count: u32,
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("xtask-table-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn rows_survive_a_save_and_load_round_trip() {
        let path = scratch("roundtrip.csv");
        let rows = vec![
            Row {
                name: "one".into(),
                count: 1,
            },
            Row {
                name: "two".into(),
                count: 2,
            },
        ];
        save(&path, &rows).unwrap();
        assert_eq!(load::<Row>(&path).unwrap(), rows);
    }

    #[test]
    fn the_header_comes_from_the_field_names() {
        let path = scratch("header.csv");
        save(
            &path,
            &[Row {
                name: "x".into(),
                count: 3,
            }],
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("name,count\n"), "{text}");
    }

    #[test]
    fn a_field_holding_a_comma_is_quoted_by_the_writer() {
        let path = scratch("comma.csv");
        save(
            &path,
            &[Row {
                name: "one,two".into(),
                count: 0,
            }],
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"one,two\""), "{text}");
        assert_eq!(load::<Row>(&path).unwrap()[0].name, "one,two");
    }

    #[test]
    fn saving_creates_the_results_directory() {
        let path = scratch("nested/deeper/rows.csv");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        save(
            &path,
            &[Row {
                name: "n".into(),
                count: 9,
            }],
        )
        .unwrap();
        assert!(path.is_file());
    }

    #[test]
    fn a_missing_table_reports_its_path() {
        let error = load::<Row>(Path::new("/nonexistent/xtask/table.csv")).unwrap_err();
        assert!(error.to_string().contains("table.csv"));
    }

    #[test]
    fn words_joins_a_rule_list_into_one_cell() {
        assert_eq!(words(&["a".into(), "b".into()]), "a b");
        assert_eq!(words(&[]), "");
    }
}
