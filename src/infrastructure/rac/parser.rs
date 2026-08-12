use std::{fmt, iter::FusedIterator};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RacRecord {
    fields: IndexMap<String, String>,
}

impl RacRecord {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    pub fn fields(&self) -> &IndexMap<String, String> {
        &self.fields
    }

    pub fn into_fields(self) -> IndexMap<String, String> {
        self.fields
    }

    pub fn iter(&self) -> RacRecordIter<'_> {
        RacRecordIter(self.fields.iter())
    }

    pub fn insert(&mut self, key: impl AsRef<str>, value: impl Into<String>) -> Option<String> {
        self.fields
            .insert(normalize_field_name(key.as_ref()), value.into())
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }
}

impl fmt::Debug for RacRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RacRecord")
            .field("field_names", &self.fields.keys().collect::<Vec<_>>())
            .field("field_count", &self.fields.len())
            .finish()
    }
}

pub struct RacRecordIter<'a>(indexmap::map::Iter<'a, String, String>);

impl<'a> Iterator for RacRecordIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for RacRecordIter<'_> {}
impl FusedIterator for RacRecordIter<'_> {}

#[derive(Clone, Copy, Debug, Default)]
pub struct RacRecordParser;

impl RacRecordParser {
    pub fn parse(text: &str) -> Result<Vec<RacRecord>, RacParseError> {
        parse_rac_records(text)
    }
}

pub fn parse_rac_records(text: &str) -> Result<Vec<RacRecord>, RacParseError> {
    let mut records = Vec::new();
    let mut current = RacRecord::new();

    for (line_index, source_line) in text.split('\n').enumerate() {
        let mut line = source_line.strip_suffix('\r').unwrap_or(source_line);
        if line_index == 0 {
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
        }

        if line.trim().is_empty() {
            if !current.is_empty() {
                records.push(current);
                current = RacRecord::new();
            }
            continue;
        }

        let (key, value) = line.split_once(':').ok_or(RacParseError {
            line: line_index + 1,
            kind: RacParseErrorKind::MissingSeparator,
        })?;
        let key = key.trim();
        if key.is_empty() {
            return Err(RacParseError {
                line: line_index + 1,
                kind: RacParseErrorKind::EmptyKey,
            });
        }

        let normalized = normalize_field_name(key);
        if current.fields.contains_key(&normalized) {
            return Err(RacParseError {
                line: line_index + 1,
                kind: RacParseErrorKind::DuplicateNormalizedKey,
            });
        }
        current.fields.insert(normalized, value.trim().to_owned());
    }

    if !current.is_empty() {
        records.push(current);
    }

    Ok(records)
}

pub fn normalize_field_name(name: &str) -> String {
    name.trim()
        .chars()
        .map(|character| {
            if character == '-' {
                '_'
            } else {
                character.to_ascii_lowercase()
            }
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RacParseErrorKind {
    MissingSeparator,
    EmptyKey,
    DuplicateNormalizedKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RacParseError {
    line: usize,
    kind: RacParseErrorKind,
}

impl RacParseError {
    pub const fn line(self) -> usize {
        self.line
    }

    pub const fn kind(self) -> RacParseErrorKind {
        self.kind
    }
}

impl fmt::Display for RacParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            RacParseErrorKind::MissingSeparator => "отсутствует разделитель ':'",
            RacParseErrorKind::EmptyKey => "пустое имя поля",
            RacParseErrorKind::DuplicateNormalizedKey => {
                "повторяющееся имя поля после нормализации"
            }
        };
        write!(
            formatter,
            "ошибка разбора ответа RAC в строке {}: {reason}",
            self.line
        )
    }
}

impl std::error::Error for RacParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    const RAC_8_3_20: &str = concat!(
        "cluster : 11111111-1111-1111-1111-111111111111\r\n",
        "name : First cluster\r\n",
        "host : server-1\r\n",
        "port : 1541\r\n",
        "description : \r\n",
        "\r\n",
        "cluster : 22222222-2222-2222-2222-222222222222\r\n",
        "name : Value: with: colons\r\n",
    );

    const RAC_CURRENT: &str = concat!(
        "session : aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n",
        "session-id : 17\n",
        "cpu-time-total : 123456\n",
        "future-field : preserved\n",
    );

    #[test]
    fn parses_crlf_records_empty_values_and_colons() {
        let records = parse_rac_records(RAC_8_3_20).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].get("description"), Some(""));
        assert_eq!(records[1].get("name"), Some("Value: with: colons"));
    }

    #[test]
    fn normalizes_kebab_case_and_keeps_unknown_fields() {
        let records = RacRecordParser::parse(RAC_CURRENT).unwrap();
        let record = &records[0];

        assert_eq!(
            record.get("session"),
            Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        );
        assert_eq!(record.get("session_id"), Some("17"));
        assert_eq!(record.get("cpu_time_total"), Some("123456"));
        assert_eq!(record.get("future_field"), Some("preserved"));
    }

    #[test]
    fn accepts_multiple_blank_lines_and_no_trailing_newline() {
        let records = parse_rac_records("host: first\n\n\n host: second").unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[1].get("host"), Some("second"));
    }

    #[test]
    fn parse_error_never_contains_source_line() {
        let secret = "password=must-not-escape";
        let error = parse_rac_records(secret).unwrap_err();

        assert_eq!(error.kind(), RacParseErrorKind::MissingSeparator);
        assert!(!format!("{error:?}").contains(secret));
        assert!(!error.to_string().contains(secret));
    }

    #[test]
    fn duplicate_normalized_keys_are_rejected() {
        let error = parse_rac_records("future-field: one\nfuture_field: two\n").unwrap_err();

        assert_eq!(error.kind(), RacParseErrorKind::DuplicateNormalizedKey);
    }
}
