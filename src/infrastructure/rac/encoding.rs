use std::fmt;

use encoding_rs::{IBM866, WINDOWS_1251};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RacEncoding {
    Utf8,
    Windows1251,
    Ibm866,
}

pub struct DecodedRacOutput {
    text: String,
    encoding: RacEncoding,
}

impl DecodedRacOutput {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn into_text(self) -> String {
        self.text
    }

    pub const fn encoding(&self) -> RacEncoding {
        self.encoding
    }
}

impl fmt::Debug for DecodedRacOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedRacOutput")
            .field("encoding", &self.encoding)
            .field("bytes", &self.text.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RacOutputDecoder;

impl RacOutputDecoder {
    pub fn decode(bytes: &[u8]) -> DecodedRacOutput {
        decode_rac_output(bytes)
    }
}

pub fn decode_rac_output(bytes: &[u8]) -> DecodedRacOutput {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return DecodedRacOutput {
            text: text.strip_prefix('\u{feff}').unwrap_or(text).to_owned(),
            encoding: RacEncoding::Utf8,
        };
    }

    let (windows_text, windows_had_errors) = WINDOWS_1251.decode_without_bom_handling(bytes);
    let (oem_text, oem_had_errors) = IBM866.decode_without_bom_handling(bytes);
    let windows_score = score_decoding(&windows_text, windows_had_errors);
    let oem_score = score_decoding(&oem_text, oem_had_errors);

    if oem_score > windows_score {
        DecodedRacOutput {
            text: oem_text.into_owned(),
            encoding: RacEncoding::Ibm866,
        }
    } else {
        // ANSI is the deterministic tie-breaker for output with no Cyrillic signal.
        DecodedRacOutput {
            text: windows_text.into_owned(),
            encoding: RacEncoding::Windows1251,
        }
    }
}

fn score_decoding(text: &str, had_errors: bool) -> i64 {
    let lowercase = text.to_lowercase();
    let mut score = if had_errors { -10_000 } else { 0 };

    for diagnostic in [
        "ошиб",
        "кластер",
        "сервер",
        "соединен",
        "подключен",
        "пользовател",
        "парол",
        "аутентиф",
        "авторизац",
        "команд",
        "параметр",
        "сеанс",
        "информацион",
        "время ожидания",
        "не поддерж",
        "не найден",
    ] {
        if lowercase.contains(diagnostic) {
            score += 100;
        }
    }

    for key in [
        "cluster",
        "cluster-id",
        "infobase",
        "infobase-id",
        "session",
        "connection",
        "process",
        "user-name",
        "host",
        "port",
    ] {
        if lowercase.lines().any(|line| {
            line.trim_start()
                .strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with(':'))
        }) {
            score += 5;
        }
    }

    for character in text.chars() {
        score += match character {
            '\u{2500}'..='\u{257f}' => -40,
            '\u{fffd}' => -200,
            character if character.is_control() && !matches!(character, '\r' | '\n' | '\t') => -40,
            'А'..='я' | 'Ё' | 'ё' => 1,
            '\u{0400}'..='\u{052f}' => -8,
            _ => 0,
        };
    }

    for common_pair in [
        "ст", "но", "ен", "то", "на", "ов", "ни", "ра", "ко", "ер", "по", "ро", "ос", "не", "пр",
        "ве", "ть",
    ] {
        score += lowercase.matches(common_pair).count() as i64 * 2;
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_utf8_has_priority() {
        let source = "cluster : 00000000-0000-0000-0000-000000000000\nname : Тест\n";
        let decoded = decode_rac_output(source.as_bytes());

        assert_eq!(decoded.encoding(), RacEncoding::Utf8);
        assert_eq!(decoded.text(), source);
    }

    #[test]
    fn detects_windows_1251_diagnostic() {
        let source = "Ошибка аутентификации пользователя: неверный пароль";
        let (bytes, _, had_errors) = WINDOWS_1251.encode(source);
        assert!(!had_errors);

        let decoded = decode_rac_output(&bytes);

        assert_eq!(decoded.encoding(), RacEncoding::Windows1251);
        assert_eq!(decoded.text(), source);
    }

    #[test]
    fn detects_cp866_diagnostic() {
        let source = "Ошибка подключения к серверу: время ожидания истекло";
        let (bytes, _, had_errors) = IBM866.encode(source);
        assert!(!had_errors);

        let decoded = decode_rac_output(&bytes);

        assert_eq!(decoded.encoding(), RacEncoding::Ibm866);
        assert_eq!(decoded.text(), source);
    }

    #[test]
    fn ascii_is_valid_utf8() {
        let decoded = decode_rac_output(b"host : server\r\nport : 1541\r\n");

        assert_eq!(decoded.encoding(), RacEncoding::Utf8);
    }
}
