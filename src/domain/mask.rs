use regex::Regex;

use super::DomainError;

#[derive(Clone, Debug)]
pub struct SqlMask {
    source: String,
    regex: Regex,
    has_wildcards: bool,
}

impl SqlMask {
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        let mut expression = String::from("(?i)\\A");
        let mut literal = String::new();
        let mut characters = input.char_indices();
        let mut has_wildcards = false;

        while let Some((position, character)) = characters.next() {
            match character {
                '%' => {
                    append_literal(&mut expression, &mut literal);
                    expression.push_str("(?s:.*)");
                    has_wildcards = true;
                }
                '_' => {
                    append_literal(&mut expression, &mut literal);
                    expression.push_str("(?s:.)");
                    has_wildcards = true;
                }
                '\\' => match characters.next() {
                    Some((_, escaped @ ('%' | '_' | '\\'))) => literal.push(escaped),
                    Some((_, escaped)) => {
                        return Err(DomainError::InvalidMask {
                            position,
                            reason: format!(
                                "escape `\\{escaped}` не поддерживается; разрешены \\%, \\_ и \\\\"
                            ),
                        });
                    }
                    None => {
                        return Err(DomainError::InvalidMask {
                            position,
                            reason: "обратная косая черта без экранируемого символа".to_owned(),
                        });
                    }
                },
                _ => literal.push(character),
            }
        }

        append_literal(&mut expression, &mut literal);
        expression.push_str("\\z");
        let regex = Regex::new(&expression).map_err(|error| DomainError::InvalidMask {
            position: 0,
            reason: format!("маска слишком сложна: {error}"),
        })?;

        Ok(Self {
            source: input.to_owned(),
            regex,
            has_wildcards,
        })
    }

    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        self.regex.is_match(candidate)
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub const fn has_wildcards(&self) -> bool {
        self.has_wildcards
    }
}

fn append_literal(expression: &mut String, literal: &mut String) {
    if !literal.is_empty() {
        expression.push_str(&regex::escape(literal));
        literal.clear();
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn no_wildcards_means_exact_case_insensitive_match() {
        let mask = SqlMask::parse("zup_corp").unwrap_or_else(|error| panic!("{error}"));

        assert!(mask.matches("ZUP_CORP"));
        assert!(!mask.matches("prefix-zup_corp"));
        assert!(!mask.matches("zup_corp-suffix"));
    }

    #[test]
    fn percent_and_underscore_have_sql_like_meaning() {
        let mask = SqlMask::parse("APP-_%").unwrap_or_else(|error| panic!("{error}"));

        assert!(mask.matches("app-X"));
        assert!(mask.matches("APP-123"));
        assert!(!mask.matches("APP-"));
    }

    #[test]
    fn escaped_metacharacters_are_literals() {
        let mask = SqlMask::parse(r"100\%\_\\done").unwrap_or_else(|error| panic!("{error}"));

        assert!(mask.matches(r"100%_\done"));
        assert!(!mask.has_wildcards());
    }

    #[test]
    fn invalid_escapes_are_rejected() {
        assert!(SqlMask::parse(r"name\x").is_err());
        assert!(SqlMask::parse("name\\").is_err());
    }

    #[test]
    fn matching_is_unicode_case_insensitive() {
        let mask = SqlMask::parse("ПОЛЬЗОВАТЕЛЬ%").unwrap_or_else(|error| panic!("{error}"));

        assert!(mask.matches("пользователь 1"));
    }

    proptest! {
        #[test]
        fn literal_patterns_never_turn_into_substring_search(value in "[a-zA-Z0-9.-]{0,40}") {
            let mask = SqlMask::parse(&value);
            prop_assert!(mask.is_ok());
            if let Ok(mask) = mask {
                let prefixed = format!("x{}", value);
                prop_assert!(mask.matches(&value));
                prop_assert!(!mask.matches(&prefixed));
            }
        }

        #[test]
        fn percent_matches_any_suffix(prefix in "[a-zA-Z0-9.-]{0,30}", suffix in ".{0,30}") {
            let mask = SqlMask::parse(&format!("{}%", prefix));
            prop_assert!(mask.is_ok());
            if let Ok(mask) = mask {
                let candidate = format!("{}{}", prefix, suffix);
                prop_assert!(mask.matches(&candidate));
            }
        }
    }
}
