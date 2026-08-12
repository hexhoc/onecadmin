use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;
use std::str::FromStr;

use chrono::{DateTime, FixedOffset};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use super::DomainError;

#[derive(Clone)]
pub struct ClusterAlias(String);

impl ClusterAlias {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::InvalidClusterAlias {
                value,
                reason: "alias не может быть пустым",
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
        {
            return Err(DomainError::InvalidClusterAlias {
                value,
                reason: "разрешены только латинские буквы, цифры и символы . _ - :",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClusterAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ClusterAlias")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ClusterAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl PartialEq for ClusterAlias {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for ClusterAlias {}

impl PartialOrd for ClusterAlias {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ClusterAlias {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(other.0.bytes().map(|byte| byte.to_ascii_lowercase()))
    }
}

impl Hash for ClusterAlias {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_lowercase());
        }
    }
}

impl FromStr for ClusterAlias {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ClusterAlias {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for ClusterAlias {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ClusterAlias {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RasEndpoint {
    host: String,
    port: u16,
    address: String,
}

impl RasEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, DomainError> {
        let host = host.into();
        validate_host(&host)?;
        if port == 0 {
            return Err(DomainError::InvalidRasEndpoint {
                value: format_endpoint(&host, port),
                reason: "порт должен быть в диапазоне 1..=65535",
            });
        }
        let address = format_endpoint(&host, port);
        Ok(Self {
            host,
            port,
            address,
        })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.address
    }
}

fn validate_host(host: &str) -> Result<(), DomainError> {
    if host.is_empty() {
        return Err(DomainError::InvalidRasEndpoint {
            value: host.to_owned(),
            reason: "имя хоста не может быть пустым",
        });
    }
    if host.chars().any(char::is_whitespace)
        || host.chars().any(char::is_control)
        || host.contains(['[', ']', '/', '\\', '"', ';'])
    {
        return Err(DomainError::InvalidRasEndpoint {
            value: host.to_owned(),
            reason: "имя хоста содержит недопустимые символы",
        });
    }
    if host.contains(':') && host.parse::<Ipv6Addr>().is_err() {
        return Err(DomainError::InvalidRasEndpoint {
            value: host.to_owned(),
            reason: "адрес с двоеточиями должен быть корректным IPv6-адресом",
        });
    }
    Ok(())
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl fmt::Display for RasEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.address)
    }
}

impl FromStr for RasEndpoint {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (host, port) = if let Some(rest) = value.strip_prefix('[') {
            let Some((host, port)) = rest.split_once("]:") else {
                return Err(DomainError::InvalidRasEndpoint {
                    value: value.to_owned(),
                    reason: "ожидается адрес вида [IPv6]:port",
                });
            };
            if port.contains(':') || port.contains(' ') {
                return Err(DomainError::InvalidRasEndpoint {
                    value: value.to_owned(),
                    reason: "ожидается адрес вида [IPv6]:port",
                });
            }
            (host, port)
        } else {
            let Some((host, port)) = value.rsplit_once(':') else {
                return Err(DomainError::InvalidRasEndpoint {
                    value: value.to_owned(),
                    reason: "ожидается адрес вида host:port",
                });
            };
            if host.contains(':') {
                return Err(DomainError::InvalidRasEndpoint {
                    value: value.to_owned(),
                    reason: "IPv6-адрес должен быть заключен в квадратные скобки",
                });
            }
            (host, port)
        };
        let port = port
            .parse::<u16>()
            .map_err(|_| DomainError::InvalidRasEndpoint {
                value: value.to_owned(),
                reason: "порт должен быть числом в диапазоне 1..=65535",
            })?;
        Self::new(host, port)
    }
}

impl Serialize for RasEndpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RasEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlatformVersion {
    components: [u32; 4],
}

impl PlatformVersion {
    pub const MIN_SUPPORTED: Self = Self::new(8, 3, 20, 0);

    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32, build: u32) -> Self {
        Self {
            components: [major, minor, patch, build],
        }
    }

    #[must_use]
    pub const fn components(self) -> [u32; 4] {
        self.components
    }

    #[must_use]
    pub const fn major(self) -> u32 {
        self.components[0]
    }

    #[must_use]
    pub const fn minor(self) -> u32 {
        self.components[1]
    }

    #[must_use]
    pub const fn patch(self) -> u32 {
        self.components[2]
    }

    #[must_use]
    pub const fn build(self) -> u32 {
        self.components[3]
    }

    #[must_use]
    pub fn is_supported(self) -> bool {
        self >= Self::MIN_SUPPORTED
    }
}

impl fmt::Display for PlatformVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{}.{}.{}",
            self.components[0], self.components[1], self.components[2], self.components[3]
        )
    }
}

impl FromStr for PlatformVersion {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parsed = [0_u32; 4];
        let mut parts = value.split('.');
        for component in &mut parsed {
            let Some(part) = parts.next() else {
                return Err(DomainError::InvalidPlatformVersion {
                    value: value.to_owned(),
                });
            };
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(DomainError::InvalidPlatformVersion {
                    value: value.to_owned(),
                });
            }
            *component = part
                .parse()
                .map_err(|_| DomainError::InvalidPlatformVersion {
                    value: value.to_owned(),
                })?;
        }
        if parts.next().is_some() {
            return Err(DomainError::InvalidPlatformVersion {
                value: value.to_owned(),
            });
        }
        Ok(Self { components: parsed })
    }
}

impl Serialize for PlatformVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PlatformVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

macro_rules! entity_uuid {
    ($name:ident, $entity:literal) => {
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub const fn new(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            #[must_use]
            pub const fn is_nil(self) -> bool {
                self.0.is_nil()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::new(value)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map(Self::new)
                    .map_err(|_| DomainError::InvalidUuid {
                        entity: $entity,
                        value: value.to_owned(),
                    })
            }
        }
    };
}

entity_uuid!(ClusterUuid, "cluster");
entity_uuid!(InfobaseUuid, "infobase");
entity_uuid!(SessionUuid, "session");
entity_uuid!(ConnectionUuid, "connection");
entity_uuid!(ProcessUuid, "process");

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FieldType {
    Uuid,
    Int,
    Bool,
    DateTime,
    Str,
}

impl FieldType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uuid => "UUID",
            Self::Int => "int",
            Self::Bool => "bool",
            Self::DateTime => "datetime (ISO 8601)",
            Self::Str => "str",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    Uuid(Uuid),
    Int(i64),
    Bool(bool),
    DateTime(DateTime<FixedOffset>),
    Str(String),
    Null,
}

impl FieldValue {
    #[must_use]
    pub const fn field_type(&self) -> Option<FieldType> {
        match self {
            Self::Uuid(_) => Some(FieldType::Uuid),
            Self::Int(_) => Some(FieldType::Int),
            Self::Bool(_) => Some(FieldType::Bool),
            Self::DateTime(_) => Some(FieldType::DateTime),
            Self::Str(_) => Some(FieldType::Str),
            Self::Null => None,
        }
    }

    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    #[must_use]
    pub fn as_ref(&self) -> FieldValueRef<'_> {
        match self {
            Self::Uuid(value) => FieldValueRef::Uuid(value),
            Self::Int(value) => FieldValueRef::Int(*value),
            Self::Bool(value) => FieldValueRef::Bool(*value),
            Self::DateTime(value) => FieldValueRef::DateTime(value),
            Self::Str(value) => FieldValueRef::Str(value),
            Self::Null => FieldValueRef::Null,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldValueRef<'a> {
    Uuid(&'a Uuid),
    Int(i64),
    Bool(bool),
    DateTime(&'a DateTime<FixedOffset>),
    Str(&'a str),
    Null,
}

impl FieldValueRef<'_> {
    #[must_use]
    pub const fn field_type(self) -> Option<FieldType> {
        match self {
            Self::Uuid(_) => Some(FieldType::Uuid),
            Self::Int(_) => Some(FieldType::Int),
            Self::Bool(_) => Some(FieldType::Bool),
            Self::DateTime(_) => Some(FieldType::DateTime),
            Self::Str(_) => Some(FieldType::Str),
            Self::Null => None,
        }
    }

    #[must_use]
    pub const fn is_null(self) -> bool {
        matches!(self, Self::Null)
    }

    #[must_use]
    pub fn into_owned(self) -> FieldValue {
        match self {
            Self::Uuid(value) => FieldValue::Uuid(*value),
            Self::Int(value) => FieldValue::Int(value),
            Self::Bool(value) => FieldValue::Bool(value),
            Self::DateTime(value) => FieldValue::DateTime(*value),
            Self::Str(value) => FieldValue::Str(value.to_owned()),
            Self::Null => FieldValue::Null,
        }
    }
}

pub type ExtraFields = IndexMap<String, FieldValue>;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn aliases_are_case_insensitively_equal_and_hash_compatible() {
        let lower = ClusterAlias::new("prod.eu").unwrap_or_else(|error| panic!("{error}"));
        let upper = ClusterAlias::new("PROD.EU").unwrap_or_else(|error| panic!("{error}"));
        let aliases = HashSet::from([lower.clone()]);

        assert_eq!(lower, upper);
        assert!(aliases.contains(&upper));
    }

    #[test]
    fn alias_rejects_non_ascii_and_spaces() {
        assert!(ClusterAlias::new("prod eu").is_err());
        assert!(ClusterAlias::new("прод").is_err());
    }

    #[test]
    fn endpoint_parses_dns_ipv4_and_bracketed_ipv6() {
        let dns: RasEndpoint = "RV-DEV-1C01:1545"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        let ipv6: RasEndpoint = "[2001:db8::1]:1545"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(dns.host(), "RV-DEV-1C01");
        assert_eq!(dns.port(), 1545);
        assert_eq!(ipv6.to_string(), "[2001:db8::1]:1545");
        assert!("2001:db8::1:1545".parse::<RasEndpoint>().is_err());
        assert!("host:0".parse::<RasEndpoint>().is_err());
    }

    #[test]
    fn platform_version_requires_exactly_four_numbers() {
        let version: PlatformVersion = "8.3.20.1710"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(version.components(), [8, 3, 20, 1710]);
        assert!(version.is_supported());
        assert!("8.3.20".parse::<PlatformVersion>().is_err());
        assert!("8.3.20.1.2".parse::<PlatformVersion>().is_err());
        assert!("8.3.x.1".parse::<PlatformVersion>().is_err());
    }

    proptest! {
        #[test]
        fn platform_version_round_trips(
            major in any::<u32>(),
            minor in any::<u32>(),
            patch in any::<u32>(),
            build in any::<u32>(),
        ) {
            let version = PlatformVersion::new(major, minor, patch, build);
            let parsed = version.to_string().parse::<PlatformVersion>();
            prop_assert_eq!(parsed, Ok(version));
        }
    }
}
