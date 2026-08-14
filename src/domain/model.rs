use std::path::PathBuf;

use chrono::{DateTime, FixedOffset};

use super::{
    AuthConfig, ClusterAlias, ClusterUuid, ConnectionUuid, DomainError, ExtraFields, FieldValue,
    FieldValueRef, InfobaseUuid, PlatformVersion, ProcessUuid, RasEndpoint, SessionUuid,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecordKind {
    Infobase,
    Session,
    Connection,
}

impl RecordKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Infobase => "infobase",
            Self::Session => "session",
            Self::Connection => "connection",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum RacPolicy {
    #[default]
    Auto,
    Version(PlatformVersion),
    ExplicitPath(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredCluster {
    pub uuid: ClusterUuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub extra: ExtraFields,
}

impl DiscoveredCluster {
    pub fn new(
        uuid: ClusterUuid,
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, DomainError> {
        let endpoint = RasEndpoint::new(host, port)?;
        Ok(Self {
            uuid,
            name: name.into(),
            host: endpoint.host().to_owned(),
            port: endpoint.port(),
            extra: ExtraFields::new(),
        })
    }

    pub fn endpoint(&self) -> Result<RasEndpoint, DomainError> {
        RasEndpoint::new(self.host.clone(), self.port)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfobaseAuthOverride {
    infobase: Option<String>,
    infobase_uuid: Option<InfobaseUuid>,
    auth: AuthConfig,
}

impl InfobaseAuthOverride {
    pub fn new(
        infobase: Option<String>,
        infobase_uuid: Option<InfobaseUuid>,
        auth: AuthConfig,
    ) -> Result<Self, DomainError> {
        if infobase.as_deref().is_some_and(str::is_empty) {
            return Err(DomainError::InvalidAuthOverride {
                reason: "имя информационной базы не может быть пустым",
            });
        }
        if infobase.is_none() && infobase_uuid.is_none() {
            return Err(DomainError::InvalidAuthOverride {
                reason: "требуется имя или UUID информационной базы",
            });
        }
        Ok(Self {
            infobase,
            infobase_uuid,
            auth,
        })
    }

    #[must_use]
    pub fn infobase(&self) -> Option<&str> {
        self.infobase.as_deref()
    }

    #[must_use]
    pub const fn infobase_uuid(&self) -> Option<InfobaseUuid> {
        self.infobase_uuid
    }

    #[must_use]
    pub const fn auth(&self) -> &AuthConfig {
        &self.auth
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfobaseAuthPolicy {
    default: AuthConfig,
    overrides: Vec<InfobaseAuthOverride>,
}

impl InfobaseAuthPolicy {
    pub fn new(
        default: AuthConfig,
        overrides: Vec<InfobaseAuthOverride>,
    ) -> Result<Self, DomainError> {
        for (index, candidate) in overrides.iter().enumerate() {
            for existing in overrides.iter().take(index) {
                if candidate.infobase_uuid.is_some()
                    && candidate.infobase_uuid == existing.infobase_uuid
                {
                    return Err(DomainError::InvalidAuthOverride {
                        reason: "UUID информационной базы повторяется",
                    });
                }
                if candidate
                    .infobase()
                    .zip(existing.infobase())
                    .is_some_and(|(left, right)| left.to_lowercase() == right.to_lowercase())
                {
                    return Err(DomainError::InvalidAuthOverride {
                        reason: "имя информационной базы повторяется без учета регистра",
                    });
                }
            }
        }
        Ok(Self { default, overrides })
    }

    #[must_use]
    pub fn default_auth(&self) -> &AuthConfig {
        &self.default
    }

    #[must_use]
    pub fn overrides(&self) -> &[InfobaseAuthOverride] {
        &self.overrides
    }

    #[must_use]
    pub fn resolve(&self, uuid: Option<InfobaseUuid>, name: &str) -> &AuthConfig {
        if let Some(uuid) = uuid
            && let Some(item) = self
                .overrides
                .iter()
                .find(|item| item.infobase_uuid == Some(uuid))
        {
            return &item.auth;
        }
        self.overrides
            .iter()
            .find(|item| {
                item.infobase()
                    .is_some_and(|candidate| candidate.to_lowercase() == name.to_lowercase())
            })
            .map_or(&self.default, |item| &item.auth)
    }
}

impl Default for InfobaseAuthPolicy {
    fn default() -> Self {
        Self {
            default: AuthConfig::none(),
            overrides: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterTarget {
    pub alias: ClusterAlias,
    pub ras: RasEndpoint,
    pub discovered_cluster: DiscoveredCluster,
    pub rac_policy: RacPolicy,
    pub cluster_auth: AuthConfig,
    pub infobase_auth: InfobaseAuthPolicy,
}

impl ClusterTarget {
    #[must_use]
    pub fn new(
        alias: ClusterAlias,
        ras: RasEndpoint,
        discovered_cluster: DiscoveredCluster,
        rac_policy: RacPolicy,
        cluster_auth: AuthConfig,
        infobase_auth: InfobaseAuthPolicy,
    ) -> Self {
        Self {
            alias,
            ras,
            discovered_cluster,
            rac_policy,
            cluster_auth,
            infobase_auth,
        }
    }

    #[must_use]
    pub fn source(&self) -> ClusterSource {
        ClusterSource {
            cluster: self.alias.clone(),
            cluster_uuid: self.discovered_cluster.uuid,
            cluster_name: self.discovered_cluster.name.clone(),
            ras_address: self.ras.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterSource {
    pub cluster: ClusterAlias,
    pub cluster_uuid: ClusterUuid,
    pub cluster_name: String,
    pub ras_address: RasEndpoint,
}

impl ClusterSource {
    #[must_use]
    pub fn new(
        cluster: ClusterAlias,
        cluster_uuid: ClusterUuid,
        cluster_name: impl Into<String>,
        ras_address: RasEndpoint,
    ) -> Self {
        Self {
            cluster,
            cluster_uuid,
            cluster_name: cluster_name.into(),
            ras_address,
        }
    }
}

pub trait FieldAccess {
    fn record_kind(&self) -> RecordKind;
    fn field(&self, name: &str) -> Option<FieldValueRef<'_>>;
    fn extra_fields(&self) -> &ExtraFields;

    fn field_owned(&self, name: &str) -> Option<FieldValue> {
        self.field(name).map(FieldValueRef::into_owned)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InfobaseRecord {
    pub source: ClusterSource,
    pub infobase: String,
    pub infobase_uuid: InfobaseUuid,
    pub connection_string: String,
    pub extra: ExtraFields,
}

impl InfobaseRecord {
    #[must_use]
    pub fn new(
        source: ClusterSource,
        infobase: impl Into<String>,
        infobase_uuid: InfobaseUuid,
        connection_string: impl Into<String>,
    ) -> Self {
        Self {
            source,
            infobase: infobase.into(),
            infobase_uuid,
            connection_string: connection_string.into(),
            extra: ExtraFields::new(),
        }
    }

    #[must_use]
    pub fn build_connection_string(cluster: &DiscoveredCluster, infobase: &str) -> String {
        let escaped_host = cluster.host.replace('"', "\"\"");
        let escaped_infobase = infobase.replace('"', "\"\"");
        format!(
            "Srvr=\"{escaped_host}:{}\";Ref=\"{escaped_infobase}\";",
            cluster.port
        )
    }
}

impl FieldAccess for InfobaseRecord {
    fn record_kind(&self) -> RecordKind {
        RecordKind::Infobase
    }

    fn field(&self, name: &str) -> Option<FieldValueRef<'_>> {
        source_field(&self.source, name)
            .or_else(|| match name {
                "infobase" => Some(FieldValueRef::Str(&self.infobase)),
                "infobase_uuid" => Some(FieldValueRef::Uuid(self.infobase_uuid.as_uuid())),
                "connection_string" => Some(FieldValueRef::Str(&self.connection_string)),
                _ => None,
            })
            .or_else(|| extra_field(&self.extra, name))
    }

    fn extra_fields(&self) -> &ExtraFields {
        &self.extra
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    pub source: ClusterSource,
    pub infobase: Option<String>,
    pub infobase_uuid: Option<InfobaseUuid>,
    pub session: SessionUuid,
    pub session_id: Option<i64>,
    pub connection: Option<ConnectionUuid>,
    pub process: Option<ProcessUuid>,
    pub user_name: Option<String>,
    pub host: Option<String>,
    pub app_id: Option<String>,
    pub locale: Option<String>,
    pub started_at: Option<DateTime<FixedOffset>>,
    pub last_active_at: Option<DateTime<FixedOffset>>,
    pub hibernate: Option<bool>,
    pub passive_session_hibernate_time: Option<i64>,
    pub hibernate_session_terminate_time: Option<i64>,
    pub blocked_by_dbms: Option<i64>,
    pub blocked_by_ls: Option<i64>,
    pub bytes_all: Option<i64>,
    pub bytes_last_5min: Option<i64>,
    pub calls_all: Option<i64>,
    pub calls_last_5min: Option<i64>,
    pub dbms_bytes_all: Option<i64>,
    pub dbms_bytes_last_5min: Option<i64>,
    pub db_proc_info: Option<String>,
    pub db_proc_took: Option<i64>,
    pub db_proc_took_at: Option<DateTime<FixedOffset>>,
    pub duration_all: Option<i64>,
    pub duration_all_dbms: Option<i64>,
    pub duration_current: Option<i64>,
    pub duration_current_dbms: Option<i64>,
    pub duration_last_5min: Option<i64>,
    pub duration_last_5min_dbms: Option<i64>,
    pub memory_current: Option<i64>,
    pub memory_last_5min: Option<i64>,
    pub memory_total: Option<i64>,
    pub read_current: Option<i64>,
    pub read_last_5min: Option<i64>,
    pub read_total: Option<i64>,
    pub write_current: Option<i64>,
    pub write_last_5min: Option<i64>,
    pub write_total: Option<i64>,
    pub duration_current_service: Option<i64>,
    pub duration_last_5min_service: Option<i64>,
    pub duration_all_service: Option<i64>,
    pub current_service_name: Option<String>,
    pub cpu_time_current: Option<i64>,
    pub cpu_time_last_5min: Option<i64>,
    pub cpu_time_total: Option<i64>,
    pub data_separation: Option<String>,
    pub client_ip: Option<String>,
    pub extra: ExtraFields,
}

impl SessionRecord {
    #[must_use]
    pub fn new(source: ClusterSource, session: SessionUuid) -> Self {
        Self {
            source,
            infobase: None,
            infobase_uuid: None,
            session,
            session_id: None,
            connection: None,
            process: None,
            user_name: None,
            host: None,
            app_id: None,
            locale: None,
            started_at: None,
            last_active_at: None,
            hibernate: None,
            passive_session_hibernate_time: None,
            hibernate_session_terminate_time: None,
            blocked_by_dbms: None,
            blocked_by_ls: None,
            bytes_all: None,
            bytes_last_5min: None,
            calls_all: None,
            calls_last_5min: None,
            dbms_bytes_all: None,
            dbms_bytes_last_5min: None,
            db_proc_info: None,
            db_proc_took: None,
            db_proc_took_at: None,
            duration_all: None,
            duration_all_dbms: None,
            duration_current: None,
            duration_current_dbms: None,
            duration_last_5min: None,
            duration_last_5min_dbms: None,
            memory_current: None,
            memory_last_5min: None,
            memory_total: None,
            read_current: None,
            read_last_5min: None,
            read_total: None,
            write_current: None,
            write_last_5min: None,
            write_total: None,
            duration_current_service: None,
            duration_last_5min_service: None,
            duration_all_service: None,
            current_service_name: None,
            cpu_time_current: None,
            cpu_time_last_5min: None,
            cpu_time_total: None,
            data_separation: None,
            client_ip: None,
            extra: ExtraFields::new(),
        }
    }
}

impl FieldAccess for SessionRecord {
    fn record_kind(&self) -> RecordKind {
        RecordKind::Session
    }

    fn field(&self, name: &str) -> Option<FieldValueRef<'_>> {
        source_field(&self.source, name)
            .or_else(|| session_field(self, name))
            .or_else(|| extra_field(&self.extra, name))
    }

    fn extra_fields(&self) -> &ExtraFields {
        &self.extra
    }
}

fn session_field<'a>(record: &'a SessionRecord, name: &str) -> Option<FieldValueRef<'a>> {
    Some(match name {
        "infobase" => optional_str(&record.infobase),
        "infobase_uuid" => optional_uuid(record.infobase_uuid.as_ref().map(InfobaseUuid::as_uuid)),
        "session" => FieldValueRef::Uuid(record.session.as_uuid()),
        "session_id" => optional_int(record.session_id),
        "connection" => optional_uuid(record.connection.as_ref().map(ConnectionUuid::as_uuid)),
        "process" => optional_uuid(record.process.as_ref().map(ProcessUuid::as_uuid)),
        "user_name" => optional_str(&record.user_name),
        "host" => optional_str(&record.host),
        "app_id" => optional_str(&record.app_id),
        "locale" => optional_str(&record.locale),
        "started_at" => optional_datetime(record.started_at.as_ref()),
        "last_active_at" => optional_datetime(record.last_active_at.as_ref()),
        "hibernate" => optional_bool(record.hibernate),
        "passive_session_hibernate_time" => optional_int(record.passive_session_hibernate_time),
        "hibernate_session_terminate_time" => optional_int(record.hibernate_session_terminate_time),
        "blocked_by_dbms" => optional_int(record.blocked_by_dbms),
        "blocked_by_ls" => optional_int(record.blocked_by_ls),
        "bytes_all" => optional_int(record.bytes_all),
        "bytes_last_5min" => optional_int(record.bytes_last_5min),
        "calls_all" => optional_int(record.calls_all),
        "calls_last_5min" => optional_int(record.calls_last_5min),
        "dbms_bytes_all" => optional_int(record.dbms_bytes_all),
        "dbms_bytes_last_5min" => optional_int(record.dbms_bytes_last_5min),
        "db_proc_info" => optional_str(&record.db_proc_info),
        "db_proc_took" => optional_int(record.db_proc_took),
        "db_proc_took_at" => optional_datetime(record.db_proc_took_at.as_ref()),
        "duration_all" => optional_int(record.duration_all),
        "duration_all_dbms" => optional_int(record.duration_all_dbms),
        "duration_current" => optional_int(record.duration_current),
        "duration_current_dbms" => optional_int(record.duration_current_dbms),
        "duration_last_5min" => optional_int(record.duration_last_5min),
        "duration_last_5min_dbms" => optional_int(record.duration_last_5min_dbms),
        "memory_current" => optional_int(record.memory_current),
        "memory_last_5min" => optional_int(record.memory_last_5min),
        "memory_total" => optional_int(record.memory_total),
        "read_current" => optional_int(record.read_current),
        "read_last_5min" => optional_int(record.read_last_5min),
        "read_total" => optional_int(record.read_total),
        "write_current" => optional_int(record.write_current),
        "write_last_5min" => optional_int(record.write_last_5min),
        "write_total" => optional_int(record.write_total),
        "duration_current_service" => optional_int(record.duration_current_service),
        "duration_last_5min_service" => optional_int(record.duration_last_5min_service),
        "duration_all_service" => optional_int(record.duration_all_service),
        "current_service_name" => optional_str(&record.current_service_name),
        "cpu_time_current" => optional_int(record.cpu_time_current),
        "cpu_time_last_5min" => optional_int(record.cpu_time_last_5min),
        "cpu_time_total" => optional_int(record.cpu_time_total),
        "data_separation" => optional_str(&record.data_separation),
        "client_ip" => optional_str(&record.client_ip),
        _ => return None,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionRecord {
    pub source: ClusterSource,
    pub infobase: Option<String>,
    pub infobase_uuid: Option<InfobaseUuid>,
    pub connection: ConnectionUuid,
    pub conn_id: Option<i64>,
    pub host: Option<String>,
    pub process: ProcessUuid,
    pub application: Option<String>,
    pub connected_at: Option<DateTime<FixedOffset>>,
    pub session_number: Option<i64>,
    pub blocked_by_ls: Option<i64>,
    pub extra: ExtraFields,
}

impl ConnectionRecord {
    #[must_use]
    pub fn new(source: ClusterSource, connection: ConnectionUuid, process: ProcessUuid) -> Self {
        Self {
            source,
            infobase: None,
            infobase_uuid: None,
            connection,
            conn_id: None,
            host: None,
            process,
            application: None,
            connected_at: None,
            session_number: None,
            blocked_by_ls: None,
            extra: ExtraFields::new(),
        }
    }
}

impl FieldAccess for ConnectionRecord {
    fn record_kind(&self) -> RecordKind {
        RecordKind::Connection
    }

    fn field(&self, name: &str) -> Option<FieldValueRef<'_>> {
        source_field(&self.source, name)
            .or_else(|| {
                Some(match name {
                    "infobase" => optional_str(&self.infobase),
                    "infobase_uuid" => {
                        optional_uuid(self.infobase_uuid.as_ref().map(InfobaseUuid::as_uuid))
                    }
                    "connection" => FieldValueRef::Uuid(self.connection.as_uuid()),
                    "conn_id" => optional_int(self.conn_id),
                    "host" => optional_str(&self.host),
                    "process" => FieldValueRef::Uuid(self.process.as_uuid()),
                    "application" => optional_str(&self.application),
                    "connected_at" => optional_datetime(self.connected_at.as_ref()),
                    "session_number" => optional_int(self.session_number),
                    "blocked_by_ls" => optional_int(self.blocked_by_ls),
                    _ => return None,
                })
            })
            .or_else(|| extra_field(&self.extra, name))
    }

    fn extra_fields(&self) -> &ExtraFields {
        &self.extra
    }
}

fn source_field<'a>(source: &'a ClusterSource, name: &str) -> Option<FieldValueRef<'a>> {
    Some(match name {
        "cluster" => FieldValueRef::Str(source.cluster.as_str()),
        "cluster_uuid" => FieldValueRef::Uuid(source.cluster_uuid.as_uuid()),
        "cluster_name" => FieldValueRef::Str(&source.cluster_name),
        "ras_address" => FieldValueRef::Str(source.ras_address.as_str()),
        _ => return None,
    })
}

fn extra_field<'a>(extra: &'a ExtraFields, name: &str) -> Option<FieldValueRef<'a>> {
    extra.get(name).map(FieldValue::as_ref)
}

fn optional_str(value: &Option<String>) -> FieldValueRef<'_> {
    value
        .as_deref()
        .map_or(FieldValueRef::Null, FieldValueRef::Str)
}

fn optional_uuid(value: Option<&uuid::Uuid>) -> FieldValueRef<'_> {
    value.map_or(FieldValueRef::Null, FieldValueRef::Uuid)
}

const fn optional_int(value: Option<i64>) -> FieldValueRef<'static> {
    match value {
        Some(value) => FieldValueRef::Int(value),
        None => FieldValueRef::Null,
    }
}

const fn optional_bool(value: Option<bool>) -> FieldValueRef<'static> {
    match value {
        Some(value) => FieldValueRef::Bool(value),
        None => FieldValueRef::Null,
    }
}

fn optional_datetime(value: Option<&DateTime<FixedOffset>>) -> FieldValueRef<'_> {
    value.map_or(FieldValueRef::Null, FieldValueRef::DateTime)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::super::{AuthMode, SecretString};
    use super::*;

    fn source() -> ClusterSource {
        ClusterSource::new(
            ClusterAlias::new("dev").unwrap_or_else(|error| panic!("{error}")),
            ClusterUuid::new(Uuid::from_u128(1)),
            "Development",
            "ras.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        )
    }

    #[test]
    fn known_source_fields_win_over_unknown_extras() {
        let mut record = SessionRecord::new(source(), SessionUuid::new(Uuid::from_u128(2)));
        record
            .extra
            .insert("cluster".to_owned(), FieldValue::Str("evil".to_owned()));
        record.extra.insert(
            "future_field".to_owned(),
            FieldValue::Str("preserved".to_owned()),
        );

        assert_eq!(record.field("cluster"), Some(FieldValueRef::Str("dev")));
        assert_eq!(
            record.field("future_field"),
            Some(FieldValueRef::Str("preserved"))
        );
    }

    #[test]
    fn every_known_optional_field_is_visible_as_null() {
        let record = SessionRecord::new(source(), SessionUuid::new(Uuid::from_u128(2)));

        assert_eq!(record.field("user_name"), Some(FieldValueRef::Null));
        assert_eq!(record.field("missing"), None);
    }

    #[test]
    fn connection_string_always_contains_cluster_port() {
        let cluster = DiscoveredCluster::new(
            ClusterUuid::new(Uuid::from_u128(1)),
            "cluster",
            "srv.local",
            1541,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            InfobaseRecord::build_connection_string(&cluster, "WorkFlow_TEST"),
            "Srvr=\"srv.local:1541\";Ref=\"WorkFlow_TEST\";"
        );
    }

    #[test]
    fn infobase_override_prefers_uuid_then_exact_case_insensitive_name() {
        let id = InfobaseUuid::new(Uuid::from_u128(10));
        let by_name = InfobaseAuthOverride::new(
            Some("Accounting".to_owned()),
            None,
            AuthConfig::password("name-user", SecretString::new("name-secret"))
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let by_uuid = InfobaseAuthOverride::new(
            Some("Other".to_owned()),
            Some(id),
            AuthConfig::password("admin", SecretString::new("password"))
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let policy = InfobaseAuthPolicy::new(AuthConfig::none(), vec![by_name, by_uuid])
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            policy.resolve(Some(id), "Accounting").mode(),
            AuthMode::Password
        );
        assert_eq!(
            policy.resolve(None, "ACCOUNTING").mode(),
            AuthMode::Password
        );
        assert_eq!(policy.resolve(None, "Accounting%").mode(), AuthMode::None);
    }
}
