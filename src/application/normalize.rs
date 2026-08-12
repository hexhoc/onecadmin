use std::collections::HashSet;
use std::fmt;

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use uuid::Uuid;

use crate::domain::{
    ClusterSource, ClusterUuid, ConnectionRecord, ConnectionUuid, DiscoveredCluster, ExtraFields,
    FieldValue, InfobaseRecord, InfobaseUuid, ProcessUuid, SessionRecord, SessionUuid,
};
use crate::infrastructure::rac::RacRecord;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizationError {
    code: &'static str,
    message: String,
}

impl NormalizationError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NormalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for NormalizationError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct RacNormalizer;

impl RacNormalizer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn cluster(&self, record: &RacRecord) -> Result<DiscoveredCluster, NormalizationError> {
        normalize_cluster(record)
    }

    pub fn infobase(
        &self,
        record: &RacRecord,
        source: ClusterSource,
        cluster: &DiscoveredCluster,
    ) -> Result<InfobaseRecord, NormalizationError> {
        normalize_infobase(record, source, cluster)
    }

    pub fn session(
        &self,
        record: &RacRecord,
        source: ClusterSource,
    ) -> Result<SessionRecord, NormalizationError> {
        normalize_session(record, source)
    }

    pub fn connection(
        &self,
        record: &RacRecord,
        source: ClusterSource,
    ) -> Result<ConnectionRecord, NormalizationError> {
        normalize_connection(record, source)
    }
}

pub fn normalize_cluster(record: &RacRecord) -> Result<DiscoveredCluster, NormalizationError> {
    let mut reader = RecordReader::new(record);
    let uuid = required_uuid(
        &mut reader,
        "cluster",
        &["cluster", "cluster_uuid", "cluster_id"],
    )?;
    let name = required_string(&mut reader, "name", &["name", "cluster_name"])?;
    let host = required_string(&mut reader, "host", &["host", "cluster_host"])?;
    let port = required_port(&mut reader, "port", &["port", "cluster_port"])?;
    let mut cluster = DiscoveredCluster::new(ClusterUuid::new(uuid), name, host, port)
        .map_err(|error| NormalizationError::new("invalid_cluster_record", error.to_string()))?;
    cluster.extra = reader.finish();
    Ok(cluster)
}

pub fn normalize_infobase(
    record: &RacRecord,
    source: ClusterSource,
    cluster: &DiscoveredCluster,
) -> Result<InfobaseRecord, NormalizationError> {
    let mut reader = RecordReader::new(record);
    reader.consume(&["cluster", "cluster_uuid", "cluster_id"]);
    let uuid = required_uuid(
        &mut reader,
        "infobase",
        &["infobase", "infobase_uuid", "infobase_id"],
    )?;
    let name = required_string(&mut reader, "name", &["name", "infobase_name"])?;
    let connection_string = InfobaseRecord::build_connection_string(cluster, &name);
    let mut normalized =
        InfobaseRecord::new(source, name, InfobaseUuid::new(uuid), connection_string);
    normalized.extra = reader.finish();
    Ok(normalized)
}

pub fn normalize_session(
    record: &RacRecord,
    source: ClusterSource,
) -> Result<SessionRecord, NormalizationError> {
    let mut reader = RecordReader::new(record);
    reader.consume(&["cluster", "cluster_uuid", "cluster_id"]);
    let (session, session_id) = session_identity(&mut reader)?;
    let mut normalized = SessionRecord::new(source, SessionUuid::new(session));
    normalized.session_id = session_id;
    normalized.infobase_uuid = optional_uuid(
        &mut reader,
        "infobase_uuid",
        &["infobase", "infobase_uuid", "infobase_id"],
    )
    .map(InfobaseUuid::new);
    normalized.connection = optional_uuid(
        &mut reader,
        "connection",
        &["connection", "connection_uuid"],
    )
    .map(ConnectionUuid::new);
    normalized.process =
        optional_uuid(&mut reader, "process", &["process", "process_uuid"]).map(ProcessUuid::new);
    normalized.user_name = optional_string(&mut reader, &["user_name"]);
    normalized.host = optional_string(&mut reader, &["host"]);
    normalized.app_id = optional_string(&mut reader, &["app_id"]);
    normalized.locale = optional_string(&mut reader, &["locale"]);
    normalized.started_at = optional_datetime(&mut reader, "started_at", &["started_at"]);
    normalized.last_active_at =
        optional_datetime(&mut reader, "last_active_at", &["last_active_at"]);
    normalized.hibernate = optional_bool(&mut reader, "hibernate", &["hibernate"]);
    normalized.passive_session_hibernate_time = optional_int(
        &mut reader,
        "passive_session_hibernate_time",
        &["passive_session_hibernate_time"],
    );
    normalized.hibernate_session_terminate_time = optional_int(
        &mut reader,
        "hibernate_session_terminate_time",
        &["hibernate_session_terminate_time"],
    );
    normalized.blocked_by_dbms = optional_int(&mut reader, "blocked_by_dbms", &["blocked_by_dbms"]);
    normalized.blocked_by_ls = optional_int(&mut reader, "blocked_by_ls", &["blocked_by_ls"]);
    normalized.bytes_all = optional_int(&mut reader, "bytes_all", &["bytes_all"]);
    normalized.bytes_last_5min = optional_int(&mut reader, "bytes_last_5min", &["bytes_last_5min"]);
    normalized.calls_all = optional_int(&mut reader, "calls_all", &["calls_all"]);
    normalized.calls_last_5min = optional_int(&mut reader, "calls_last_5min", &["calls_last_5min"]);
    normalized.dbms_bytes_all = optional_int(&mut reader, "dbms_bytes_all", &["dbms_bytes_all"]);
    normalized.dbms_bytes_last_5min = optional_int(
        &mut reader,
        "dbms_bytes_last_5min",
        &["dbms_bytes_last_5min"],
    );
    normalized.db_proc_info = optional_string(&mut reader, &["db_proc_info"]);
    normalized.db_proc_took = optional_int(&mut reader, "db_proc_took", &["db_proc_took"]);
    normalized.db_proc_took_at =
        optional_datetime(&mut reader, "db_proc_took_at", &["db_proc_took_at"]);
    normalized.duration_all = optional_int(&mut reader, "duration_all", &["duration_all"]);
    normalized.duration_all_dbms =
        optional_int(&mut reader, "duration_all_dbms", &["duration_all_dbms"]);
    normalized.duration_current =
        optional_int(&mut reader, "duration_current", &["duration_current"]);
    normalized.duration_current_dbms = optional_int(
        &mut reader,
        "duration_current_dbms",
        &["duration_current_dbms"],
    );
    normalized.duration_last_5min =
        optional_int(&mut reader, "duration_last_5min", &["duration_last_5min"]);
    normalized.duration_last_5min_dbms = optional_int(
        &mut reader,
        "duration_last_5min_dbms",
        &["duration_last_5min_dbms"],
    );
    normalized.memory_current = optional_int(&mut reader, "memory_current", &["memory_current"]);
    normalized.memory_last_5min =
        optional_int(&mut reader, "memory_last_5min", &["memory_last_5min"]);
    normalized.memory_total = optional_int(&mut reader, "memory_total", &["memory_total"]);
    normalized.read_current = optional_int(&mut reader, "read_current", &["read_current"]);
    normalized.read_last_5min = optional_int(&mut reader, "read_last_5min", &["read_last_5min"]);
    normalized.read_total = optional_int(&mut reader, "read_total", &["read_total"]);
    normalized.write_current = optional_int(&mut reader, "write_current", &["write_current"]);
    normalized.write_last_5min = optional_int(&mut reader, "write_last_5min", &["write_last_5min"]);
    normalized.write_total = optional_int(&mut reader, "write_total", &["write_total"]);
    normalized.duration_current_service = optional_int(
        &mut reader,
        "duration_current_service",
        &["duration_current_service"],
    );
    normalized.duration_last_5min_service = optional_int(
        &mut reader,
        "duration_last_5min_service",
        &["duration_last_5min_service"],
    );
    normalized.duration_all_service = optional_int(
        &mut reader,
        "duration_all_service",
        &["duration_all_service"],
    );
    normalized.current_service_name = optional_string(&mut reader, &["current_service_name"]);
    normalized.cpu_time_current =
        optional_int(&mut reader, "cpu_time_current", &["cpu_time_current"]);
    normalized.cpu_time_last_5min =
        optional_int(&mut reader, "cpu_time_last_5min", &["cpu_time_last_5min"]);
    normalized.cpu_time_total = optional_int(&mut reader, "cpu_time_total", &["cpu_time_total"]);
    normalized.data_separation = optional_string(&mut reader, &["data_separation"]);
    normalized.client_ip = optional_string(&mut reader, &["client_ip"]);
    normalized.extra = reader.finish();
    Ok(normalized)
}

pub fn normalize_connection(
    record: &RacRecord,
    source: ClusterSource,
) -> Result<ConnectionRecord, NormalizationError> {
    let mut reader = RecordReader::new(record);
    reader.consume(&["cluster", "cluster_uuid", "cluster_id"]);
    let connection = required_uuid(
        &mut reader,
        "connection",
        &["connection", "connection_uuid"],
    )?;
    let process = required_uuid(&mut reader, "process", &["process", "process_uuid"])?;
    let mut normalized = ConnectionRecord::new(
        source,
        ConnectionUuid::new(connection),
        ProcessUuid::new(process),
    );
    normalized.infobase_uuid = optional_uuid(
        &mut reader,
        "infobase_uuid",
        &["infobase", "infobase_uuid", "infobase_id"],
    )
    .map(InfobaseUuid::new);
    normalized.conn_id = optional_int(&mut reader, "conn_id", &["conn_id", "connection_id"]);
    normalized.host = optional_string(&mut reader, &["host"]);
    normalized.application = optional_string(&mut reader, &["application", "app_id"]);
    normalized.connected_at = optional_datetime(&mut reader, "connected_at", &["connected_at"]);
    normalized.session_number = optional_int(
        &mut reader,
        "session_number",
        &["session_number", "session_id"],
    );
    normalized.blocked_by_ls = optional_int(&mut reader, "blocked_by_ls", &["blocked_by_ls"]);
    normalized.extra = reader.finish();
    Ok(normalized)
}

fn session_identity(
    reader: &mut RecordReader<'_>,
) -> Result<(Uuid, Option<i64>), NormalizationError> {
    let session = reader.take(&["session", "session_uuid"]);
    let session_id = reader.take(&["session_id"]);
    match (session, session_id) {
        (Some(session), number) => match Uuid::parse_str(session.trim()) {
            Ok(uuid) => {
                let number = number.and_then(|raw| parse_optional_int(reader, "session", raw));
                Ok((uuid, number))
            }
            Err(_) => {
                let Some(raw_uuid) = number else {
                    return Err(required_uuid_error("session"));
                };
                let uuid =
                    Uuid::parse_str(raw_uuid.trim()).map_err(|_| required_uuid_error("session"))?;
                let number = parse_optional_int(reader, "session", session);
                Ok((uuid, number))
            }
        },
        (None, Some(raw_uuid)) => Uuid::parse_str(raw_uuid.trim())
            .map(|uuid| (uuid, None))
            .map_err(|_| required_uuid_error("session")),
        (None, None) => Err(required_uuid_error("session")),
    }
}

fn required_uuid(
    reader: &mut RecordReader<'_>,
    field: &'static str,
    aliases: &[&str],
) -> Result<Uuid, NormalizationError> {
    let value = reader
        .take(aliases)
        .ok_or_else(|| required_uuid_error(field))?;
    Uuid::parse_str(value.trim())
        .ok()
        .filter(|uuid| !uuid.is_nil())
        .ok_or_else(|| required_uuid_error(field))
}

fn required_uuid_error(field: &'static str) -> NormalizationError {
    NormalizationError::new(
        "invalid_required_uuid",
        format!("В ответе RAC отсутствует корректный обязательный UUID поля `{field}`"),
    )
}

fn required_string(
    reader: &mut RecordReader<'_>,
    field: &'static str,
    aliases: &[&str],
) -> Result<String, NormalizationError> {
    reader
        .take(aliases)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            NormalizationError::new(
                "missing_required_field",
                format!("В ответе RAC отсутствует обязательное поле `{field}`"),
            )
        })
}

fn required_port(
    reader: &mut RecordReader<'_>,
    field: &'static str,
    aliases: &[&str],
) -> Result<u16, NormalizationError> {
    let value = reader.take(aliases).ok_or_else(|| {
        NormalizationError::new(
            "missing_required_field",
            format!("В ответе RAC отсутствует обязательное поле `{field}`"),
        )
    })?;
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            NormalizationError::new(
                "invalid_required_integer",
                format!("В ответе RAC поле `{field}` не содержит корректный порт"),
            )
        })
}

fn optional_uuid(
    reader: &mut RecordReader<'_>,
    canonical: &'static str,
    aliases: &[&str],
) -> Option<Uuid> {
    let value = reader.take(aliases)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    match Uuid::parse_str(trimmed) {
        Ok(uuid) if uuid.is_nil() => None,
        Ok(uuid) => Some(uuid),
        Err(_) => {
            reader.preserve_invalid(canonical, value);
            None
        }
    }
}

fn optional_string(reader: &mut RecordReader<'_>, aliases: &[&str]) -> Option<String> {
    reader.take(aliases).filter(|value| !value.is_empty())
}

fn optional_int(
    reader: &mut RecordReader<'_>,
    canonical: &'static str,
    aliases: &[&str],
) -> Option<i64> {
    let value = reader.take(aliases)?;
    parse_optional_int(reader, canonical, value)
}

fn parse_optional_int(
    reader: &mut RecordReader<'_>,
    canonical: &'static str,
    value: String,
) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<i64>() {
        Ok(value) => Some(value),
        Err(_) => {
            reader.preserve_invalid(canonical, value);
            None
        }
    }
}

fn optional_bool(
    reader: &mut RecordReader<'_>,
    canonical: &'static str,
    aliases: &[&str],
) -> Option<bool> {
    let value = reader.take(aliases)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.to_lowercase();
    if matches!(normalized.as_str(), "true" | "yes" | "1" | "да") {
        Some(true)
    } else if matches!(normalized.as_str(), "false" | "no" | "0" | "нет") {
        Some(false)
    } else {
        reader.preserve_invalid(canonical, value);
        None
    }
}

fn optional_datetime(
    reader: &mut RecordReader<'_>,
    canonical: &'static str,
    aliases: &[&str],
) -> Option<DateTime<FixedOffset>> {
    let value = reader.take(aliases)?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("0001-01-01") {
        return None;
    }
    if let Ok(value) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(value);
    }
    if let Ok(value) = DateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f%z") {
        return Some(value);
    }
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y%m%d%H%M%S",
    ] {
        if let Ok(value) = NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(value, Utc).fixed_offset());
        }
    }
    reader.preserve_invalid(canonical, value);
    None
}

struct RecordReader<'a> {
    record: &'a RacRecord,
    consumed: HashSet<String>,
    extra: ExtraFields,
}

impl<'a> RecordReader<'a> {
    fn new(record: &'a RacRecord) -> Self {
        Self {
            record,
            consumed: HashSet::new(),
            extra: ExtraFields::new(),
        }
    }

    fn consume(&mut self, aliases: &[&str]) {
        for alias in aliases {
            if self.record.contains_key(alias) {
                self.consumed.insert((*alias).to_owned());
            }
        }
    }

    fn take(&mut self, aliases: &[&str]) -> Option<String> {
        let mut selected = None;
        for alias in aliases {
            if let Some(value) = self.record.get(alias) {
                self.consumed.insert((*alias).to_owned());
                if selected.is_none() {
                    selected = Some(value.to_owned());
                }
            }
        }
        selected
    }

    fn preserve_invalid(&mut self, canonical: &str, value: String) {
        let base = format!("rac_raw_{canonical}");
        insert_unique(&mut self.extra, base, FieldValue::Str(value));
    }

    fn finish(mut self) -> ExtraFields {
        for (name, value) in self.record.iter() {
            if !self.consumed.contains(name) {
                insert_unique(
                    &mut self.extra,
                    name.to_owned(),
                    FieldValue::Str(value.to_owned()),
                );
            }
        }
        self.extra
    }
}

fn insert_unique(extra: &mut ExtraFields, base: String, value: FieldValue) {
    if !extra.contains_key(&base) {
        extra.insert(base, value);
        return;
    }
    let mut suffix = 2_usize;
    loop {
        let candidate = format!("{base}_{suffix}");
        if !extra.contains_key(&candidate) {
            extra.insert(candidate, value);
            return;
        }
        suffix += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ClusterAlias, RasEndpoint};

    fn source() -> ClusterSource {
        ClusterSource::new(
            ClusterAlias::new("dev").unwrap_or_else(|error| panic!("{error}")),
            ClusterUuid::new(Uuid::from_u128(1)),
            "Development",
            "ras.local:1545"
                .parse::<RasEndpoint>()
                .unwrap_or_else(|error| panic!("{error}")),
        )
    }

    #[test]
    fn session_swaps_rac_uuid_and_numeric_session_fields() {
        let mut record = RacRecord::new();
        record.insert("session", Uuid::from_u128(2).to_string());
        record.insert("session-id", "42");
        record.insert("cpu-time-total", "123");
        record.insert("hibernate", "true");
        record.insert("started-at", "2026-08-11T10:00:00+03:00");
        record.insert("future-field", "preserved");

        let session =
            normalize_session(&record, source()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(session.session.into_uuid().as_u128(), 2);
        assert_eq!(session.session_id, Some(42));
        assert_eq!(session.cpu_time_total, Some(123));
        assert_eq!(session.hibernate, Some(true));
        assert!(session.started_at.is_some());
        assert_eq!(
            session.extra.get("future_field"),
            Some(&FieldValue::Str("preserved".to_owned()))
        );
    }

    #[test]
    fn malformed_required_uuid_rejects_record_but_optional_value_is_preserved() {
        let mut invalid = RacRecord::new();
        invalid.insert("connection", "not-a-uuid");
        invalid.insert("process", Uuid::from_u128(3).to_string());
        assert_eq!(
            normalize_connection(&invalid, source())
                .err()
                .map(|error| error.code()),
            Some("invalid_required_uuid")
        );

        let mut session = RacRecord::new();
        session.insert("session", Uuid::from_u128(2).to_string());
        session.insert("cpu-time-total", "future-format");
        let session =
            normalize_session(&session, source()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(session.cpu_time_total, None);
        assert_eq!(
            session.extra.get("rac_raw_cpu_time_total"),
            Some(&FieldValue::Str("future-format".to_owned()))
        );
    }
}
