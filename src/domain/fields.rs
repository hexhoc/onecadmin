use std::str::FromStr;

use super::{DomainError, FieldType, RecordKind};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FilterOperator {
    Eq,
    Ne,
    Like,
    Gt,
    Ge,
    Lt,
    Le,
}

impl FilterOperator {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Like => "like",
            Self::Gt => "gt",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Le => "le",
        }
    }
}

impl FromStr for FilterOperator {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "eq" => Ok(Self::Eq),
            "ne" => Ok(Self::Ne),
            "like" => Ok(Self::Like),
            "gt" => Ok(Self::Gt),
            "ge" => Ok(Self::Ge),
            "lt" => Ok(Self::Lt),
            "le" => Ok(Self::Le),
            _ => Err(DomainError::UnknownFilterOperator {
                operator: value.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SortDirection {
    Asc,
    Desc,
}

impl SortDirection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

impl FromStr for SortDirection {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "asc" => Ok(Self::Asc),
            "desc" => Ok(Self::Desc),
            _ => Err(DomainError::InvalidSortSyntax {
                input: value.to_owned(),
                reason: "направление должно быть `asc` или `desc`",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FieldUnit {
    Bytes,
    Count,
    Milliseconds,
    Microseconds,
    Seconds,
}

impl FieldUnit {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Count => "count",
            Self::Milliseconds => "milliseconds",
            Self::Microseconds => "microseconds",
            Self::Seconds => "seconds",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldDefinition {
    pub name: &'static str,
    pub field_type: FieldType,
    pub applies_to: &'static [RecordKind],
    pub allowed_operators: &'static [FilterOperator],
    pub unit: Option<FieldUnit>,
    pub sortable: bool,
}

impl FieldDefinition {
    #[must_use]
    pub fn applies_to(&self, kind: RecordKind) -> bool {
        self.applies_to.contains(&kind)
    }

    #[must_use]
    pub fn allows(&self, operator: FilterOperator) -> bool {
        self.allowed_operators.contains(&operator)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SortKey {
    field: &'static str,
    direction: SortDirection,
    field_type: FieldType,
}

impl SortKey {
    const fn new(field: &'static str, direction: SortDirection, field_type: FieldType) -> Self {
        Self {
            field,
            direction,
            field_type,
        }
    }

    pub fn parse(
        input: &str,
        kind: RecordKind,
        registry: &FieldRegistry,
    ) -> Result<Self, DomainError> {
        let Some((field, direction)) = input.split_once(':') else {
            return Err(DomainError::InvalidSortSyntax {
                input: input.to_owned(),
                reason: "ожидается формат field:asc или field:desc",
            });
        };
        if field.is_empty() || direction.is_empty() || direction.contains(':') {
            return Err(DomainError::InvalidSortSyntax {
                input: input.to_owned(),
                reason: "ожидается ровно одно поле и одно направление",
            });
        }
        let definition = registry.definition(kind, field)?;
        if !definition.sortable {
            return Err(DomainError::FieldNotSortable {
                field: field.to_owned(),
            });
        }
        let direction = match direction {
            "asc" => SortDirection::Asc,
            "desc" => SortDirection::Desc,
            _ => {
                return Err(DomainError::InvalidSortSyntax {
                    input: input.to_owned(),
                    reason: "направление должно быть `asc` или `desc`",
                });
            }
        };
        Ok(Self::new(definition.name, direction, definition.field_type))
    }

    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }

    #[must_use]
    pub const fn direction(self) -> SortDirection {
        self.direction
    }

    #[must_use]
    pub const fn field_type(self) -> FieldType {
        self.field_type
    }
}

const SOURCE_FIELDS: &[RecordKind] = &[
    RecordKind::Infobase,
    RecordKind::Session,
    RecordKind::Connection,
    RecordKind::Process,
];
const ALL_RECORDS: &[RecordKind] = &[
    RecordKind::Infobase,
    RecordKind::Session,
    RecordKind::Connection,
];
const INFOBASE_ONLY: &[RecordKind] = &[RecordKind::Infobase];
const SESSION_ONLY: &[RecordKind] = &[RecordKind::Session];
const CONNECTION_ONLY: &[RecordKind] = &[RecordKind::Connection];
const PROCESS_ONLY: &[RecordKind] = &[RecordKind::Process];

const STRING_OPERATORS: &[FilterOperator] =
    &[FilterOperator::Eq, FilterOperator::Ne, FilterOperator::Like];
const ORDERED_OPERATORS: &[FilterOperator] = &[
    FilterOperator::Eq,
    FilterOperator::Ne,
    FilterOperator::Gt,
    FilterOperator::Ge,
    FilterOperator::Lt,
    FilterOperator::Le,
];
const EQUALITY_OPERATORS: &[FilterOperator] = &[FilterOperator::Eq, FilterOperator::Ne];

macro_rules! field {
    ($name:literal, $type:ident, $kinds:ident, $operators:ident) => {
        FieldDefinition {
            name: $name,
            field_type: FieldType::$type,
            applies_to: $kinds,
            allowed_operators: $operators,
            unit: None,
            sortable: true,
        }
    };
    ($name:literal, $type:ident, $kinds:ident, $operators:ident, $unit:ident) => {
        FieldDefinition {
            name: $name,
            field_type: FieldType::$type,
            applies_to: $kinds,
            allowed_operators: $operators,
            unit: Some(FieldUnit::$unit),
            sortable: true,
        }
    };
}

static FIELD_DEFINITIONS: &[FieldDefinition] = &[
    field!("cluster", Str, SOURCE_FIELDS, STRING_OPERATORS),
    field!("cluster_uuid", Uuid, SOURCE_FIELDS, EQUALITY_OPERATORS),
    field!("cluster_name", Str, SOURCE_FIELDS, STRING_OPERATORS),
    field!("ras_address", Str, SOURCE_FIELDS, STRING_OPERATORS),
    field!("infobase", Str, ALL_RECORDS, STRING_OPERATORS),
    field!("infobase_uuid", Uuid, ALL_RECORDS, EQUALITY_OPERATORS),
    field!("connection_string", Str, INFOBASE_ONLY, STRING_OPERATORS),
    field!("session", Uuid, SESSION_ONLY, EQUALITY_OPERATORS),
    field!("session_id", Int, SESSION_ONLY, ORDERED_OPERATORS),
    field!("connection", Uuid, SESSION_ONLY, EQUALITY_OPERATORS),
    field!("process", Uuid, SESSION_ONLY, EQUALITY_OPERATORS),
    field!("user_name", Str, SESSION_ONLY, STRING_OPERATORS),
    field!("host", Str, SESSION_ONLY, STRING_OPERATORS),
    field!("app_id", Str, SESSION_ONLY, STRING_OPERATORS),
    field!("locale", Str, SESSION_ONLY, STRING_OPERATORS),
    field!("started_at", DateTime, SESSION_ONLY, ORDERED_OPERATORS),
    field!("last_active_at", DateTime, SESSION_ONLY, ORDERED_OPERATORS),
    field!("hibernate", Bool, SESSION_ONLY, EQUALITY_OPERATORS),
    field!(
        "passive_session_hibernate_time",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Seconds
    ),
    field!(
        "hibernate_session_terminate_time",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Seconds
    ),
    field!("blocked_by_dbms", Int, SESSION_ONLY, ORDERED_OPERATORS),
    field!("blocked_by_ls", Int, SESSION_ONLY, ORDERED_OPERATORS),
    field!("bytes_all", Int, SESSION_ONLY, ORDERED_OPERATORS, Bytes),
    field!(
        "bytes_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Bytes
    ),
    field!("calls_all", Int, SESSION_ONLY, ORDERED_OPERATORS, Count),
    field!(
        "calls_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Count
    ),
    field!(
        "dbms_bytes_all",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Bytes
    ),
    field!(
        "dbms_bytes_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Bytes
    ),
    field!("db_proc_info", Str, SESSION_ONLY, STRING_OPERATORS),
    field!(
        "db_proc_took",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!("db_proc_took_at", DateTime, SESSION_ONLY, ORDERED_OPERATORS),
    field!(
        "duration_all",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "duration_all_dbms",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "duration_current",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "duration_current_dbms",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "duration_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "duration_last_5min_dbms",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "memory_current",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Bytes
    ),
    field!(
        "memory_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Bytes
    ),
    field!("memory_total", Int, SESSION_ONLY, ORDERED_OPERATORS, Bytes),
    field!("read_current", Int, SESSION_ONLY, ORDERED_OPERATORS, Bytes),
    field!(
        "read_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Bytes
    ),
    field!("read_total", Int, SESSION_ONLY, ORDERED_OPERATORS, Bytes),
    field!("write_current", Int, SESSION_ONLY, ORDERED_OPERATORS, Bytes),
    field!(
        "write_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Bytes
    ),
    field!("write_total", Int, SESSION_ONLY, ORDERED_OPERATORS, Bytes),
    field!(
        "duration_current_service",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "duration_last_5min_service",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "duration_all_service",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!("current_service_name", Str, SESSION_ONLY, STRING_OPERATORS),
    field!(
        "cpu_time_current",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "cpu_time_last_5min",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!(
        "cpu_time_total",
        Int,
        SESSION_ONLY,
        ORDERED_OPERATORS,
        Milliseconds
    ),
    field!("data_separation", Str, SESSION_ONLY, STRING_OPERATORS),
    field!("client_ip", Str, SESSION_ONLY, STRING_OPERATORS),
    field!("connection", Uuid, CONNECTION_ONLY, EQUALITY_OPERATORS),
    field!("conn_id", Int, CONNECTION_ONLY, ORDERED_OPERATORS),
    field!("host", Str, CONNECTION_ONLY, STRING_OPERATORS),
    field!("process", Uuid, CONNECTION_ONLY, EQUALITY_OPERATORS),
    field!("application", Str, CONNECTION_ONLY, STRING_OPERATORS),
    field!("connected_at", DateTime, CONNECTION_ONLY, ORDERED_OPERATORS),
    field!("session_number", Int, CONNECTION_ONLY, ORDERED_OPERATORS),
    field!("blocked_by_ls", Int, CONNECTION_ONLY, ORDERED_OPERATORS),
    field!("process", Uuid, PROCESS_ONLY, EQUALITY_OPERATORS),
    field!("server", Uuid, PROCESS_ONLY, EQUALITY_OPERATORS),
    field!("pid", Int, PROCESS_ONLY, ORDERED_OPERATORS),
    field!("started_at", DateTime, PROCESS_ONLY, ORDERED_OPERATORS),
];

const INFOBASE_DEFAULT_COLUMNS: &[&str] = &[
    "cluster",
    "cluster_name",
    "ras_address",
    "infobase",
    "infobase_uuid",
    "description",
];
const SESSION_DEFAULT_COLUMNS: &[&str] = &[
    "cluster",
    "infobase",
    "session_id",
    "user_name",
    "host",
    "app_id",
    "started_at",
    "last_active_at",
    "cpu_time_total",
    "memory_current",
];
const CONNECTION_DEFAULT_COLUMNS: &[&str] = &[
    "cluster",
    "infobase",
    "conn_id",
    "host",
    "application",
    "connected_at",
    "session_number",
    "process",
];
const PROCESS_DEFAULT_COLUMNS: &[&str] = &[
    "cluster",
    "ras_address",
    "pid",
    "started_at",
    "connections",
    "memory",
    "on",
    "running",
    "use",
];

const INFOBASE_DEFAULT_SORT: &[SortKey] = &[
    SortKey::new("cluster", SortDirection::Asc, FieldType::Str),
    SortKey::new("infobase", SortDirection::Asc, FieldType::Str),
    SortKey::new("infobase_uuid", SortDirection::Asc, FieldType::Uuid),
];
const SESSION_DEFAULT_SORT: &[SortKey] = &[
    SortKey::new("cluster", SortDirection::Asc, FieldType::Str),
    SortKey::new("infobase", SortDirection::Asc, FieldType::Str),
    SortKey::new("session_id", SortDirection::Asc, FieldType::Int),
];
const CONNECTION_DEFAULT_SORT: &[SortKey] = &[
    SortKey::new("cluster", SortDirection::Asc, FieldType::Str),
    SortKey::new("infobase", SortDirection::Asc, FieldType::Str),
    SortKey::new("conn_id", SortDirection::Asc, FieldType::Int),
];
const PROCESS_DEFAULT_SORT: &[SortKey] = &[
    SortKey::new("cluster", SortDirection::Asc, FieldType::Str),
    SortKey::new("pid", SortDirection::Asc, FieldType::Int),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct FieldRegistry;

impl FieldRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn definition(
        &self,
        kind: RecordKind,
        name: &str,
    ) -> Result<&'static FieldDefinition, DomainError> {
        if let Some(definition) = FIELD_DEFINITIONS
            .iter()
            .find(|definition| definition.name == name && definition.applies_to(kind))
        {
            return Ok(definition);
        }
        if FIELD_DEFINITIONS
            .iter()
            .any(|definition| definition.name == name)
        {
            return Err(DomainError::FieldNotApplicable {
                field: name.to_owned(),
                record_kind: kind.as_str(),
            });
        }
        Err(DomainError::UnknownField {
            field: name.to_owned(),
        })
    }

    #[must_use]
    pub fn definitions(&self, kind: RecordKind) -> Vec<&'static FieldDefinition> {
        FIELD_DEFINITIONS
            .iter()
            .filter(|definition| definition.applies_to(kind))
            .collect()
    }

    #[must_use]
    pub const fn default_columns(&self, kind: RecordKind) -> &'static [&'static str] {
        match kind {
            RecordKind::Infobase => INFOBASE_DEFAULT_COLUMNS,
            RecordKind::Session => SESSION_DEFAULT_COLUMNS,
            RecordKind::Connection => CONNECTION_DEFAULT_COLUMNS,
            RecordKind::Process => PROCESS_DEFAULT_COLUMNS,
        }
    }

    #[must_use]
    pub const fn default_sort(&self, kind: RecordKind) -> &'static [SortKey] {
        match kind {
            RecordKind::Infobase => INFOBASE_DEFAULT_SORT,
            RecordKind::Session => SESSION_DEFAULT_SORT,
            RecordKind::Connection => CONNECTION_DEFAULT_SORT,
            RecordKind::Process => PROCESS_DEFAULT_SORT,
        }
    }

    pub fn validate_operator(
        &self,
        kind: RecordKind,
        field: &str,
        operator: FilterOperator,
    ) -> Result<&'static FieldDefinition, DomainError> {
        let definition = self.definition(kind, field)?;
        if definition.allows(operator) {
            Ok(definition)
        } else {
            Err(DomainError::OperatorNotAllowed {
                field: field.to_owned(),
                operator: operator.as_str(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_rejects_alias_and_inapplicable_fields() {
        let registry = FieldRegistry::new();

        assert!(matches!(
            registry.definition(RecordKind::Session, "cpu_time"),
            Err(DomainError::UnknownField { .. })
        ));
        assert!(matches!(
            registry.definition(RecordKind::Connection, "cpu_time_total"),
            Err(DomainError::FieldNotApplicable { .. })
        ));
    }

    #[test]
    fn operators_follow_field_types() {
        let registry = FieldRegistry::new();

        assert!(
            registry
                .validate_operator(RecordKind::Session, "cpu_time_total", FilterOperator::Gt)
                .is_ok()
        );
        assert!(
            registry
                .validate_operator(RecordKind::Session, "user_name", FilterOperator::Like)
                .is_ok()
        );
        assert!(
            registry
                .validate_operator(RecordKind::Session, "user_name", FilterOperator::Gt)
                .is_err()
        );
        assert!(
            registry
                .validate_operator(RecordKind::Session, "session_id", FilterOperator::Like)
                .is_err()
        );
    }

    #[test]
    fn defaults_match_the_contract() {
        let registry = FieldRegistry::new();

        assert_eq!(
            registry.default_columns(RecordKind::Connection),
            CONNECTION_DEFAULT_COLUMNS
        );
        assert_eq!(
            registry
                .default_sort(RecordKind::Session)
                .iter()
                .map(|key| (key.field(), key.direction()))
                .collect::<Vec<_>>(),
            vec![
                ("cluster", SortDirection::Asc),
                ("infobase", SortDirection::Asc),
                ("session_id", SortDirection::Asc),
            ]
        );
    }

    #[test]
    fn all_numeric_metrics_have_explicit_units_where_units_are_meaningful() {
        let registry = FieldRegistry::new();

        assert_eq!(
            registry
                .definition(RecordKind::Session, "memory_current")
                .map(|field| field.unit),
            Ok(Some(FieldUnit::Bytes))
        );
        assert_eq!(
            registry
                .definition(RecordKind::Session, "cpu_time_total")
                .map(|field| field.unit),
            Ok(Some(FieldUnit::Milliseconds))
        );
        assert_eq!(
            registry
                .definition(RecordKind::Session, "calls_all")
                .map(|field| field.unit),
            Ok(Some(FieldUnit::Count))
        );
    }
}
