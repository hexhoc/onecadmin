use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    #[error("Некорректный alias кластера `{value}`: {reason}")]
    InvalidClusterAlias { value: String, reason: &'static str },

    #[error("Некорректный адрес RAS `{value}`: {reason}")]
    InvalidRasEndpoint { value: String, reason: &'static str },

    #[error("Некорректная версия платформы `{value}`: ожидаются четыре числовых компонента")]
    InvalidPlatformVersion { value: String },

    #[error("Некорректный {entity} UUID `{value}`")]
    InvalidUuid { entity: &'static str, value: String },

    #[error("Некорректная конфигурация аутентификации: {reason}")]
    InvalidAuth { reason: &'static str },

    #[error("Некорректное переопределение credentials: {reason}")]
    InvalidAuthOverride { reason: &'static str },

    #[error("Некорректная маска в позиции {position}: {reason}")]
    InvalidMask { position: usize, reason: String },

    #[error("Некорректный фильтр `{input}`: {reason}")]
    InvalidFilterSyntax { input: String, reason: &'static str },

    #[error("Неизвестный оператор фильтра `{operator}`")]
    UnknownFilterOperator { operator: String },

    #[error("Неизвестное каноническое поле `{field}`")]
    UnknownField { field: String },

    #[error("Поле `{field}` неприменимо к записям типа `{record_kind}`")]
    FieldNotApplicable {
        field: String,
        record_kind: &'static str,
    },

    #[error("Оператор `{operator}` недоступен для поля `{field}`")]
    OperatorNotAllowed {
        field: String,
        operator: &'static str,
    },

    #[error("Некорректное значение поля `{field}`: ожидается {expected}")]
    InvalidFieldValue {
        field: String,
        expected: &'static str,
    },

    #[error("Некорректная сортировка `{input}`: {reason}")]
    InvalidSortSyntax { input: String, reason: &'static str },

    #[error("Поле `{field}` не поддерживает сортировку")]
    FieldNotSortable { field: String },

    #[error("Некорректное значение top `{value}`: ожидается положительное целое число")]
    InvalidTop { value: String },

    #[error("Некорректная проекция колонок `{input}`: {reason}")]
    InvalidProjection { input: String, reason: &'static str },

    #[error("Запрос типа `{expected}` получил запись типа `{actual}`")]
    RecordKindMismatch {
        expected: &'static str,
        actual: &'static str,
    },

    #[error("План разрушительной операции не может быть пустым")]
    EmptyKillPlan,

    #[error("Снимок содержит повторяющуюся цель разрушительной операции")]
    DuplicateKillTarget,

    #[error("В записи отсутствует обязательный идентификатор для разрушительной операции: {field}")]
    MissingKillIdentity { field: &'static str },
}

impl DomainError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidClusterAlias { .. } => "invalid_cluster_alias",
            Self::InvalidRasEndpoint { .. } => "invalid_ras_endpoint",
            Self::InvalidPlatformVersion { .. } => "invalid_platform_version",
            Self::InvalidUuid { .. } => "invalid_uuid",
            Self::InvalidAuth { .. } => "invalid_auth",
            Self::InvalidAuthOverride { .. } => "invalid_auth_override",
            Self::InvalidMask { .. } => "invalid_mask",
            Self::InvalidFilterSyntax { .. } => "invalid_filter",
            Self::UnknownFilterOperator { .. } => "unknown_filter_operator",
            Self::UnknownField { .. } => "unknown_field",
            Self::FieldNotApplicable { .. } => "field_not_applicable",
            Self::OperatorNotAllowed { .. } => "operator_not_allowed",
            Self::InvalidFieldValue { .. } => "invalid_field_value",
            Self::InvalidSortSyntax { .. } => "invalid_sort",
            Self::FieldNotSortable { .. } => "field_not_sortable",
            Self::InvalidTop { .. } => "invalid_top",
            Self::InvalidProjection { .. } => "invalid_projection",
            Self::RecordKindMismatch { .. } => "record_kind_mismatch",
            Self::EmptyKillPlan => "empty_kill_plan",
            Self::DuplicateKillTarget => "duplicate_kill_target",
            Self::MissingKillIdentity { .. } => "missing_kill_identity",
        }
    }
}
