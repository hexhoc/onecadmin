use std::cmp::Ordering;
use std::num::NonZeroUsize;
use std::str::FromStr;

use chrono::DateTime;
use indexmap::IndexMap;
use uuid::Uuid;

use super::{
    DomainError, ExtraFields, FieldAccess, FieldRegistry, FieldType, FieldValue, FieldValueRef,
    FilterOperator, QueryOutcome, RecordKind, SortDirection, SortKey, SqlMask, TargetError,
};

#[derive(Clone, Debug)]
enum FilterOperand {
    Scalar(FieldValue),
    Mask(SqlMask),
}

#[derive(Clone, Debug)]
pub struct Filter {
    kind: RecordKind,
    field: &'static str,
    operator: FilterOperator,
    operand: FilterOperand,
}

impl Filter {
    pub fn parse(
        input: &str,
        kind: RecordKind,
        registry: &FieldRegistry,
    ) -> Result<Self, DomainError> {
        let mut parts = input.splitn(3, ':');
        let field = parts.next().unwrap_or_default();
        let operator = parts.next();
        let value = parts.next();
        let (Some(operator), Some(value)) = (operator, value) else {
            return Err(DomainError::InvalidFilterSyntax {
                input: input.to_owned(),
                reason: "ожидается формат field:operator:value",
            });
        };
        if field.is_empty() || operator.is_empty() {
            return Err(DomainError::InvalidFilterSyntax {
                input: input.to_owned(),
                reason: "поле и оператор не могут быть пустыми",
            });
        }
        let operator = FilterOperator::from_str(operator)?;
        let definition = registry.validate_operator(kind, field, operator)?;
        let operand = if operator == FilterOperator::Like {
            FilterOperand::Mask(SqlMask::parse(value)?)
        } else {
            FilterOperand::Scalar(parse_value(value, definition.field_type, definition.name)?)
        };
        Ok(Self {
            kind,
            field: definition.name,
            operator,
            operand,
        })
    }

    pub fn from_value(
        kind: RecordKind,
        field: &str,
        operator: FilterOperator,
        value: FieldValue,
        registry: &FieldRegistry,
    ) -> Result<Self, DomainError> {
        let definition = registry.validate_operator(kind, field, operator)?;
        if !value.is_null() && value.field_type() != Some(definition.field_type) {
            return Err(DomainError::InvalidFieldValue {
                field: field.to_owned(),
                expected: definition.field_type.as_str(),
            });
        }
        let operand = if operator == FilterOperator::Like {
            match value {
                FieldValue::Str(value) => FilterOperand::Mask(SqlMask::parse(&value)?),
                _ => {
                    return Err(DomainError::InvalidFieldValue {
                        field: field.to_owned(),
                        expected: FieldType::Str.as_str(),
                    });
                }
            }
        } else {
            FilterOperand::Scalar(value)
        };
        Ok(Self {
            kind,
            field: definition.name,
            operator,
            operand,
        })
    }

    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    #[must_use]
    pub const fn operator(&self) -> FilterOperator {
        self.operator
    }

    #[must_use]
    pub fn matches<R: FieldAccess>(&self, record: &R) -> bool {
        let Some(actual) = record.field(self.field) else {
            return false;
        };
        match (&self.operand, self.operator) {
            (FilterOperand::Mask(mask), FilterOperator::Like) => {
                matches!(actual, FieldValueRef::Str(value) if mask.matches(value))
            }
            (FilterOperand::Scalar(expected), FilterOperator::Eq) => {
                values_equal(actual, expected.as_ref())
            }
            (FilterOperand::Scalar(expected), FilterOperator::Ne) => {
                !values_equal(actual, expected.as_ref())
            }
            (FilterOperand::Scalar(expected), operator) => {
                compare_non_null(actual, expected.as_ref()).is_some_and(|ordering| match operator {
                    FilterOperator::Gt => ordering == Ordering::Greater,
                    FilterOperator::Ge => ordering != Ordering::Less,
                    FilterOperator::Lt => ordering == Ordering::Less,
                    FilterOperator::Le => ordering != Ordering::Greater,
                    FilterOperator::Eq | FilterOperator::Ne | FilterOperator::Like => false,
                })
            }
            (FilterOperand::Mask(_), _) => false,
        }
    }
}

fn parse_value(
    value: &str,
    field_type: FieldType,
    field: &'static str,
) -> Result<FieldValue, DomainError> {
    let invalid = || DomainError::InvalidFieldValue {
        field: field.to_owned(),
        expected: field_type.as_str(),
    };
    match field_type {
        FieldType::Uuid => Uuid::parse_str(value)
            .map(FieldValue::Uuid)
            .map_err(|_| invalid()),
        FieldType::Int => value
            .parse::<i64>()
            .map(FieldValue::Int)
            .map_err(|_| invalid()),
        FieldType::Bool => {
            if value.eq_ignore_ascii_case("true") {
                Ok(FieldValue::Bool(true))
            } else if value.eq_ignore_ascii_case("false") {
                Ok(FieldValue::Bool(false))
            } else {
                Err(invalid())
            }
        }
        FieldType::DateTime => DateTime::parse_from_rfc3339(value)
            .map(FieldValue::DateTime)
            .map_err(|_| invalid()),
        FieldType::Str => Ok(FieldValue::Str(value.to_owned())),
    }
}

fn values_equal(left: FieldValueRef<'_>, right: FieldValueRef<'_>) -> bool {
    match (left, right) {
        (FieldValueRef::Uuid(left), FieldValueRef::Uuid(right)) => left == right,
        (FieldValueRef::Int(left), FieldValueRef::Int(right)) => left == right,
        (FieldValueRef::Bool(left), FieldValueRef::Bool(right)) => left == right,
        (FieldValueRef::DateTime(left), FieldValueRef::DateTime(right)) => left == right,
        (FieldValueRef::Str(left), FieldValueRef::Str(right)) => {
            left.to_lowercase() == right.to_lowercase()
        }
        (FieldValueRef::Null, FieldValueRef::Null) => true,
        _ => false,
    }
}

fn compare_non_null(left: FieldValueRef<'_>, right: FieldValueRef<'_>) -> Option<Ordering> {
    match (left, right) {
        (FieldValueRef::Uuid(left), FieldValueRef::Uuid(right)) => Some(left.cmp(right)),
        (FieldValueRef::Int(left), FieldValueRef::Int(right)) => Some(left.cmp(&right)),
        (FieldValueRef::Bool(left), FieldValueRef::Bool(right)) => Some(left.cmp(&right)),
        (FieldValueRef::DateTime(left), FieldValueRef::DateTime(right)) => Some(left.cmp(right)),
        (FieldValueRef::Str(left), FieldValueRef::Str(right)) => {
            Some(left.to_lowercase().cmp(&right.to_lowercase()))
        }
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct TextQuery {
    mask: SqlMask,
    fields: Vec<&'static str>,
}

impl TextQuery {
    pub fn for_kind(
        kind: RecordKind,
        input: &str,
        registry: &FieldRegistry,
    ) -> Result<Self, DomainError> {
        let fields: &[&str] = match kind {
            RecordKind::Infobase => &["infobase"],
            RecordKind::Session => &["user_name", "host"],
            RecordKind::Connection => &["host", "application"],
            RecordKind::Process => &[],
        };
        Self::new(kind, input, fields.iter().copied(), registry)
    }

    pub fn new<'a>(
        kind: RecordKind,
        input: &str,
        fields: impl IntoIterator<Item = &'a str>,
        registry: &FieldRegistry,
    ) -> Result<Self, DomainError> {
        let mut validated = Vec::new();
        for field in fields {
            let definition = registry.definition(kind, field)?;
            if definition.field_type != FieldType::Str {
                return Err(DomainError::InvalidFieldValue {
                    field: field.to_owned(),
                    expected: FieldType::Str.as_str(),
                });
            }
            if !validated.contains(&definition.name) {
                validated.push(definition.name);
            }
        }
        if validated.is_empty() {
            return Err(DomainError::InvalidProjection {
                input: String::new(),
                reason: "для текстового запроса требуется хотя бы одно строковое поле",
            });
        }
        Ok(Self {
            mask: SqlMask::parse(input)?,
            fields: validated,
        })
    }

    #[must_use]
    pub fn matches<R: FieldAccess>(&self, record: &R) -> bool {
        self.fields.iter().any(|field| {
            matches!(record.field(field), Some(FieldValueRef::Str(value)) if self.mask.matches(value))
        })
    }

    #[must_use]
    pub fn fields(&self) -> &[&'static str] {
        &self.fields
    }

    #[must_use]
    pub const fn mask(&self) -> &SqlMask {
        &self.mask
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Top(NonZeroUsize);

impl Top {
    pub fn new(value: usize) -> Result<Self, DomainError> {
        NonZeroUsize::new(value)
            .map(Self)
            .ok_or_else(|| DomainError::InvalidTop {
                value: value.to_string(),
            })
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl FromStr for Top {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DomainError::InvalidTop {
                value: value.to_owned(),
            });
        }
        value
            .parse::<usize>()
            .ok()
            .and_then(NonZeroUsize::new)
            .map(Self)
            .ok_or_else(|| DomainError::InvalidTop {
                value: value.to_owned(),
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Projection {
    columns: Vec<&'static str>,
    all: bool,
}

impl Projection {
    pub fn parse(
        input: Option<&str>,
        kind: RecordKind,
        registry: &FieldRegistry,
    ) -> Result<Self, DomainError> {
        let Some(input) = input else {
            return Ok(Self {
                columns: registry.default_columns(kind).to_vec(),
                all: false,
            });
        };
        if input == "*" {
            let mut columns = Vec::new();
            for definition in registry.definitions(kind) {
                if !columns.contains(&definition.name) {
                    columns.push(definition.name);
                }
            }
            return Ok(Self { columns, all: true });
        }
        if input.is_empty() {
            return Err(DomainError::InvalidProjection {
                input: input.to_owned(),
                reason: "список колонок не может быть пустым",
            });
        }
        let mut columns = Vec::new();
        for raw_column in input.split(',') {
            let column = raw_column.trim();
            if column.is_empty() || column == "*" {
                return Err(DomainError::InvalidProjection {
                    input: input.to_owned(),
                    reason: "`*` разрешена только как единственное значение",
                });
            }
            let definition = registry.definition(kind, column)?;
            if columns.contains(&definition.name) {
                return Err(DomainError::InvalidProjection {
                    input: input.to_owned(),
                    reason: "колонки не должны повторяться",
                });
            }
            columns.push(definition.name);
        }
        Ok(Self {
            columns,
            all: false,
        })
    }

    #[must_use]
    pub fn columns(&self) -> &[&'static str] {
        &self.columns
    }

    #[must_use]
    pub const fn is_all(&self) -> bool {
        self.all
    }

    #[must_use]
    pub fn project<R: FieldAccess>(&self, record: &R) -> ExtraFields {
        let mut projected = IndexMap::new();
        for column in &self.columns {
            projected.insert(
                (*column).to_owned(),
                record.field_owned(column).unwrap_or(FieldValue::Null),
            );
        }
        if self.all {
            for (name, value) in record.extra_fields() {
                if !projected.contains_key(name) {
                    projected.insert(name.clone(), value.clone());
                }
            }
        }
        projected
    }

    #[must_use]
    pub fn resolved_columns<R: FieldAccess>(&self, records: &[R]) -> Vec<String> {
        let mut columns = self
            .columns
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<Vec<_>>();
        if self.all {
            for record in records {
                for name in record.extra_fields().keys() {
                    if !columns.contains(name) {
                        columns.push(name.clone());
                    }
                }
            }
        }
        columns
    }
}

#[derive(Clone, Debug)]
pub struct QuerySpec {
    kind: RecordKind,
    filters: Vec<Filter>,
    text_query: Option<TextQuery>,
    sort: Vec<SortKey>,
    top: Option<Top>,
    projection: Projection,
}

impl QuerySpec {
    pub fn parse<'a, 'b>(
        kind: RecordKind,
        filters: impl IntoIterator<Item = &'a str>,
        query: Option<&str>,
        sort: impl IntoIterator<Item = &'b str>,
        top: Option<&str>,
        columns: Option<&str>,
        registry: &FieldRegistry,
    ) -> Result<Self, DomainError> {
        let filters = filters
            .into_iter()
            .map(|input| Filter::parse(input, kind, registry))
            .collect::<Result<Vec<_>, _>>()?;
        let text_query = query
            .map(|input| TextQuery::for_kind(kind, input, registry))
            .transpose()?;
        let mut parsed_sort = sort
            .into_iter()
            .map(|input| SortKey::parse(input, kind, registry))
            .collect::<Result<Vec<_>, _>>()?;
        if parsed_sort.is_empty() {
            parsed_sort.extend_from_slice(registry.default_sort(kind));
        }
        let top = top.map(Top::from_str).transpose()?;
        let projection = Projection::parse(columns, kind, registry)?;
        Ok(Self {
            kind,
            filters,
            text_query,
            sort: parsed_sort,
            top,
            projection,
        })
    }

    pub fn new(kind: RecordKind, registry: &FieldRegistry) -> Result<Self, DomainError> {
        Self::parse(
            kind,
            std::iter::empty::<&str>(),
            None,
            std::iter::empty::<&str>(),
            None,
            None,
            registry,
        )
    }

    pub fn push_filter(&mut self, filter: Filter) -> Result<(), DomainError> {
        if filter.kind != self.kind {
            return Err(DomainError::FieldNotApplicable {
                field: filter.field.to_owned(),
                record_kind: self.kind.as_str(),
            });
        }
        self.filters.push(filter);
        Ok(())
    }

    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    #[must_use]
    pub fn filters(&self) -> &[Filter] {
        &self.filters
    }

    #[must_use]
    pub const fn text_query(&self) -> Option<&TextQuery> {
        self.text_query.as_ref()
    }

    #[must_use]
    pub fn sort(&self) -> &[SortKey] {
        &self.sort
    }

    #[must_use]
    pub const fn top(&self) -> Option<Top> {
        self.top
    }

    #[must_use]
    pub const fn projection(&self) -> &Projection {
        &self.projection
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct QueryEngine;

impl QueryEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn execute<R: FieldAccess>(
        &self,
        mut records: Vec<R>,
        errors: Vec<TargetError>,
        successful_targets: usize,
        spec: &QuerySpec,
    ) -> Result<QueryOutcome<R>, DomainError> {
        if let Some(record) = records
            .iter()
            .find(|record| record.record_kind() != spec.kind)
        {
            return Err(DomainError::RecordKindMismatch {
                expected: spec.kind.as_str(),
                actual: record.record_kind().as_str(),
            });
        }
        records.retain(|record| {
            spec.filters.iter().all(|filter| filter.matches(record))
                && spec
                    .text_query
                    .as_ref()
                    .is_none_or(|query| query.matches(record))
        });
        let matched = records.len();
        records.sort_by(|left, right| compare_records(left, right, &spec.sort));
        if let Some(top) = spec.top {
            records.truncate(top.get());
        }
        Ok(QueryOutcome::new(
            records,
            errors,
            matched,
            successful_targets,
        ))
    }
}

fn compare_records<R: FieldAccess>(left: &R, right: &R, sort: &[SortKey]) -> Ordering {
    for key in sort {
        let ordering = compare_sort_field(left, right, *key);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn compare_sort_field<R: FieldAccess>(left: &R, right: &R, key: SortKey) -> Ordering {
    let left = typed_sort_value(left.field(key.field()), key.field_type());
    let right = typed_sort_value(right.field(key.field()), key.field_type());
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => {
            let ordering = compare_non_null(left, right).unwrap_or(Ordering::Equal);
            match key.direction() {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            }
        }
    }
}

fn typed_sort_value(
    value: Option<FieldValueRef<'_>>,
    expected: FieldType,
) -> Option<FieldValueRef<'_>> {
    value.filter(|value| value.field_type() == Some(expected))
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    use proptest::prelude::*;
    use uuid::Uuid;

    use super::super::{ClusterAlias, ClusterSource, ClusterUuid, SessionRecord, SessionUuid};
    use super::*;

    fn source(alias: &str) -> ClusterSource {
        ClusterSource::new(
            ClusterAlias::new(alias).unwrap_or_else(|error| panic!("{error}")),
            ClusterUuid::new(Uuid::from_u128(1)),
            "cluster",
            "ras.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        )
    }

    fn session(id: u128, cpu: Option<i64>, user: &str, host: &str) -> SessionRecord {
        let mut record = SessionRecord::new(source("dev"), SessionUuid::new(Uuid::from_u128(id)));
        record.infobase = Some("Accounting".to_owned());
        record.cpu_time_total = cpu;
        record.user_name = Some(user.to_owned());
        record.host = Some(host.to_owned());
        record
    }

    #[test]
    fn filter_splits_only_first_two_colons() {
        let registry = FieldRegistry::new();
        let filter = Filter::parse(
            "user_name:eq:DOMAIN\\user:role",
            RecordKind::Session,
            &registry,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let record = session(1, Some(1), "domain\\USER:ROLE", "host");

        assert!(filter.matches(&record));
    }

    #[test]
    fn typed_filter_validation_happens_during_parse() {
        let registry = FieldRegistry::new();

        assert!(
            Filter::parse(
                "cpu_time_total:gt:not-a-number",
                RecordKind::Session,
                &registry
            )
            .is_err()
        );
        assert!(Filter::parse("user_name:gt:a", RecordKind::Session, &registry).is_err());
        assert!(Filter::parse("cpu_time:eq:1", RecordKind::Session, &registry).is_err());
        assert!(Filter::parse("started_at:gt:not-a-date", RecordKind::Session, &registry).is_err());
    }

    #[test]
    fn repeated_filters_are_and_and_text_query_fields_are_or() {
        let registry = FieldRegistry::new();
        let spec = QuerySpec::parse(
            RecordKind::Session,
            ["cpu_time_total:ge:10", "user_name:like:admin%"],
            Some("PC-%"),
            ["session_id:asc"],
            None,
            None,
            &registry,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let records = vec![
            session(1, Some(20), "Administrator", "PC-01"),
            session(2, Some(5), "Administrator", "PC-02"),
            session(3, Some(20), "User", "PC-03"),
        ];
        let outcome = QueryEngine::new()
            .execute(records, Vec::new(), 1, &spec)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(outcome.meta.matched, 1);
        assert_eq!(
            outcome.data[0].session,
            SessionUuid::new(Uuid::from_u128(1))
        );
    }

    #[test]
    fn sort_is_typed_stable_and_null_is_always_last() {
        let registry = FieldRegistry::new();
        let spec = QuerySpec::parse(
            RecordKind::Session,
            std::iter::empty::<&str>(),
            None,
            ["cpu_time_total:desc", "user_name:asc"],
            None,
            None,
            &registry,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let records = vec![
            session(1, None, "z", "host"),
            session(2, Some(10), "b", "host"),
            session(3, Some(100), "a", "host"),
            session(4, Some(10), "A", "host"),
            session(5, None, "a", "host"),
        ];
        let outcome = QueryEngine::new()
            .execute(records, Vec::new(), 1, &spec)
            .unwrap_or_else(|error| panic!("{error}"));
        let ids = outcome
            .data
            .iter()
            .map(|record| record.session.into_uuid().as_u128())
            .collect::<Vec<_>>();

        assert_eq!(ids, vec![3, 4, 2, 5, 1]);
    }

    #[test]
    fn top_is_applied_after_global_sort() {
        let registry = FieldRegistry::new();
        let spec = QuerySpec::parse(
            RecordKind::Session,
            std::iter::empty::<&str>(),
            None,
            ["cpu_time_total:desc"],
            Some("2"),
            Some("cluster,cpu_time_total"),
            &registry,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let records = vec![
            session(1, Some(1), "a", "host"),
            session(2, Some(100), "b", "host"),
            session(3, Some(50), "c", "host"),
        ];
        let outcome = QueryEngine::new()
            .execute(records, Vec::new(), 2, &spec)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(outcome.meta.matched, 3);
        assert_eq!(outcome.meta.returned, 2);
        assert_eq!(outcome.data[0].cpu_time_total, Some(100));
        assert_eq!(outcome.data[1].cpu_time_total, Some(50));
    }

    #[test]
    fn datetime_comparisons_are_typed() {
        let registry = FieldRegistry::new();
        let filter = Filter::parse(
            "started_at:ge:2026-08-11T10:00:00+03:00",
            RecordKind::Session,
            &registry,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let mut record = session(1, Some(1), "user", "host");
        record.started_at = DateTime::parse_from_rfc3339("2026-08-11T07:00:00Z").ok();

        assert!(filter.matches(&record));
    }

    #[test]
    fn star_projection_includes_canonical_and_unknown_fields() {
        let registry = FieldRegistry::new();
        let projection = Projection::parse(Some("*"), RecordKind::Session, &registry)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut record = session(1, Some(1), "user", "host");
        record
            .extra
            .insert("future_metric".to_owned(), FieldValue::Int(42));
        let row = projection.project(&record);

        assert!(row.contains_key("session_id"));
        assert_eq!(row.get("future_metric"), Some(&FieldValue::Int(42)));
    }

    #[test]
    fn top_and_projection_reject_invalid_values() {
        let registry = FieldRegistry::new();

        assert!("0".parse::<Top>().is_err());
        assert!("-1".parse::<Top>().is_err());
        assert!(Projection::parse(Some("cpu_time"), RecordKind::Session, &registry).is_err());
        assert!(Projection::parse(Some("cluster,*"), RecordKind::Session, &registry).is_err());
    }

    proptest! {
        #[test]
        fn integer_sort_matches_native_order(values in prop::collection::vec(any::<i64>(), 0..100)) {
            let registry = FieldRegistry::new();
            let spec = QuerySpec::parse(
                RecordKind::Session,
                std::iter::empty::<&str>(),
                None,
                ["cpu_time_total:asc"],
                None,
                None,
                &registry,
            );
            prop_assert!(spec.is_ok());
            if let Ok(spec) = spec {
                let records = values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| session(index as u128 + 1, Some(*value), "user", "host"))
                    .collect::<Vec<_>>();
                let outcome = QueryEngine::new().execute(records, Vec::new(), 1, &spec);
                prop_assert!(outcome.is_ok());
                if let Ok(outcome) = outcome {
                    let actual = outcome
                        .data
                        .iter()
                        .filter_map(|record| record.cpu_time_total)
                        .collect::<Vec<_>>();
                    let mut expected = values;
                    expected.sort();
                    prop_assert_eq!(actual, expected);
                }
            }
        }
    }
}
