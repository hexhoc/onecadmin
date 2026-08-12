use std::io::{self, Write};

use chrono::{Local, SecondsFormat};
use comfy_table::{ContentArrangement, Table, presets};
use indexmap::IndexMap;
use serde::Serialize;
use thiserror::Error;

use super::OutputFormat;
use crate::domain::{
    FieldAccess, FieldRegistry, FieldUnit, FieldValue, Projection, QueryMeta, QueryOutcome,
    RecordKind, TargetError,
};

pub type ProjectedRow = IndexMap<String, FieldValue>;

/// Stable JSON envelope used by every record-producing CLI command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputEnvelope<T> {
    pub data: Vec<T>,
    pub errors: Vec<TargetError>,
    pub meta: QueryMeta,
}

impl<T> OutputEnvelope<T> {
    #[must_use]
    pub fn new(data: Vec<T>, errors: Vec<TargetError>, meta: QueryMeta) -> Self {
        Self { data, errors, meta }
    }
}

/// Bytes destined for the process streams. No renderer writes directly to stdout.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RenderedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl RenderedOutput {
    pub fn write_to<W, E>(&self, stdout: &mut W, stderr: &mut E) -> Result<(), OutputError>
    where
        W: Write,
        E: Write,
    {
        stdout.write_all(&self.stdout)?;
        stderr.write_all(&self.stderr)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("Не удалось сериализовать JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Не удалось сформировать CSV: {0}")]
    Csv(#[from] csv::Error),
    #[error("Не удалось записать вывод: {0}")]
    Io(#[from] io::Error),
}

/// Projects domain records and renders one consistent column set in all formats.
#[derive(Clone, Copy, Debug)]
pub struct OutputRenderer {
    format: OutputFormat,
    no_color: bool,
    terminal_width: Option<u16>,
    registry: FieldRegistry,
}

impl OutputRenderer {
    #[must_use]
    pub const fn new(format: OutputFormat, no_color: bool) -> Self {
        Self {
            format,
            no_color,
            terminal_width: None,
            registry: FieldRegistry::new(),
        }
    }

    /// Overrides terminal detection, primarily for deterministic tests and embedding.
    #[must_use]
    pub const fn with_terminal_width(mut self, width: u16) -> Self {
        self.terminal_width = Some(width);
        self
    }

    #[must_use]
    pub const fn format(&self) -> OutputFormat {
        self.format
    }

    #[must_use]
    pub const fn no_color(&self) -> bool {
        self.no_color
    }

    pub fn render<R: FieldAccess>(
        &self,
        kind: RecordKind,
        outcome: &QueryOutcome<R>,
        projection: &Projection,
    ) -> Result<RenderedOutput, OutputError> {
        let (columns, rows) = project_rows(&outcome.data, projection);
        let width = self.effective_width();
        let stdout = match self.format {
            OutputFormat::Json => render_json(OutputEnvelope::new(
                rows.clone(),
                outcome.errors.clone(),
                outcome.meta,
            ))?,
            OutputFormat::Csv => render_csv(&columns, &rows)?,
            OutputFormat::Table => render_table(&columns, &rows, kind, &self.registry, width),
        };
        let stderr = render_errors_for_stderr(&outcome.errors, self.format, Some(width))?;
        Ok(RenderedOutput { stdout, stderr })
    }

    fn effective_width(&self) -> u16 {
        self.terminal_width
            .or_else(|| crossterm::terminal::size().ok().map(|(width, _)| width))
            .unwrap_or(120)
            .max(20)
    }
}

/// Renders per-target failures for the caller to write to stderr.
///
/// JSON embeds these failures in `OutputEnvelope`, so its stderr payload is empty.
pub fn render_errors_for_stderr(
    errors: &[TargetError],
    format: OutputFormat,
    terminal_width: Option<u16>,
) -> Result<Vec<u8>, OutputError> {
    if errors.is_empty() || format == OutputFormat::Json {
        return Ok(Vec::new());
    }
    let columns = ["cluster", "ras_address", "code", "message"];
    let rows = errors
        .iter()
        .map(|error| {
            [
                error.cluster.to_string(),
                error.ras_address.to_string(),
                error.code().to_owned(),
                error.message.clone(),
            ]
        })
        .collect::<Vec<_>>();
    match format {
        OutputFormat::Csv => render_string_csv(&columns, &rows),
        OutputFormat::Table => Ok(render_string_table(
            &columns,
            &rows,
            terminal_width.unwrap_or(120).max(20),
        )),
        OutputFormat::Json => Ok(Vec::new()),
    }
}

fn project_rows<R: FieldAccess>(
    records: &[R],
    projection: &Projection,
) -> (Vec<String>, Vec<ProjectedRow>) {
    let columns = projection.resolved_columns(records);
    let rows = records
        .iter()
        .map(|record| {
            let projected = projection.project(record);
            columns
                .iter()
                .map(|column| {
                    (
                        column.clone(),
                        projected.get(column).cloned().unwrap_or(FieldValue::Null),
                    )
                })
                .collect()
        })
        .collect();
    (columns, rows)
}

fn render_json(envelope: OutputEnvelope<ProjectedRow>) -> Result<Vec<u8>, OutputError> {
    let mut bytes = serde_json::to_vec_pretty(&envelope)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn render_csv(columns: &[String], rows: &[ProjectedRow]) -> Result<Vec<u8>, OutputError> {
    let mut output = Vec::new();
    {
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::CRLF)
            .from_writer(&mut output);
        writer.write_record(columns)?;
        for row in rows {
            let values = columns
                .iter()
                .map(|column| row.get(column).map_or_else(String::new, machine_value))
                .collect::<Vec<_>>();
            writer.write_record(values)?;
        }
        writer.flush()?;
    }
    Ok(output)
}

fn render_string_csv<const N: usize>(
    columns: &[&str; N],
    rows: &[[String; N]],
) -> Result<Vec<u8>, OutputError> {
    let mut output = Vec::new();
    {
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::CRLF)
            .from_writer(&mut output);
        writer.write_record(columns)?;
        for row in rows {
            writer.write_record(row)?;
        }
        writer.flush()?;
    }
    Ok(output)
}

fn render_table(
    columns: &[String],
    rows: &[ProjectedRow],
    kind: RecordKind,
    registry: &FieldRegistry,
    width: u16,
) -> Vec<u8> {
    let rendered_rows = rows
        .iter()
        .map(|row| {
            columns
                .iter()
                .map(|column| {
                    let definition = registry.definition(kind, column).ok();
                    row.get(column)
                        .map_or_else(String::new, |value| table_value(value, definition))
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let headers = columns.iter().map(String::as_str).collect::<Vec<_>>();
    render_string_table(&headers, &rendered_rows, width)
}

fn render_string_table<H, R, S>(headers: &[H], rows: &[R], width: u16) -> Vec<u8>
where
    H: AsRef<str>,
    R: AsRef<[S]>,
    S: AsRef<str>,
{
    let mut table = Table::new();
    table.load_preset(presets::UTF8_FULL_CONDENSED);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_width(width.max(20));
    table.set_header(headers.iter().map(AsRef::as_ref));
    for row in rows {
        table.add_row(row.as_ref().iter().map(AsRef::as_ref));
    }
    let mut output = table.to_string().into_bytes();
    output.push(b'\n');
    output
}

fn machine_value(value: &FieldValue) -> String {
    match value {
        FieldValue::Uuid(value) => value.hyphenated().to_string(),
        FieldValue::Int(value) => value.to_string(),
        FieldValue::Bool(value) => value.to_string(),
        FieldValue::DateTime(value) => value.to_rfc3339_opts(SecondsFormat::AutoSi, false),
        FieldValue::Str(value) => value.clone(),
        FieldValue::Null => String::new(),
    }
}

fn table_value(value: &FieldValue, definition: Option<&crate::domain::FieldDefinition>) -> String {
    match value {
        FieldValue::DateTime(value) => value
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S %:z")
            .to_string(),
        FieldValue::Int(value) => match definition.and_then(|field| field.unit) {
            Some(FieldUnit::Bytes) => format_bytes(*value),
            Some(FieldUnit::Milliseconds) => format_milliseconds(*value),
            Some(FieldUnit::Microseconds) => format_microseconds(*value),
            Some(FieldUnit::Seconds) => format_seconds(*value),
            Some(FieldUnit::Count) | None => value.to_string(),
        },
        _ => machine_value(value),
    }
}

fn format_bytes(value: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut scaled = value.unsigned_abs() as f64;
    let mut unit = 0;
    while scaled >= 1024.0 && unit + 1 < UNITS.len() {
        scaled /= 1024.0;
        unit += 1;
    }
    if value.is_negative() {
        scaled = -scaled;
    }
    if unit == 0 {
        format!("{value} {}", UNITS[unit])
    } else {
        format!("{scaled:.1} {}", UNITS[unit])
    }
}

fn format_microseconds(value: i64) -> String {
    let absolute = value.unsigned_abs();
    if absolute < 1_000 {
        format!("{value} us")
    } else if absolute < 1_000_000 {
        format!("{:.1} ms", value as f64 / 1_000.0)
    } else {
        format_seconds_f64(value as f64 / 1_000_000.0)
    }
}

fn format_milliseconds(value: i64) -> String {
    if value.unsigned_abs() < 1_000 {
        format!("{value} ms")
    } else {
        format_seconds_f64(value as f64 / 1_000.0)
    }
}

fn format_seconds(value: i64) -> String {
    format_seconds_f64(value as f64)
}

fn format_seconds_f64(seconds: f64) -> String {
    let absolute = seconds.abs();
    if absolute < 60.0 {
        format!("{seconds:.2} s")
    } else if absolute < 3_600.0 {
        format!("{:.1} min", seconds / 60.0)
    } else {
        format!("{:.1} h", seconds / 3_600.0)
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    use serde_json::Value;
    use uuid::Uuid;

    use super::*;
    use crate::domain::{
        ClusterAlias, ClusterSource, ClusterUuid, SessionRecord, SessionUuid, TargetErrorKind,
    };

    fn session() -> SessionRecord {
        let source = ClusterSource::new(
            ClusterAlias::new("dev").unwrap_or_else(|error| panic!("{error}")),
            ClusterUuid::new(Uuid::from_u128(1)),
            "Разработка",
            "ras.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut record = SessionRecord::new(
            source,
            SessionUuid::new(
                Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
                    .unwrap_or_else(|error| panic!("{error}")),
            ),
        );
        record.infobase = Some("Бухгалтерия, основная".to_owned());
        record.user_name = Some("DOMAIN\\Иванов".to_owned());
        record.cpu_time_total = Some(1_500_000);
        record.memory_current = Some(1_536);
        record.started_at = DateTime::parse_from_rfc3339("2026-08-11T10:20:30+03:00").ok();
        record
    }

    fn outcome(errors: Vec<TargetError>) -> QueryOutcome<SessionRecord> {
        QueryOutcome::new(vec![session()], errors, 1, 1)
    }

    fn projection(columns: &str) -> Projection {
        Projection::parse(Some(columns), RecordKind::Session, &FieldRegistry::new())
            .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn json_uses_envelope_selected_columns_typed_values_and_utf8() {
        let output = OutputRenderer::new(OutputFormat::Json, true)
            .render(
                RecordKind::Session,
                &outcome(Vec::new()),
                &projection("cluster,session,user_name,cpu_time_total,started_at"),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let json: Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(json["data"][0]["cluster"], "dev");
        assert_eq!(
            json["data"][0]["session"],
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        assert_eq!(json["data"][0]["cpu_time_total"], 1_500_000);
        assert_eq!(json["data"][0]["started_at"], "2026-08-11T10:20:30+03:00");
        assert_eq!(json["meta"]["matched"], 1);
        assert_eq!(json["errors"], Value::Array(Vec::new()));
        assert!(String::from_utf8_lossy(&output.stdout).contains("Иванов"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("\\u0418"));
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn csv_is_rfc4180_crlf_and_uses_exact_projection_order() {
        let output = OutputRenderer::new(OutputFormat::Csv, true)
            .render(
                RecordKind::Session,
                &outcome(Vec::new()),
                &projection("infobase,session,cpu_time_total,started_at"),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let csv = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));

        assert!(csv.starts_with("infobase,session,cpu_time_total,started_at\r\n"));
        assert!(csv.contains("\"Бухгалтерия, основная\""));
        assert!(csv.contains("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        assert!(csv.contains(",1500000,2026-08-11T10:20:30+03:00\r\n"));
        assert!(!csv.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn table_formats_units_for_humans_without_changing_machine_formats() {
        let output = OutputRenderer::new(OutputFormat::Table, true)
            .with_terminal_width(160)
            .render(
                RecordKind::Session,
                &outcome(Vec::new()),
                &projection("cpu_time_total,memory_current"),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let table = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));

        assert!(table.contains("25.0 min"));
        assert!(table.contains("1.5 KiB"));
    }

    #[test]
    fn table_and_csv_errors_are_separate_stderr_payloads() {
        let error = TargetError::new(
            ClusterAlias::new("prod").unwrap_or_else(|error| panic!("{error}")),
            "prod.local:1545"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            TargetErrorKind::Timeout,
            "Истек тайм-аут",
        );
        let output = OutputRenderer::new(OutputFormat::Csv, true)
            .render(
                RecordKind::Session,
                &outcome(vec![error]),
                &projection("cluster,session_id"),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let stderr = String::from_utf8(output.stderr).unwrap_or_else(|error| panic!("{error}"));

        assert!(stderr.starts_with("cluster,ras_address,code,message\r\n"));
        assert!(stderr.contains("prod,prod.local:1545,timeout,Истек тайм-аут\r\n"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Истек тайм-аут"));
    }

    #[test]
    fn all_formats_use_the_same_requested_columns() {
        let projection = projection("user_name,cluster");
        let outcome = outcome(Vec::new());
        let json = OutputRenderer::new(OutputFormat::Json, true)
            .render(RecordKind::Session, &outcome, &projection)
            .unwrap_or_else(|error| panic!("{error}"));
        let csv = OutputRenderer::new(OutputFormat::Csv, true)
            .render(RecordKind::Session, &outcome, &projection)
            .unwrap_or_else(|error| panic!("{error}"));

        let parsed: Value =
            serde_json::from_slice(&json.stdout).unwrap_or_else(|error| panic!("{error}"));
        let keys = parsed["data"][0]
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        assert_eq!(keys, ["user_name", "cluster"]);
        assert!(String::from_utf8_lossy(&csv.stdout).starts_with("user_name,cluster\r\n"));
    }
}
