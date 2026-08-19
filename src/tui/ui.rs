use chrono::Local;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Table, TableState, Tabs, Wrap,
};
use unicode_width::UnicodeWidthStr;

use crate::domain::{
    AuthMode, FieldAccess, FieldDefinition, FieldRegistry, FieldUnit, FieldValueRef, Projection,
    QueryOutcome, RecordKind,
};

use super::state::{
    App, ClusterForm, ClusterPicker, ClusterRow, CredentialForm, CredentialRow, DetailsModal,
    FormAuthMode, LoadState, Modal, QuerySettings, RowKey, Screen, TableNav, TableScreen,
    TaskFailure, TextSelection, cluster_key, cluster_status_text, connection_key, credential_key,
    details_visual_rows, infobase_key, process_key, session_key,
};

const ACCENT: Color = Color::Rgb(90, 180, 210);
const SELECTED: Color = Color::Rgb(35, 65, 75);
const MUTED: Color = Color::DarkGray;
const ERROR: Color = Color::LightRed;

pub(crate) fn render(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < 24 || area.height < 9 {
        frame.render_widget(
            Paragraph::new("Терминал слишком мал\nМинимум: 24x9")
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title(" onecadmin ")),
            area,
        );
        return;
    }

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);

    app.tab_area = Some(Rect::new(
        sections[0].x.saturating_add(1),
        sections[0].y.saturating_add(1),
        sections[0].width.saturating_sub(2),
        1,
    ));
    app.table_area = Some(sections[2]);

    render_tabs(frame, sections[0], app.screen);
    render_settings(frame, sections[1], app);
    let registry = app.registry;
    match app.screen {
        Screen::Clusters => render_clusters(frame, sections[2], &mut app.clusters),
        Screen::Credentials => render_credentials(frame, sections[2], &mut app.credentials),
        Screen::Infobases => render_records(
            frame,
            sections[2],
            "Информационные базы",
            &mut app.infobases,
            RecordKind::Infobase,
            &registry,
            infobase_key,
            false,
        ),
        Screen::Sessions => render_records(
            frame,
            sections[2],
            "Сеансы",
            &mut app.sessions,
            RecordKind::Session,
            &registry,
            session_key,
            true,
        ),
        Screen::Connections => render_records(
            frame,
            sections[2],
            "Соединения",
            &mut app.connections,
            RecordKind::Connection,
            &registry,
            connection_key,
            true,
        ),
        Screen::Processes => render_records(
            frame,
            sections[2],
            "Процессы",
            &mut app.processes,
            RecordKind::Process,
            &registry,
            process_key,
            true,
        ),
        Screen::Diagnostics => render_diagnostics(frame, sections[2], app),
    }
    render_status(frame, sections[3], app);

    if let Some(modal) = app.modal.as_mut() {
        render_modal(frame, modal);
    }
}

fn render_tabs(frame: &mut Frame<'_>, area: Rect, selected: Screen) {
    let titles = Screen::ALL
        .iter()
        .enumerate()
        .map(|(index, screen)| Line::from(format!(" {} {} ", index + 1, screen.title())))
        .collect::<Vec<_>>();
    let tabs = Tabs::new(titles)
        .select(selected_index(selected))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" onecadmin ")
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");
    frame.render_widget(tabs, area);
}

const fn selected_index(screen: Screen) -> usize {
    match screen {
        Screen::Clusters => 0,
        Screen::Credentials => 1,
        Screen::Infobases => 2,
        Screen::Sessions => 3,
        Screen::Connections => 4,
        Screen::Processes => 5,
        Screen::Diagnostics => 6,
    }
}

fn render_settings(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let busy = if app.current_refresh_active() {
        Span::styled("  ОБНОВЛЕНИЕ", Style::default().fg(Color::Yellow))
    } else {
        Span::raw("")
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Параметры: ", Style::default().fg(MUTED)),
            Span::raw(app.current_settings_summary()),
            busy,
        ]))
        .style(Style::default().fg(Color::Gray)),
        area,
    );
}

fn render_clusters(frame: &mut Frame<'_>, area: Rect, screen: &mut TableScreen<Vec<ClusterRow>>) {
    match &screen.resource.state {
        LoadState::Loading => render_loading(frame, area, "Кластеры"),
        LoadState::Error(error) => render_error(frame, area, "Кластеры", error),
        LoadState::Data(records) => {
            let active = screen.resource.is_active();
            render_table(
                frame,
                area,
                table_title("Кластеры", active, records.len()),
                &[
                    "alias",
                    "ras_address",
                    "cluster_name",
                    "cluster_uuid",
                    "host",
                    "port",
                    "auth",
                    "status",
                ],
                records,
                &mut screen.nav,
                cluster_key,
                false,
                |record| {
                    vec![
                        record.target.alias.to_string(),
                        record.target.ras.to_string(),
                        record.target.discovered_cluster.name.clone(),
                        record.target.discovered_cluster.uuid.to_string(),
                        record.target.discovered_cluster.host.clone(),
                        record.target.discovered_cluster.port.to_string(),
                        auth_mode(record.target.cluster_auth.mode()).to_owned(),
                        cluster_status_text(&record.status),
                    ]
                },
            );
        }
    }
}

fn render_credentials(
    frame: &mut Frame<'_>,
    area: Rect,
    screen: &mut TableScreen<Vec<CredentialRow>>,
) {
    match &screen.resource.state {
        LoadState::Loading => render_loading(frame, area, "Credentials"),
        LoadState::Error(error) => render_error(frame, area, "Credentials", error),
        LoadState::Data(records) => {
            let active = screen.resource.is_active();
            render_table(
                frame,
                area,
                table_title("Credentials", active, records.len()),
                &["cluster", "infobase", "infobase_uuid", "auth_mode", "user"],
                records,
                &mut screen.nav,
                credential_key,
                false,
                |record| {
                    vec![
                        record.cluster.to_string(),
                        record.entry.infobase().unwrap_or_default().to_owned(),
                        record
                            .entry
                            .infobase_uuid()
                            .map_or_else(String::new, |uuid| uuid.to_string()),
                        auth_mode(record.entry.auth().mode()).to_owned(),
                        record.entry.auth().user().unwrap_or_default().to_owned(),
                    ]
                },
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_records<R, K>(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    screen: &mut TableScreen<QueryOutcome<R>>,
    kind: RecordKind,
    registry: &FieldRegistry,
    key: K,
    markable: bool,
) where
    R: FieldAccess,
    K: Fn(&R) -> RowKey + Copy,
{
    match &screen.resource.state {
        LoadState::Loading => render_loading(frame, area, title),
        LoadState::Error(error) => render_error(frame, area, title, error),
        LoadState::Data(outcome) => {
            let columns = resolved_columns(&screen.settings, kind, registry, &outcome.data);
            let headers = columns.iter().map(String::as_str).collect::<Vec<_>>();
            let active = screen.resource.is_active();
            render_table(
                frame,
                area,
                table_title(title, active, outcome.data.len()),
                &headers,
                &outcome.data,
                &mut screen.nav,
                key,
                markable,
                |record| {
                    columns
                        .iter()
                        .map(|column| {
                            let definition = registry.definition(kind, column).ok();
                            display_value(
                                record.field(column).unwrap_or(FieldValueRef::Null),
                                definition,
                            )
                        })
                        .collect()
                },
            );
        }
    }
}

fn resolved_columns<R: FieldAccess>(
    settings: &QuerySettings,
    kind: RecordKind,
    registry: &FieldRegistry,
    records: &[R],
) -> Vec<String> {
    Projection::parse(
        (!settings.columns.trim().is_empty()).then_some(settings.columns.trim()),
        kind,
        registry,
    )
    .map(|projection| projection.resolved_columns(records))
    .unwrap_or_else(|_| {
        registry
            .default_columns(kind)
            .iter()
            .map(|column| (*column).to_owned())
            .collect()
    })
}

#[allow(clippy::too_many_arguments)]
fn render_table<T, K, V>(
    frame: &mut Frame<'_>,
    area: Rect,
    title: String,
    headers: &[&str],
    records: &[T],
    nav: &mut TableNav,
    key: K,
    markable: bool,
    values: V,
) where
    K: Fn(&T) -> RowKey,
    V: Fn(&T) -> Vec<String>,
{
    // Borders and the header consume three rows. Only this slice is converted
    // into ratatui Rows/Cells, regardless of the full result size.
    let viewport_height = area.height.saturating_sub(3) as usize;
    nav.set_viewport_height(viewport_height, records.len());
    let offset = nav.offset;
    let selected = nav.selected.and_then(|index| index.checked_sub(offset));
    let visible = records
        .iter()
        .skip(offset)
        .take(viewport_height)
        .map(|record| {
            let mut cells = Vec::with_capacity(headers.len() + usize::from(markable));
            if markable {
                cells.push(Cell::from(if nav.marked.contains(&key(record)) {
                    "[x]"
                } else {
                    "[ ]"
                }));
            }
            cells.extend(values(record).into_iter().map(Cell::from));
            Row::new(cells)
        });
    let mut header_cells = Vec::with_capacity(headers.len() + usize::from(markable));
    if markable {
        header_cells.push(Cell::from("sel"));
    }
    header_cells.extend(
        headers
            .iter()
            .map(|header| Cell::from((*header).to_owned())),
    );
    let header = Row::new(header_cells)
        .style(
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .height(1);
    let mut widths = Vec::with_capacity(headers.len() + usize::from(markable));
    if markable {
        widths.push(Constraint::Length(3));
    }
    widths.extend(headers.iter().map(|header| column_constraint(header)));
    let table = Table::new(visible, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} "))
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .row_highlight_style(
            Style::default()
                .bg(SELECTED)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut table_state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn column_constraint(header: &str) -> Constraint {
    if header.ends_with("uuid") || matches!(header, "session" | "connection" | "process") {
        Constraint::Length(36)
    } else if header.ends_with("_at") || header == "on" {
        Constraint::Length(21)
    } else if header == "description" {
        Constraint::Length(60)
    } else if matches!(header, "connection_string" | "path" | "message") {
        Constraint::Length(32)
    } else if matches!(header, "cluster" | "auth" | "auth_mode" | "port" | "sel") {
        Constraint::Length(12)
    } else {
        Constraint::Length(18)
    }
}

fn render_loading(frame: &mut Frame<'_>, area: Rect, title: &str) {
    frame.render_widget(
        Paragraph::new("Загрузка выполняется асинхронно...\nEsc отменяет операцию в модальном окне; F5 не создает overlap.")
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {title} · Loading ")),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_error(frame: &mut Frame<'_>, area: Rect, title: &str, error: &TaskFailure) {
    let mut lines = vec![
        Line::styled(
            "Ошибка загрузки",
            Style::default().fg(ERROR).add_modifier(Modifier::BOLD),
        ),
        Line::raw(format!("code: {}", error.code)),
        Line::raw(format!("message: {}", error.message)),
    ];
    for target in &error.target_errors {
        lines.push(Line::raw(format!(
            "{} | {} | {} | {}",
            target.cluster,
            target.ras_address,
            target.code(),
            target.message
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {title} · Error "))
                    .border_style(Style::default().fg(ERROR)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn table_title(title: &str, active: bool, count: usize) -> String {
    if active {
        format!("{title} · Data · {count} · обновление")
    } else {
        format!("{title} · Data · {count}")
    }
}

fn render_diagnostics(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    match &app.diagnostics.resource.state {
        LoadState::Loading => render_loading(frame, area, "Диагностика"),
        LoadState::Error(error) => render_error(frame, area, "Диагностика", error),
        LoadState::Data(snapshot) => {
            let mut all = Vec::new();
            all.push("SELECTED RAC".to_owned());
            if snapshot.selected_rac.is_empty() {
                all.push("  Нет выбранных кандидатов rac.exe".to_owned());
            }
            for selected in &snapshot.selected_rac {
                all.push(format!(
                    "  {} | {} | version={} | origin={} | path={}",
                    selected.cluster,
                    selected.ras_address,
                    selected.version,
                    selected.origin,
                    selected.path.display()
                ));
            }
            all.push(String::new());
            all.push("ОШИБКИ ПО ЦЕЛЯМ".to_owned());
            if snapshot.target_errors.is_empty() {
                all.push("  Нет ошибок последнего application-запроса".to_owned());
            }
            for error in &snapshot.target_errors {
                all.push(format!(
                    "  {} | {} | {} | {}",
                    error.cluster,
                    error.ras_address,
                    error.code(),
                    error.message
                ));
            }
            all.push(String::new());
            all.push("ОШИБКИ TUI / ACTION".to_owned());
            if app.local_errors.is_empty() {
                all.push("  Нет локальных ошибок".to_owned());
            }
            all.extend(app.local_errors.iter().map(|error| format!("  {error}")));
            if let Some(updated) = snapshot.updated_at {
                all.push(String::new());
                all.push(format!("updated_at: {}", updated.to_rfc3339()));
            }

            let height = area.height.saturating_sub(2) as usize;
            let max_scroll = all.len().saturating_sub(height.max(1));
            app.diagnostics.scroll = app.diagnostics.scroll.min(max_scroll);
            let visible = all
                .iter()
                .skip(app.diagnostics.scroll)
                .take(height)
                .map(|line| Line::raw(line.clone()))
                .collect::<Vec<_>>();
            frame.render_widget(
                Paragraph::new(visible)
                    .block(Block::default().borders(Borders::ALL).title(format!(
                        " Диагностика · Data · строки {}–{} из {} ",
                        app.diagnostics.scroll.saturating_add(1),
                        app.diagnostics.scroll.saturating_add(height).min(all.len()),
                        all.len()
                    )))
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
    }
}

fn render_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let contextual = match app.screen {
        Screen::Clusters => "n добавить · Del удалить с планом",
        Screen::Credentials => "n добавить override · Del удалить",
        Screen::Sessions => "Space отметить · k завершить с планом",
        Screen::Connections => "Space отметить · k разорвать с планом",
        Screen::Processes => "Space отметить · k выключить с планом",
        Screen::Infobases => "Enter детали/строка подключения",
        Screen::Diagnostics => "↑↓ прокрутка · F5 снимок",
    };
    let auto = if app.auto_refresh.enabled {
        format!("авто {}с", app.auto_refresh.interval.as_secs())
    } else {
        format!("авто выкл/{}с", app.auto_refresh.interval.as_secs())
    };
    let state_style = if app.status_is_error {
        Style::default().fg(ERROR)
    } else {
        Style::default().fg(Color::White)
    };
    let first = Line::from(vec![
        Span::styled(" F5 ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::raw(" обновить · "),
        Span::styled("a", Style::default().fg(ACCENT)),
        Span::raw(format!(
            " {auto} · [ ] интервалы · ↑↓ Pg навигация · {contextual}"
        )),
    ]);
    let second = Line::from(vec![
        Span::styled(
            " / query · f filter · s sort · c columns · g кластер · m мышь ",
            Style::default().fg(Color::Gray),
        ),
        Span::raw("│ "),
        Span::styled(&app.status, state_style),
        Span::raw(format!(
            " │ отмечено {} │ q/Esc выход",
            app.selected_count()
        )),
    ]);
    frame.render_widget(
        Paragraph::new(vec![first, second]).style(Style::default().bg(Color::Rgb(18, 22, 25))),
        area,
    );
}

fn render_modal(frame: &mut Frame<'_>, modal: &mut Modal) {
    match modal {
        Modal::Details(details) => render_details_modal(frame, details, false),
        Modal::Confirm(confirm) => {
            let mut details = DetailsModal {
                title: confirm.title.clone(),
                lines: confirm.lines.clone(),
                scroll: confirm.scroll,
                selection: None,
                text_area: None,
                rows: None,
            };
            render_details_modal(frame, &mut details, true);
        }
        Modal::Edit(edit) => {
            let area = centered_rect_fixed(84, 7, frame.area());
            frame.render_widget(Clear, area);
            let mut lines = vec![
                Line::styled(edit.kind.title(), Style::default().fg(ACCENT)),
                Line::raw(""),
                Line::styled(
                    format!("> {}", edit.value),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::styled(
                    "Enter применить · Ctrl+U очистить · Esc отменить",
                    Style::default().fg(MUTED),
                ),
            ];
            if let Some(error) = &edit.error {
                lines.push(Line::styled(error.clone(), Style::default().fg(ERROR)));
            }
            frame.render_widget(
                Paragraph::new(lines)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Редактирование ")
                            .border_style(Style::default().fg(ACCENT)),
                    )
                    .wrap(Wrap { trim: false }),
                area,
            );
            let cursor_x = area
                .x
                .saturating_add(3)
                .saturating_add(UnicodeWidthStr::width(&edit.value[..edit.cursor]) as u16)
                .min(area.right().saturating_sub(2));
            frame.set_cursor_position(Position::new(cursor_x, area.y.saturating_add(3)));
        }
        Modal::ClusterPicker(picker) => render_cluster_picker(frame, picker),
        Modal::ClusterForm(form) => render_cluster_form(frame, form),
        Modal::CredentialForm(form) => render_credential_form(frame, form),
        Modal::Progress { title, .. } => {
            let area = centered_rect(64, 7, frame.area());
            frame.render_widget(Clear, area);
            frame.render_widget(
                Gauge::default()
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Фоновая операция ")
                            .border_style(Style::default().fg(Color::Yellow)),
                    )
                    .gauge_style(Style::default().fg(ACCENT))
                    .label(format!("{title}  Esc: отменить"))
                    .use_unicode(true)
                    .ratio(0.5),
                area,
            );
        }
    }
}

fn render_details_modal(frame: &mut Frame<'_>, details: &mut DetailsModal, confirm: bool) {
    let area = centered_rect(90, 80, frame.area());
    frame.render_widget(Clear, area);
    let inner_height = area.height.saturating_sub(3) as usize;
    let max_scroll = details.lines.len().saturating_sub(inner_height.max(1));
    let scroll = details.scroll.min(max_scroll);
    let text_area = Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        inner_height as u16,
    );
    details.text_area = Some(text_area);

    let rows = details_visual_rows(
        &details.lines,
        text_area.width as usize,
        scroll,
        inner_height,
    );
    details.rows = Some(rows.clone());

    let mut lines = rows
        .iter()
        .map(|&(line_index, byte_start, byte_end)| {
            Line::from(details_row_spans(
                &details.lines,
                line_index,
                byte_start,
                byte_end,
                details.selection,
            ))
        })
        .collect::<Vec<_>>();
    if confirm {
        lines.push(Line::styled(
            "Enter/y: подтвердить · Esc/n: отменить",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", details.title))
                    .border_style(Style::default().fg(if confirm { ERROR } else { ACCENT })),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn details_row_spans(
    lines: &[String],
    line_index: usize,
    byte_start: usize,
    byte_end: usize,
    selection: Option<TextSelection>,
) -> Vec<Span<'static>> {
    let line = &lines[line_index];
    let Some(sel) = selection else {
        return vec![Span::raw(line[byte_start..byte_end].to_owned())];
    };
    let (start, end) = if sel.start <= sel.end {
        (sel.start, sel.end)
    } else {
        (sel.end, sel.start)
    };
    let (start_line, start_byte) = start;
    let (end_line, end_byte) = end;

    let overlap_start = if line_index < start_line {
        byte_end
    } else if line_index == start_line {
        byte_start.max(start_byte)
    } else {
        byte_start
    };
    let overlap_end = if line_index > end_line {
        byte_start
    } else if line_index == end_line {
        byte_end.min(end_byte)
    } else {
        byte_end
    };

    if overlap_start >= overlap_end {
        return vec![Span::raw(line[byte_start..byte_end].to_owned())];
    }
    let selected = Style::default().bg(Color::White).fg(Color::Black);
    vec![
        Span::raw(line[byte_start..overlap_start].to_owned()),
        Span::styled(line[overlap_start..overlap_end].to_owned(), selected),
        Span::raw(line[overlap_end..byte_end].to_owned()),
    ]
}

fn render_cluster_picker(frame: &mut Frame<'_>, picker: &mut ClusterPicker) {
    let height = (picker.options.len() as u16)
        .saturating_add(4)
        .min(frame.area().height)
        .max(6);
    let area = centered_rect_fixed(60, height, frame.area());
    frame.render_widget(Clear, area);

    let list_height = area.height.saturating_sub(3) as usize;
    let offset = picker
        .selected
        .saturating_sub(list_height.saturating_sub(1))
        .min(picker.options.len().saturating_sub(list_height));

    picker.offset = offset;
    picker.list_area = Some(Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        list_height as u16,
    ));

    let mut lines = picker
        .options
        .iter()
        .enumerate()
        .skip(offset)
        .take(list_height)
        .map(|(index, option)| {
            let selected = index == picker.selected;
            let style = if selected {
                Style::default()
                    .bg(SELECTED)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(vec![
                Span::styled(
                    if selected { "▶ " } else { "  " },
                    if selected {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    },
                ),
                Span::styled(option.clone(), style),
            ])
        })
        .collect::<Vec<_>>();
    lines.push(Line::styled(
        "↑↓/колесо/клик · Enter применить · Esc отменить",
        Style::default().fg(MUTED),
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Кластер ")
                    .border_style(Style::default().fg(ACCENT)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_cluster_form(frame: &mut Frame<'_>, form: &ClusterForm) {
    render_form(
        frame,
        "Добавление кластера",
        &form.fields(),
        form.field,
        form.cursor_display_width(),
        form.auth_mode,
        form.error.as_deref(),
    );
}

fn render_credential_form(frame: &mut Frame<'_>, form: &CredentialForm) {
    render_form(
        frame,
        "Добавление credential override",
        &form.fields(),
        form.field,
        form.cursor_display_width(),
        form.auth_mode,
        form.error.as_deref(),
    );
}

fn render_form(
    frame: &mut Frame<'_>,
    title: &str,
    fields: &[(&'static str, String, bool)],
    selected: usize,
    cursor_width: usize,
    auth_mode: FormAuthMode,
    error: Option<&str>,
) {
    let height = (fields.len() as u16)
        .saturating_add(7)
        .min(frame.area().height);
    let area = centered_rect_fixed(88, height, frame.area());
    frame.render_widget(Clear, area);
    let label_width = fields
        .iter()
        .map(|(label, _, _)| UnicodeWidthStr::width(*label))
        .max()
        .unwrap_or_default();
    let mut lines = Vec::with_capacity(fields.len() + 3);
    for (index, (label, value, secret)) in fields.iter().enumerate() {
        let marker = if index == selected { "▶" } else { " " };
        let shown = if *secret {
            value.clone()
        } else if value.is_empty() {
            " ".to_owned()
        } else {
            value.clone()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{marker} {label:label_width$}: "),
                if index == selected {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
            Span::styled(
                shown,
                if index == selected {
                    Style::default().bg(SELECTED).fg(Color::White)
                } else {
                    Style::default()
                },
            ),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!(
            "Tab/Shift+Tab поля · F2 auth_mode ({}) · Enter отправить · Esc отменить",
            auth_mode.label()
        ),
        Style::default().fg(MUTED),
    ));
    if let Some(error) = error {
        lines.push(Line::styled(error.to_owned(), Style::default().fg(ERROR)));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {title} "))
                    .border_style(Style::default().fg(ACCENT)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );

    let prefix = 2 + label_width + 2;
    let cursor_x = area
        .x
        .saturating_add(1)
        .saturating_add(prefix as u16)
        .saturating_add(cursor_width as u16)
        .min(area.right().saturating_sub(2));
    let cursor_y = area
        .y
        .saturating_add(1)
        .saturating_add(selected.min(fields.len().saturating_sub(1)) as u16);
    frame.set_cursor_position(Position::new(cursor_x, cursor_y));
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn centered_rect_fixed(width_percent: u16, height: u16, area: Rect) -> Rect {
    let height = height.min(area.height);
    let vertical_margin = area.height.saturating_sub(height) / 2;
    let vertical = Rect::new(
        area.x,
        area.y.saturating_add(vertical_margin),
        area.width,
        height,
    );
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_percent) / 2),
            Constraint::Percentage(width_percent),
            Constraint::Percentage((100 - width_percent) / 2),
        ])
        .split(vertical);
    horizontal[1]
}

fn display_value(value: FieldValueRef<'_>, definition: Option<&FieldDefinition>) -> String {
    match value {
        FieldValueRef::Uuid(value) => value.to_string(),
        FieldValueRef::Int(value) => match definition.and_then(|field| field.unit) {
            Some(FieldUnit::Bytes) => format_bytes(value),
            Some(FieldUnit::Milliseconds) => format_milliseconds(value),
            Some(FieldUnit::Microseconds) => format_microseconds(value),
            Some(FieldUnit::Seconds) => format_seconds(value),
            Some(FieldUnit::Count) | None => value.to_string(),
        },
        FieldValueRef::Bool(value) => value.to_string(),
        FieldValueRef::DateTime(value) => value
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        FieldValueRef::Str(value) => value.to_owned(),
        FieldValueRef::Null => "—".to_owned(),
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
    if value.unsigned_abs() < 1_000 {
        format!("{value} us")
    } else if value.unsigned_abs() < 1_000_000 {
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

const fn auth_mode(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::None => "none",
        AuthMode::Password => "password",
    }
}
