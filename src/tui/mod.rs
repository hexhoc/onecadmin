//! Full-screen terminal adapter.

mod state;
mod tasks;
mod terminal;
mod ui;

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use crate::application::{AppServices, RacOptions};

use self::state::{App, BackgroundMessage, Intent, RequestId, Screen};
use self::tasks::spawn_job;
use self::terminal::TerminalGuard;

pub use self::state::Screen as TuiScreen;

/// Smallest accepted custom auto-refresh interval.
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

/// Presets exposed by `[` and `]` in the interface.
pub const REFRESH_INTERVAL_PRESETS: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

#[derive(Clone, Debug)]
pub struct TuiOptions {
    refresh_interval: Duration,
    event_tick: Duration,
    rac_options: RacOptions,
}

impl TuiOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_refresh_interval(mut self, interval: Duration) -> Result<Self, TuiError> {
        validate_refresh_interval(interval)?;
        self.refresh_interval = interval;
        Ok(self)
    }

    #[must_use]
    pub fn with_rac_options(mut self, options: RacOptions) -> Self {
        self.rac_options = options;
        self
    }

    #[must_use]
    pub const fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }

    #[must_use]
    pub const fn rac_options(&self) -> &RacOptions {
        &self.rac_options
    }

    #[cfg(test)]
    pub(crate) fn with_event_tick(mut self, tick: Duration) -> Self {
        self.event_tick = tick;
        self
    }
}

impl Default for TuiOptions {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(10),
            event_tick: Duration::from_millis(200),
            rac_options: RacOptions::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("Ошибка терминала: {0}")]
    Terminal(#[from] io::Error),
    #[error("Интервал автообновления должен быть не меньше 2 секунд")]
    RefreshIntervalTooSmall,
    #[error("Интервал обработки событий должен быть больше нуля")]
    InvalidEventTick,
    #[error("Поток событий терминала неожиданно завершился")]
    EventStreamClosed,
}

/// Runs the full-screen interface until `q`, `Esc`, `Ctrl+C`, or cancellation.
///
/// The function borrows the application composition root and clones its cheap,
/// shared handles for background tasks. Auto-refresh is always disabled on
/// entry; `options.refresh_interval` only selects the interval used after the
/// user enables it.
pub async fn run(
    services: &AppServices,
    options: TuiOptions,
    cancellation: &CancellationToken,
) -> Result<(), TuiError> {
    validate_refresh_interval(options.refresh_interval)?;
    if options.event_tick.is_zero() {
        return Err(TuiError::InvalidEventTick);
    }
    if cancellation.is_cancelled() {
        return Ok(());
    }

    let mut terminal = TerminalGuard::enter()?;
    let mut events = EventStream::new();
    let (sender, mut receiver) = mpsc::unbounded_channel::<BackgroundMessage>();
    let task_root = cancellation.child_token();
    let mut task_tokens = HashMap::<RequestId, CancellationToken>::new();
    let mut app = App::new(&options);
    let mut ticker = tokio::time::interval(options.event_tick);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    dispatch_intents(
        vec![Intent::Refresh(Screen::Clusters)],
        &mut app,
        &mut terminal,
        services,
        &sender,
        &task_root,
        &mut task_tokens,
    );

    let result = loop {
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        tokio::select! {
            biased;
            () = cancellation.cancelled() => break Ok(()),
            message = receiver.recv() => {
                let Some(message) = message else {
                    break Ok(());
                };
                task_tokens.remove(&message.request_id);
                let intents = app.apply_background(message);
                if dispatch_intents(
                    intents,
                    &mut app,
                    &mut terminal,
                    services,
                    &sender,
                    &task_root,
                    &mut task_tokens,
                ) {
                    break Ok(());
                }
            }
            event = events.next() => {
                match event {
                    Some(Ok(Event::Key(key)))
                        if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                    {
                        let intents = app.handle_key(key);
                        if dispatch_intents(
                            intents,
                            &mut app,
                            &mut terminal,
                            services,
                            &sender,
                            &task_root,
                            &mut task_tokens,
                        ) {
                            break Ok(());
                        }
                    }
                    Some(Ok(Event::Resize(_, _))) => {}
                    Some(Ok(Event::Mouse(mouse))) => {
                        let intents = app.handle_mouse(mouse);
                        if dispatch_intents(
                            intents,
                            &mut app,
                            &mut terminal,
                            services,
                            &sender,
                            &task_root,
                            &mut task_tokens,
                        ) {
                            break Ok(());
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => break Err(TuiError::Terminal(error)),
                    None => break Err(TuiError::EventStreamClosed),
                }
            }
            _ = ticker.tick() => {
                let intents = app.on_tick(tokio::time::Instant::now());
                if dispatch_intents(
                    intents,
                    &mut app,
                    &mut terminal,
                    services,
                    &sender,
                    &task_root,
                    &mut task_tokens,
                ) {
                    break Ok(());
                }
            }
        }
    };

    task_root.cancel();
    for token in task_tokens.into_values() {
        token.cancel();
    }
    result
}

fn dispatch_intents(
    intents: Vec<Intent>,
    app: &mut App,
    terminal: &mut TerminalGuard,
    services: &AppServices,
    sender: &mpsc::UnboundedSender<BackgroundMessage>,
    task_root: &CancellationToken,
    task_tokens: &mut HashMap<RequestId, CancellationToken>,
) -> bool {
    for intent in intents {
        match intent {
            Intent::Quit => return true,
            Intent::ToggleMouseCapture => {
                let _ = terminal.set_mouse_capture(app.mouse_capture);
            }
            Intent::Refresh(screen) => match app.begin_refresh(screen) {
                Ok(Some(job)) => {
                    let token = task_root.child_token();
                    task_tokens.insert(job.request_id(), token.clone());
                    spawn_job(services.clone(), job, token, sender.clone());
                }
                Ok(None) => {}
                Err(message) => app.set_status_error(message),
            },
            Intent::Spawn(job) => {
                let token = task_root.child_token();
                task_tokens.insert(job.request_id(), token.clone());
                spawn_job(services.clone(), *job, token, sender.clone());
            }
            Intent::Cancel(request_id) => {
                if let Some(token) = task_tokens.remove(&request_id) {
                    token.cancel();
                }
            }
        }
    }
    false
}

fn validate_refresh_interval(interval: Duration) -> Result<(), TuiError> {
    if interval < MIN_REFRESH_INTERVAL {
        Err(TuiError::RefreshIntervalTooSmall)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_enforces_minimum_and_accepts_presets() {
        assert!(
            TuiOptions::new()
                .with_refresh_interval(Duration::from_secs(1))
                .is_err()
        );
        assert!(
            TuiOptions::new()
                .with_refresh_interval(MIN_REFRESH_INTERVAL)
                .is_ok()
        );
        for interval in REFRESH_INTERVAL_PRESETS {
            assert!(TuiOptions::new().with_refresh_interval(interval).is_ok());
        }
    }

    #[test]
    fn zero_event_tick_is_representable_only_for_run_validation_test_paths() {
        assert!(
            TuiOptions::new()
                .with_event_tick(Duration::ZERO)
                .event_tick
                .is_zero()
        );
    }
}
