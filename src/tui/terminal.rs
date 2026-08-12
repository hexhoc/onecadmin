use std::io::{self, Stdout};

use crossterm::cursor;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

pub(crate) type TuiTerminal = Terminal<CrosstermBackend<Stdout>>;

pub(crate) struct TerminalGuard {
    terminal: Option<TuiTerminal>,
    raw_mode: bool,
    alternate_screen: bool,
}

impl TerminalGuard {
    pub(crate) fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut guard = Self {
            terminal: None,
            raw_mode: true,
            alternate_screen: false,
        };

        let mut stdout = io::stdout();
        // Mark it before writing so Drop emits a harmless LeaveAlternateScreen
        // even if the terminal write itself reports a partial failure.
        guard.alternate_screen = true;
        execute!(stdout, EnterAlternateScreen)?;
        execute!(stdout, EnableMouseCapture, cursor::Hide)?;
        let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        terminal.clear()?;
        guard.terminal = Some(terminal);
        Ok(guard)
    }

    pub(crate) fn draw<F>(&mut self, render: F) -> io::Result<()>
    where
        F: FnOnce(&mut ratatui::Frame<'_>),
    {
        let Some(terminal) = self.terminal.as_mut() else {
            return Err(io::Error::other("терминал TUI не инициализирован"));
        };
        terminal.draw(render).map(|_| ())
    }

    fn restore(&mut self) {
        if let Some(terminal) = self.terminal.as_mut() {
            let _ = terminal.show_cursor();
            if self.alternate_screen {
                let _ = execute!(
                    terminal.backend_mut(),
                    DisableMouseCapture,
                    LeaveAlternateScreen,
                    cursor::Show
                );
                self.alternate_screen = false;
            }
        } else if self.alternate_screen {
            let mut stdout = io::stdout();
            let _ = execute!(
                stdout,
                DisableMouseCapture,
                LeaveAlternateScreen,
                cursor::Show
            );
            self.alternate_screen = false;
        }
        if self.raw_mode {
            let _ = disable_raw_mode();
            self.raw_mode = false;
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}
