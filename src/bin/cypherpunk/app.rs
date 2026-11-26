//! The interactive view, laid out like the Codex TUI.
//!
//! The screen has four parts. A session header box at the top shows the version,
//! chain, mode, protection and service state. Below it, a history of action cells is
//! anchored to the bottom. Then comes one status line, which carries the spinner
//! while an action runs. The footer shows bold keys with dim labels, separated by `·`.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding, Paragraph};
use serde_json::Value;

use crate::actions::{Done, perform};
use crate::cells::{Cell, Row, chain_short, connection_guidance, hop_place, hop_role, render};
use crate::controller::{Controller, is_root};
use crate::guided;
use crate::theme::Theme;

/// Shown once on a device that is not enrolled yet. Generated from the endpoint catalog
/// (`tools/providers.py`); the test suite fails if the two differ.
const GET_STARTED: &str = include_str!("get_started.txt");

/// The "Get started" cell: free places to run servers, and the next commands.
pub fn get_started() -> Cell {
    let mut lines = GET_STARTED.lines();
    let title = lines.next().unwrap_or("Get started").to_string();
    let summary = lines.next().map(str::to_string);
    let rows = lines
        .map(|l| match l.split_once('\t') {
            Some((label, value)) => Row::pair(label, value),
            None => Row::detail(l),
        })
        .collect();
    Cell::Result {
        title,
        summary,
        rows,
    }
}

/// A finished background action: whether to refresh the header, and its result.
type Finished = (bool, Done);

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Keys shown in the footer, in order.
pub const KEYS: &[(&str, &str)] = &[
    ("/", "commands"),
    ("k", "kill switch"),
    ("m", "scope"),
    ("c", "connect"),
    ("u", "unlock"),
    ("l", "locations"),
    ("p", "settings"),
    ("e", "setup"),
    ("d", "disconnect"),
    ("h", "hops"),
    ("s", "status"),
    ("i", "info"),
    ("o", "doctor"),
    ("?", "help"),
    ("q", "quit"),
];

const SLASH_COMMANDS: &[(&str, &str)] = &[
    ("killswitch-disarm", "restore ordinary internet access"),
    ("lockdown", "review or change protection after disconnect"),
    (
        "scope",
        "switch between whole-device and application protection",
    ),
    ("applications", "select and launch protected applications"),
    ("status", "show current protection and tunnel checks"),
    ("connect", "start the VPN"),
    ("disconnect", "stop the VPN and keep the kill switch"),
    ("unlock", "answer the Nitrokey PIN prompt"),
    ("settings", "change protection scope and other preferences"),
    ("locations", "view and select saved routes"),
    ("credits", "show the mesh wallet and redemption status"),
    ("shared", "show shared-access pilot status and sealed credits"),
    ("hops", "show the enrolled route"),
    ("setup", "set up or enroll this device"),
    ("doctor", "check this device"),
    ("info", "show enrollment and preferences"),
    ("help", "list keyboard shortcuts"),
    ("quit", "leave the VPN view"),
];

fn matching_commands(prefix: &str) -> impl Iterator<Item = (&'static str, &'static str)> {
    SLASH_COMMANDS
        .iter()
        .copied()
        .filter(move |(name, _)| name.starts_with(prefix))
}

fn scope_shortcut(key: &KeyEvent) -> bool {
    (key.code == KeyCode::BackTab && key.modifiers.contains(KeyModifiers::CONTROL))
        || (key.code == KeyCode::Tab
            && key
                .modifiers
                .contains(KeyModifiers::CONTROL | KeyModifiers::SHIFT))
}

/// What the header box shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// `client → relay → exit`, or `not enrolled`.
    pub chain: String,
    /// `applications · rate fast`.
    pub mode: String,
    /// `nitrokey`, `systemd-creds (host+tpm2)`, ...
    pub protection: String,
    /// The supervisor state.
    pub status: String,
    pub locations: Vec<String>,
    pub lockdown: Option<bool>,
    /// The next milestone or action associated with the current status.
    pub guidance: Option<&'static str>,
}

impl Header {
    /// Build the header from an `info` result.
    pub fn from_info(v: &Value) -> Self {
        let i = v.get("info").cloned().unwrap_or(Value::Null);
        let get = |k: &str| i.get(k).and_then(Value::as_str).map(str::to_string);
        let chain = i.get("chain").and_then(chain_short).unwrap_or_else(|| {
            match i.get("enrolled").and_then(Value::as_bool) {
                Some(false) => "not enrolled".into(),
                Some(true) => "enrolled".into(),
                None => "unknown".into(),
            }
        });
        let state = &i["status"];
        let scope = state["scope"]
            .as_str()
            .filter(|scope| matches!(*scope, "applications" | "whole-device"))
            .map(str::to_owned)
            .or_else(|| get("mode"));
        let mode = match (scope, get("rate")) {
            (Some(m), Some(r)) => format!("{m} · rate {r}"),
            (Some(m), None) => m,
            _ => "—".into(),
        };
        let protection = match (get("protection"), get("creds_key")) {
            (Some(p), Some(k)) => format!("{p} ({k})"),
            (Some(p), None) => p,
            _ => "—".into(),
        };
        let status = state
            .get("lifecycle")
            .or_else(|| state.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let guidance = match chain.as_str() {
            "not enrolled" => Some("Press e to start setup or import a signed bundle."),
            "unknown" => {
                Some("Press e for setup. Open sudo cypherpunk to see private device status.")
            }
            _ => connection_guidance(state),
        };
        let locations = i["chain"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|hop| hop.get("country").is_some())
            .map(|hop| format!("{}  {}", hop_role(hop), hop_place(hop)))
            .collect();
        Self {
            chain,
            mode,
            protection,
            status,
            locations,
            lockdown: i["lockdown"].as_bool(),
            guidance,
        }
    }
}

/// An action in progress.
struct Busy {
    label: String,
    since: Instant,
}

/// Interactive state. Rendering is a pure function of it, so it is snapshot-tested.
pub struct App {
    theme: Theme,
    reduced_motion: bool,
    /// The header box contents.
    pub header: Header,
    /// Everything shown so far.
    pub history: Vec<Cell>,
    busy: Option<Busy>,
    /// Lines scrolled up from the bottom.
    pub scroll: usize,
    /// Set when the user quits.
    pub quit: bool,
    command: Option<String>,
    selected_command: usize,
    started: Instant,
}

impl App {
    /// A new view with an empty history.
    pub fn new(theme: Theme, reduced_motion: bool, header: Header) -> Self {
        Self {
            theme,
            reduced_motion,
            header,
            history: Vec::new(),
            busy: None,
            scroll: 0,
            quit: false,
            command: None,
            selected_command: 0,
            started: Instant::now(),
        }
    }

    /// Mark an action as running.
    pub fn start(&mut self, label: &str) {
        self.history
            .push(Cell::Command(format!("cypherpunk {label}")));
        self.busy = Some(Busy {
            label: label.to_string(),
            since: Instant::now(),
        });
        self.scroll = 0;
    }

    /// Record a finished action.
    pub fn finish(&mut self, done: Done) {
        self.busy = None;
        self.history.extend(done.cells);
        self.scroll = 0;
    }

    /// Whether an action is running.
    pub fn busy(&self) -> bool {
        self.busy.is_some()
    }

    fn header_lines(&self) -> Vec<Line<'static>> {
        let t = self.theme;
        let status_style = match self.header.status.as_str() {
            "connected" => t.success(),
            "blocked" => t.error(),
            _ => t.dim(),
        };
        let label = |l: &str| Span::styled(format!("{l:<12}"), t.dim());
        let mut lines = vec![
            Line::from(vec![
                Span::styled(">_ ", t.dim()),
                Span::styled("CYPHERPUNK VPN", t.brand()),
                Span::styled(format!(" (v{})", env!("CARGO_PKG_VERSION")), t.dim()),
            ]),
            Line::default(),
            Line::from(vec![
                label("chain:"),
                Span::styled(self.header.chain.clone(), t.text()),
            ]),
            Line::from(vec![
                label("mode:"),
                Span::styled(self.header.mode.clone(), t.text()),
            ]),
            Line::from(vec![
                label("protection:"),
                Span::styled(self.header.protection.clone(), t.text()),
                Span::styled(" · service ", t.dim()),
                Span::styled(self.header.status.clone(), status_style),
            ]),
        ];
        if self.header.mode.starts_with("applications") && self.header.status == "connected" {
            lines.push(Line::from(Span::styled(
                "Only apps started through CYPHERPUNK use the VPN.",
                t.accent(),
            )));
        }
        if let Some(enabled) = self.header.lockdown {
            lines.push(Line::from(vec![
                label("lockdown:"),
                Span::styled(
                    if enabled { "on" } else { "off" },
                    if enabled { t.success() } else { t.dim() },
                ),
                Span::styled(" · k to change", t.dim()),
            ]));
        }
        lines.extend(self.header.locations.iter().map(|location| {
            Line::from(vec![
                Span::raw("  "),
                Span::styled(location.clone(), t.text()),
            ])
        }));
        lines
    }

    fn footer(&self) -> Line<'static> {
        let t = self.theme;
        let mut spans = vec![Span::raw(" ")];
        for (i, (key, label)) in KEYS
            .iter()
            .filter(|(k, _)| matches!(*k, "/" | "k" | "m" | "c" | "d" | "p" | "e" | "q"))
            .enumerate()
        {
            if i > 0 {
                spans.push(Span::styled(" · ", t.dim()));
            }
            spans.push(Span::styled(*key, t.bold()));
            spans.push(Span::styled(
                format!(" {}", if *key == "d" { "stop" } else { label }),
                t.dim(),
            ));
        }
        Line::from(spans)
    }

    fn status_line(&self, now: Instant) -> Line<'static> {
        let t = self.theme;
        if let Some(command) = &self.command {
            return Line::from(Span::styled(format!(" /{command}"), t.accent()));
        }
        match &self.busy {
            Some(b) => {
                let frame = if self.reduced_motion {
                    "•"
                } else {
                    SPINNER[(now.duration_since(self.started).as_millis() / 80) as usize
                        % SPINNER.len()]
                };
                Line::from(vec![
                    Span::styled(format!(" {frame} "), t.accent()),
                    Span::styled(format!("Working on {}", b.label), t.bold()),
                    Span::styled(
                        format!(" ({}s)", now.duration_since(b.since).as_secs()),
                        t.dim(),
                    ),
                ])
            }
            None => self.header.guidance.map_or_else(Line::default, |hint| {
                Line::from(Span::styled(hint, t.accent()))
            }),
        }
    }

    /// Draw the whole screen.
    pub fn draw(&self, f: &mut Frame, now: Instant) {
        let area = f.area();
        f.buffer_mut().set_style(area, self.theme.surface());
        let header = self.header_lines();
        let inner_width = header.iter().map(Line::width).max().unwrap_or(0) as u16 + 2;
        let box_width = (inner_width + 2).min(area.width);
        let [top, history, status, footer] = Layout::vertical([
            Constraint::Length(header.len() as u16 + 2),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(self.theme.dim())
            .padding(Padding::horizontal(1));
        f.render_widget(
            Paragraph::new(header).block(block).style(self.theme.text()),
            Rect {
                width: box_width,
                ..top
            },
        );
        let mut lines = vec![Line::default()];
        if let Some(command) = &self.command {
            let visible = (history.height as usize).clamp(1, 6);
            for (index, (name, description)) in matching_commands(command)
                .enumerate()
                .skip(self.selected_command.saturating_sub(visible - 1))
                .take(visible)
            {
                let selected = index == self.selected_command;
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(" {} /{name}  ", if selected { "›" } else { " " }),
                        if selected {
                            self.theme.accent().patch(self.theme.bold())
                        } else {
                            self.theme.text()
                        },
                    ),
                    Span::styled(description, self.theme.dim()),
                ]));
            }
            if lines.len() == 1 {
                lines.push(Line::from("  No matching command."));
            }
        } else if self.history.is_empty() {
            lines.push(Line::from(Span::styled(
                "  Press a key below. Every action is also a command: cypherpunk help",
                self.theme.dim(),
            )));
        }
        if self.command.is_none() {
            lines.extend(render(&self.history, self.theme));
        }
        let height = history.height as usize;
        let end = lines.len().saturating_sub(if self.command.is_some() {
            0
        } else {
            self.scroll.min(lines.len().saturating_sub(height))
        });
        let start = end.saturating_sub(height);
        f.render_widget(Paragraph::new(lines[start..end].to_vec()), history);
        let prompt = self.status_line(now);
        let mut horizontal = 0;
        if !self.busy() && status.width > 0 && status.height > 0 {
            let end = prompt.width().min(u16::MAX as usize) as u16;
            if self.command.is_some() {
                horizontal = end.saturating_sub(status.width.saturating_sub(1));
            }
            f.set_cursor_position((
                status.x + (end - horizontal).min(status.width - 1),
                status.y,
            ));
        }
        f.render_widget(Paragraph::new(prompt).scroll((0, horizontal)), status);
        let shortcuts = if self.command.is_some() {
            Line::from(" ↑↓ select · Enter run · Tab complete · Esc cancel")
        } else {
            self.footer()
        };
        f.render_widget(Paragraph::new(shortcuts), footer);
    }

    /// The action a key starts, if any.
    pub fn action_for(key: &KeyEvent) -> Option<&'static str> {
        if scope_shortcut(key) {
            return Some("scope");
        }
        match key.code {
            KeyCode::Char('c') => Some("connect"),
            KeyCode::Char('u') => Some("unlock"),
            KeyCode::Char('l') => Some("locations"),
            KeyCode::Char('p') => Some("settings"),
            KeyCode::Char('e') => Some("setup"),
            KeyCode::Char('d') => Some("disconnect"),
            KeyCode::Char('h') => Some("hops"),
            KeyCode::Char('s') => Some("status"),
            KeyCode::Char('i') => Some("info"),
            KeyCode::Char('o') => Some("doctor"),
            KeyCode::Char('k') => Some("lockdown"),
            KeyCode::Char('m') => Some("scope"),
            _ => None,
        }
    }

    fn command_key(&mut self, key: &KeyEvent) -> Option<&'static str> {
        let command = self.command.as_mut()?;
        match key.code {
            KeyCode::Esc => self.command = None,
            KeyCode::Backspace => {
                command.pop();
                self.selected_command = 0;
            }
            KeyCode::Up => self.selected_command = self.selected_command.saturating_sub(1),
            KeyCode::Down => {
                self.selected_command = (self.selected_command + 1)
                    .min(matching_commands(command).count().saturating_sub(1));
            }
            KeyCode::Tab => {
                let selected = matching_commands(command).nth(self.selected_command);
                if let Some((name, _)) = selected {
                    *command = name.into();
                    self.selected_command = 0;
                }
            }
            KeyCode::Enter => {
                let action = matching_commands(command)
                    .nth(self.selected_command)
                    .map(|(name, _)| name);
                if action.is_some() {
                    self.command = None;
                }
                return action;
            }
            KeyCode::Char(c) if command.len() < 64 && (c.is_ascii_lowercase() || c == '-') => {
                command.push(c);
                self.selected_command = 0;
            }
            _ => {}
        }
        None
    }

    /// Handle a key that does not start an action.
    pub fn key(&mut self, key: &KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('?') => self.history.push(Cell::Result {
                title: "Keys".into(),
                summary: Some("every action is also a command".into()),
                rows: KEYS
                    .iter()
                    .map(|(k, l)| Row::pair(*k, *l))
                    .chain([
                        Row::pair("PgUp/PgDn", "scroll"),
                        Row::pair("reference", "cypherpunk help TOPIC"),
                    ])
                    .collect(),
            }),
            KeyCode::PageUp => self.scroll += 10,
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            _ => {}
        }
    }
}

/// Run the interactive view until the user quits.
pub fn run(ctrl: Controller, theme: Theme, reduced_motion: bool) -> Result<()> {
    let mut header = Header::from_info(&Value::Null);
    header.guidance = Some("Reading local enrollment and VPN status…");
    let mut app = App::new(theme, reduced_motion, header);
    let mut first_refresh = true;
    let (tx, rx): (Sender<Finished>, Receiver<Finished>) = channel();
    let (header_tx, header_rx) = channel();
    let mut refreshing = false;
    let mut revision = 0;
    let mut next_refresh = Instant::now();
    let mut terminal = ratatui::try_init()?;
    let result = (|| -> Result<()> {
        use ratatui::crossterm::cursor::{SetCursorStyle, Show};
        ratatui::crossterm::execute!(std::io::stdout(), SetCursorStyle::BlinkingBar)?;
        while !app.quit {
            terminal.draw(|f| app.draw(f, Instant::now()))?;
            if let Ok((refresh, done)) = rx.try_recv() {
                app.finish(done);
                if refresh {
                    revision += 1;
                    if let Ok(o) = ctrl.call("info", &[]) {
                        app.header = Header::from_info(&o.value);
                    }
                }
            }
            if let Ok((observed_revision, header)) = header_rx.try_recv() {
                if observed_revision == revision
                    && let Some(header) = header
                {
                    app.header = header;
                    if first_refresh && app.header.chain == "not enrolled" {
                        app.history.push(get_started());
                    }
                    first_refresh = false;
                }
                refreshing = false;
            }
            if !app.busy() && !refreshing && Instant::now() >= next_refresh {
                refreshing = true;
                next_refresh = Instant::now() + Duration::from_secs(2);
                let (ctrl, header_tx) = (ctrl.clone(), header_tx.clone());
                std::thread::spawn(move || {
                    let header = ctrl
                        .call("info", &[])
                        .ok()
                        .map(|o| Header::from_info(&o.value));
                    let _ = header_tx.send((revision, header));
                });
            }
            if !event::poll(Duration::from_millis(80))? {
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if !app.busy() && key.code == KeyCode::Char('/') && app.command.is_none() {
                app.command = Some(String::new());
                app.selected_command = 0;
                continue;
            }
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                app.key(&key);
                continue;
            }
            let shortcut = App::action_for(&key);
            let action = if scope_shortcut(&key) {
                app.command = None;
                shortcut
            } else if app.command.is_some() {
                match app.command_key(&key) {
                    Some("quit") => {
                        app.quit = true;
                        continue;
                    }
                    Some("help") => {
                        app.key(&KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
                        continue;
                    }
                    Some(action) => Some(action),
                    None => continue,
                }
            } else {
                shortcut
            };
            match action {
                Some(_)
                    if key.modifiers.contains(KeyModifiers::CONTROL) && !scope_shortcut(&key) =>
                {
                    app.key(&key)
                }
                Some(action) if !app.busy() && terminal_action(action) => {
                    ratatui::try_restore()?;
                    ratatui::crossterm::execute!(
                        std::io::stdout(),
                        SetCursorStyle::BlinkingBar,
                        Show
                    )?;
                    let result = run_terminal_action(&ctrl, action, theme, reduced_motion);
                    terminal = ratatui::try_init()?;
                    result?;
                    revision += 1;
                    if let Ok(o) = ctrl.call("info", &[]) {
                        app.header = Header::from_info(&o.value);
                    }
                    next_refresh = Instant::now();
                }
                Some(action) if !app.busy() => {
                    app.start(action);
                    let (ctrl, tx) = (ctrl.clone(), tx.clone());
                    let refresh = matches!(action, "connect" | "disconnect" | "info" | "status");
                    std::thread::spawn(move || {
                        let _ = tx.send((refresh, perform(&ctrl, action, &[])));
                    });
                }
                Some(_) => {}
                None => app.key(&key),
            }
        }
        Ok(())
    })();
    ratatui::restore();
    let cursor = ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::cursor::SetCursorStyle::DefaultUserShape
    );
    result?;
    cursor?;
    Ok(())
}

fn terminal_action(action: &str) -> bool {
    matches!(
        action,
        "setup"
            | "unlock"
            | "locations"
            | "settings"
            | "killswitch-disarm"
            | "lockdown"
            | "scope"
            | "applications"
    ) || (action == "connect" && is_root())
}

fn run_terminal_action(
    ctrl: &Controller,
    action: &str,
    theme: Theme,
    reduced_motion: bool,
) -> Result<()> {
    match action {
        "setup" => guided::setup(ctrl, theme, reduced_motion)?,
        "locations" => guided::locations(ctrl, theme)?,
        "settings" => guided::settings(ctrl, theme)?,
        "lockdown" => guided::lockdown(ctrl, theme)?,
        "scope" => guided::switch_scope(ctrl, theme)?,
        "applications" => guided::applications(ctrl, theme)?,
        "killswitch-disarm" => guided::disarm(ctrl, theme)?,
        "unlock" if !is_root() => {
            println!("Run sudo cypherpunk and press u, or run sudo cypherpunk unlock here.")
        }
        "unlock" => {
            if ctrl.command(false, "unlock", &[]).status()?.success() {
                return Ok(());
            }
        }
        "connect" if guided::connect(ctrl, theme)? => return Ok(()),
        "connect" => {}
        _ => unreachable!(),
    }
    guided::prompt("\nPress Enter to return to the VPN view. ")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use serde_json::json;

    fn screen(app: &App, w: u16, h: u16) -> Vec<String> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        let now = app.started;
        term.draw(|f| app.draw(f, now)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn header() -> Header {
        Header::from_info(&json!({"ok": true, "info": {
            "enrolled": true, "role": "client", "hops": 2, "protection": "nitrokey",
            "mode": "applications", "defense": "strong", "rate": "fast",
            "chain": [{"hop": "relay", "endpoint": "192.0.2.1:41194"}, {"hop": "exit", "endpoint": "198.51.100.2:4444"}],
            "status": {"state": "supervising"}}}))
    }

    #[test]
    fn snapshot_empty_session() {
        let app = App::new(Theme::full(), true, header());
        let s = screen(&app, 90, 14);
        let v = env!("CARGO_PKG_VERSION");
        let title = format!("│ >_ CYPHERPUNK VPN (v{v})");
        assert_eq!(s[0].chars().next(), Some('╭'));
        assert!(s[1].starts_with(&title), "{s:#?}");
        assert!(
            s[3].starts_with("│ chain:      client → relay → exit"),
            "{s:#?}"
        );
        let right = s[0].chars().count();
        assert!(
            s[1..6]
                .iter()
                .all(|l| l.chars().count() == right && l.ends_with('│')),
            "{s:#?}"
        );
        assert!(
            s[4].starts_with("│ mode:       applications · rate fast"),
            "{s:#?}"
        );
        assert!(
            s[5].starts_with("│ protection: nitrokey · service supervising"),
            "{s:#?}"
        );
        assert!(s[6].starts_with('╰'));
        assert!(s[8].contains("Press a key below"));
        assert_eq!(
            s[13],
            " / commands · k kill switch · m scope · c connect · p settings · e setup · d stop · q quit"
        );
    }

    #[test]
    fn snapshot_history_and_spinner() {
        let mut app = App::new(Theme::full(), true, header());
        app.start("hops");
        let s = screen(&app, 90, 14);
        assert_eq!(s[8], "$ cypherpunk hops");
        assert!(s[12].starts_with(" • Working on hops (0s)"), "{s:#?}");
        app.finish(Done {
            code: 0,
            cells: vec![Cell::Result {
                title: "Chain".into(),
                summary: Some("2-hop".into()),
                rows: vec![Row::detail(
                    "client → relay 192.0.2.1:41194 → exit 198.51.100.2:4444",
                )],
            }],
        });
        let s = screen(&app, 90, 14);
        assert_eq!(
            &s[8..12],
            [
                "$ cypherpunk hops",
                "",
                "• Chain  2-hop",
                "  └ client → relay 192.0.2.1:41194 → exit 198.51.100.2:4444"
            ]
        );
        assert_eq!(s[12], "");
    }

    #[test]
    fn history_is_bottom_anchored_and_scrolls() {
        let mut app = App::new(Theme::plain(), true, header());
        for i in 0..30 {
            app.history.push(Cell::Command(format!("cypherpunk n{i}")));
        }
        let s = screen(&app, 60, 14);
        assert_eq!(s[11], "$ cypherpunk n29");
        assert_eq!(s[10], "");
        app.scroll = 2;
        let s = screen(&app, 60, 14);
        assert_eq!(s[11], "$ cypherpunk n28");
        // Scrolling past the top clamps to the first entry.
        app.scroll = 10_000;
        let s = screen(&app, 60, 14);
        assert_eq!(&s[7..9], ["", "$ cypherpunk n0"]);
    }

    #[test]
    fn keys_map_to_actions_and_quit() {
        let k = |c| KeyEvent::from(KeyCode::Char(c));
        assert_eq!(App::action_for(&k('h')), Some("hops"));
        assert_eq!(App::action_for(&k('u')), Some("unlock"));
        assert_eq!(App::action_for(&k('e')), Some("setup"));
        assert_eq!(App::action_for(&k('x')), None);
        let mut app = App::new(Theme::plain(), true, Header::default());
        app.key(&k('?'));
        assert!(matches!(&app.history[0], Cell::Result { title, .. } if title == "Keys"));
        app.key(&k('q'));
        assert!(app.quit);
    }

    #[test]
    fn enter_runs_a_unique_prefix_and_arrow_keys_choose_among_matches() {
        let mut app = App::new(Theme::plain(), true, Header::default());
        app.command = Some("sett".into());
        assert_eq!(app.command_key(&KeyCode::Enter.into()), Some("settings"));
        app.command = Some("s".into());
        app.command_key(&KeyCode::Down.into());
        assert_eq!(app.command_key(&KeyCode::Enter.into()), Some("status"));
        assert_eq!(
            App::action_for(&KeyEvent::new(
                KeyCode::BackTab,
                KeyModifiers::CONTROL | KeyModifiers::SHIFT
            )),
            Some("scope")
        );
    }

    #[test]
    fn spinner_respects_reduced_motion() {
        let mut moving = App::new(Theme::plain(), false, Header::default());
        moving.start("doctor");
        let later = moving.started + Duration::from_millis(160);
        let frame = moving.status_line(later).spans[0].content.to_string();
        assert_eq!(frame, " ⠹ ");
        let mut still = App::new(Theme::plain(), true, Header::default());
        still.start("doctor");
        assert_eq!(still.status_line(later).spans[0].content, " • ");
    }

    #[test]
    fn get_started_lists_free_endpoints_and_the_next_commands() {
        let app = {
            let mut a = App::new(
                Theme::plain(),
                true,
                Header::from_info(&json!({"info": {"enrolled": false}})),
            );
            a.history.push(get_started());
            a
        };
        let text = screen(&app, 110, 24).join("\n");
        for expected in [
            "• Get started  this device is not enrolled yet",
            "Oracle Cloud: no expiry",
            "10 TiB/month out",
            "cypherpunk cloud suggest",
            "cypherpunk cloud chain --apply",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
    }

    #[test]
    fn unknown_info_falls_back_cleanly() {
        let h = Header::from_info(&json!({"ok": false}));
        assert_eq!(h.chain, "unknown");
        assert_eq!(h.status, "unknown");
    }

    #[test]
    fn narrow_view_shows_each_hop_location_without_a_painted_background() {
        let header = Header::from_info(&json!({"info": {"enrolled": true, "chain": [
            {"hop": "relay", "city": "Dubai", "country": "United Arab Emirates"},
            {"hop": "middle", "city": null, "country": null},
            {"hop": "exit", "city": "Frankfurt", "country": "Germany", "primary": true}
        ]}}));
        let app = App::new(Theme::full(), true, header);
        let mut terminal = Terminal::new(TestBackend::new(48, 17)).unwrap();
        terminal.draw(|f| app.draw(f, app.started)).unwrap();
        let buffer = terminal.backend().buffer();
        let screen = screen(&app, 48, 17).join("\n");
        for place in [
            "Dubai, United Arab Emirates",
            "middle  Unknown",
            "primary exit  Frankfurt, Germany",
        ] {
            assert!(screen.contains(place), "{screen}");
        }
        assert!(
            buffer
                .content
                .iter()
                .all(|cell| cell.bg == ratatui::style::Color::Reset)
        );
    }

    #[test]
    fn connection_hint_names_the_waiting_step() {
        let view =
            |status| Header::from_info(&json!({"info": {"enrolled": true, "status": status}}));
        let pin = view(json!({"state": "waiting for the Nitrokey PIN"}));
        assert!(pin.guidance.unwrap().contains("Press u"));
        let path = view(
            json!({"state": "supervising", "lifecycle": "connecting", "stale": {"probe": null}}),
        );
        assert_eq!(path.status, "connecting");
        assert!(path.guidance.unwrap().contains("Exit DNS check"));
    }

    #[test]
    fn connected_header_displays_the_live_scope_while_a_preference_is_pending() {
        let header = Header::from_info(&json!({"info": {
            "enrolled": true, "mode": "whole-device",
            "status": {"state": "supervising", "lifecycle": "connected",
                       "protection": "protected", "scope": "applications"}
        }}));
        assert_eq!(header.mode, "applications");
        let app = App::new(Theme::full(), true, header);
        let rendered = screen(&app, 100, 17).join("\n");
        assert!(rendered.contains("Only apps started through CYPHERPUNK"));
        assert!(rendered.contains("launch protected apps or m to change scope"));
    }
}
