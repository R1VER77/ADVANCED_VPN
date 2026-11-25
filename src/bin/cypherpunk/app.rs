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
        let mode = match (get("mode"), get("rate")) {
            (Some(m), Some(r)) => format!("{m} · rate {r}"),
            (Some(m), None) => m,
            _ => "—".into(),
        };
        let protection = match (get("protection"), get("creds_key")) {
            (Some(p), Some(k)) => format!("{p} ({k})"),
            (Some(p), None) => p,
            _ => "—".into(),
        };
        let state = &i["status"];
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
            .filter(|(k, _)| !matches!(*k, "h" | "s" | "i" | "o"))
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
        if self.history.is_empty() {
            lines.push(Line::from(Span::styled(
                "  Press a key below. Every action is also a command: cypherpunk help",
                self.theme.dim(),
            )));
        }
        lines.extend(render(&self.history, self.theme));
        let height = history.height as usize;
        let end = lines
            .len()
            .saturating_sub(self.scroll.min(lines.len().saturating_sub(height)));
        let start = end.saturating_sub(height);
        f.render_widget(Paragraph::new(lines[start..end].to_vec()), history);
        f.render_widget(Paragraph::new(self.status_line(now)), status);
        f.render_widget(Paragraph::new(self.footer()), footer);
    }

    /// The action a key starts, if any.
    pub fn action_for(key: &KeyEvent) -> Option<&'static str> {
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
            _ => None,
        }
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
    let header = ctrl
        .call("info", &[])
        .map(|o| Header::from_info(&o.value))
        .unwrap_or_default();
    let mut app = App::new(theme, reduced_motion, header);
    if app.header.chain == "not enrolled" {
        app.history.push(get_started());
    }
    let (tx, rx): (Sender<Finished>, Receiver<Finished>) = channel();
    let (header_tx, header_rx) = channel();
    let mut refreshing = false;
    let mut next_refresh = Instant::now() + Duration::from_secs(2);
    let mut terminal = ratatui::try_init()?;
    let result = (|| -> Result<()> {
        while !app.quit {
            terminal.draw(|f| app.draw(f, Instant::now()))?;
            if let Ok((refresh, done)) = rx.try_recv() {
                app.finish(done);
                if refresh && let Ok(o) = ctrl.call("info", &[]) {
                    app.header = Header::from_info(&o.value);
                }
            }
            if let Ok(header) = header_rx.try_recv() {
                if let Some(header) = header {
                    app.header = header;
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
                    let _ = header_tx.send(header);
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
            match App::action_for(&key) {
                Some(_) if key.modifiers.contains(KeyModifiers::CONTROL) => app.key(&key),
                Some(action) if !app.busy() && terminal_action(action, &app.header) => {
                    ratatui::try_restore()?;
                    ratatui::crossterm::execute!(
                        std::io::stdout(),
                        ratatui::crossterm::cursor::Show
                    )?;
                    let result = run_terminal_action(&ctrl, action, theme, reduced_motion);
                    terminal = ratatui::try_init()?;
                    result?;
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
    result
}

fn terminal_action(action: &str, header: &Header) -> bool {
    matches!(action, "setup" | "unlock" | "locations" | "settings")
        || (action == "connect" && is_root() && header.protection.starts_with("nitrokey"))
}

fn run_terminal_action(
    ctrl: &Controller,
    action: &str,
    theme: Theme,
    reduced_motion: bool,
) -> Result<()> {
    match action {
        "setup" => guided::setup(ctrl, theme, reduced_motion)?,
        "locations" => guided::locations(ctrl)?,
        "settings" => guided::settings(ctrl, theme)?,
        "unlock" if !is_root() => {
            println!("Run sudo cypherpunk and press u, or run sudo cypherpunk unlock here.")
        }
        "unlock" => {
            ctrl.command(false, "unlock", &[]).status()?;
        }
        "connect" => {
            println!("Starting the VPN service…");
            let started = perform(ctrl, "connect", &[]);
            for line in render(&started.cells, theme) {
                println!("{}", crate::theme::to_ansi(&[line], theme).trim_end());
            }
            if started.code == 0 {
                ctrl.command(false, "unlock", &["--if-needed".into()])
                    .status()?;
            }
        }
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
            " c connect · u unlock · l locations · p settings · e setup · d stop · ? help · q quit"
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
        assert!(path.guidance.unwrap().contains("end-to-end"));
    }
}
