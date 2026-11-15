//! A long operation as a live checklist, in the style of a task panel: every step
//! listed up front, a turning arc on the one running, a tick when it is done, a dotted
//! circle for those still to come, a cross with the reason when one fails, and a
//! diamond when a step waits for the person (a PIN, a touch). It is fed by the cloud
//! tool's structured progress events (`AVPN_PROGRESS=events`) and redrawn in place.

use std::time::{Duration, Instant};

use ratatui::text::{Line, Span};
use serde_json::Value;

use crate::theme::Theme;

/// The arc turns a quarter every frame.
const ARC: [&str; 4] = ["◜", "◝", "◞", "◟"];
const FRAME: Duration = Duration::from_millis(120);

#[derive(Clone, Debug, PartialEq)]
enum State {
    Pending,
    Running {
        since: Instant,
        note: Option<String>,
    },
    Waiting {
        since: Instant,
        note: String,
    },
    Done {
        took: Duration,
    },
    Failed {
        note: String,
    },
}

/// The steps of one operation and where each one is.
#[derive(Clone, Debug)]
pub struct Checklist {
    steps: Vec<(String, State)>,
    reduced_motion: bool,
}

impl Checklist {
    /// An empty list; the first event carries the plan.
    pub fn new(reduced_motion: bool) -> Self {
        Self {
            steps: Vec::new(),
            reduced_motion,
        }
    }

    /// Apply one progress event: `{"plan": [..]}` or `{"step": i, "state": .., "note": ..}`.
    pub fn apply(&mut self, event: &Value, now: Instant) {
        if let Some(plan) = event.get("plan").and_then(Value::as_array) {
            self.steps = plan
                .iter()
                .map(|s| (s.as_str().unwrap_or_default().to_string(), State::Pending))
                .collect();
            return;
        }
        let Some(i) = event.get("step").and_then(Value::as_u64) else {
            return;
        };
        let Some((_, state)) = self.steps.get_mut(i as usize) else {
            return;
        };
        let note = event
            .get("note")
            .and_then(Value::as_str)
            .map(str::to_string);
        let since = match state {
            State::Running { since, .. } | State::Waiting { since, .. } => *since,
            _ => now,
        };
        *state = match event.get("state").and_then(Value::as_str) {
            Some("run") => State::Running { since, note },
            Some("wait") => State::Waiting {
                since,
                note: note.unwrap_or_default(),
            },
            Some("done") => State::Done {
                took: now.saturating_duration_since(since),
            },
            Some("fail") => State::Failed {
                note: note.unwrap_or_default(),
            },
            _ => return,
        };
    }

    /// Whether a step is turning (so the view should keep redrawing).
    pub fn animating(&self) -> bool {
        !self.reduced_motion
            && self
                .steps
                .iter()
                .any(|(_, s)| matches!(s, State::Running { .. }))
    }

    /// Whether a step waits for the person.
    pub fn waiting(&self) -> bool {
        self.steps
            .iter()
            .any(|(_, s)| matches!(s, State::Waiting { .. }))
    }

    /// Number of steps.
    pub fn height(&self) -> usize {
        self.steps.len()
    }

    /// The checklist as styled lines at `now` (`start` paces the arc), unclipped.
    #[cfg(test)]
    pub fn lines(&self, start: Instant, now: Instant, theme: Theme) -> Vec<Line<'static>> {
        self.groups(start, now, theme)
            .into_iter()
            .flatten()
            .collect()
    }

    /// The lines of each step: one, or two for a step that waits for the person (what
    /// to do goes on its own line, so a narrow terminal cannot cut it off).
    fn groups(&self, start: Instant, now: Instant, theme: Theme) -> Vec<Vec<Line<'static>>> {
        let t = theme;
        let width = self
            .steps
            .iter()
            .map(|(s, _)| s.chars().count())
            .max()
            .unwrap_or(0);
        let frame = (now.saturating_duration_since(start).as_millis() / FRAME.as_millis()) as usize;
        self.steps
            .iter()
            .map(|(text, state)| {
                let pad = " ".repeat(width.saturating_sub(text.chars().count()) + 2);
                let mut spans = vec![Span::raw("  ")];
                let mut below = None;
                match state {
                    State::Pending => {
                        spans.push(Span::styled("◌ ", t.dim()));
                        spans.push(Span::styled(text.clone(), t.dim()));
                    }
                    State::Running { since, note } => {
                        let mark = if self.reduced_motion {
                            "•"
                        } else {
                            ARC[frame % ARC.len()]
                        };
                        spans.push(Span::styled(format!("{mark} "), t.accent()));
                        spans.push(Span::styled(text.clone(), t.bold()));
                        spans.push(Span::raw(pad));
                        spans.push(Span::styled(
                            format!("{}s", now.saturating_duration_since(*since).as_secs()),
                            t.dim(),
                        ));
                        if let Some(n) = note {
                            spans.push(Span::styled(format!("  {n}"), t.dim()));
                        }
                    }
                    State::Waiting { note, .. } => {
                        spans.push(Span::styled("◆ ", t.accent()));
                        spans.push(Span::styled(text.clone(), t.bold()));
                        below = Some(Line::from(vec![
                            Span::styled("    └ ", t.dim()),
                            Span::styled(note.clone(), t.accent()),
                        ]));
                    }
                    State::Done { took } => {
                        spans.push(Span::styled("✓ ", t.success()));
                        spans.push(Span::raw(text.clone()));
                        spans.push(Span::raw(pad));
                        spans.push(Span::styled(format!("{}s", took.as_secs()), t.dim()));
                    }
                    State::Failed { note } => {
                        spans.push(Span::styled("✗ ", t.error()));
                        spans.push(Span::raw(text.clone()));
                        spans.push(Span::raw(pad));
                        spans.push(Span::styled(note.clone(), t.error()));
                    }
                }
                let mut group = vec![Line::from(spans)];
                group.extend(below);
                group
            })
            .collect()
    }

    /// What fits a terminal of `rows` x `cols`: no line wider than the terminal (a
    /// wrapped line would throw off the redraw by a row), and when the list is taller
    /// than the terminal, only a window around the step in progress (the rows above it
    /// scroll away and could no longer be redrawn). Same height on every call for the
    /// same terminal, so a redraw always covers exactly the previous one.
    pub fn view(
        &self,
        start: Instant,
        now: Instant,
        theme: Theme,
        rows: usize,
        cols: usize,
    ) -> Vec<Line<'static>> {
        let groups = self.groups(start, now, theme);
        let active = self
            .steps
            .iter()
            .position(|(_, s)| !matches!(s, State::Done { .. }))
            .unwrap_or(groups.len().saturating_sub(1));
        // The row of the step before the active one: the window starts there.
        let lead: usize = groups
            .iter()
            .take(active.saturating_sub(1))
            .map(Vec::len)
            .sum();
        let all: Vec<Line<'static>> = groups.into_iter().flatten().collect();
        let room = rows.saturating_sub(1).max(1);
        let lines = if all.len() <= room {
            all
        } else {
            let first = lead.min(all.len() - room);
            let last = first + room;
            let mut window: Vec<Line<'static>> = all[first..last].to_vec();
            if first > 0 && room > 2 {
                window[0] = Line::from(Span::styled(
                    format!("  ⋯ {} done above", first + 1),
                    theme.dim(),
                ));
            }
            if last < all.len() && room > 2 {
                window[room - 1] = Line::from(Span::styled(
                    format!("  ⋯ {} more", all.len() - last + 1),
                    theme.dim(),
                ));
            }
            window
        };
        lines
            .into_iter()
            .map(|l| clip(l, cols.saturating_sub(1).max(1)))
            .collect()
    }
}

/// `line` cut to at most `width` terminal cells.
fn clip(line: Line<'static>, width: usize) -> Line<'static> {
    let mut left = width;
    let mut spans = Vec::new();
    for span in line.spans {
        let w = span.width();
        if w <= left {
            left -= w;
            spans.push(span);
            continue;
        }
        let mut cut = String::new();
        for ch in span.content.chars() {
            let cw = Span::raw(ch.to_string()).width();
            if cw > left {
                break;
            }
            left -= cw;
            cut.push(ch);
        }
        spans.push(Span::styled(cut, span.style));
        break;
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::Checklist;
    use crate::theme::Theme;
    use serde_json::json;
    use std::time::{Duration, Instant};

    fn text(c: &Checklist, start: Instant, now: Instant) -> Vec<String> {
        c.lines(start, now, Theme::plain())
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn steps_move_from_pending_through_running_to_done() {
        let t0 = Instant::now();
        let mut c = Checklist::new(false);
        c.apply(
            &json!({"plan": ["Open the firewalls", "Sign the chain", "Close SSH"]}),
            t0,
        );
        assert_eq!(
            text(&c, t0, t0),
            [
                "  ◌ Open the firewalls",
                "  ◌ Sign the chain",
                "  ◌ Close SSH"
            ]
        );
        c.apply(&json!({"step": 0, "state": "run"}), t0);
        let t1 = t0 + Duration::from_secs(3);
        // 3 s at 120 ms a frame is frame 25: the arc's second position.
        assert_eq!(text(&c, t0, t1)[0], "  ◝ Open the firewalls  3s");
        assert!(c.animating());
        c.apply(&json!({"step": 0, "state": "done"}), t1);
        c.apply(&json!({"step": 1, "state": "run"}), t1);
        c.apply(&json!({"step": 1, "state": "wait", "note": "enter the Nitrokey PIN, then touch the key"}), t1);
        let lines = text(&c, t0, t1);
        assert_eq!(lines[0], "  ✓ Open the firewalls  3s");
        assert_eq!(lines[1], "  ◆ Sign the chain");
        assert_eq!(lines[2], "    └ enter the Nitrokey PIN, then touch the key");
        assert_eq!(lines[3], "  ◌ Close SSH");
        assert!(c.waiting() && !c.animating());
    }

    #[test]
    fn a_step_that_waited_reports_its_whole_time() {
        let t0 = Instant::now();
        let mut c = Checklist::new(false);
        c.apply(&json!({"plan": ["Sign the chain"]}), t0);
        c.apply(&json!({"step": 0, "state": "run"}), t0);
        let t1 = t0 + Duration::from_secs(1);
        c.apply(&json!({"step": 0, "state": "wait", "note": "PIN"}), t1);
        let t2 = t0 + Duration::from_secs(9);
        c.apply(&json!({"step": 0, "state": "done"}), t2);
        assert_eq!(text(&c, t0, t2), ["  ✓ Sign the chain  9s"]);
    }

    fn view(c: &Checklist, t: Instant, rows: usize, cols: usize) -> Vec<String> {
        c.view(t, t, Theme::plain(), rows, cols)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    fn long_list(t0: Instant) -> Checklist {
        let mut c = Checklist::new(false);
        let plan: Vec<String> = (0..8).map(|i| format!("Step number {i}")).collect();
        c.apply(&json!({ "plan": plan }), t0);
        for i in 0..5 {
            c.apply(&json!({"step": i, "state": "done"}), t0);
        }
        c.apply(&json!({"step": 5, "state": "wait", "note": "enter the Nitrokey PIN, then touch the key"}), t0);
        c
    }

    #[test]
    fn no_line_is_wider_than_the_terminal() {
        // A line that wraps takes two rows, and the next redraw lands a row short:
        // the top line was printed twice in a 60-column terminal.
        let t0 = Instant::now();
        let c = long_list(t0);
        for cols in [20, 40, 60] {
            for line in view(&c, t0, 50, cols) {
                assert!(
                    ratatui::text::Span::raw(line.clone()).width() < cols,
                    "{cols}: {line:?}"
                );
            }
        }
        assert_eq!(
            view(&c, t0, 50, 80).len(),
            9,
            "fits: every step plus the note"
        );
    }

    #[test]
    fn a_short_terminal_shows_a_window_around_the_step_in_progress() {
        // Rows that scroll off cannot be redrawn: a 6-row terminal printed the top
        // line 108 times. The view never uses more than rows - 1.
        let t0 = Instant::now();
        let c = long_list(t0);
        assert_eq!(
            view(&c, t0, 6, 80),
            [
                "  ⋯ 5 done above",
                "  ◆ Step number 5",
                "    └ enter the Nitrokey PIN, then touch the key",
                "  ◌ Step number 6",
                "  ◌ Step number 7",
            ]
        );
        for rows in 1..12 {
            assert!(view(&c, t0, rows, 80).len() <= rows.saturating_sub(1).max(1));
        }
    }

    #[test]
    fn a_failure_shows_its_reason_on_its_own_line() {
        let t0 = Instant::now();
        let mut c = Checklist::new(false);
        c.apply(&json!({"plan": ["Install avpn-exit", "Sign"]}), t0);
        c.apply(&json!({"step": 0, "state": "run"}), t0);
        c.apply(
            &json!({"step": 0, "state": "fail", "note": "no systemd-creds"}),
            t0,
        );
        assert_eq!(
            text(&c, t0, t0)[0],
            "  ✗ Install avpn-exit  no systemd-creds"
        );
        assert_eq!(text(&c, t0, t0)[1], "  ◌ Sign");
    }

    #[test]
    fn the_arc_turns_and_reduced_motion_holds_it_still() {
        let t0 = Instant::now();
        let mut c = Checklist::new(false);
        c.apply(&json!({"plan": ["Install"]}), t0);
        c.apply(&json!({"step": 0, "state": "run"}), t0);
        let marks: Vec<String> = (0..4)
            .map(|k| text(&c, t0, t0 + Duration::from_millis(120 * k))[0][2..5].to_string())
            .collect();
        assert_eq!(marks, ["◜", "◝", "◞", "◟"]);
        let mut still = Checklist::new(true);
        still.apply(&json!({"plan": ["Install"]}), t0);
        still.apply(&json!({"step": 0, "state": "run"}), t0);
        assert!(text(&still, t0, t0 + Duration::from_secs(1))[0].starts_with("  • Install"));
        assert!(!still.animating());
    }

    #[test]
    fn unknown_or_out_of_range_events_change_nothing() {
        let t0 = Instant::now();
        let mut c = Checklist::new(false);
        c.apply(&json!({"plan": ["A"]}), t0);
        c.apply(&json!({"step": 7, "state": "run"}), t0);
        c.apply(&json!({"step": 0, "state": "explode"}), t0);
        c.apply(&json!({"other": 1}), t0);
        assert_eq!(text(&c, t0, t0), ["  ◌ A"]);
    }
}
