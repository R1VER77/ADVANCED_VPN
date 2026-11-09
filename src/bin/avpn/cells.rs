//! History cells: the unit of output, in the Codex transcript format.
//!
//! A result starts with `•` and a bold title, followed by an optional dim summary.
//! Its details continue under `└`. Doctor checks use `✓` and `✗`, and errors start
//! with a red `■`. The same cells are printed by one-shot commands and shown in the
//! interactive history, so both look identical.

use ratatui::text::{Line, Span};
use serde_json::Value;

use crate::controller::Outcome;
use crate::theme::Theme;

/// How a detail row is marked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// A passing check (`✓`, green).
    Pass,
    /// A failing check (`✗`, red).
    Fail,
    /// A plain detail line under `└`.
    Detail,
}

/// One detail row: a mark, a label and an optional dim value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Its mark.
    pub mark: Mark,
    /// The main text.
    pub label: String,
    /// Secondary text, shown dim after the label.
    pub value: Option<String>,
}

impl Row {
    /// A plain detail.
    pub fn detail(label: impl Into<String>) -> Self {
        Self {
            mark: Mark::Detail,
            label: label.into(),
            value: None,
        }
    }

    /// A `label  value` pair, aligned by the renderer.
    pub fn pair(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            mark: Mark::Detail,
            label: label.into(),
            value: Some(value.into()),
        }
    }

    /// A check result.
    pub fn check(ok: bool, label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            mark: if ok { Mark::Pass } else { Mark::Fail },
            label: label.into(),
            value: Some(value.into()),
        }
    }
}

/// One entry in the history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cell {
    /// The command the user ran, shown `$`-prefixed.
    Command(String),
    /// A result: `• title  summary`, then rows.
    Result {
        /// Bold title.
        title: String,
        /// Dim text after the title.
        summary: Option<String>,
        /// Detail rows.
        rows: Vec<Row>,
    },
    /// A failure: `■ title`, then dim hints.
    Error {
        /// What failed.
        title: String,
        /// How to fix it.
        hints: Vec<String>,
    },
}

impl Cell {
    /// The styled lines of this cell. Pair labels in one cell share a column.
    pub fn lines(&self, t: Theme) -> Vec<Line<'static>> {
        match self {
            Cell::Command(cmd) => vec![Line::from(vec![
                Span::styled("$ ", t.dim()),
                Span::styled(cmd.clone(), t.accent()),
            ])],
            Cell::Result {
                title,
                summary,
                rows,
            } => {
                let mut head = vec![
                    Span::styled("• ", t.dim()),
                    Span::styled(title.clone(), t.bold()),
                ];
                if let Some(s) = summary {
                    head.push(Span::styled(format!("  {s}"), t.dim()));
                }
                let mut out = vec![Line::from(head)];
                let width = rows
                    .iter()
                    .filter(|r| r.mark == Mark::Detail && r.value.is_some())
                    .map(|r| r.label.chars().count())
                    .max()
                    .unwrap_or(0);
                let mut first_detail = true;
                for r in rows {
                    let mut spans = Vec::new();
                    match r.mark {
                        Mark::Pass => spans.push(Span::styled("  ✓ ", t.success())),
                        Mark::Fail => spans.push(Span::styled("  ✗ ", t.error())),
                        Mark::Detail => {
                            spans.push(Span::styled(
                                if first_detail { "  └ " } else { "    " },
                                t.dim(),
                            ));
                            first_detail = false;
                        }
                    }
                    match (&r.value, r.mark) {
                        (Some(v), Mark::Detail) => {
                            spans.push(Span::styled(format!("{:<width$}  ", r.label), t.dim()));
                            spans.push(Span::styled(v.clone(), t.text()));
                        }
                        (Some(v), _) => {
                            spans.push(Span::styled(r.label.clone(), t.text()));
                            spans.push(Span::styled(format!("  {v}"), t.dim()));
                        }
                        (None, _) => spans.push(Span::styled(r.label.clone(), t.text())),
                    }
                    out.push(Line::from(spans));
                }
                out
            }
            Cell::Error { title, hints } => {
                let mut out = vec![Line::from(vec![
                    Span::styled("■ ", t.error()),
                    Span::styled(title.clone(), t.error().patch(t.bold())),
                ])];
                for (i, h) in hints.iter().enumerate() {
                    out.push(Line::from(vec![
                        Span::styled(if i == 0 { "  └ " } else { "    " }, t.dim()),
                        Span::styled(h.clone(), t.dim()),
                    ]));
                }
                out
            }
        }
    }
}

/// Lines for several cells, separated by one blank line as in the Codex transcript.
pub fn render(cells: &[Cell], t: Theme) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for (i, c) in cells.iter().enumerate() {
        if i > 0 {
            out.push(Line::default());
        }
        out.extend(c.lines(t));
    }
    out
}

fn s(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::Null => None,
        Value::String(x) => Some(x.clone()),
        other => Some(other.to_string()),
    }
}

/// `client → relay 1.2.3.4:41194 → exit 5.6.7.8:4444`
pub fn chain_text(chain: &Value) -> Option<String> {
    let hops = chain.as_array().filter(|a| !a.is_empty())?;
    let mut parts = vec!["client".to_string()];
    for h in hops {
        parts.push(format!("{} {}", s(h, "hop")?, s(h, "endpoint")?));
    }
    Some(parts.join(" → "))
}

/// `client → relay → exit`, for the header.
pub fn chain_short(chain: &Value) -> Option<String> {
    let hops = chain.as_array().filter(|a| !a.is_empty())?;
    let mut parts = vec!["client".to_string()];
    for h in hops {
        parts.push(s(h, "hop")?);
    }
    Some(parts.join(" → "))
}

fn title_case(action: &str) -> String {
    let mut c = action.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

/// A hint for a failure, from the controller's error type and stderr.
fn hints(action: &str, o: &Outcome) -> Vec<String> {
    let error = s(&o.value, "error").unwrap_or_default();
    let mut out = Vec::new();
    match error.as_str() {
        "PermissionError" => out.push(format!("needs root: sudo avpn {action}")),
        "FileNotFoundError" => out.push("a file it needs is missing; see avpn doctor".to_string()),
        "NoJsonFromController" => {
            out.push("the controller printed no result; is it installed?".to_string())
        }
        _ => {}
    }
    if let Some(line) = o.stderr.lines().rev().find(|l| !l.trim().is_empty()) {
        out.push(line.trim().to_string());
    }
    out.push(format!("avpn help {action}"));
    out
}

/// Status rows from a status object.
pub fn status_rows(st: &Value) -> Vec<Row> {
    let mut rows = Vec::new();
    if let Some(k) = st.get("kill_switch").and_then(Value::as_bool) {
        rows.push(Row::pair(
            "kill switch",
            if k { "in place" } else { "removed" },
        ));
    }
    if let Some(r) = s(st, "reason") {
        rows.push(Row::pair("reason", r));
    }
    if let Some(l) = st.get("daily_limit_bytes").and_then(Value::as_u64) {
        rows.push(Row::pair("daily limit", format!("{} MiB", l >> 20)));
    }
    if let Some(children) = st.get("children").and_then(Value::as_object) {
        for (name, c) in children {
            let alive = c.get("alive").and_then(Value::as_bool).unwrap_or(false);
            let pid = s(c, "pid").unwrap_or_else(|| "?".into());
            rows.push(Row::check(alive, name.clone(), format!("pid {pid}")));
        }
    }
    rows
}

/// Turn a controller result into cells.
pub fn from_outcome(action: &str, o: &Outcome) -> Vec<Cell> {
    let v = &o.value;
    if !o.ok() {
        let error = s(v, "error").unwrap_or_else(|| "failed".into());
        let mut h = hints(action, o);
        if let Some(m) = s(v, "message").filter(|m| !o.stderr.contains(m.as_str())) {
            h.insert(0, m);
        }
        return vec![Cell::Error {
            title: format!("{action} failed: {error}"),
            hints: h,
        }];
    }
    match action {
        "hops" => {
            let chain = v.get("chain").cloned().unwrap_or(Value::Null);
            match chain_text(&chain) {
                Some(text) => vec![Cell::Result {
                    title: "Chain".into(),
                    summary: s(v, "hops").map(|h| format!("{h}-hop")),
                    rows: vec![Row::detail(text)],
                }],
                None => vec![Cell::Result {
                    title: "Chain".into(),
                    summary: Some("not enrolled".into()),
                    rows: vec![Row::detail("run avpn request, then avpn enroll")],
                }],
            }
        }
        "info" => {
            let i = v.get("info").cloned().unwrap_or(Value::Null);
            let mut rows = Vec::new();
            for (label, key) in [
                ("role", "role"),
                ("hops", "hops"),
                ("protection", "protection"),
                ("mode", "mode"),
                ("defense", "defense"),
            ] {
                if let Some(x) = s(&i, key) {
                    let x = if key == "protection" {
                        s(&i, "creds_key").map_or(x.clone(), |k| format!("{x} ({k})"))
                    } else {
                        x
                    };
                    rows.push(Row::pair(label, x));
                }
            }
            if let Some(c) = i.get("chain").and_then(chain_text) {
                rows.push(Row::pair("chain", c));
            }
            if i.get("role").and_then(Value::as_str) == Some("client") {
                let limit = i.get("daily_limit_bytes").and_then(Value::as_u64);
                rows.push(Row::pair(
                    "daily limit",
                    limit.map_or("none".into(), |l| format!("{} MiB", l >> 20)),
                ));
            }
            if let Some(st) = i.get("status") {
                rows.push(Row::pair(
                    "status",
                    s(st, "state").unwrap_or_else(|| "unknown".into()),
                ));
            }
            rows.push(Row::pair("state", s(&i, "state").unwrap_or_default()));
            let enrolled = i.get("enrolled").and_then(Value::as_bool) == Some(true);
            vec![Cell::Result {
                title: "Device".into(),
                summary: Some(if enrolled {
                    "enrolled".into()
                } else {
                    "not enrolled".into()
                }),
                rows,
            }]
        }
        "status" => {
            let st = v.get("status").cloned().unwrap_or(Value::Null);
            vec![Cell::Result {
                title: "Status".into(),
                summary: Some(s(&st, "state").unwrap_or_else(|| "unknown".into())),
                rows: status_rows(&st),
            }]
        }
        "doctor" => {
            let checks = v
                .get("checks")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let rows: Vec<Row> = checks
                .iter()
                .map(|c| {
                    Row::check(
                        c.get("ok").and_then(Value::as_bool).unwrap_or(false),
                        s(c, "check").unwrap_or_default(),
                        s(c, "detail").unwrap_or_default(),
                    )
                })
                .collect();
            let failed = rows.iter().filter(|r| r.mark == Mark::Fail).count();
            vec![Cell::Result {
                title: "Doctor".into(),
                summary: Some(format!("{} passed · {failed} failed", rows.len() - failed)),
                rows,
            }]
        }
        _ if v.get("rows").is_some_and(Value::is_array) => {
            let rows = v["rows"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|r| {
                    Row::pair(
                        s(r, "label").unwrap_or_default(),
                        s(r, "value").unwrap_or_default(),
                    )
                })
                .collect();
            vec![Cell::Result {
                title: s(v, "title").unwrap_or_else(|| title_case(action)),
                summary: s(v, "summary"),
                rows,
            }]
        }
        _ => {
            let message = s(v, "message").unwrap_or_else(|| "done".into());
            let mut lines = message.lines();
            let first = lines.next().unwrap_or("done").to_string();
            vec![Cell::Result {
                title: title_case(action),
                summary: None,
                rows: std::iter::once(first)
                    .chain(lines.map(str::to_string))
                    .map(Row::detail)
                    .collect(),
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::to_ansi;
    use serde_json::json;

    fn ok(value: Value) -> Outcome {
        Outcome {
            code: 0,
            value,
            stderr: String::new(),
        }
    }

    fn plain(cells: &[Cell]) -> String {
        to_ansi(&render(cells, Theme::plain()), Theme::plain())
    }

    #[test]
    fn hops_renders_the_chain_as_a_path() {
        let o = ok(json!({"ok": true, "hops": 2, "chain": [
            {"hop": "relay", "endpoint": "192.0.2.1:41194"},
            {"hop": "exit", "endpoint": "198.51.100.2:4444"}]}));
        assert_eq!(
            plain(&from_outcome("hops", &o)),
            "• Chain  2-hop\n  └ client → relay 192.0.2.1:41194 → exit 198.51.100.2:4444\n"
        );
    }

    #[test]
    fn doctor_counts_and_marks_checks() {
        let o = ok(json!({"ok": true, "healthy": false, "checks": [
            {"check": "trusted ip", "ok": true, "detail": "/usr/bin/ip"},
            {"check": "running as root", "ok": false, "detail": "privileged checks need root"}]}));
        assert_eq!(
            plain(&from_outcome("doctor", &o)),
            "• Doctor  1 passed · 1 failed\n  ✓ trusted ip  /usr/bin/ip\n  ✗ running as root  privileged checks need root\n"
        );
    }

    #[test]
    fn errors_are_red_squares_with_hints() {
        let o = Outcome {
            code: 1,
            value: json!({"ok": false, "error": "PermissionError"}),
            stderr: "Managed operation stopped: PermissionError.\n".into(),
        };
        assert_eq!(
            plain(&from_outcome("status", &o)),
            "■ status failed: PermissionError\n  └ needs root: sudo avpn status\n    Managed operation stopped: PermissionError.\n    avpn help status\n"
        );
        let colored = to_ansi(
            &render(&from_outcome("status", &o), Theme::full()),
            Theme::full(),
        );
        assert!(
            colored.starts_with("\x1b[31m■ \x1b[0m\x1b[1;31mstatus failed"),
            "{colored:?}"
        );
    }

    #[test]
    fn exit_code_zero_without_ok_true_is_still_a_failure() {
        let o = ok(json!({"ok": false, "error": "ValueError"}));
        assert!(matches!(from_outcome("info", &o)[0], Cell::Error { .. }));
    }

    #[test]
    fn info_aligns_pairs_and_shows_protection_key() {
        let o = ok(json!({"ok": true, "info": {
            "enrolled": true, "role": "client", "hops": 1, "protection": "systemd-creds",
            "creds_key": "host+tpm2", "mode": "applications", "defense": "balanced",
            "chain": [{"hop": "exit", "endpoint": "198.51.100.2:51820"}],
            "daily_limit_bytes": null, "status": {"state": "supervising"}, "state": "/etc/advanced-vpn/enrolled"}}));
        let text = plain(&from_outcome("info", &o));
        assert!(
            text.starts_with("• Device  enrolled\n  └ role         client\n"),
            "{text}"
        );
        assert!(
            text.contains("    protection   systemd-creds (host+tpm2)\n"),
            "{text}"
        );
        assert!(
            text.contains("    chain        client → exit 198.51.100.2:51820\n"),
            "{text}"
        );
        assert!(text.contains("    daily limit  none\n"), "{text}");
    }

    #[test]
    fn other_actions_show_the_message() {
        let o = ok(json!({"ok": true, "message": "Preferences saved."}));
        assert_eq!(
            plain(&from_outcome("preferences", &o)),
            "• Preferences\n  └ Preferences saved.\n"
        );
    }
}
