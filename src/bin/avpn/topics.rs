//! Built-in reference: every page under `docs/cli/`, compiled into the binary.
//!
//! `avpn help TOPIC` and `avpn COMMAND --help` show these pages. The same files are
//! the published documentation, so the two can never disagree.

use ratatui::text::{Line, Span};

use crate::theme::Theme;

/// One help page.
#[derive(Debug)]
pub struct Topic {
    /// The name used with `avpn help`.
    pub name: &'static str,
    /// One line for the topic list.
    pub summary: &'static str,
    /// The Markdown page.
    pub body: &'static str,
}

/// Every page, commands first, then concepts.
pub const TOPICS: &[Topic] = &[
    Topic {
        name: "overview",
        summary: "what avpn is, global options and every command",
        body: include_str!("../../../docs/cli/overview.md"),
    },
    Topic {
        name: "status",
        summary: "runtime status written by the supervisor",
        body: include_str!("../../../docs/cli/status.md"),
    },
    Topic {
        name: "info",
        summary: "non-secret summary of this device",
        body: include_str!("../../../docs/cli/info.md"),
    },
    Topic {
        name: "hops",
        summary: "the enrolled chain, hop by hop",
        body: include_str!("../../../docs/cli/hops.md"),
    },
    Topic {
        name: "doctor",
        summary: "self-checks, and the address your first hop sees",
        body: include_str!("../../../docs/cli/doctor.md"),
    },
    Topic {
        name: "connect",
        summary: "start the VPN service",
        body: include_str!("../../../docs/cli/connect.md"),
    },
    Topic {
        name: "disconnect",
        summary: "stop the VPN service; the kill switch stays",
        body: include_str!("../../../docs/cli/disconnect.md"),
    },
    Topic {
        name: "run",
        summary: "run one program inside the protected namespace",
        body: include_str!("../../../docs/cli/run.md"),
    },
    Topic {
        name: "request",
        summary: "generate this device's keys and a public request",
        body: include_str!("../../../docs/cli/request.md"),
    },
    Topic {
        name: "init",
        summary: "operator: sign a chain from the requests",
        body: include_str!("../../../docs/cli/init.md"),
    },
    Topic {
        name: "enroll",
        summary: "verify and install this device's bundle",
        body: include_str!("../../../docs/cli/enroll.md"),
    },
    Topic {
        name: "preferences",
        summary: "mode, defense, daily cap and upstream entry",
        body: include_str!("../../../docs/cli/preferences.md"),
    },
    Topic {
        name: "rotate",
        summary: "rotate session certificates now",
        body: include_str!("../../../docs/cli/rotate.md"),
    },
    Topic {
        name: "guard",
        summary: "re-apply the boot-time kill switch",
        body: include_str!("../../../docs/cli/guard.md"),
    },
    Topic {
        name: "unlock",
        summary: "answer the Nitrokey PIN prompt after boot",
        body: include_str!("../../../docs/cli/unlock.md"),
    },
    Topic {
        name: "reset",
        summary: "remove the kill switch",
        body: include_str!("../../../docs/cli/reset.md"),
    },
    Topic {
        name: "cloud",
        summary: "create, inspect and remove the chain's cloud servers",
        body: include_str!("../../../docs/cli/cloud.md"),
    },
    Topic {
        name: "chains",
        summary: "1, 2 and 3 hops, layers and switching",
        body: include_str!("../../../docs/cli/chains.md"),
    },
    Topic {
        name: "keys",
        summary: "where keys are made, sealed and used",
        body: include_str!("../../../docs/cli/keys.md"),
    },
    Topic {
        name: "privacy",
        summary: "what each hop can know; hiding your address",
        body: include_str!("../../../docs/cli/privacy.md"),
    },
    Topic {
        name: "retention",
        summary: "why the servers hold nothing to hand over",
        body: include_str!("../../../docs/cli/retention.md"),
    },
    Topic {
        name: "interactive",
        summary: "the interactive view and its keys",
        body: include_str!("../../../docs/cli/interactive.md"),
    },
];

/// The page called `name`.
pub fn find(name: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|t| t.name == name)
}

/// Inline Markdown: `code` becomes accent-coloured, **bold** becomes bold.
fn inline(text: &str, base: ratatui::style::Style, t: Theme) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let next = [rest.find('`'), rest.find("**")]
            .into_iter()
            .flatten()
            .min();
        let Some(i) = next else {
            out.push(Span::styled(rest.to_string(), base));
            break;
        };
        if i > 0 {
            out.push(Span::styled(rest[..i].to_string(), base));
        }
        let (marker, style) = if rest[i..].starts_with("**") {
            ("**", base.patch(t.bold()))
        } else {
            ("`", t.accent())
        };
        let after = &rest[i + marker.len()..];
        match after.find(marker) {
            Some(j) => {
                out.push(Span::styled(after[..j].to_string(), style));
                rest = &after[j + marker.len()..];
            }
            None => {
                out.push(Span::styled(rest[i..].to_string(), base));
                break;
            }
        }
    }
    out
}

/// Render a page for the terminal: headings bold (the title in the brand colour),
/// bullets as `•`, indented examples dim, inline code in the accent colour.
pub fn render(body: &str, t: Theme) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for raw in body.lines() {
        if let Some(h) = raw.strip_prefix("# ") {
            out.push(Line::from(Span::styled(h.to_string(), t.brand())));
        } else if let Some(h) = raw.strip_prefix("## ") {
            out.push(Line::from(Span::styled(h.to_string(), t.bold())));
        } else if let Some(code) = raw
            .strip_prefix("    ")
            .filter(|_| !raw.trim_start().starts_with("- "))
        {
            out.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(code.to_string(), t.accent()),
            ]));
        } else if let Some(pos) = raw.find("- ").filter(|p| raw[..*p].trim().is_empty()) {
            let mut spans = vec![Span::raw(" ".repeat(pos + 2)), Span::styled("• ", t.dim())];
            spans.extend(inline(&raw[pos + 2..], t.text(), t));
            out.push(Line::from(spans));
        } else {
            out.push(Line::from(inline(raw, t.text(), t)));
        }
    }
    out
}

/// The topic list for `avpn help`.
pub fn index(t: Theme) -> Vec<Line<'static>> {
    let width = TOPICS.iter().map(|x| x.name.len()).max().unwrap_or(0);
    let mut out = vec![
        Line::from(vec![
            Span::styled("avpn help", t.brand()),
            Span::styled(" TOPIC", t.dim()),
        ]),
        Line::default(),
    ];
    for x in TOPICS {
        out.push(Line::from(vec![
            Span::styled(format!("  {:<width$}  ", x.name), t.accent()),
            Span::styled(x.summary, t.dim()),
        ]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::to_ansi;

    #[test]
    fn every_page_has_a_title_and_usage_or_body() {
        for x in TOPICS {
            assert!(x.body.starts_with("# "), "{} has no title", x.name);
            assert!(x.body.lines().count() > 3, "{} is empty", x.name);
        }
    }

    #[test]
    fn names_are_unique() {
        let mut names: Vec<_> = TOPICS.iter().map(|x| x.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TOPICS.len());
    }

    #[test]
    fn markdown_renders_without_markers() {
        let text = to_ansi(
            &render("# T\n\n- `a`: **b** c\n\n    avpn x\n", Theme::plain()),
            Theme::plain(),
        );
        assert_eq!(text, "T\n\n  • a: b c\n\n  avpn x\n");
    }
}
