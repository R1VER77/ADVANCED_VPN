//! Colour and emphasis rules, after the Codex TUI style guide.
//!
//! Most text uses the terminal's default foreground. Headers are **bold**, secondary
//! text is dim, success is green, errors are red, the brand is magenta and active
//! controls are cyan. Blue, yellow, black, white and custom RGB foregrounds are
//! never used, so the output stays legible on light and dark themes. The font is
//! always the terminal's own.

use std::io::IsTerminal;

use ratatui::style::{Color, Modifier, Style};

/// Which escape sequences the output may contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    /// Emphasis (bold, dim) is allowed: the output is an interactive terminal.
    pub ansi: bool,
    /// Colour is allowed as well (no `NO_COLOR`, no `--no-color`).
    pub color: bool,
}

impl Theme {
    /// Decide from the environment: a non-terminal or `TERM=dumb` gets plain text,
    /// and `NO_COLOR` (any value) or `--no-color` drops colour but keeps emphasis.
    pub fn detect(no_color_flag: bool) -> Self {
        let ansi =
            std::io::stdout().is_terminal() && std::env::var("TERM").map_or(true, |t| t != "dumb");
        let color = ansi && !no_color_flag && std::env::var_os("NO_COLOR").is_none();
        Self { ansi, color }
    }

    /// No escape sequences at all (pipes, files, tests).
    #[cfg(test)]
    pub const fn plain() -> Self {
        Self {
            ansi: false,
            color: false,
        }
    }

    /// Emphasis and colour (the interactive view, tests of styling).
    #[cfg(test)]
    pub const fn full() -> Self {
        Self {
            ansi: true,
            color: true,
        }
    }

    fn colored(&self, color: Color) -> Style {
        if self.color {
            Style::new().fg(color)
        } else {
            Style::new()
        }
    }

    /// Default foreground: most text.
    pub fn text(&self) -> Style {
        Style::new()
    }

    /// Headers and key names.
    pub fn bold(&self) -> Style {
        if self.ansi {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        }
    }

    /// Secondary text: labels, continuation glyphs, footers.
    pub fn dim(&self) -> Style {
        if self.ansi {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            Style::new()
        }
    }

    /// Success marks and healthy states.
    pub fn success(&self) -> Style {
        self.colored(Color::Green)
    }

    /// Errors and failing checks.
    pub fn error(&self) -> Style {
        self.colored(Color::Red)
    }

    /// The product name.
    pub fn brand(&self) -> Style {
        self.colored(Color::Magenta).patch(self.bold())
    }

    /// Active controls, commands and inline code.
    pub fn accent(&self) -> Style {
        self.colored(Color::Cyan)
    }
}

/// Render styled lines to a string: SGR escapes when the theme allows them, plain
/// text otherwise. Only the attributes [`Theme`] can produce are translated.
pub fn to_ansi(lines: &[ratatui::text::Line<'_>], theme: Theme) -> String {
    let mut out = String::new();
    for line in lines {
        for span in &line.spans {
            let style = line.style.patch(span.style);
            let mut codes: Vec<&str> = Vec::new();
            if theme.ansi {
                if style.add_modifier.contains(Modifier::BOLD) {
                    codes.push("1");
                }
                if style.add_modifier.contains(Modifier::DIM) {
                    codes.push("2");
                }
            }
            if theme.color {
                match style.fg {
                    Some(Color::Red) => codes.push("31"),
                    Some(Color::Green) => codes.push("32"),
                    Some(Color::Magenta) => codes.push("35"),
                    Some(Color::Cyan) => codes.push("36"),
                    _ => {}
                }
            }
            if codes.is_empty() {
                out.push_str(&span.content);
            } else {
                out.push_str("\x1b[");
                out.push_str(&codes.join(";"));
                out.push('m');
                out.push_str(&span.content);
                out.push_str("\x1b[0m");
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::text::{Line, Span};

    #[test]
    fn plain_theme_emits_no_escape_sequences() {
        let t = Theme::plain();
        let lines = vec![Line::from(vec![
            Span::styled("ok", t.success()),
            Span::styled(" x", t.bold()),
        ])];
        assert_eq!(to_ansi(&lines, t), "ok x\n");
    }

    #[test]
    fn no_color_keeps_emphasis_but_drops_colour() {
        let t = Theme {
            ansi: true,
            color: false,
        };
        let lines = vec![Line::from(vec![
            Span::styled("a", t.error()),
            Span::styled("b", t.bold()),
        ])];
        assert_eq!(to_ansi(&lines, t), "a\x1b[1mb\x1b[0m\n");
    }

    #[test]
    fn full_theme_uses_only_the_allowed_palette() {
        let t = Theme::full();
        for style in [
            t.text(),
            t.bold(),
            t.dim(),
            t.success(),
            t.error(),
            t.brand(),
            t.accent(),
        ] {
            assert!(
                matches!(
                    style.fg,
                    None | Some(Color::Red | Color::Green | Color::Magenta | Color::Cyan)
                ),
                "{style:?}"
            );
        }
    }
}
