//! Catppuccin Mocha colours and terminal emphasis for the VPN CLI.

use std::io::IsTerminal;

use ratatui::style::{Color, Modifier, Style};

// https://catppuccin.com/palette/#mocha
const BASE: Color = Color::Rgb(30, 30, 46);
const TEXT: Color = Color::Rgb(205, 214, 244);
const SUBTEXT: Color = Color::Rgb(166, 173, 200);
const MAUVE: Color = Color::Rgb(203, 166, 247);
const TEAL: Color = Color::Rgb(148, 226, 213);
const GREEN: Color = Color::Rgb(166, 227, 161);
const RED: Color = Color::Rgb(243, 139, 168);

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

    /// The foreground for most text.
    pub fn text(&self) -> Style {
        self.colored(TEXT)
    }

    /// The base foreground and background for the view and command output.
    pub fn surface(&self) -> Style {
        if self.color {
            self.text().bg(BASE)
        } else {
            Style::new()
        }
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
        if self.color {
            self.colored(SUBTEXT)
        } else if self.ansi {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            Style::new()
        }
    }

    /// Success marks and healthy states.
    pub fn success(&self) -> Style {
        self.colored(GREEN)
    }

    /// Errors and failing checks.
    pub fn error(&self) -> Style {
        self.colored(RED)
    }

    /// The product name.
    pub fn brand(&self) -> Style {
        self.colored(MAUVE).patch(self.bold())
    }

    /// Active controls, commands and inline code.
    pub fn accent(&self) -> Style {
        self.colored(TEAL)
    }
}

/// Render styled lines to a string: SGR escapes when the theme allows them, plain
/// text otherwise. Only the attributes [`Theme`] can produce are translated.
pub fn to_ansi(lines: &[ratatui::text::Line<'_>], theme: Theme) -> String {
    let mut out = String::new();
    for line in lines {
        let line_style = theme.surface().patch(line.style);
        for span in &line.spans {
            let style = line_style.patch(span.style);
            let mut codes = Vec::new();
            if theme.ansi {
                if style.add_modifier.contains(Modifier::BOLD) {
                    codes.push("1".into());
                }
                if style.add_modifier.contains(Modifier::DIM) {
                    codes.push("2".into());
                }
            }
            if theme.color {
                for (mode, color) in [(38, style.fg), (48, style.bg)] {
                    if let Some(Color::Rgb(red, green, blue)) = color {
                        codes.push(format!("{mode};2;{red};{green};{blue}"));
                    }
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
    fn full_theme_uses_the_mocha_palette_in_ansi_output() {
        let t = Theme::full();
        let lines = [Line::from(vec![
            Span::styled("VPN", t.brand()),
            Span::raw(" ready"),
        ])];
        assert_eq!(
            to_ansi(&lines, t),
            "\x1b[1;38;2;203;166;247;48;2;30;30;46mVPN\x1b[0m\x1b[38;2;205;214;244;48;2;30;30;46m ready\x1b[0m\n"
        );
    }
}
