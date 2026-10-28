//! Maps the validated configuration onto ratatui styles.

use ratatui::style::Color;
use ratatui::widgets::BorderType;
use ruxmsg_cli::config::{BorderStyle, ColorSpec, NamedColor, ThemeSpec};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Theme {
    pub(crate) border: Color,
    pub(crate) accent: Color,
    pub(crate) local: Color,
    pub(crate) remote: Color,
    pub(crate) system: Color,
    pub(crate) warning: Color,
    pub(crate) dim: Color,
    pub(crate) border_type: BorderType,
}

fn color(spec: ColorSpec) -> Color {
    match spec {
        ColorSpec::Rgb(red, green, blue) => Color::Rgb(red, green, blue),
        ColorSpec::Named(named) => match named {
            NamedColor::Black => Color::Black,
            NamedColor::Red => Color::Red,
            NamedColor::Green => Color::Green,
            NamedColor::Yellow => Color::Yellow,
            NamedColor::Blue => Color::Blue,
            NamedColor::Magenta => Color::Magenta,
            NamedColor::Cyan => Color::Cyan,
            NamedColor::Gray => Color::Gray,
            NamedColor::DarkGray => Color::DarkGray,
            NamedColor::White => Color::White,
        },
    }
}

impl Theme {
    pub(crate) fn new(spec: &ThemeSpec, border: BorderStyle) -> Self {
        Self {
            border: color(spec.border),
            accent: color(spec.accent),
            local: color(spec.local),
            remote: color(spec.remote),
            system: color(spec.system),
            warning: color(spec.warning),
            dim: color(spec.dim),
            border_type: match border {
                BorderStyle::Plain => BorderType::Plain,
                BorderStyle::Rounded => BorderType::Rounded,
                BorderStyle::Double => BorderType::Double,
                BorderStyle::Thick => BorderType::Thick,
            },
        }
    }
}
