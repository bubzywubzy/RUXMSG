//! Read-only user configuration: appearance and key bindings.
//!
//! The file is user-authored and global. It is never written by the app, is not
//! tied to any profile, and never receives session data. Because it is the one
//! input the app reads from a user-writable place, the loader is deliberately
//! strict:
//!
//! - the final path component must not be a symlink, and must be a regular file
//!   owned by the current user and not writable by group or others (Unix);
//! - at most [`MAX_CONFIG_BYTES`] are read, and the text must be UTF-8;
//! - the schema is closed (`deny_unknown_fields`), every value is a typed enum
//!   or a bounded number, and strings are never displayed or executed;
//! - there is no interpolation, include, path, command or environment value;
//! - errors are static descriptions plus a line number. They never echo file
//!   contents, because a parser's own messages quote the offending text.
//!
//! Any failure yields defaults at the call site. The SAS prompt, Enter, Ctrl-C
//! and typing keys are fixed in code and cannot be rebound here.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const MAX_CONFIG_BYTES: usize = 16 * 1024;

pub const MIN_TICK_MS: u64 = 100;
pub const MAX_TICK_MS: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The file or its metadata could not be read.
    Unreadable,
    /// Symlink, non-regular file, wrong owner, or group/world-writable.
    UnsafeFile,
    TooLarge,
    NotUtf8,
    /// Not valid TOML, or a key/value of the wrong shape. Line is 1-based.
    Syntax {
        line: usize,
    },
    InvalidColor,
    InvalidKey,
    /// A key that must stay fixed (typing, quit, SAS) or that is already bound.
    ReservedOrDuplicateKey,
    InvalidBorder,
    TickOutOfRange,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable => formatter.write_str("file could not be read"),
            Self::UnsafeFile => formatter.write_str(
                "file must be a regular file you own that others cannot write, and not a symlink",
            ),
            Self::TooLarge => write!(formatter, "file is larger than {MAX_CONFIG_BYTES} bytes"),
            Self::NotUtf8 => formatter.write_str("file is not valid UTF-8"),
            Self::Syntax { line } => write!(
                formatter,
                "invalid syntax or unknown field near line {line}"
            ),
            Self::InvalidColor => {
                formatter.write_str("invalid colour (use a listed name or #rrggbb)")
            }
            Self::InvalidKey => formatter.write_str("invalid key binding"),
            Self::ReservedOrDuplicateKey => {
                formatter.write_str("key binding is reserved, unprintable-only, or used twice")
            }
            Self::InvalidBorder => formatter.write_str("unknown border style"),
            Self::TickOutOfRange => {
                write!(formatter, "tick_ms must be {MIN_TICK_MS} to {MAX_TICK_MS}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedColor {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    Gray,
    DarkGray,
    White,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSpec {
    Named(NamedColor),
    Rgb(u8, u8, u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorderStyle {
    Plain,
    Rounded,
    Double,
    Thick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemeSpec {
    pub border: ColorSpec,
    pub accent: ColorSpec,
    pub local: ColorSpec,
    pub remote: ColorSpec,
    pub system: ColorSpec,
    pub warning: ColorSpec,
    pub dim: ColorSpec,
}

impl Default for ThemeSpec {
    fn default() -> Self {
        use NamedColor::{Cyan, DarkGray, Gray, Green, Magenta, Red, Yellow};

        Self {
            border: ColorSpec::Named(DarkGray),
            accent: ColorSpec::Named(Cyan),
            local: ColorSpec::Named(Green),
            remote: ColorSpec::Named(Yellow),
            system: ColorSpec::Named(Magenta),
            warning: ColorSpec::Named(Red),
            dim: ColorSpec::Named(Gray),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyName {
    Esc,
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Function(u8),
    /// Only valid together with Ctrl or Alt.
    Letter(char),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySpec {
    pub key: KeyName,
    pub ctrl: bool,
    pub alt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMap {
    pub leave: KeySpec,
    pub rekey: KeySpec,
    pub scroll_up: KeySpec,
    pub scroll_down: KeySpec,
    pub page_up: KeySpec,
    pub page_down: KeySpec,
}

const fn plain(key: KeyName) -> KeySpec {
    KeySpec {
        key,
        ctrl: false,
        alt: false,
    }
}

impl Default for KeyMap {
    fn default() -> Self {
        Self {
            leave: plain(KeyName::Esc),
            rekey: KeySpec {
                key: KeyName::Letter('r'),
                ctrl: true,
                alt: false,
            },
            scroll_up: plain(KeyName::Up),
            scroll_down: plain(KeyName::Down),
            page_up: plain(KeyName::PageUp),
            page_down: plain(KeyName::PageDown),
        }
    }
}

impl KeyMap {
    fn all(&self) -> [KeySpec; 6] {
        [
            self.leave,
            self.rekey,
            self.scroll_up,
            self.scroll_down,
            self.page_up,
            self.page_down,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub theme: ThemeSpec,
    pub keys: KeyMap,
    pub border: BorderStyle,
    pub tick_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: ThemeSpec::default(),
            keys: KeyMap::default(),
            border: BorderStyle::Plain,
            tick_ms: 250,
        }
    }
}

// ------------------------------------------------------------------- schema

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    theme: Option<RawTheme>,
    keys: Option<RawKeys>,
    ui: Option<RawUi>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawTheme {
    border: Option<String>,
    accent: Option<String>,
    local: Option<String>,
    remote: Option<String>,
    system: Option<String>,
    warning: Option<String>,
    dim: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawKeys {
    leave: Option<String>,
    rekey: Option<String>,
    scroll_up: Option<String>,
    scroll_down: Option<String>,
    page_up: Option<String>,
    page_down: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawUi {
    border: Option<String>,
    tick_ms: Option<u64>,
}

// ------------------------------------------------------------------ parsing

fn parse_color(text: &str) -> Result<ColorSpec, ConfigError> {
    use NamedColor::*;

    if let Some(hex) = text.strip_prefix('#') {
        if hex.len() != 6 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConfigError::InvalidColor);
        }

        let channel = |range: std::ops::Range<usize>| {
            u8::from_str_radix(&hex[range], 16).map_err(|_| ConfigError::InvalidColor)
        };

        return Ok(ColorSpec::Rgb(
            channel(0..2)?,
            channel(2..4)?,
            channel(4..6)?,
        ));
    }

    let named = match text.to_ascii_lowercase().as_str() {
        "black" => Black,
        "red" => Red,
        "green" => Green,
        "yellow" => Yellow,
        "blue" => Blue,
        "magenta" => Magenta,
        "cyan" => Cyan,
        "gray" | "grey" => Gray,
        "dark-gray" | "dark-grey" => DarkGray,
        "white" => White,
        _ => return Err(ConfigError::InvalidColor),
    };

    Ok(ColorSpec::Named(named))
}

fn parse_key(text: &str) -> Result<KeySpec, ConfigError> {
    if text.is_empty() || text.len() > 16 || !text.is_ascii() {
        return Err(ConfigError::InvalidKey);
    }

    let lowered = text.to_ascii_lowercase();

    let mut ctrl = false;
    let mut alt = false;
    let mut rest = lowered.as_str();

    loop {
        if let Some(tail) = rest.strip_prefix("ctrl-") {
            ctrl = true;
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("alt-") {
            alt = true;
            rest = tail;
        } else {
            break;
        }
    }

    let key = match rest {
        "esc" => KeyName::Esc,
        "up" => KeyName::Up,
        "down" => KeyName::Down,
        "pageup" => KeyName::PageUp,
        "pagedown" => KeyName::PageDown,
        "home" => KeyName::Home,
        "end" => KeyName::End,
        other => {
            if let Some(number) = other.strip_prefix('f') {
                match number.parse::<u8>() {
                    Ok(number) if (1..=12).contains(&number) => KeyName::Function(number),
                    _ => return Err(ConfigError::InvalidKey),
                }
            } else {
                let mut characters = other.chars();

                match (characters.next(), characters.next()) {
                    (Some(letter), None) if letter.is_ascii_lowercase() => KeyName::Letter(letter),
                    _ => return Err(ConfigError::InvalidKey),
                }
            }
        }
    };

    // A bare letter would swallow typing.
    if matches!(key, KeyName::Letter(_)) && !(ctrl || alt) {
        return Err(ConfigError::ReservedOrDuplicateKey);
    }

    // Ctrl-C and Ctrl-D always leave or quit; they cannot be rebound.
    if matches!(key, KeyName::Letter('c' | 'd')) && ctrl {
        return Err(ConfigError::ReservedOrDuplicateKey);
    }

    Ok(KeySpec { key, ctrl, alt })
}

fn pick<T>(
    raw: Option<String>,
    default: T,
    parse: impl Fn(&str) -> Result<T, ConfigError>,
) -> Result<T, ConfigError> {
    match raw {
        Some(text) => parse(&text),
        None => Ok(default),
    }
}

fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());

    text.as_bytes()[..end]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

/// Parses configuration text. Never panics and never echoes `text` in errors.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }

    let raw: RawConfig = toml::from_str(text).map_err(|error| ConfigError::Syntax {
        line: error.span().map_or(1, |span| line_of(text, span.start)),
    })?;

    let defaults = Config::default();

    let theme = raw.theme.unwrap_or_default();
    let keys = raw.keys.unwrap_or_default();
    let ui = raw.ui.unwrap_or_default();

    let theme = ThemeSpec {
        border: pick(theme.border, defaults.theme.border, parse_color)?,
        accent: pick(theme.accent, defaults.theme.accent, parse_color)?,
        local: pick(theme.local, defaults.theme.local, parse_color)?,
        remote: pick(theme.remote, defaults.theme.remote, parse_color)?,
        system: pick(theme.system, defaults.theme.system, parse_color)?,
        warning: pick(theme.warning, defaults.theme.warning, parse_color)?,
        dim: pick(theme.dim, defaults.theme.dim, parse_color)?,
    };

    let keys = KeyMap {
        leave: pick(keys.leave, defaults.keys.leave, parse_key)?,
        rekey: pick(keys.rekey, defaults.keys.rekey, parse_key)?,
        scroll_up: pick(keys.scroll_up, defaults.keys.scroll_up, parse_key)?,
        scroll_down: pick(keys.scroll_down, defaults.keys.scroll_down, parse_key)?,
        page_up: pick(keys.page_up, defaults.keys.page_up, parse_key)?,
        page_down: pick(keys.page_down, defaults.keys.page_down, parse_key)?,
    };

    let bound = keys.all();
    for (index, spec) in bound.iter().enumerate() {
        if bound[..index].contains(spec) {
            return Err(ConfigError::ReservedOrDuplicateKey);
        }
    }

    let border = pick(ui.border, defaults.border, |text| {
        match text.to_ascii_lowercase().as_str() {
            "plain" => Ok(BorderStyle::Plain),
            "rounded" => Ok(BorderStyle::Rounded),
            "double" => Ok(BorderStyle::Double),
            "thick" => Ok(BorderStyle::Thick),
            _ => Err(ConfigError::InvalidBorder),
        }
    })?;

    let tick_ms = ui.tick_ms.unwrap_or(defaults.tick_ms);
    if !(MIN_TICK_MS..=MAX_TICK_MS).contains(&tick_ms) {
        return Err(ConfigError::TickOutOfRange);
    }

    Ok(Config {
        theme,
        keys,
        border,
        tick_ms,
    })
}

// ------------------------------------------------------------------ loading

/// `$XDG_CONFIG_HOME/ruxmsg/config.toml`, else `~/.config/ruxmsg/config.toml`.
/// Relative `XDG_CONFIG_HOME` values are ignored, as the XDG spec requires.
pub fn default_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };

    Some(base.join("ruxmsg").join("config.toml"))
}

/// Loads `path`. A missing file is not an error: it yields the defaults.
pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // NOFOLLOW refuses a symlink; NONBLOCK keeps a FIFO from hanging the open.
        let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
        options.custom_flags(flags.bits().cast_signed());
    }

    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Config::default());
        }
        Err(_) => return Err(ConfigError::UnsafeFile),
    };

    let metadata = file.metadata().map_err(|_| ConfigError::Unreadable)?;

    if !metadata.is_file() {
        return Err(ConfigError::UnsafeFile);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let owned = metadata.uid() == rustix::process::getuid().as_raw();

        if !owned || metadata.mode() & 0o022 != 0 {
            return Err(ConfigError::UnsafeFile);
        }
    }

    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ConfigError::TooLarge);
    }

    let mut bytes = Vec::new();

    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::Unreadable)?;

    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }

    let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::NotUtf8)?;

    parse(text)
}
