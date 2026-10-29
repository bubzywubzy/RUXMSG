//! Configuration loader: strict schema, safe file handling, no content in errors.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use ruxmsg_cli::config::{
    BorderStyle, ColorSpec, Config, ConfigError, KeyName, MAX_CONFIG_BYTES, NamedColor, load_from,
    parse,
};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruxmsg-config-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(unix)]
fn write(dir: &std::path::Path, text: &str, mode: u32) -> PathBuf {
    let path = dir.join("config.toml");
    fs::write(&path, text).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

// ---------------------------------------------------------------- parsing

#[test]
fn empty_text_yields_the_defaults() {
    assert_eq!(parse("").unwrap(), Config::default());
}

#[test]
fn valid_settings_are_applied() {
    let config = parse(
        r##"
        [theme]
        accent = "#ff8800"
        local = "Blue"

        [keys]
        rekey = "alt-k"
        leave = "f10"
        page_up = "ctrl-u"

        [ui]
        border = "rounded"
        tick_ms = 500
        "##,
    )
    .unwrap();

    assert_eq!(config.theme.accent, ColorSpec::Rgb(0xff, 0x88, 0x00));
    assert_eq!(config.theme.local, ColorSpec::Named(NamedColor::Blue));
    assert_eq!(config.keys.leave.key, KeyName::Function(10));
    assert!(config.keys.rekey.alt && !config.keys.rekey.ctrl);
    assert_eq!(config.border, BorderStyle::Rounded);
    assert_eq!(config.tick_ms, 500);
}

#[test]
fn unknown_tables_and_fields_are_rejected() {
    for text in [
        "unknown = 1",
        "[theme]\nsurprise = \"red\"",
        "[keys]\nsend = \"enter\"",
        "[exec]\ncommand = \"sh\"",
        "[ui]\ninclude = \"/etc/passwd\"",
    ] {
        assert!(
            matches!(parse(text), Err(ConfigError::Syntax { .. })),
            "{text}"
        );
    }
}

#[test]
fn values_of_the_wrong_type_are_rejected() {
    for text in [
        "[ui]\ntick_ms = \"fast\"",
        "[theme]\naccent = 5",
        "[keys]\nleave = [\"esc\"]",
        "theme = \"dark\"",
    ] {
        assert!(
            matches!(parse(text), Err(ConfigError::Syntax { .. })),
            "{text}"
        );
    }
}

#[test]
fn bad_colours_are_rejected() {
    for text in [
        "#12345",
        "#gggggg",
        "#1234567",
        "chartreuse",
        "rgb(1,2,3)",
        "",
    ] {
        let config = format!("[theme]\naccent = \"{text}\"");
        assert_eq!(parse(&config), Err(ConfigError::InvalidColor), "{text}");
    }
}

#[test]
fn key_bindings_cannot_take_over_typing_or_the_exit_keys() {
    for key in [
        "a",
        "x",
        "ctrl-c",
        "ctrl-d",
        "alt-ctrl-c",
        "enter",
        "backspace",
        "tab",
        "ctrl-1",
    ] {
        let config = format!("[keys]\nrekey = \"{key}\"");
        assert!(
            matches!(
                parse(&config),
                Err(ConfigError::InvalidKey | ConfigError::ReservedOrDuplicateKey)
            ),
            "{key}"
        );
    }
}

#[test]
fn a_key_cannot_be_bound_to_two_actions() {
    assert_eq!(
        parse("[keys]\nrekey = \"esc\""),
        Err(ConfigError::ReservedOrDuplicateKey)
    );
}

#[test]
fn numeric_and_style_ranges_are_enforced() {
    assert_eq!(
        parse("[ui]\ntick_ms = 99"),
        Err(ConfigError::TickOutOfRange)
    );
    assert_eq!(
        parse("[ui]\ntick_ms = 1001"),
        Err(ConfigError::TickOutOfRange)
    );
    // TOML integers are signed 64-bit, so this is a syntax error rather than a range error.
    assert!(parse("[ui]\ntick_ms = 18446744073709551615").is_err());
    assert!(parse("[ui]\ntick_ms = -5").is_err());
    assert_eq!(
        parse("[ui]\nborder = \"dotted\""),
        Err(ConfigError::InvalidBorder)
    );
}

#[test]
fn oversized_text_is_rejected_before_parsing() {
    let text = format!("# {}", "x".repeat(MAX_CONFIG_BYTES));
    assert_eq!(parse(&text), Err(ConfigError::TooLarge));
}

#[test]
fn hostile_nesting_neither_panics_nor_overflows_the_stack() {
    let budget = MAX_CONFIG_BYTES - 16;

    for text in [
        format!("a = {}", "[".repeat(budget)),
        format!("a = {}{}", "[".repeat(budget / 2), "]".repeat(budget / 2)),
        format!("a = {}", "{a=".repeat(budget / 3)),
        "[a.".repeat(budget / 3),
    ] {
        assert!(parse(&text).is_err());
    }
}

#[test]
fn errors_never_quote_the_file() {
    let canary = "CANARY-secret-7f3a";

    for text in [
        format!("[theme]\naccent = \"{canary}\""),
        format!("[keys]\nrekey = \"{canary}\""),
        format!("{canary} = 1"),
        format!("[ui]\nborder = \"{canary}\""),
        format!("[ui]\ntick_ms = \"{canary}\""),
        format!("= {canary}"),
    ] {
        let error = parse(&text).unwrap_err();

        assert!(!format!("{error}").contains(canary));
        assert!(!format!("{error:?}").contains(canary));
    }
}

#[test]
fn syntax_errors_report_only_a_line_number() {
    assert_eq!(
        parse("[ui]\ntick_ms = 300\nbogus line here"),
        Err(ConfigError::Syntax { line: 3 })
    );
}

// ---------------------------------------------------------------- loading

#[test]
fn a_missing_file_means_defaults() {
    let dir = scratch("missing");

    assert_eq!(
        load_from(&dir.join("nope.toml")).unwrap(),
        Config::default()
    );
}

#[test]
#[cfg(unix)]
fn a_private_regular_file_loads() {
    let dir = scratch("ok");
    let path = write(&dir, "[ui]\ntick_ms = 400", 0o600);

    assert_eq!(load_from(&path).unwrap().tick_ms, 400);
}

#[test]
#[cfg(unix)]
fn files_others_can_write_are_refused() {
    for mode in [0o666, 0o662, 0o626, 0o660 | 0o020] {
        let dir = scratch(&format!("mode{mode:o}"));
        let path = write(&dir, "[ui]\ntick_ms = 400", mode);

        assert_eq!(load_from(&path), Err(ConfigError::UnsafeFile), "{mode:o}");
    }
}

#[test]
#[cfg(unix)]
fn symlinks_are_refused_even_to_a_good_file() {
    let dir = scratch("symlink");
    let target = write(&dir, "[ui]\ntick_ms = 400", 0o600);
    let link = dir.join("link.toml");
    symlink(&target, &link).unwrap();

    assert_eq!(load_from(&link), Err(ConfigError::UnsafeFile));
}

#[test]
#[cfg(unix)]
fn directories_and_fifos_are_refused_without_hanging() {
    let dir = scratch("special");

    assert_eq!(load_from(&dir), Err(ConfigError::UnsafeFile));

    let fifo = dir.join("pipe.toml");
    std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();

    assert_eq!(load_from(&fifo), Err(ConfigError::UnsafeFile));
}

#[test]
#[cfg(unix)]
fn large_and_non_utf8_files_are_refused() {
    let dir = scratch("big");
    let path = write(&dir, &"#".repeat(MAX_CONFIG_BYTES + 1), 0o600);
    assert_eq!(load_from(&path), Err(ConfigError::TooLarge));

    let dir = scratch("utf8");
    let path = dir.join("config.toml");
    fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(load_from(&path), Err(ConfigError::NotUtf8));
}

#[test]
#[cfg(unix)]
fn loading_never_modifies_the_file_or_its_directory() {
    let dir = scratch("readonly");
    let path = write(&dir, "[ui]\ntick_ms = 400", 0o600);
    let before = fs::read(&path).unwrap();
    let entries = fs::read_dir(&dir).unwrap().count();

    let _ = load_from(&path);

    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read_dir(&dir).unwrap().count(), entries);
}
