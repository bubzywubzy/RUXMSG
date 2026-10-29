//! Best-effort process hardening and exit handling.
//!
//! Nothing here can defend against a live local compromise or `SIGKILL`; it
//! only narrows what a crash or a later local reader can recover.

use std::io::{self, Write};

/// Disables core dumps and ptrace-style memory reads where the OS allows it.
/// Returns a warning for each step that could not be applied.
pub(crate) fn apply() -> Vec<&'static str> {
    #[cfg(unix)]
    let mut warnings = Vec::new();

    #[cfg(not(unix))]
    let warnings = Vec::new();

    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};

        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };

        if setrlimit(Resource::Core, none).is_err() {
            warnings.push("could not disable core dumps");
        }
    }

    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};

        if set_dumpable_behavior(DumpableBehavior::NotDumpable).is_err() {
            warnings.push("could not mark the process non-dumpable");
        }
    }

    warnings
}

/// Clears the screen and the terminal's scrollback where supported.
pub(crate) fn wipe_screen() {
    let mut stdout = io::stdout();
    let _ = stdout.write_all(b"\x1b[2J\x1b[3J\x1b[H");
    let _ = stdout.flush();
}

/// Restores the terminal and clears it before any panic message is printed.
pub(crate) fn install_panic_hook() {
    let previous = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        let _ = crossterm::terminal::disable_raw_mode();
        wipe_screen();
        previous(info);
    }));
}

/// Resolves when the process is asked to terminate.
#[cfg(unix)]
pub(crate) async fn terminate_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let (Ok(mut term), Ok(mut hup), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
        signal(SignalKind::interrupt()),
    ) else {
        return std::future::pending().await;
    };

    tokio::select! {
        _ = term.recv() => {}
        _ = hup.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(not(unix))]
pub(crate) async fn terminate_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
