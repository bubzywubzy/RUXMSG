//! ruxmsg — volatile P2P E2EE messaging client.
//!
//! A REPL connects and controls the app; conversations happen in a full-screen
//! view, one at a time. Esc returns from a conversation to the REPL.
//!
//!     $ ruxmsg
//!
//!     ruxmsg> profile use alice
//!     ruxmsg> start
//!     ruxmsg> connect 100.64.0.10:4443
//!     ruxmsg> chat peer1
//!
//! Nothing but the identity seed is ever written to disk. Messages, peers and
//! approvals live in memory and are wiped when a session closes or the app exits.

use std::io;

use clap::Parser;

mod app;
mod commands;
mod hardening;
mod repl;
mod scrollback;
mod tailscale;
mod theme;
mod tui;

use crate::app::App;
use ruxmsg_cli::config::{self, Config};

#[derive(Parser, Debug)]
#[command(
    name = "ruxmsg",
    about = "RUXMSG — volatile P2P E2EE messaging",
    version
)]
struct Args {
    /// Identity profile to load at startup.
    ///
    /// Interactive profile management remains inside the REPL.
    #[arg(long)]
    profile: Option<String>,

    /// Read configuration from this file instead of the default location.
    ///
    /// The file is only ever read, never written.
    #[arg(long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,
}

// A single thread keeps secrets out of other threads' stacks and caches.
#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let warnings = hardening::apply();
    hardening::install_panic_hook();

    let args = Args::parse();

    let path = args.config.clone().or_else(config::default_path);
    let (config, config_warning) = match path.as_deref().map(config::load_from) {
        Some(Ok(config)) => (config, None),
        Some(Err(error)) => (Config::default(), Some(error)),
        None => (Config::default(), None),
    };

    let mut app = App::new(&config);

    println!("{}", repl::LOGO);
    println!("    {}\n", repl::TAGLINE);

    for warning in warnings {
        println!("warning: {warning}");
    }

    if let Some(error) = config_warning {
        println!("warning: configuration ignored, using defaults: {error}");
    }

    if let Some(profile) = args.profile.as_deref() {
        match app.profile_use(profile).await {
            Ok(fingerprint) => {
                println!("loaded profile '{profile}', fingerprint {fingerprint}");
            }
            Err(error) => {
                println!(
                    "could not load profile '{profile}': {error}\n\
                     run `profile init {profile}` first if it does not exist"
                );
            }
        }
    }

    println!("{}", repl::HELP_TEXT);

    app.run().await
}
