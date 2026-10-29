//! Line-oriented REPL for connecting and controlling the application.
//!
//! The REPL owns the terminal in raw mode while no chat is open. Network
//! events are printed above a redrawn prompt, so nothing the user is typing is
//! lost. Messages are never written to disk; only the terminal itself holds
//! what was printed.

use std::io::{self, Write};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use zeroize::{Zeroize, Zeroizing};

use ruxmsg::protocol::{MAX_CONTENT, SAS_DECISION_TIMEOUT_SECS};

use crate::app::{App, Mode, is_approval};
use crate::commands::{Command, CommandParser, ProfileCommand, TailscaleCommand};
use crate::tailscale::{tailscale_ip, tailscale_status, tailscale_up};

pub(crate) const LOGO: &str = r#"
██████╗  ██╗   ██╗ ██╗  ██╗ ███╗   ███╗ ███████╗ ██████╗  
██╔══██╗ ██║   ██║ ╚██╗██╔╝ ████╗ ████║ ██╔════╝ ██╔════╝ 
██████╔╝ ██║   ██║  ╚███╔╝  ██╔████╔██║ ███████╗ ██║  ███╗
██╔══██╗ ██║   ██║  ██╔██╗  ██║╚██╔╝██║ ╚════██║ ██║   ██║
██║  ██║ ╚██████╔╝ ██╔╝ ██╗ ██║ ╚═╝ ██║ ███████║ ╚██████╔╝
╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝  ╚═════╝
"#;

pub(crate) const TAGLINE: &str = "Volatile P2P End-to-End Encrypted Messaging";

pub(crate) const HELP_TEXT: &str = "\
RUXMSG COMMANDS

IDENTITY
  profile init <name>       create a new identity profile
  profile use <name>        load an existing identity profile
  profile list              explain why profile enumeration is unavailable
  fingerprint [label]       show own or peer identity fingerprint

NETWORK
  start [--addr <addr>]     start accepting connections
                            default: 127.0.0.1:4443 (loopback only)
  stop                      stop accepting new connections
  connect <addr>            connect to a peer

SESSIONS
  peers                     list active sessions
  use <label>               set the default chat target
  session <label>           show session information
  rekey <label>             start a rekey now
  close <label>             close a session

MESSAGING
  chat [label]              open the conversation view
  msg <label> <text>        send a message directly
  <text>                    send to the default target

VERIFICATION
  Every new connection shows a Short Authentication String. Compare the
  three words with your peer over a separate channel, then type `yes` and
  press Enter. Anything else rejects the connection.

TAILSCALE
  tailscale status          show Tailscale state
  tailscale up              bring Tailscale up
  tailscale ip              print the Tailscale address

GENERAL
  help                      show this guide
  quit                      close sessions, wipe the screen and exit

CONVERSATION VIEW
  Enter                     send message
  Esc / Ctrl+C              return to the REPL
  Ctrl+R                    rekey this session
  Up/Down, PageUp/PageDown  scroll";

impl App {
    fn prompt_text(&self) -> String {
        match self.sas.front() {
            Some(pending) => format!("sas[{}]> ", pending.label),
            None => "ruxmsg> ".to_string(),
        }
    }

    /// Redraws the prompt and the line being edited.
    pub(crate) fn redraw_prompt(&self) -> io::Result<()> {
        if !matches!(self.mode, Mode::Repl) {
            return Ok(());
        }

        let line = self
            .sas
            .front()
            .map_or(self.input.as_str(), |pending| pending.typed.as_str());

        let prompt = self.prompt_text();
        let (cols, _) = crossterm::terminal::size().unwrap_or((80, 24));

        let max_len = (cols as usize)
            .saturating_sub(prompt.len())
            .saturating_sub(1);

        let display_line = if line.chars().count() > max_len {
            let start = line.chars().count() - max_len;
            line.chars().skip(start).collect::<String>()
        } else {
            line.to_string()
        };
        let mut stdout = io::stdout();
        stdout.write_all(b"\r\x1b[2K")?;
        stdout.write_all(prompt.as_bytes())?;
        stdout.write_all(display_line.as_bytes())?;
        stdout.flush()
    }

    /// Prints a status line above the prompt. Silent while a chat is open.
    pub(crate) fn say(&self, text: &str) {
        if !matches!(self.mode, Mode::Repl) {
            return;
        }

        let mut stdout = io::stdout();
        let _ = stdout.write_all(b"\r\x1b[2K");

        for line in text.trim_end().split('\n') {
            let _ = stdout.write_all(line.as_bytes());
            let _ = stdout.write_all(b"\r\n");
        }

        let _ = stdout.flush();
        let _ = self.redraw_prompt();
    }

    /// Prints a peer message without composing an intermediate copy of it.
    pub(crate) fn say_message(&self, label: &str, text: &str) {
        if !matches!(self.mode, Mode::Repl) {
            return;
        }

        let mut stdout = io::stdout();
        let _ = stdout.write_all(b"\r\x1b[2K[");
        let _ = stdout.write_all(label.as_bytes());
        let _ = stdout.write_all(b"] ");

        for (index, line) in text.split('\n').enumerate() {
            if index > 0 {
                let _ = stdout.write_all(b"\r\n    ");
            }
            let _ = stdout.write_all(line.as_bytes());
        }

        let _ = stdout.write_all(b"\r\n");
        let _ = stdout.flush();
        let _ = self.redraw_prompt();
    }

    /// Shows the SAS at the head of the queue, if any.
    pub(crate) fn announce_sas(&self) {
        let Some(pending) = self.sas.front() else {
            let _ = self.redraw_prompt();
            return;
        };

        let label = &pending.label;

        self.say(&format!(
            "[{label}] SECURITY VERIFICATION — Short Authentication String ({})\n\
             [{label}] compare these words with your peer over a separate channel:\n\
             \n\
             \x20       {} {} {}\n\
             \n\
             [{label}] peer key (claimed until approved): {}\n\
             [{label}] type `yes` and press Enter to approve; anything else rejects \
             ({SAS_DECISION_TIMEOUT_SECS} s).",
            if pending.outbound {
                "outbound"
            } else {
                "inbound"
            },
            pending.words[0],
            pending.words[1],
            pending.words[2],
            pending.fingerprint,
        ));
    }

    // ---------------------------------------------------------------- keys

    pub(crate) async fn repl_key(&mut self, key: KeyEvent) -> io::Result<()> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        if control && matches!(key.code, KeyCode::Char('c' | 'd')) {
            self.quit = true;
            return Ok(());
        }

        if !self.sas.is_empty() {
            return self.repl_sas_key(key);
        }

        match key.code {
            KeyCode::Enter => {
                let line = Zeroizing::new(self.input.trim().to_string());
                self.input.zeroize();

                io::stdout().write_all(b"\r\n")?;

                if !line.is_empty() {
                    self.dispatch(&line).await?;
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(character)
                if !control && self.input.len() + character.len_utf8() <= MAX_CONTENT =>
            {
                self.input.push(character);
            }
            _ => {}
        }

        self.redraw_prompt()
    }

    fn repl_sas_key(&mut self, key: KeyEvent) -> io::Result<()> {
        match key.code {
            KeyCode::Enter => {
                let approved = self
                    .sas
                    .front()
                    .is_some_and(|pending| is_approval(&pending.typed));

                self.answer_sas(approved);
            }
            KeyCode::Esc => self.answer_sas(false),
            KeyCode::Backspace => {
                if let Some(pending) = self.sas.front_mut() {
                    pending.typed.pop();
                }
            }
            KeyCode::Char(character) => {
                if let Some(pending) = self.sas.front_mut()
                    && pending.typed.len() < 16
                {
                    pending.typed.push(character);
                }
            }
            _ => {}
        }

        self.redraw_prompt()
    }

    // ------------------------------------------------------------ commands

    async fn dispatch(&mut self, line: &str) -> io::Result<()> {
        let command = match CommandParser::parse(line) {
            Ok(command) => command,
            Err(error) => {
                self.say(&format!("error: {error}"));
                return Ok(());
            }
        };

        match command {
            Command::Profile(command) => self.execute_profile(command).await,

            Command::Start { addr } => match self.start(&addr).await {
                Ok(bound) => {
                    self.say(&format!("listening on {bound}"));

                    if bound.ip().is_unspecified() {
                        self.say(
                            "warning: listening on every interface; prefer loopback or a \
                             tailnet address",
                        );
                    }
                }
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Stop => match self.stop() {
                Ok(addr) => self.say(&format!("stopped listening on {addr}")),
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Connect { addr } => match self.dial(&addr) {
                Ok(()) => self.say(&format!("dialing {addr}…")),
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Peers => self.say(&self.peers_table()),

            Command::Use { label } => match self.use_target(&label) {
                Ok(()) => self.say(&format!("default target set to '{label}'")),
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Message { label, text } => {
                if let Err(error) = self.send_text(&label, text) {
                    self.say(&format!("error: {error}"));
                }
            }

            Command::BareMessage(text) => match self.default_target.clone() {
                Some(target) => {
                    if let Err(error) = self.send_text(&target, text) {
                        self.say(&format!("error: {error}"));
                    }
                }
                None => self.say("unknown command — no default chat target; type `help`"),
            },

            Command::Close { label } => match self.close_session(&label) {
                Ok(()) => self.say(&format!("closing '{label}'")),
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Rekey { label } => match self.request_rekey(&label) {
                Ok(()) => self.say(&format!("rekeying '{label}'")),
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Fingerprint { label } => match self.fingerprint_of(label.as_deref()) {
                Ok(fingerprint) => self.say(&fingerprint),
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Session { label } => match self.session_info(&label) {
                Ok(info) => self.say(&info),
                Err(error) => self.say(&format!("error: {error}")),
            },

            Command::Chat { label } => {
                let target = label.or_else(|| self.default_target.clone());

                match target {
                    Some(target) => {
                        if let Err(error) = self.try_enter_chat(&target) {
                            self.say(&format!("error: {error}"));
                        }
                    }
                    None => {
                        self.say("usage: chat <label>\nor select a target first with `use <label>`")
                    }
                }
            }

            Command::Tailscale(command) => self.run_tailscale(command).await,

            Command::Help => self.say(HELP_TEXT),

            Command::Quit => self.quit = true,
        }

        Ok(())
    }

    async fn execute_profile(&mut self, command: ProfileCommand) {
        match command {
            ProfileCommand::Init(name) => match self.profile_init(&name).await {
                Ok(fingerprint) => self.say(&format!(
                    "created profile '{name}', fingerprint {fingerprint}"
                )),
                Err(error) => self.say(&format!("error: {error}")),
            },

            ProfileCommand::Use(name) => match self.profile_use(&name).await {
                Ok(fingerprint) => self.say(&format!(
                    "loaded profile '{name}', fingerprint {fingerprint}"
                )),
                Err(error) => self.say(&format!("error: {error}")),
            },

            ProfileCommand::List => self.say(
                "profile list isn't supported: identity seeds persist in the OS keyring, \
                 and OS keyrings do not provide a portable enumeration-by-prefix \
                 interface.\nTrack profile names yourself and use `profile use <name>`.",
            ),
        }
    }

    /// The Tailscale helpers print directly, so they run outside raw mode and
    /// off the event loop (`tailscale up` can wait for a login).
    async fn run_tailscale(&mut self, command: TailscaleCommand) {
        let _ = disable_raw_mode();
        println!();

        let _ = tokio::task::spawn_blocking(move || match command {
            TailscaleCommand::Status => tailscale_status(),
            TailscaleCommand::Up => tailscale_up(),
            TailscaleCommand::Ip => tailscale_ip(),
        })
        .await;

        let _ = enable_raw_mode();
    }
}
