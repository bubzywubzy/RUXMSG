//! ruxmsg — volatile P2P E2EE messaging client.
//!
//! The binary has two interactive frontends:
//!
//! 1. A line-oriented REPL for application/session control.
//! 2. A Ratatui chat interface for conversational interaction.
//!
//! Neither frontend owns networking, cryptography, persistence, or session
//! lifecycle. Those responsibilities remain in the application/session layer.
//!
//! REPL:
//!
//!     $ ruxmsg
//!
//!     ruxmsg> profile use bubzy
//!     ruxmsg> start --addr 0.0.0.0:4443
//!     ruxmsg> connect 100.64.0.10:4443
//!     ruxmsg> chat peer1
//!
//! Chat:
//!
//!     ┌──────────────────────────────────────────────┐
//!     │ RUXMSG — peer1                               │
//!     │                                              │
//!     │ peer1  hello                                 │
//!     │ you    hey                                   │
//!     │                                              │
//!     │ > type a message...                          │
//!     └──────────────────────────────────────────────┘
//!
//! Esc returns from the chat interface to the REPL.
//!
//! The network session itself remains alive while the frontend changes.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use ruxmsg::close::CloseReason;
use ruxmsg::connection::{ConnectionEvent, PeerConnection};
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::identity::PeerIdentity;
use ruxmsg::storage::{IdentityKeyStore, KeyringSecretStore};
use ruxmsg::transport::FramedTransport;

// =====================================================================
// CLI
// =====================================================================

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
}

// =====================================================================
// ASCII BRANDING
// =====================================================================

const LOGO: &str = r#"
██████╗ ██╗   ██╗██╗  ██╗██╗   ███╗███████╗ ██████╗
██╔══██╗██║   ██║╚██╗██╔╝██║ ████╔╝██╔════╝██╔════╝
██████╔╝██║   ██║ ╚███╔╝ ██║██╔╝██║███████╗██║
██╔══██╗██║   ██║ ██╔██╗ ██║██║  ██║╚════██║██║
██║  ██║╚██████╔╝██╔╝ ██╗██║██║  ██║███████║╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝
"#;

const TAGLINE: &str = "Volatile P2P End-to-End Encrypted Messaging";

// =====================================================================
// APPLICATION
// =====================================================================

fn main() -> io::Result<()> {
    let args = Args::parse();

    let mut app = Application::new();

    app.print_banner();

    if let Some(profile) = args.profile.as_deref() {
        match app.profile_use(profile) {
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

    app.print_help();
    app.run()
}

// =====================================================================
// SESSION MODEL
// =====================================================================

#[derive(Clone, Debug)]
enum SessionStatus {
    Handshaking,
    Connected,
    Closed(String),
}

impl SessionStatus {
    fn as_str(&self) -> String {
        match self {
            Self::Handshaking => "handshaking".to_string(),
            Self::Connected => "connected".to_string(),
            Self::Closed(reason) => format!("closed ({reason})"),
        }
    }
}

struct PeerHandle {
    remote_addr: String,
    fingerprint: Option<String>,
    status: SessionStatus,
    outbound: bool,
    tx: mpsc::Sender<SessionCommand>,
}

/// Commands directed to one live session.
enum SessionCommand {
    Send(String),
    Close,
}

/// Network/application events.
///
/// These are the only things the frontends need to know about networking.
enum NetEvent {
    Sas {
        label: String,
        words: [&'static str; 3],
        answer_tx: mpsc::Sender<bool>,
    },

    Ready {
        label: String,
        fingerprint: String,
    },

    Message {
        label: String,
        text: String,
    },

    PeerClosed {
        label: String,
        reason: CloseReason,
    },

    Error {
        label: String,
        message: String,
    },

    ListenerStopped {
        addr: String,
        error: Option<String>,
    },
}

// =====================================================================
// APPLICATION STATE
// =====================================================================

struct ActiveIdentity {
    profile: String,
    keypair: Arc<IdentityKeypair>,
}

struct PendingSas {
    label: String,
    words: [&'static str; 3],
    answer_tx: mpsc::Sender<bool>,
}

struct ListenerHandle {
    addr: String,
    stop_flag: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

/// The actual RUXMSG application.
///
/// Frontends operate on this state but do not own it.
struct Application {
    identity: Option<ActiveIdentity>,

    sessions: Arc<Mutex<HashMap<String, PeerHandle>>>,

    default_target: Option<String>,

    next_label: Arc<Mutex<usize>>,

    listener: Option<ListenerHandle>,

    pending_sas: Option<PendingSas>,

    events_tx: mpsc::Sender<NetEvent>,
    events_rx: mpsc::Receiver<NetEvent>,
}

impl Application {
    fn new() -> Self {
        let (events_tx, events_rx) = mpsc::channel();

        Self {
            identity: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            default_target: None,
            next_label: Arc::new(Mutex::new(0)),
            listener: None,
            pending_sas: None,
            events_tx,
            events_rx,
        }
    }

    // -----------------------------------------------------------------
    // Branding
    // -----------------------------------------------------------------

    fn print_banner(&self) {
        println!("{LOGO}");
        println!("    {TAGLINE}\n");
    }

    fn print_help(&self) {
        println!("{HELP_TEXT}");
    }

    // -----------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------

    fn own_fingerprint(&self) -> Option<String> {
        self.identity
            .as_ref()
            .map(|identity| own_identity_string(&identity.keypair))
    }

    fn profile_init(&mut self, name: &str) -> ruxmsg::Result<String> {
        validate_profile_name(name)?;

        let mut store = IdentityKeyStore::new(
            KeyringSecretStore::new(format!("ruxmsg-{name}")),
            "identity",
        );

        if store.load()?.is_some() {
            return Err(ruxmsg::Error::Storage(format!(
                "profile '{name}' already exists"
            )));
        }

        let identity = IdentityKeypair::generate();
        let fingerprint = format_identity(&identity.identity());

        store.save(&identity)?;

        self.identity = Some(ActiveIdentity {
            profile: name.to_string(),
            keypair: Arc::new(identity),
        });

        Ok(fingerprint)
    }

    fn profile_use(&mut self, name: &str) -> ruxmsg::Result<String> {
        validate_profile_name(name)?;

        let store = IdentityKeyStore::new(
            KeyringSecretStore::new(format!("ruxmsg-{name}")),
            "identity",
        );

        let identity = store
            .load()?
            .ok_or_else(|| ruxmsg::Error::Storage(format!("profile '{name}' does not exist")))?;

        let fingerprint = format_identity(&identity.identity());

        self.identity = Some(ActiveIdentity {
            profile: name.to_string(),
            keypair: Arc::new(identity),
        });

        Ok(fingerprint)
    }

    // -----------------------------------------------------------------
    // Listener
    // -----------------------------------------------------------------

    fn start(&mut self, addr: &str) -> Result<(), String> {
        if self.listener.is_some() {
            return Err("already listening — run `stop` first".into());
        }

        let identity = self
            .identity
            .as_ref()
            .map(|identity| Arc::clone(&identity.keypair))
            .ok_or_else(|| "no identity loaded — run `profile use <name>` first".to_string())?;

        let listener = TcpListener::bind(addr).map_err(|error| error.to_string())?;

        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;

        let bound_addr = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .to_string();

        let stop_flag = Arc::new(AtomicBool::new(false));

        let stop_flag_thread = Arc::clone(&stop_flag);
        let sessions = Arc::clone(&self.sessions);
        let events_tx = self.events_tx.clone();
        let next_label = Arc::clone(&self.next_label);

        let thread_addr = bound_addr.clone();

        let join = thread::spawn(move || {
            loop {
                if stop_flag_thread.load(Ordering::Acquire) {
                    break;
                }

                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        let label = fresh_label(&next_label);

                        spawn_session(
                            stream,
                            Arc::clone(&identity),
                            false,
                            label,
                            peer_addr.to_string(),
                            Arc::clone(&sessions),
                            events_tx.clone(),
                        );
                    }

                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }

                    Err(error) => {
                        let _ = events_tx.send(NetEvent::ListenerStopped {
                            addr: thread_addr,
                            error: Some(error.to_string()),
                        });

                        break;
                    }
                }
            }
        });

        self.listener = Some(ListenerHandle {
            addr: bound_addr,
            stop_flag,
            join,
        });

        Ok(())
    }

    fn stop(&mut self) -> Result<String, String> {
        let Some(listener) = self.listener.take() else {
            return Err("not listening".into());
        };

        listener.stop_flag.store(true, Ordering::Release);

        let addr = listener.addr.clone();

        let _ = listener.join.join();

        Ok(addr)
    }

    // -----------------------------------------------------------------
    // Connections
    // -----------------------------------------------------------------

    fn connect(&mut self, addr: &str) -> Result<String, String> {
        let identity = self
            .identity
            .as_ref()
            .map(|identity| Arc::clone(&identity.keypair))
            .ok_or_else(|| "no identity loaded — run `profile use <name>` first".to_string())?;

        let stream = TcpStream::connect(addr).map_err(|error| error.to_string())?;

        let label = fresh_label(&self.next_label);

        spawn_session(
            stream,
            identity,
            true,
            label.clone(),
            addr.to_string(),
            Arc::clone(&self.sessions),
            self.events_tx.clone(),
        );

        Ok(label)
    }

    // -----------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------

    fn send_message(&self, label: &str, text: &str) -> Result<(), String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;

        let handle = sessions
            .get(label)
            .ok_or_else(|| format!("no such session '{label}'"))?;

        handle
            .tx
            .send(SessionCommand::Send(text.to_string()))
            .map_err(|_| "session channel closed".to_string())
    }

    fn close_session(&self, label: &str) -> Result<(), String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;

        let handle = sessions
            .get(label)
            .ok_or_else(|| format!("no such session '{label}'"))?;

        handle
            .tx
            .send(SessionCommand::Close)
            .map_err(|_| "session channel already closed".to_string())
    }

    fn use_target(&mut self, label: &str) -> Result<(), String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;

        if !sessions.contains_key(label) {
            return Err(format!("no such session '{label}'"));
        }

        self.default_target = Some(label.to_string());

        Ok(())
    }

    fn peers(&self) -> Result<String, String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;

        if sessions.is_empty() {
            return Ok("no active sessions".to_string());
        }

        let mut labels: Vec<_> = sessions.keys().cloned().collect();
        labels.sort();

        let mut output = String::new();

        output.push_str("  LABEL    DIR  REMOTE                 STATUS\n");
        output.push_str("  ───────  ───  ─────────────────────  ─────────────\n");

        for label in labels {
            let session = &sessions[&label];

            let direction = if session.outbound { "out" } else { "in" };

            output.push_str(&format!(
                "  {label:<8} {direction:<4} {:<21} {}\n",
                session.remote_addr,
                session.status.as_str()
            ));
        }

        Ok(output)
    }

    fn fingerprint(&self, label: Option<&str>) -> Result<String, String> {
        match label {
            None => self
                .own_fingerprint()
                .ok_or_else(|| "no identity loaded".to_string()),

            Some(label) => {
                let sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| "session state poisoned".to_string())?;

                let session = sessions
                    .get(label)
                    .ok_or_else(|| format!("no such session '{label}'"))?;

                session
                    .fingerprint
                    .clone()
                    .ok_or_else(|| "handshake not complete yet".to_string())
            }
        }
    }

    fn session_info(&self, label: &str) -> Result<String, String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| "session state poisoned".to_string())?;

        let session = sessions
            .get(label)
            .ok_or_else(|| format!("no such session '{label}'"))?;

        Ok(format!(
            "label:       {label}\n\
             remote addr: {}\n\
             direction:   {}\n\
             status:      {}\n\
             fingerprint: {}",
            session.remote_addr,
            if session.outbound {
                "outbound"
            } else {
                "inbound"
            },
            session.status.as_str(),
            session.fingerprint.as_deref().unwrap_or("(pending)")
        ))
    }

    // -----------------------------------------------------------------
    // Event handling
    // -----------------------------------------------------------------

    fn drain_events(&mut self) -> Vec<NetEvent> {
        let mut events = Vec::new();

        while let Ok(event) = self.events_rx.try_recv() {
            events.push(event);
        }

        events
    }

    fn handle_event_for_repl(&mut self, event: NetEvent) {
        match event {
            NetEvent::Sas {
                label,
                words,
                answer_tx,
            } => {
                if self.pending_sas.is_some() {
                    let _ = answer_tx.send(false);

                    println!(
                        "\n[{label}] another SAS verification is already pending; \
                         this connection was rejected"
                    );

                    return;
                }

                println!(
                    "\n[{label}] SECURITY VERIFICATION\n\
                     [{label}] compare these words with your peer:\n\
                       {} {} {}\n\
                     [{label}] type 'y' or 'yes' to approve; anything else rejects.",
                    words[0], words[1], words[2]
                );

                self.pending_sas = Some(PendingSas {
                    label,
                    words,
                    answer_tx,
                });
            }

            NetEvent::Ready { label, fingerprint } => {
                println!("\n[{label}] connected");
                println!("    peer fingerprint: {fingerprint}");
            }

            NetEvent::Message { label, text } => {
                println!("\n[{label}] {text}");
            }

            NetEvent::PeerClosed { label, reason } => {
                println!("\n[{label}] peer closed ({reason:?})");

                if self.default_target.as_deref() == Some(label.as_str()) {
                    self.default_target = None;
                }
            }

            NetEvent::Error { label, message } => {
                println!("\n[{label}] error: {message}");
            }

            NetEvent::ListenerStopped { addr, error } => {
                if let Some(listener) = self.listener.take() {
                    // The worker already exited. Do not join ourselves here.
                    // Dropping the completed handle is sufficient.
                    let _ = listener;
                }

                match error {
                    Some(error) => {
                        println!("\nlistener on {addr} stopped: {error}");
                    }
                    None => {
                        println!("\nlistener on {addr} stopped");
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Chat
    // -----------------------------------------------------------------

    fn enter_chat(&mut self, label: &str) -> io::Result<()> {
        {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| io::Error::other("session state poisoned"))?;

            let session = sessions.get(label).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such session '{label}'"),
                )
            })?;

            if !matches!(session.status, SessionStatus::Connected) {
                return Err(io::Error::other(format!(
                    "session '{label}' is not connected"
                )));
            }
        }

        self.default_target = Some(label.to_string());

        /*
         * The REPL itself uses Crossterm raw mode so that it can remain
         * responsive to network events without a background stdin thread.
         *
         * Chat takes over the terminal completely.
         *
         * We therefore temporarily leave REPL raw mode, let Ratatui own
         * the terminal, then restore the REPL terminal state afterward.
         */
        disable_raw_mode()?;

        let result = self.run_chat_tui(label);

        /*
         * run_chat_tui restores the alternate screen and leaves raw mode.
         * The REPL owns raw mode again after this point.
         */
        enable_raw_mode()?;

        println!();

        result
    }

    fn run_chat_tui(&mut self, label: &str) -> io::Result<()> {
        let mut terminal = ratatui::init();

        let mut chat = ChatApp::new(label.to_string());

        let result = loop {
            for event in self.drain_events() {
                chat.handle_network_event(event, self);
            }

            terminal.draw(|frame| chat.render(frame))?;

            if event::poll(Duration::from_millis(50))? {
                match event::read()? {
                    CEvent::Key(key) if key.kind == KeyEventKind::Press => {
                        if chat.handle_key(key, self)? {
                            break Ok(());
                        }
                    }

                    CEvent::Resize(_, _) => {
                        // Ratatui redraws using the new frame area.
                    }

                    _ => {}
                }
            }

            if chat.closed {
                break Ok(());
            }
        };

        ratatui::restore();

        result
    }

    // -----------------------------------------------------------------
    // REPL
    // -----------------------------------------------------------------

    fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;

        let result = self.run_repl();

        disable_raw_mode()?;

        self.shutdown();

        result
    }

    fn run_repl(&mut self) -> io::Result<()> {
        let mut input = String::new();

        self.print_prompt()?;

        loop {
            for event in self.drain_events() {
                self.handle_event_for_repl(event);
            }

            if event::poll(Duration::from_millis(50))? {
                match event::read()? {
                    CEvent::Key(key) if key.kind == KeyEventKind::Press => {
                        if self.handle_repl_key(key, &mut input)? {
                            break;
                        }
                    }

                    CEvent::Resize(_, _) => {}

                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn handle_repl_key(&mut self, key: KeyEvent, input: &mut String) -> io::Result<bool> {
        if let Some(pending) = self.pending_sas.take() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let _ = pending.answer_tx.send(true);
                    self.write_line(&format!("[{}] approved", pending.label))?;
                    self.print_prompt()?;
                    return Ok(false);
                }

                KeyCode::Char('n')
                | KeyCode::Char('N')
                | KeyCode::Enter
                | KeyCode::Esc
                | KeyCode::Char(_) => {
                    let approved = matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y'));

                    let _ = pending.answer_tx.send(approved);

                    self.write_line(&format!(
                        "[{}] {}",
                        pending.label,
                        if approved { "approved" } else { "rejected" }
                    ))?;

                    self.print_prompt()?;

                    return Ok(false);
                }

                _ => {
                    self.pending_sas = Some(pending);
                    return Ok(false);
                }
            }
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(true);
            }

            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(true);
            }

            KeyCode::Enter => {
                let line = input.trim().to_string();

                self.clear_current_input()?;

                if !line.is_empty() {
                    if self.dispatch(&line)? {
                        return Ok(true);
                    }
                }

                input.clear();
                self.print_prompt()?;
            }

            KeyCode::Backspace => {
                if input.pop().is_some() {
                    print!("\x08 \x08");
                    io::stdout().flush()?;
                }
            }

            KeyCode::Char(character) => {
                input.push(character);
                print!("{character}");
                io::stdout().flush()?;
            }

            _ => {}
        }

        Ok(false)
    }

    fn dispatch(&mut self, line: &str) -> io::Result<bool> {
        let command = match CommandParser::parse(line) {
            Ok(command) => command,

            Err(error) => {
                self.write_line(&format!("error: {error}"))?;
                return Ok(false);
            }
        };

        match command {
            Command::Profile(command) => self.execute_profile(command)?,

            Command::Start { addr } => match self.start(&addr) {
                Ok(()) => self.write_line(&format!("listening on {addr}"))?,
                Err(error) => self.write_line(&format!("error: {error}"))?,
            },

            Command::Stop => match self.stop() {
                Ok(addr) => self.write_line(&format!("stopped listening on {addr}"))?,
                Err(error) => self.write_line(&format!("error: {error}"))?,
            },

            Command::Connect { addr } => match self.connect(&addr) {
                Ok(label) => self.write_line(&format!(
                    "dialing {addr} as '{label}' — waiting for handshake"
                ))?,
                Err(error) => self.write_line(&format!("error: {error}"))?,
            },

            Command::Peers => {
                let peers = self
                    .peers()
                    .unwrap_or_else(|error| format!("error: {error}"));
                self.write_line(&peers)?;
            }

            Command::Use { label } => match self.use_target(&label) {
                Ok(()) => self.write_line(&format!("default target set to '{label}'"))?,
                Err(error) => self.write_line(&format!("error: {error}"))?,
            },

            Command::Message { label, text } => {
                if let Err(error) = self.send_message(&label, &text) {
                    self.write_line(&format!("error: {error}"))?;
                }
            }

            Command::BareMessage(text) => {
                if let Some(target) = self.default_target.clone() {
                    if let Err(error) = self.send_message(&target, &text) {
                        self.write_line(&format!("error: {error}"))?;
                    }
                } else {
                    self.write_line("unknown command — no default chat target; type `help`")?;
                }
            }

            Command::Close { label } => match self.close_session(&label) {
                Ok(()) => self.write_line(&format!("closing '{label}'"))?,
                Err(error) => self.write_line(&format!("error: {error}"))?,
            },

            Command::Fingerprint { label } => match self.fingerprint(label.as_deref()) {
                Ok(fingerprint) => self.write_line(&fingerprint)?,
                Err(error) => self.write_line(&format!("error: {error}"))?,
            },

            Command::Session { label } => match self.session_info(&label) {
                Ok(info) => self.write_line(&info)?,
                Err(error) => self.write_line(&format!("error: {error}"))?,
            },

            Command::Chat { label } => {
                let target = label.or_else(|| self.default_target.clone());

                match target {
                    Some(target) => {
                        if let Err(error) = self.enter_chat(&target) {
                            self.write_line(&format!("error: {error}"))?;
                        }
                    }

                    None => {
                        self.write_line("usage: chat <label>")?;
                        self.write_line("or select a target first with `use <label>`")?;
                    }
                }
            }

            Command::Tailscale(command) => {
                self.execute_tailscale(command);
            }

            Command::Help => self.write_line(HELP_TEXT)?,

            Command::Quit => return Ok(true),
        }

        Ok(false)
    }

    fn execute_profile(&mut self, command: ProfileCommand) -> io::Result<()> {
        match command {
            ProfileCommand::Init(name) => match self.profile_init(&name) {
                Ok(fingerprint) => self.write_line(&format!(
                    "created profile '{name}', fingerprint {fingerprint}"
                ))?,

                Err(error) => {
                    self.write_line(&format!("error: {error}"))?;
                }
            },

            ProfileCommand::Use(name) => match self.profile_use(&name) {
                Ok(fingerprint) => self.write_line(&format!(
                    "loaded profile '{name}', fingerprint {fingerprint}"
                ))?,

                Err(error) => {
                    self.write_line(&format!("error: {error}"))?;
                }
            },

            ProfileCommand::List => {
                self.write_line(
                    "profile list isn't supported: identity seeds persist in \
                     the OS keyring, and OS keyrings do not provide a portable \
                     enumeration-by-prefix interface.\n\
                     Track profile names yourself and use `profile use <name>`.",
                )?;
            }
        }

        Ok(())
    }

    fn execute_tailscale(&self, command: TailscaleCommand) {
        match command {
            TailscaleCommand::Status => tailscale_status(),
            TailscaleCommand::Up => tailscale_up(),
            TailscaleCommand::Ip => tailscale_ip(),
        }
    }

    fn print_prompt(&self) -> io::Result<()> {
        print!("\r\nruxmsg> ");
        io::stdout().flush()
    }

    fn clear_current_input(&self) -> io::Result<()> {
        print!("\r\x1b[2K");
        io::stdout().flush()
    }

    fn write_line(&self, text: &str) -> io::Result<()> {
        print!("\r\x1b[2K{text}\r\n");
        io::stdout().flush()
    }

    // -----------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------

    fn shutdown(&mut self) {
        let _ = self.stop();

        let labels = self
            .sessions
            .lock()
            .map(|sessions| sessions.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        for label in labels {
            let _ = self.close_session(&label);
        }

        /*
         * Give close commands a bounded amount of time to enter the
         * session workers. We deliberately do not make application
         * shutdown depend on an arbitrary long sleep.
         */
        let deadline = Instant::now() + Duration::from_millis(500);

        while Instant::now() < deadline {
            let empty = self
                .sessions
                .lock()
                .map(|sessions| sessions.is_empty())
                .unwrap_or(true);

            if empty {
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }
    }
}

// =====================================================================
// COMMAND MODEL
// =====================================================================

enum Command {
    Profile(ProfileCommand),

    Start { addr: String },

    Stop,

    Connect { addr: String },

    Peers,

    Use { label: String },

    Message { label: String, text: String },

    BareMessage(String),

    Close { label: String },

    Fingerprint { label: Option<String> },

    Session { label: String },

    Chat { label: Option<String> },

    Tailscale(TailscaleCommand),

    Help,

    Quit,
}

enum ProfileCommand {
    Init(String),
    Use(String),
    List,
}

enum TailscaleCommand {
    Status,
    Up,
    Ip,
}

struct CommandParser;

impl CommandParser {
    fn parse(line: &str) -> Result<Command, String> {
        let line = line.trim();

        if line.is_empty() {
            return Err("empty command".into());
        }

        let mut words = line.split_whitespace();

        let command = words.next().unwrap_or_default();

        match command {
            "profile" => Self::parse_profile(words),

            "start" => {
                let args: Vec<_> = words.collect();

                if args.is_empty() {
                    return Ok(Command::Start {
                        addr: "0.0.0.0:4443".to_string(),
                    });
                }

                if args.len() == 2 && args[0] == "--addr" {
                    return Ok(Command::Start {
                        addr: args[1].to_string(),
                    });
                }

                Err("usage: start [--addr <addr>]".into())
            }

            "stop" => Self::no_args(words, Command::Stop, "stop"),

            "connect" => {
                let addr = words
                    .next()
                    .ok_or_else(|| "usage: connect <addr>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: connect <addr>".into());
                }

                Ok(Command::Connect {
                    addr: addr.to_string(),
                })
            }

            "peers" => Self::no_args(words, Command::Peers, "peers"),

            "use" => {
                let label = words
                    .next()
                    .ok_or_else(|| "usage: use <label>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: use <label>".into());
                }

                Ok(Command::Use {
                    label: label.to_string(),
                })
            }

            "msg" => {
                let mut parts = line.splitn(3, char::is_whitespace);

                let _ = parts.next();

                let label = parts
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "usage: msg <label> <text>".to_string())?;

                let text = parts
                    .next()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "usage: msg <label> <text>".to_string())?;

                Ok(Command::Message {
                    label: label.to_string(),
                    text: text.to_string(),
                })
            }

            "close" => {
                let label = words
                    .next()
                    .ok_or_else(|| "usage: close <label>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: close <label>".into());
                }

                Ok(Command::Close {
                    label: label.to_string(),
                })
            }

            "fingerprint" => {
                let label = words.next().map(str::to_string);

                if words.next().is_some() {
                    return Err("usage: fingerprint [label]".into());
                }

                Ok(Command::Fingerprint { label })
            }

            "session" => {
                let label = words
                    .next()
                    .ok_or_else(|| "usage: session <label>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: session <label>".into());
                }

                Ok(Command::Session {
                    label: label.to_string(),
                })
            }

            "chat" => {
                let label = words.next().map(str::to_string);

                if words.next().is_some() {
                    return Err("usage: chat [label]".into());
                }

                Ok(Command::Chat { label })
            }

            "tailscale" => Self::parse_tailscale(words),

            "help" => Self::no_args(words, Command::Help, "help"),

            "quit" | "exit" => Self::no_args(words, Command::Quit, "quit"),

            /*
             * Bare input remains a message if a default target exists.
             *
             * The application decides whether a bare command is a message
             * or an unknown command because only the application knows
             * whether a target is selected.
             */
            _ => Ok(Command::BareMessage(line.to_string())),
        }
    }

    fn parse_profile<'a>(mut words: impl Iterator<Item = &'a str>) -> Result<Command, String> {
        let subcommand = words
            .next()
            .ok_or_else(|| "usage: profile <init|use|list> ...".to_string())?;

        match subcommand {
            "init" => {
                let name = words
                    .next()
                    .ok_or_else(|| "usage: profile init <name>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: profile init <name>".into());
                }

                Ok(Command::Profile(ProfileCommand::Init(name.to_string())))
            }

            "use" => {
                let name = words
                    .next()
                    .ok_or_else(|| "usage: profile use <name>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: profile use <name>".into());
                }

                Ok(Command::Profile(ProfileCommand::Use(name.to_string())))
            }

            "list" => Self::no_args(
                words,
                Command::Profile(ProfileCommand::List),
                "profile list",
            ),

            _ => Err("usage: profile <init|use|list> ...".into()),
        }
    }

    fn parse_tailscale<'a>(mut words: impl Iterator<Item = &'a str>) -> Result<Command, String> {
        let subcommand = words.next().unwrap_or("status");

        if words.next().is_some() {
            return Err("usage: tailscale <status|up|ip>".into());
        }

        let command = match subcommand {
            "status" => TailscaleCommand::Status,
            "up" => TailscaleCommand::Up,
            "ip" => TailscaleCommand::Ip,
            _ => return Err("usage: tailscale <status|up|ip>".into()),
        };

        Ok(Command::Tailscale(command))
    }

    fn no_args<'a>(
        mut words: impl Iterator<Item = &'a str>,
        command: Command,
        usage: &str,
    ) -> Result<Command, String> {
        if words.next().is_some() {
            return Err(format!("usage: {usage}"));
        }

        Ok(command)
    }
}

// =====================================================================
// CHAT TUI
// =====================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageAuthor {
    Local,
    Remote,
    System,
}

struct ChatMessage {
    author: MessageAuthor,
    text: String,
}

struct ChatApp {
    label: String,
    messages: Vec<ChatMessage>,
    input: String,
    closed: bool,
    scroll: u16,
}

impl ChatApp {
    fn new(label: String) -> Self {
        Self {
            label,
            messages: Vec::new(),
            input: String::new(),
            closed: false,
            scroll: 0,
        }
    }

    fn handle_network_event(&mut self, event: NetEvent, app: &mut Application) {
        match event {
            NetEvent::Message { label, text } => {
                if label == self.label {
                    self.messages.push(ChatMessage {
                        author: MessageAuthor::Remote,
                        text,
                    });

                    self.scroll = u16::MAX;
                } else {
                    /*
                     * Another peer changed state while this chat was open.
                     * For now we retain the event at the application level
                     * only if it affects lifecycle.
                     */
                }
            }

            NetEvent::Ready { label, fingerprint } => {
                if label == self.label {
                    self.messages.push(ChatMessage {
                        author: MessageAuthor::System,
                        text: format!(
                            "secure session established — peer fingerprint {fingerprint}"
                        ),
                    });
                }
            }

            NetEvent::PeerClosed { label, reason } => {
                if label == self.label {
                    self.messages.push(ChatMessage {
                        author: MessageAuthor::System,
                        text: format!("peer closed the session: {reason:?}"),
                    });

                    self.closed = true;
                }
            }

            NetEvent::Error { label, message } => {
                if label == self.label {
                    self.messages.push(ChatMessage {
                        author: MessageAuthor::System,
                        text: format!("session error: {message}"),
                    });
                }
            }

            NetEvent::Sas {
                label,
                words,
                answer_tx,
            } => {
                /*
                 * SAS is an operator/security interaction. The first
                 * implementation keeps it in the application boundary.
                 *
                 * If a SAS arrives while chatting, present it in-band
                 * rather than allowing an unrelated session to consume it.
                 */
                if label == self.label {
                    self.messages.push(ChatMessage {
                        author: MessageAuthor::System,
                        text: format!("VERIFY WITH PEER: {} {} {}", words[0], words[1], words[2]),
                    });

                    self.messages.push(ChatMessage {
                        author: MessageAuthor::System,
                        text: "SAS approval from chat UI is not yet enabled; \
                               return to the REPL to approve or reject."
                            .to_string(),
                    });

                    app.pending_sas = Some(PendingSas {
                        label,
                        words,
                        answer_tx,
                    });
                } else {
                    let _ = answer_tx.send(false);
                }
            }

            NetEvent::ListenerStopped { .. } => {
                // Listener state is application-owned. Nothing visual
                // needs to happen inside a peer chat.
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, app: &mut Application) -> io::Result<bool> {
        match key.code {
            KeyCode::Esc => {
                self.closed = true;
                return Ok(true);
            }

            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.closed = true;
                return Ok(true);
            }

            KeyCode::Enter => {
                let message = self.input.trim().to_string();

                if !message.is_empty() {
                    match app.send_message(&self.label, &message) {
                        Ok(()) => {
                            self.messages.push(ChatMessage {
                                author: MessageAuthor::Local,
                                text: message,
                            });

                            self.input.clear();
                            self.scroll = u16::MAX;
                        }

                        Err(error) => {
                            self.messages.push(ChatMessage {
                                author: MessageAuthor::System,
                                text: format!("send failed: {error}"),
                            });
                        }
                    }
                }
            }

            KeyCode::Backspace => {
                self.input.pop();
            }

            KeyCode::Up => {
                self.scroll = self.scroll.saturating_add(1);
            }

            KeyCode::Down => {
                self.scroll = self.scroll.saturating_sub(1);
            }

            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_add(10);
            }

            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_sub(10);
            }

            KeyCode::Char(character) => {
                if !key.modifiers.contains(KeyModifiers::CONTROL) {
                    self.input.push(character);
                }
            }

            _ => {}
        }

        Ok(false)
    }

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();

        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(area);

        self.render_header(frame, vertical[0]);
        self.render_messages(frame, vertical[1]);
        self.render_input(frame, vertical[2]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let title = format!(" RUXMSG — {} ", self.label);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_bottom(" Esc: return to REPL ");

        frame.render_widget(block, area);
    }

    fn render_messages(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title(" Messages ");

        let inner = block.inner(area);

        frame.render_widget(block, area);

        let available_height = inner.height as usize;

        let total = self.messages.len();

        let start = if self.scroll == u16::MAX {
            total.saturating_sub(available_height)
        } else {
            total
                .saturating_sub(available_height)
                .saturating_sub(self.scroll as usize)
        };

        let visible = self
            .messages
            .iter()
            .skip(start)
            .take(available_height)
            .map(|message| {
                let prefix = match message.author {
                    MessageAuthor::Local => "you  ",
                    MessageAuthor::Remote => "peer ",
                    MessageAuthor::System => "*    ",
                };

                Line::from(format!("{prefix}{}", message.text))
            })
            .collect::<Vec<_>>();

        let paragraph = Paragraph::new(visible)
            .wrap(Wrap { trim: false })
            .scroll((0, 0));

        frame.render_widget(paragraph, inner);
    }

    fn render_input(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Message ")
            .title_bottom(" Enter: send • Esc: REPL ");

        let paragraph = Paragraph::new(self.input.as_str())
            .block(block)
            .wrap(Wrap { trim: false });

        frame.render_widget(paragraph, area);

        let cursor_x = area
            .x
            .saturating_add(1)
            .saturating_add(self.input.len() as u16);

        let cursor_y = area.y.saturating_add(1);

        frame.set_cursor_position(Position::new(cursor_x, cursor_y));
    }
}

// =====================================================================
// NETWORK SESSION WORKER
// =====================================================================

fn spawn_session(
    stream: TcpStream,
    identity: Arc<IdentityKeypair>,
    as_initiator: bool,
    label: String,
    remote_addr: String,
    sessions: Arc<Mutex<HashMap<String, PeerHandle>>>,
    events_tx: mpsc::Sender<NetEvent>,
) {
    let (tx, rx) = mpsc::channel::<SessionCommand>();

    {
        let mut sessions_guard = match sessions.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        sessions_guard.insert(
            label.clone(),
            PeerHandle {
                remote_addr,
                fingerprint: None,
                status: SessionStatus::Handshaking,
                outbound: as_initiator,
                tx,
            },
        );
    }

    thread::spawn(move || {
        let transport = FramedTransport::new(stream);

        let sas_events_tx = events_tx.clone();
        let sas_label = label.clone();

        let sas_approved = move |words: [&'static str; 3]| -> bool {
            let (answer_tx, answer_rx) = mpsc::channel();

            if sas_events_tx
                .send(NetEvent::Sas {
                    label: sas_label.clone(),
                    words,
                    answer_tx,
                })
                .is_err()
            {
                return false;
            }

            answer_rx.recv().unwrap_or(false)
        };

        let established = if as_initiator {
            PeerConnection::establish_as_initiator(
                transport,
                (*identity).clone(),
                sas_approved,
                Instant::now(),
            )
        } else {
            PeerConnection::establish_as_responder(
                transport,
                (*identity).clone(),
                sas_approved,
                Instant::now(),
            )
        };

        let connection = match established {
            Ok(connection) => connection,

            Err(error) => {
                let _ = events_tx.send(NetEvent::Error {
                    label: label.clone(),
                    message: error.to_string(),
                });

                if let Ok(mut sessions) = sessions.lock() {
                    sessions.remove(&label);
                }

                return;
            }
        };

        let fingerprint = format_identity(&connection.manager().active().peer_identity());

        let (mut reader, writer) = match connection.split_tcp() {
            Ok(halves) => halves,

            Err(error) => {
                let _ = events_tx.send(NetEvent::Error {
                    label: label.clone(),
                    message: error.to_string(),
                });

                if let Ok(mut sessions) = sessions.lock() {
                    sessions.remove(&label);
                }

                return;
            }
        };

        if let Ok(mut sessions) = sessions.lock() {
            if let Some(handle) = sessions.get_mut(&label) {
                handle.fingerprint = Some(fingerprint.clone());
                handle.status = SessionStatus::Connected;
            }
        }

        let _ = events_tx.send(NetEvent::Ready {
            label: label.clone(),
            fingerprint,
        });

        let writer_events_tx = events_tx.clone();
        let writer_label = label.clone();

        let writer_thread = thread::spawn(move || {
            for command in rx {
                match command {
                    SessionCommand::Send(text) => {
                        if let Err(error) = writer.send(text.as_bytes()) {
                            let _ = writer_events_tx.send(NetEvent::Error {
                                label: writer_label.clone(),
                                message: error.to_string(),
                            });

                            break;
                        }
                    }

                    SessionCommand::Close => {
                        let _ = writer.close(CloseReason::Normal);
                        break;
                    }
                }
            }
        });

        loop {
            match reader.recv_next() {
                Ok(ConnectionEvent::Data(bytes)) => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();

                    if events_tx
                        .send(NetEvent::Message {
                            label: label.clone(),
                            text,
                        })
                        .is_err()
                    {
                        break;
                    }
                }

                Ok(ConnectionEvent::PeerClosed(reason)) => {
                    let _ = events_tx.send(NetEvent::PeerClosed {
                        label: label.clone(),
                        reason,
                    });

                    break;
                }

                Err(error) => {
                    let _ = events_tx.send(NetEvent::Error {
                        label: label.clone(),
                        message: error.to_string(),
                    });

                    break;
                }
            }
        }

        let _ = writer_thread.join();

        if let Ok(mut sessions) = sessions.lock() {
            sessions.remove(&label);
        }
    });
}

// =====================================================================
// IDENTITY HELPERS
// =====================================================================

fn format_identity(identity: &PeerIdentity) -> String {
    identity
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn own_identity_string(keypair: &IdentityKeypair) -> String {
    format_identity(&keypair.identity())
}

fn validate_profile_name(name: &str) -> ruxmsg::Result<()> {
    if name.is_empty() {
        return Err(ruxmsg::Error::Storage(
            "profile name cannot be empty".into(),
        ));
    }

    if name.len() > 64 {
        return Err(ruxmsg::Error::Storage("profile name is too long".into()));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(ruxmsg::Error::Storage(
            "profile names may contain only ASCII letters, digits, '-' and '_'".into(),
        ));
    }

    Ok(())
}

fn fresh_label(counter: &Arc<Mutex<usize>>) -> String {
    let mut number = counter.lock().expect("session label counter poisoned");

    *number += 1;

    format!("peer{number}")
}

// =====================================================================
// REPL HELP
// =====================================================================

const HELP_TEXT: &str = "\
RUXMSG COMMANDS

IDENTITY
  profile init <name>       create a new identity profile
  profile use <name>        load an existing identity profile
  profile list              explain why profile enumeration is unavailable
  fingerprint [label]       show own or peer identity fingerprint

NETWORK
  start [--addr <addr>]     start accepting connections
                            default: 0.0.0.0:4443
  stop                      stop accepting new connections
  connect <addr>            connect to a peer

SESSIONS
  peers                     list active sessions
  use <label>               set the default chat target
  session <label>           show session information
  close <label>             close a session

MESSAGING
  chat [label]              open the Ratatui chat interface
  msg <label> <text>        send a message directly
  <text>                    send to the default target

TAILSCALE
  tailscale status          show Tailscale state
  tailscale up              bring Tailscale up
  tailscale ip              print the Tailscale address

GENERAL
  help                      show this guide
  quit                      close sessions and exit

CHAT
  Enter                     send message
  Esc                       return to the REPL
  Ctrl+C                    return to the REPL
  Up/Down                   scroll
  PageUp/PageDown            scroll faster";

// =====================================================================
// TAILSCALE
// =====================================================================

fn tailscale_missing_message() -> String {
    "tailscale not found on PATH — install it from \
     https://tailscale.com/download and try again"
        .to_string()
}

fn tailscale_status() {
    match ProcessCommand::new("tailscale")
        .args(["status", "--json"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);

            if text.contains("\"BackendState\":\"Running\"") {
                println!("tailscale: running");
            } else if text.contains("\"BackendState\":\"NeedsLogin\"") {
                println!("tailscale: installed, not logged in — run `tailscale up`");
            } else {
                println!("tailscale: installed, not running");
            }
        }

        Ok(output) => {
            println!(
                "tailscale status failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Err(_) => {
            println!("{}", tailscale_missing_message());
        }
    }
}

fn tailscale_up() {
    match ProcessCommand::new("tailscale")
        .arg("up")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) if status.success() => {
            println!("tailscale is up");
        }

        Ok(status) => {
            println!("`tailscale up` exited with {status}");
        }

        Err(_) => {
            println!("{}", tailscale_missing_message());
        }
    }
}

fn tailscale_ip() {
    match ProcessCommand::new("tailscale").arg("ip").output() {
        Ok(output) if output.status.success() => {
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }

        Ok(output) => {
            println!(
                "tailscale ip failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Err(_) => {
            println!("{}", tailscale_missing_message());
        }
    }
}
