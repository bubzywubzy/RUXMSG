//! ruxmsg — volatile P2P E2EE messaging REPL.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

use ruxmsg::close::CloseReason;
use ruxmsg::connection::{ConnectionEvent, PeerConnection};
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::identity::PeerIdentity;
use ruxmsg::storage::{IdentityKeyStore, KeyringSecretStore};
use ruxmsg::transport::FramedTransport;

fn format_identity(identity: &PeerIdentity) -> String {
    identity
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn own_identity_string(keypair: &IdentityKeypair) -> String {
    format_identity(&keypair.identity())
}

#[derive(Parser)]
#[command(name = "ruxmsg", about = "RUXMSG — volatile P2P E2EE messaging REPL")]
struct Args {
    /// Identity profile to load at startup. Omit and use `profile use
    /// <name>` (or `profile init <name>` for a first run) once the REPL
    /// is up.
    #[arg(long)]
    profile: Option<String>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let mut repl = Repl::new();

    if let Some(name) = &args.profile {
        match repl.profile_use(name) {
            Ok(fingerprint) => println!("loaded profile '{name}', fingerprint {fingerprint}"),
            Err(error) => println!(
                "could not load profile '{name}': {error} \
                 (run `profile init {name}` first if it doesn't exist yet)"
            ),
        }
    }

    repl.print_help();
    repl.run()
}

// ---------------------------------------------------------------------
// Session bookkeeping — purely in-memory, dropped on process exit
// ---------------------------------------------------------------------

#[derive(Clone)]
enum SessionStatus {
    Handshaking,
    Connected,
    Closed(String),
}

struct PeerHandle {
    remote_addr: String,
    fingerprint: Option<String>,
    status: SessionStatus,
    outbound: bool,
    ui_tx: mpsc::Sender<UiCommand>,
}

/// Sent from a session's network thread to the REPL's event loop.
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
}

/// Sent from the REPL to one session's writer thread.
enum UiCommand {
    Send(String),
    Close,
}

struct ListenerHandle {
    addr: String,
    stop_flag: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}

struct Repl {
    identity: Option<(String, Arc<IdentityKeypair>)>,
    sessions: Arc<Mutex<HashMap<String, PeerHandle>>>,
    default_target: Option<String>,
    next_label: Arc<Mutex<usize>>,
    listener_ctl: Option<ListenerHandle>,
    pending_sas: Vec<(String, mpsc::Sender<bool>)>,
    events_tx: mpsc::Sender<NetEvent>,
    events_rx: mpsc::Receiver<NetEvent>,
}

impl Repl {
    fn new() -> Self {
        let (events_tx, events_rx) = mpsc::channel();
        Repl {
            identity: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            default_target: None,
            next_label: Arc::new(Mutex::new(0)),
            listener_ctl: None,
            pending_sas: Vec::new(),
            events_tx,
            events_rx,
        }
    }

    fn own_fingerprint(&self) -> Option<String> {
        self.identity
            .as_ref()
            .map(|(_, keypair)| own_identity_string(keypair))
    }

    // -- profiles --------------------------------------------------

    fn profile_init(&mut self, name: &str) -> ruxmsg::Result<String> {
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
        store.save(&identity)?;

        let fingerprint = format_identity(&identity.identity()); // compute before the move below
        self.identity = Some((name.to_string(), Arc::new(identity)));
        Ok(fingerprint)
    }

    fn profile_use(&mut self, name: &str) -> ruxmsg::Result<String> {
        let store = IdentityKeyStore::new(
            KeyringSecretStore::new(format!("ruxmsg-{name}")),
            "identity",
        );

        let identity = store
            .load()?
            .ok_or_else(|| ruxmsg::Error::Storage(format!("profile '{name}' does not exist")))?;

        let fingerprint = format_identity(&identity.identity());
        self.identity = Some((name.to_string(), Arc::new(identity)));
        Ok(fingerprint)
    }

    // -- listening / connecting -------------------------------------

    fn start(&mut self, addr: &str) -> Result<(), String> {
        if self.listener_ctl.is_some() {
            return Err("already listening — run `stop` first".into());
        }
        let identity = match &self.identity {
            Some((_, keypair)) => Arc::clone(keypair),
            None => return Err("no identity loaded — run `profile use <name>` first".into()),
        };

        let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
        // Non-blocking so the accept loop can observe `stop` promptly
        // instead of blocking forever inside accept().
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_thread = Arc::clone(&stop_flag);
        let sessions = Arc::clone(&self.sessions);
        let events_tx = self.events_tx.clone();
        let next_label = Arc::clone(&self.next_label);
        let addr_owned = addr.to_string();

        let join = thread::spawn(move || {
            loop {
                if stop_flag_thread.load(Ordering::Relaxed) {
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
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(150));
                    }
                    Err(e) => {
                        let _ = events_tx.send(NetEvent::Error {
                            label: "listener".to_string(),
                            message: e.to_string(),
                        });
                        break;
                    }
                }
            }
        });

        self.listener_ctl = Some(ListenerHandle {
            addr: addr_owned,
            stop_flag,
            join,
        });
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        match self.listener_ctl.take() {
            Some(handle) => {
                handle.stop_flag.store(true, Ordering::Relaxed);
                let _ = handle.join.join();
                print!("stopped listening on {}", handle.addr);
                Ok(())
            }
            None => Err("not listening".into()),
        }
    }

    fn connect(&mut self, addr: &str) -> Result<String, String> {
        let identity = match &self.identity {
            Some((_, keypair)) => Arc::clone(keypair),
            None => return Err("no identity loaded — run `profile use <name>` first".into()),
        };
        let stream = TcpStream::connect(addr).map_err(|e| e.to_string())?;
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

    // -- per-session actions ------------------------------------------

    fn msg(&mut self, label: &str, text: &str) -> Result<(), String> {
        let sessions = self.sessions.lock().unwrap();
        let handle = sessions
            .get(label)
            .ok_or_else(|| format!("no such session '{label}'"))?;
        handle
            .ui_tx
            .send(UiCommand::Send(text.to_string()))
            .map_err(|_| "session channel closed".to_string())
    }

    fn close(&mut self, label: &str) -> Result<(), String> {
        let sessions = self.sessions.lock().unwrap();
        let handle = sessions
            .get(label)
            .ok_or_else(|| format!("no such session '{label}'"))?;
        handle
            .ui_tx
            .send(UiCommand::Close)
            .map_err(|_| "session channel already closed".to_string())
    }

    fn use_target(&mut self, label: &str) -> Result<(), String> {
        if !self.sessions.lock().unwrap().contains_key(label) {
            return Err(format!("no such session '{label}'"));
        }
        self.default_target = Some(label.to_string());
        Ok(())
    }

    fn peers(&self) -> String {
        let sessions = self.sessions.lock().unwrap();
        if sessions.is_empty() {
            return "no active sessions\n".to_string();
        }
        let mut labels: Vec<_> = sessions.keys().cloned().collect();
        labels.sort();
        let mut out = String::new();
        for label in labels {
            let h = &sessions[&label];
            let dir = if h.outbound { "out" } else { "in" };
            let status = match &h.status {
                SessionStatus::Handshaking => "handshaking".to_string(),
                SessionStatus::Connected => "connected".to_string(),
                SessionStatus::Closed(reason) => format!("closed ({reason})"),
            };
            let fp = h.fingerprint.as_deref().unwrap_or("(pending)");
            out.push_str(&format!(
                "  {label:<8} {dir:<3} {addr:<21} {status:<20} {fp}\n",
                addr = h.remote_addr
            ));
        }
        out
    }

    fn fingerprint(&self, label: Option<&str>) -> Result<String, String> {
        match label {
            None => self
                .own_fingerprint()
                .ok_or_else(|| "no identity loaded".to_string()),
            Some(label) => {
                let sessions = self.sessions.lock().unwrap();
                let handle = sessions
                    .get(label)
                    .ok_or_else(|| format!("no such session '{label}'"))?;
                handle
                    .fingerprint
                    .clone()
                    .ok_or_else(|| "handshake not complete yet".to_string())
            }
        }
    }

    // -- REPL loop ------------------------------------------------------

    fn run(&mut self) -> io::Result<()> {
        let (input_tx, input_rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(line) => {
                        if input_tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        print!("ruxmsg> ");
        io::stdout().flush().ok();

        loop {
            while let Ok(event) = self.events_rx.try_recv() {
                self.handle_event(event);
            }

            match input_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    let line = line.trim().to_string();
                    if let Some((label, answer_tx)) = self.pending_sas.pop() {
                        let approved = matches!(line.as_str(), "y" | "Y");
                        let _ = answer_tx.send(approved);
                        println!(
                            "[{label}] {}",
                            if approved { "approved" } else { "rejected" }
                        );
                    } else if line.is_empty() {
                        // nothing to do
                    } else if self.dispatch(&line) {
                        break; // `quit`
                    }
                    print!("ruxmsg> ");
                    io::stdout().flush().ok();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        self.shutdown();
        Ok(())
    }

    fn handle_event(&mut self, event: NetEvent) {
        match event {
            NetEvent::Sas {
                label,
                words,
                answer_tx,
            } => {
                println!(
                    "\n[{label}] verify these three words with your peer out-of-band:\n  {} {} {}",
                    words[0], words[1], words[2]
                );
                println!("[{label}] type 'y' + Enter to approve, anything else to reject.");
                self.pending_sas.push((label, answer_tx));
            }
            NetEvent::Ready { label, fingerprint } => {
                println!("\n[{label}] connected — peer fingerprint {fingerprint}");
            }
            NetEvent::Message { label, text } => {
                println!("\n[{label}] {text}");
            }
            NetEvent::PeerClosed { label, reason } => {
                println!("\n[{label}] peer closed ({reason:?})");
                if let Some(handle) = self.sessions.lock().unwrap().get_mut(&label) {
                    handle.status = SessionStatus::Closed(format!("{reason:?}"));
                }
                if self.default_target.as_deref() == Some(label.as_str()) {
                    self.default_target = None;
                }
            }
            NetEvent::Error { label, message } => {
                println!("\n[{label}] error: {message}");
            }
        }
    }

    fn dispatch(&mut self, line: &str) -> bool {
        let mut split = line.splitn(2, ' ');
        let cmd = split.next().unwrap_or("");
        let rest = split.next().unwrap_or("").trim();

        match cmd {
            "profile" => self.cmd_profile(rest),
            "start" => self.cmd_start(rest),
            "stop" => match self.stop() {
                Ok(()) => println!("stopped listening"),
                Err(e) => println!("error: {e}"),
            },
            "connect" => self.cmd_connect(rest),
            "peers" => print!("{}", self.peers()),
            "use" => self.cmd_use(rest),
            "msg" => self.cmd_msg(line),
            "close" => self.cmd_close(rest),
            "fingerprint" => self.cmd_fingerprint(rest),
            "session" => self.cmd_session(rest),
            "tailscale" => cmd_tailscale(rest),
            "help" => self.print_help(),
            "quit" => return true,
            other => {
                if let Some(target) = self.default_target.clone() {
                    // No default target set and not a known command: bare
                    // input is only ever treated as a message when a
                    // target is active.
                    if let Err(e) = self.msg(&target, line) {
                        println!("error: {e}");
                    }
                } else {
                    println!("unknown command '{other}' — type 'help'");
                }
            }
        }
        false
    }

    fn cmd_profile(&mut self, rest: &str) {
        let mut parts = rest.splitn(2, ' ');
        match parts.next() {
            Some("init") => {
                let Some(name) = parts.next().map(str::trim).filter(|s| !s.is_empty()) else {
                    println!("usage: profile init <name>");
                    return;
                };
                match self.profile_init(name) {
                    Ok(fingerprint) => {
                        println!("created profile '{name}', fingerprint {fingerprint}")
                    }
                    Err(e) => println!("error: {e}"),
                }
            }
            Some("use") => {
                let Some(name) = parts.next().map(str::trim).filter(|s| !s.is_empty()) else {
                    println!("usage: profile use <name>");
                    return;
                };
                match self.profile_use(name) {
                    Ok(fingerprint) => {
                        println!("loaded profile '{name}', fingerprint {fingerprint}")
                    }
                    Err(e) => println!("error: {e}"),
                }
            }
            Some("list") => {
                println!(
                    "profile list isn't supported: only the identity seed persists (in the \
                     OS keyring), and OS keyrings can't be enumerated by prefix. Track your \
                     profile names yourself, or `profile use <name>` a name you remember."
                );
            }
            _ => println!("usage: profile <init|use|list> ..."),
        }
    }

    fn cmd_start(&mut self, rest: &str) {
        let addr = parse_addr_flag(rest).unwrap_or_else(|| "0.0.0.0:4443".to_string());
        match self.start(&addr) {
            Ok(()) => println!("listening on {addr}"),
            Err(e) => println!("error: {e}"),
        }
    }

    fn cmd_connect(&mut self, rest: &str) {
        if rest.is_empty() {
            println!("usage: connect <addr>");
            return;
        }
        match self.connect(rest) {
            Ok(label) => println!("dialing {rest} as '{label}' — waiting for handshake"),
            Err(e) => println!("error: {e}"),
        }
    }

    fn cmd_use(&mut self, rest: &str) {
        if rest.is_empty() {
            println!("usage: use <label>");
            return;
        }
        match self.use_target(rest) {
            Ok(()) => println!("default target set to '{rest}'"),
            Err(e) => println!("error: {e}"),
        }
    }

    fn cmd_msg(&mut self, line: &str) {
        let mut parts = line.splitn(3, ' ');
        parts.next(); // "msg"
        let (Some(label), Some(text)) = (parts.next(), parts.next()) else {
            println!("usage: msg <label> <text>");
            return;
        };
        if let Err(e) = self.msg(label, text) {
            println!("error: {e}");
        }
    }

    fn cmd_close(&mut self, rest: &str) {
        if rest.is_empty() {
            println!("usage: close <label>");
            return;
        }
        match self.close(rest) {
            Ok(()) => println!("closing '{rest}'"),
            Err(e) => println!("error: {e}"),
        }
    }

    fn cmd_fingerprint(&mut self, rest: &str) {
        let label = if rest.is_empty() { None } else { Some(rest) };
        match self.fingerprint(label) {
            Ok(fp) => println!("{fp}"),
            Err(e) => println!("error: {e}"),
        }
    }

    fn cmd_session(&mut self, rest: &str) {
        if rest.is_empty() {
            println!("usage: session <label>");
            return;
        }
        let sessions = self.sessions.lock().unwrap();
        match sessions.get(rest) {
            Some(h) => {
                println!("label:       {rest}");
                println!("remote addr: {}", h.remote_addr);
                println!(
                    "direction:   {}",
                    if h.outbound { "outbound" } else { "inbound" }
                );
                let status = match &h.status {
                    SessionStatus::Handshaking => "handshaking".to_string(),
                    SessionStatus::Connected => "connected".to_string(),
                    SessionStatus::Closed(r) => format!("closed ({r})"),
                };
                println!("status:      {status}");
                println!(
                    "fingerprint: {}",
                    h.fingerprint.as_deref().unwrap_or("(pending)")
                );
                // TODO: if you want cipher/session details beyond this
                // (algorithm, sequence numbers, key epoch, etc.), the
                // PeerConnection handle isn't retained on PeerHandle today
                // — you'd add a field for whatever connection.manager()
                // exposes and stash it at handshake completion.
            }
            None => println!("no such session '{rest}'"),
        }
    }

    fn print_help(&self) {
        println!("{HELP_TEXT}");
    }

    fn shutdown(&mut self) {
        if self.listener_ctl.is_some() {
            let _ = self.stop();
        }
        let labels: Vec<String> = self.sessions.lock().unwrap().keys().cloned().collect();
        for label in labels {
            let _ = self.close(&label);
        }
        // Give session threads a moment to flush their close frames.
        thread::sleep(Duration::from_millis(200));
    }
}

const HELP_TEXT: &str = "\
profile init <name>    create a new identity profile (fails if one exists)
profile use <name>     load an existing profile into this session
profile list           explains why profile enumeration isn't supported
start [--addr <addr>]  bind + accept inbound connections (default 0.0.0.0:4443)
stop                   stop accepting new inbound connections
connect <addr>         dial a network address
peers                  list active sessions and their state
use <label>            set default send target for bare input
msg <label> <text>     send without changing default target
close <label>          close one peer's session
fingerprint [label]    show own or a peer's identity fingerprint
session <label>        show a session's connection details
tailscale status       show whether tailscale is installed / logged in / up
tailscale up           bring the tailscale interface up (interactive login if needed)
tailscale ip           print this node's tailscale address
help                   reprint this guide
quit                   close everything, exit";

fn parse_addr_flag(rest: &str) -> Option<String> {
    let mut tokens = rest.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "--addr" {
            return tokens.next().map(str::to_string);
        }
    }
    None
}

fn fresh_label(counter: &Arc<Mutex<usize>>) -> String {
    let mut n = counter.lock().unwrap();
    *n += 1;
    format!("peer{n}")
}

/// Drives one connection end to end: handshake (SAS confirmation relayed
/// through `events_tx` + a one-shot answer channel), then splits into a
/// reader loop (this thread) and a writer thread draining its `ui_rx`,
/// same concurrent send/receive shape as before — just labeled and
/// registered into the shared session map instead of being the only
/// connection in the process.
fn spawn_session(
    stream: TcpStream,
    identity: Arc<IdentityKeypair>,
    as_initiator: bool,
    label: String,
    remote_addr: String,
    sessions: Arc<Mutex<HashMap<String, PeerHandle>>>,
    events_tx: mpsc::Sender<NetEvent>,
) {
    let (ui_tx, ui_rx) = mpsc::channel::<UiCommand>();

    sessions.lock().unwrap().insert(
        label.clone(),
        PeerHandle {
            remote_addr,
            fingerprint: None,
            status: SessionStatus::Handshaking,
            outbound: as_initiator,
            ui_tx,
        },
    );

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

        // ASSUMPTION: IdentityKeypair: Clone. The keypair is now shared
        // (Arc) across every session this profile opens, rather than
        // moved into a single one-shot connection like before — a
        // keypair should be cheap to clone, but confirm the bound holds.
        //
        // No trust store: `None` here means every connection re-runs SAS,
        // every time, with no way to skip it via prior trust state.
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
                sessions.lock().unwrap().remove(&label);
                return;
            }
        };

        // `PeerIdentity` may not implement `Display`; fall back to its
        // debug formatting so the session can still publish a stable
        // fingerprint string without needing a crate-specific accessor.
        let fingerprint = format_identity(&connection.manager().active().peer_identity());

        let (mut reader, writer) = match connection.split_tcp() {
            Ok(halves) => halves,
            Err(error) => {
                let _ = events_tx.send(NetEvent::Error {
                    label: label.clone(),
                    message: error.to_string(),
                });
                sessions.lock().unwrap().remove(&label);
                return;
            }
        };

        if let Some(handle) = sessions.lock().unwrap().get_mut(&label) {
            handle.fingerprint = Some(fingerprint.clone());
            handle.status = SessionStatus::Connected;
        }
        let _ = events_tx.send(NetEvent::Ready {
            label: label.clone(),
            fingerprint,
        });

        let writer_events_tx = events_tx.clone();
        let writer_label = label.clone();
        let writer_thread = thread::spawn(move || {
            for command in ui_rx {
                match command {
                    UiCommand::Send(text) => {
                        if let Err(error) = writer.send(text.as_bytes()) {
                            let _ = writer_events_tx.send(NetEvent::Error {
                                label: writer_label.clone(),
                                message: error.to_string(),
                            });
                            break;
                        }
                    }
                    UiCommand::Close => {
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
        sessions.lock().unwrap().remove(&label);
    });
}

// ---------------------------------------------------------------------
// Tailscale — guided setup via the `tailscale` CLI binary
// ---------------------------------------------------------------------

fn cmd_tailscale(rest: &str) {
    let mut parts = rest.splitn(2, ' ');
    match parts.next() {
        Some("up") => tailscale_up(),
        Some("ip") => tailscale_ip(),
        _ => tailscale_status(), // "status", "", or anything unrecognized
    }
}

fn tailscale_missing_message() -> String {
    "tailscale not found on PATH — install it from https://tailscale.com/download and try again"
        .to_string()
}

fn tailscale_status() {
    match Command::new("tailscale")
        .args(["status", "--json"])
        .output()
    {
        Ok(output) if output.status.success() => {
            // Minimal on purpose: pull just the field the REPL needs
            // rather than pulling in a JSON crate for this alone. Swap
            // for a real JSON parse if you already depend on serde_json
            // elsewhere in the crate.
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("\"BackendState\":\"Running\"") {
                println!("tailscale: running");
            } else if text.contains("\"BackendState\":\"NeedsLogin\"") {
                println!("tailscale: installed, not logged in — run `tailscale up`");
            } else {
                println!("tailscale: installed, not running — run `tailscale up`");
            }
        }
        Ok(output) => {
            println!(
                "tailscale status failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(_) => println!("{}", tailscale_missing_message()),
    }
}

fn tailscale_up() {
    // Interactive on purpose: if login is required, `tailscale up` prints
    // an auth URL to stdout/stderr. Inheriting the REPL's stdio lets the
    // user see (and click, in most terminals) that URL directly, rather
    // than us trying to capture and re-print it.
    match Command::new("tailscale")
        .arg("up")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) if status.success() => println!("tailscale is up"),
        Ok(status) => println!("`tailscale up` exited with {status}"),
        Err(_) => println!("{}", tailscale_missing_message()),
    }
}

fn tailscale_ip() {
    match Command::new("tailscale").arg("ip").output() {
        Ok(output) if output.status.success() => {
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
        Ok(output) => println!(
            "tailscale ip failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(_) => println!("{}", tailscale_missing_message()),
    }
}
