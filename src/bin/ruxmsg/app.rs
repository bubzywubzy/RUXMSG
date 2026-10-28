//! Application state and the single async event loop.
//!
//! One task owns the terminal, the peer table and every scrollback. Network
//! events, key presses, signals and a slow tick are multiplexed with
//! `select!`; nothing here blocks on I/O except short keyring calls, which
//! run on the blocking pool.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crossterm::event::{Event as TermEvent, EventStream, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use futures_util::StreamExt;
use ratatui::DefaultTerminal;
use tokio::sync::mpsc::Receiver;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout_at};
use zeroize::{Zeroize, Zeroizing};

use ruxmsg::close::CloseReason;
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::display::sanitize_for_display;
use ruxmsg::identity::PeerIdentity;
use ruxmsg::machine::{CloseCause, RekeyFailure, SendRejection};
use ruxmsg::net::{ConnEvent, ConnId, ConnectionHandle, HandleError, Listener, Net, NetEvent};
use ruxmsg::protocol::{MAX_CONTENT, MAX_UNAUTHENTICATED_HANDSHAKES};
use ruxmsg::storage::{IdentityKeyStore, KeyringSecretStore};

use crate::hardening;
use crate::scrollback::{Author, Scrollback};
use crate::theme::Theme;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerStatus {
    Handshaking,
    Connected,
    Closed,
}

impl PeerStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Handshaking => "handshaking",
            Self::Connected => "connected",
            Self::Closed => "closed",
        }
    }
}

pub(crate) struct Peer {
    pub(crate) id: ConnId,
    pub(crate) handle: ConnectionHandle,
    pub(crate) remote: String,
    pub(crate) outbound: bool,
    pub(crate) status: PeerStatus,
    pub(crate) fingerprint: Option<String>,
    pub(crate) rekeying: bool,
    pub(crate) scrollback: Scrollback,
    pub(crate) unread: usize,
    pub(crate) close_note: Option<String>,
}

pub(crate) struct PendingSas {
    pub(crate) id: ConnId,
    pub(crate) label: String,
    pub(crate) words: [&'static str; 3],
    pub(crate) fingerprint: String,
    pub(crate) outbound: bool,
    pub(crate) since: Instant,
    pub(crate) typed: String,
}

pub(crate) struct ChatView {
    pub(crate) label: String,
    pub(crate) input: Zeroizing<String>,
    /// Rows scrolled up from the newest message.
    pub(crate) scroll: usize,
    pub(crate) max_scroll: Cell<usize>,
}

pub(crate) enum Mode {
    Repl,
    Chat(ChatView),
}

pub(crate) struct App {
    pub(crate) net: Option<Net>,
    pub(crate) net_rx: Option<Receiver<NetEvent>>,
    pub(crate) own_fingerprint: Option<String>,
    pub(crate) peers: BTreeMap<String, Peer>,
    pub(crate) by_id: HashMap<ConnId, String>,
    pub(crate) default_target: Option<String>,
    pub(crate) next_label: u64,
    pub(crate) listener: Option<Listener>,
    pub(crate) sas: VecDeque<PendingSas>,
    pub(crate) mode: Mode,
    pub(crate) input: Zeroizing<String>,
    pub(crate) terminal: Option<DefaultTerminal>,
    pub(crate) theme: Theme,
    pub(crate) quit: bool,
    /// Set once any message or SAS has been shown, so exit wipes the screen.
    pub(crate) touched: bool,
}

pub(crate) fn input_buffer() -> Zeroizing<String> {
    // Sized for a full message so typing never reallocates and strands a copy.
    Zeroizing::new(String::with_capacity(MAX_CONTENT + 4))
}

pub(crate) fn fingerprint(identity: &PeerIdentity) -> String {
    identity
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Groups a 64-character fingerprint for reading; never truncates it.
pub(crate) fn grouped(fingerprint: &str) -> String {
    let mut output = String::with_capacity(fingerprint.len() + fingerprint.len() / 8);

    for (index, character) in fingerprint.chars().enumerate() {
        if index > 0 && index % 8 == 0 {
            output.push(' ');
        }
        output.push(character);
    }

    output
}

pub(crate) fn is_approval(typed: &str) -> bool {
    typed.trim().eq_ignore_ascii_case("yes")
}

/// Converts peer bytes into display-safe text in one owned buffer.
pub(crate) fn ingest(bytes: &[u8]) -> String {
    let mut safe = sanitize_for_display(&String::from_utf8_lossy(bytes));

    if !safe.contains('\t') {
        return safe;
    }

    let spaced = safe.replace('\t', "    ");
    safe.zeroize();

    spaced
}

fn cause_text(cause: CloseCause) -> String {
    match cause {
        CloseCause::Local => "closed".to_string(),
        CloseCause::PeerUnauthenticated(reason) => {
            format!("peer closed (unauthenticated, {reason:?})")
        }
        CloseCause::TransportLost => "connection lost".to_string(),
        CloseCause::ProtocolError => "protocol error".to_string(),
        CloseCause::AuthenticationFailure => "authentication failed".to_string(),
        CloseCause::SasRejected => "SAS not approved".to_string(),
        CloseCause::Timeout => "timed out".to_string(),
    }
}

fn rekey_failure_text(failure: RekeyFailure) -> &'static str {
    match failure {
        RekeyFailure::Timeout => "rekey timed out; session unchanged",
        RekeyFailure::IdentityMismatch => "rekey rejected: identity changed; session unchanged",
        RekeyFailure::Rejected => "rekey request ignored",
        RekeyFailure::Invalid => "rekey failed; session unchanged",
    }
}

fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("profile name cannot be empty".into());
    }

    if name.len() > 64 {
        return Err("profile name is too long".into());
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("profile names may contain only ASCII letters, digits, '-' and '_'".into());
    }

    Ok(())
}

async fn next_net(receiver: &mut Option<Receiver<NetEvent>>) -> Option<NetEvent> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => pending().await,
    }
}

impl App {
    pub(crate) fn new() -> Self {
        Self {
            net: None,
            net_rx: None,
            own_fingerprint: None,
            peers: BTreeMap::new(),
            by_id: HashMap::new(),
            default_target: None,
            next_label: 0,
            listener: None,
            sas: VecDeque::new(),
            mode: Mode::Repl,
            input: input_buffer(),
            terminal: None,
            theme: Theme::default(),
            quit: false,
            touched: false,
        }
    }

    // ------------------------------------------------------------ identity

    fn ensure_idle(&self) -> Result<(), String> {
        if self.peers.is_empty() && self.listener.is_none() {
            Ok(())
        } else {
            Err("close all sessions and stop the listener before switching profiles".into())
        }
    }

    async fn load_identity(name: String, create: bool) -> Result<IdentityKeypair, String> {
        // Keyring backends may drive their own runtime, so keep them off this one.
        tokio::task::spawn_blocking(move || {
            validate_profile_name(&name)?;

            let mut store = IdentityKeyStore::new(
                KeyringSecretStore::new(format!("ruxmsg-{name}")),
                "identity",
            );

            if create {
                if store.load().map_err(|error| error.to_string())?.is_some() {
                    return Err(format!("profile '{name}' already exists"));
                }

                let identity = IdentityKeypair::generate();
                store.save(&identity).map_err(|error| error.to_string())?;

                Ok(identity)
            } else {
                store
                    .load()
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("profile '{name}' does not exist"))
            }
        })
        .await
        .map_err(|_| "storage task failed".to_string())?
    }

    pub(crate) async fn profile_init(&mut self, name: &str) -> Result<String, String> {
        self.ensure_idle()?;
        let identity = Self::load_identity(name.to_string(), true).await?;
        Ok(self.install_identity(identity))
    }

    pub(crate) async fn profile_use(&mut self, name: &str) -> Result<String, String> {
        self.ensure_idle()?;
        let identity = Self::load_identity(name.to_string(), false).await?;
        Ok(self.install_identity(identity))
    }

    fn install_identity(&mut self, identity: IdentityKeypair) -> String {
        let fingerprint = fingerprint(&identity.identity());

        let (net, receiver) = Net::new(identity);
        self.net = Some(net);
        self.net_rx = Some(receiver);
        self.own_fingerprint = Some(fingerprint.clone());

        fingerprint
    }

    // ----------------------------------------------------------- listener

    pub(crate) async fn start(&mut self, addr: &str) -> Result<SocketAddr, String> {
        if self.listener.is_some() {
            return Err("already listening — run `stop` first".into());
        }

        let net = self
            .net
            .as_ref()
            .ok_or_else(|| "no identity loaded — run `profile use <name>` first".to_string())?;

        let listener = net.listen(addr).await.map_err(|error| error.to_string())?;

        let bound = listener.local_addr();
        self.listener = Some(listener);

        Ok(bound)
    }

    pub(crate) fn stop(&mut self) -> Result<SocketAddr, String> {
        let listener = self.listener.take().ok_or("not listening")?;
        let addr = listener.local_addr();
        listener.stop();

        Ok(addr)
    }

    pub(crate) fn dial(&self, addr: &str) -> Result<(), String> {
        let net = self
            .net
            .as_ref()
            .ok_or_else(|| "no identity loaded — run `profile use <name>` first".to_string())?;

        net.dial(addr.to_string());

        Ok(())
    }

    // ------------------------------------------------------------ sessions

    fn fresh_label(&mut self) -> String {
        self.next_label += 1;
        format!("peer{}", self.next_label)
    }

    pub(crate) fn peer(&self, label: &str) -> Result<&Peer, String> {
        self.peers
            .get(label)
            .ok_or_else(|| format!("no such session '{label}'"))
    }

    pub(crate) fn send_text(&mut self, label: &str, text: String) -> Result<(), String> {
        let mut text = Zeroizing::new(text);

        if text.len() > MAX_CONTENT {
            return Err(format!("message too long (limit {MAX_CONTENT} bytes)"));
        }

        let peer = self
            .peers
            .get_mut(label)
            .ok_or_else(|| format!("no such session '{label}'"))?;

        if peer.status != PeerStatus::Connected {
            return Err(format!("session '{label}' is not connected"));
        }

        let shown = ingest(text.as_bytes());

        let bytes = Zeroizing::new(std::mem::take(&mut *text).into_bytes());

        peer.handle
            .send_message(bytes)
            .map_err(|error| match error {
                HandleError::Busy => "send queue is full; try again".to_string(),
                HandleError::Gone => "session already closed".to_string(),
            })?;

        peer.scrollback.push(Author::Local, shown);
        self.touched = true;

        Ok(())
    }

    pub(crate) fn close_session(&self, label: &str) -> Result<(), String> {
        self.peer(label)?
            .handle
            .close(CloseReason::Normal)
            .map_err(|_| "session already closed".to_string())
    }

    pub(crate) fn request_rekey(&self, label: &str) -> Result<(), String> {
        let peer = self.peer(label)?;

        if peer.status != PeerStatus::Connected {
            return Err(format!("session '{label}' is not connected"));
        }

        peer.handle
            .request_rekey()
            .map_err(|_| "session already closed".to_string())
    }

    pub(crate) fn use_target(&mut self, label: &str) -> Result<(), String> {
        self.peer(label)?;
        self.default_target = Some(label.to_string());

        Ok(())
    }

    pub(crate) fn peers_table(&self) -> String {
        if self.peers.is_empty() {
            return "no active sessions".to_string();
        }

        let mut output = String::from("  LABEL    DIR  REMOTE                 STATUS        NEW\n");
        output.push_str("  ───────  ───  ─────────────────────  ────────────  ───\n");

        for (label, peer) in &self.peers {
            output.push_str(&format!(
                "  {label:<8} {:<4} {:<21}  {:<12}  {}\n",
                if peer.outbound { "out" } else { "in" },
                peer.remote,
                peer.status.as_str(),
                peer.unread,
            ));
        }

        output
    }

    pub(crate) fn session_info(&self, label: &str) -> Result<String, String> {
        let peer = self.peer(label)?;

        Ok(format!(
            "label:       {label}\n\
             remote addr: {}\n\
             direction:   {}\n\
             status:      {}\n\
             fingerprint: {}",
            peer.remote,
            if peer.outbound { "outbound" } else { "inbound" },
            peer.status.as_str(),
            peer.fingerprint.as_deref().unwrap_or("(pending)")
        ))
    }

    pub(crate) fn fingerprint_of(&self, label: Option<&str>) -> Result<String, String> {
        match label {
            None => self
                .own_fingerprint
                .clone()
                .ok_or_else(|| "no identity loaded".to_string()),
            Some(label) => self
                .peer(label)?
                .fingerprint
                .clone()
                .ok_or_else(|| "handshake not complete yet".to_string()),
        }
    }

    // ----------------------------------------------------------------- SAS

    pub(crate) fn answer_sas(&mut self, approved: bool) {
        let Some(pending) = self.sas.pop_front() else {
            return;
        };

        if let Some(peer) = self.peers.get(&pending.label) {
            let _ = peer.handle.answer_sas(approved);
        }

        self.say(&format!(
            "[{}] {}",
            pending.label,
            if approved { "approved" } else { "rejected" }
        ));

        self.announce_sas();
    }

    // ---------------------------------------------------------- net events

    pub(crate) fn on_net_event(&mut self, event: NetEvent) -> io::Result<()> {
        match event {
            NetEvent::Opened {
                id,
                handle,
                remote,
                outbound,
            } => {
                let label = self.fresh_label();

                self.by_id.insert(id, label.clone());
                self.peers.insert(
                    label.clone(),
                    Peer {
                        id,
                        handle,
                        remote: remote.to_string(),
                        outbound,
                        status: PeerStatus::Handshaking,
                        fingerprint: None,
                        rekeying: false,
                        scrollback: Scrollback::default(),
                        unread: 0,
                        close_note: None,
                    },
                );

                self.say(&if outbound {
                    format!("[{label}] connected to {remote}; handshaking")
                } else {
                    format!("[{label}] inbound connection from {remote}; handshaking")
                });
            }

            NetEvent::DialFailed { addr, error } => {
                self.say(&format!("could not connect to {addr}: {error}"));
            }

            NetEvent::ListenerStopped { addr, error } => {
                self.listener = None;

                self.say(&match error {
                    Some(error) => format!("listener on {addr} stopped: {error}"),
                    None => format!("listener on {addr} stopped"),
                });
            }

            NetEvent::Conn { id, event } => self.on_conn_event(id, event),
        }

        self.redraw_chat()
    }

    fn on_conn_event(&mut self, id: ConnId, event: ConnEvent) {
        let Some(label) = self.by_id.get(&id).cloned() else {
            return;
        };

        match event {
            ConnEvent::SasRequired {
                words,
                peer_identity,
            } => {
                let claimed = fingerprint(&peer_identity);
                let mut outbound = false;

                if let Some(peer) = self.peers.get_mut(&label) {
                    peer.fingerprint = Some(claimed.clone());
                    outbound = peer.outbound;

                    if self.sas.len() >= MAX_UNAUTHENTICATED_HANDSHAKES {
                        let _ = peer.handle.answer_sas(false);
                        return;
                    }
                }

                self.touched = true;

                let was_empty = self.sas.is_empty();

                self.sas.push_back(PendingSas {
                    id,
                    label,
                    words,
                    fingerprint: claimed,
                    outbound,
                    since: Instant::now(),
                    typed: String::new(),
                });

                if was_empty {
                    self.announce_sas();
                }
            }

            ConnEvent::Established { peer_identity } => {
                let claimed = fingerprint(&peer_identity);

                if let Some(peer) = self.peers.get_mut(&label) {
                    peer.status = PeerStatus::Connected;
                    peer.fingerprint = Some(claimed.clone());
                    peer.scrollback
                        .push(Author::System, "secure session established".to_string());
                }

                self.say(&format!(
                    "[{label}] connected\n    peer fingerprint: {claimed}"
                ));
            }

            ConnEvent::Message(bytes) => {
                self.touched = true;

                let text = ingest(&bytes);
                let open = matches!(&self.mode, Mode::Chat(view) if view.label == label);

                if !open {
                    self.say_message(&label, &text);
                }

                if let Some(peer) = self.peers.get_mut(&label) {
                    if !open {
                        peer.unread += 1;
                    }

                    peer.scrollback.push(Author::Remote, text);
                }

                if let Mode::Chat(view) = &mut self.mode
                    && view.label == label
                {
                    view.scroll = 0;
                }
            }

            ConnEvent::RekeyStarted => {
                if let Some(peer) = self.peers.get_mut(&label) {
                    peer.rekeying = true;
                }
            }

            ConnEvent::RekeyCompleted => {
                if let Some(peer) = self.peers.get_mut(&label) {
                    peer.rekeying = false;
                }
            }

            ConnEvent::RekeyFailed(failure) => {
                let text = rekey_failure_text(failure);

                if let Some(peer) = self.peers.get_mut(&label) {
                    peer.rekeying = false;
                    peer.scrollback.push(Author::System, text.to_string());
                }

                self.say(&format!("[{label}] {text}"));
            }

            ConnEvent::DataRejected => {}

            ConnEvent::SendRejected(reason) => {
                let text = match reason {
                    SendRejection::NotActive => "message not sent: session not active",
                    SendRejection::TooLarge => "message not sent: too large",
                };

                if let Some(peer) = self.peers.get_mut(&label) {
                    peer.scrollback.push(Author::System, text.to_string());
                }

                self.say(&format!("[{label}] {text}"));
            }

            ConnEvent::Closed(cause) => self.on_closed(id, &label, cause),
        }
    }

    fn on_closed(&mut self, id: ConnId, label: &str, cause: CloseCause) {
        let was_front = self.sas.front().is_some_and(|pending| pending.id == id);
        self.sas.retain(|pending| pending.id != id);

        let note = cause_text(cause);

        let open = matches!(&self.mode, Mode::Chat(view) if view.label == label);

        if let Some(peer) = self.peers.get_mut(label) {
            peer.status = PeerStatus::Closed;
            peer.rekeying = false;
            peer.close_note = Some(note.clone());
            peer.scrollback.push(Author::System, note.clone());
        }

        self.say(&format!("[{label}] {note}"));

        if self.default_target.as_deref() == Some(label) {
            self.default_target = None;
        }

        // A closed conversation stays readable only while its chat is open.
        if !open {
            self.forget(label);
        }

        if was_front {
            self.announce_sas();
        }
    }

    /// Drops a session and, with it, its scrollback.
    pub(crate) fn forget(&mut self, label: &str) {
        if let Some(peer) = self.peers.remove(label) {
            self.by_id.remove(&peer.id);
        }
    }

    // ----------------------------------------------------------- main loop

    pub(crate) async fn run(&mut self) -> io::Result<()> {
        enable_raw_mode()?;

        let mut keys = EventStream::new();
        let mut tick = interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut terminate = Box::pin(hardening::terminate_signal());

        self.redraw_prompt()?;

        let result = loop {
            tokio::select! {
                key = keys.next() => match key {
                    Some(Ok(event)) => {
                        if let Err(error) = self.on_terminal_event(event).await {
                            break Err(error);
                        }
                    }
                    Some(Err(error)) => break Err(error),
                    None => break Ok(()),
                },
                event = next_net(&mut self.net_rx) => {
                    if let Some(event) = event
                        && let Err(error) = self.on_net_event(event)
                    {
                        break Err(error);
                    }
                }
                _ = tick.tick() => {
                    if let Err(error) = self.redraw_chat() {
                        break Err(error);
                    }
                }
                () = &mut terminate => break Ok(()),
            }

            if self.quit {
                break Ok(());
            }
        };

        self.leave_chat_terminal();
        let _ = disable_raw_mode();
        self.shutdown().await;

        result
    }

    async fn on_terminal_event(&mut self, event: TermEvent) -> io::Result<()> {
        let in_chat = matches!(self.mode, Mode::Chat(_));

        match event {
            TermEvent::Key(key) if key.kind == KeyEventKind::Press => {
                if in_chat {
                    self.chat_key(key)
                } else {
                    self.repl_key(key).await
                }
            }
            TermEvent::Resize(..) => self.redraw_chat(),
            _ => Ok(()),
        }
    }

    /// Closes every session, gives CLOSE frames a moment to leave, then wipes
    /// all in-memory conversation state.
    async fn shutdown(&mut self) {
        let _ = self.stop();

        for peer in self.peers.values() {
            let _ = peer.handle.close(CloseReason::Shutdown);
        }

        if let Some(mut receiver) = self.net_rx.take() {
            let deadline = Instant::now() + Duration::from_millis(500);

            while self
                .peers
                .values()
                .any(|peer| peer.status != PeerStatus::Closed)
            {
                match timeout_at(deadline, receiver.recv()).await {
                    Ok(Some(NetEvent::Conn {
                        id,
                        event: ConnEvent::Closed(_),
                    })) => {
                        if let Some(label) = self.by_id.get(&id)
                            && let Some(peer) = self.peers.get_mut(label)
                        {
                            peer.status = PeerStatus::Closed;
                        }
                    }
                    // Other events carry nothing worth keeping.
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }

        self.peers.clear();
        self.by_id.clear();
        self.sas.clear();
        self.input.zeroize();
        self.mode = Mode::Repl;

        if self.touched {
            hardening::wipe_screen();
        }
    }
}
