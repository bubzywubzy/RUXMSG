use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use ruxmsg::close::CloseReason;
use ruxmsg::connection::{ConnectionEvent, PeerConnection};
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::identity::{PeerRecord, TrustState};
use ruxmsg::storage::{IdentityKeyStore, KeyringSecretStore, SealedFileTrustStore, TrustStore};
use ruxmsg::transport::FramedTransport;

#[derive(Parser)]
#[command(name = "ruxmsg", about = "RUXMSG terminal messaging client")]
struct Args {
    /// Local profile name; scopes the keychain identity and trust-store file.
    #[arg(long, default_value = "default")]
    profile: String,
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Wait for a single incoming peer connection.
    Listen {
        #[arg(long, default_value = "127.0.0.1:4443")]
        addr: String,
    },
    /// Dial a peer that is listening.
    Connect { addr: String },
}

/// Sent from the network thread to the UI thread.
enum NetEvent {
    Sas([&'static str; 3], mpsc::Sender<bool>),
    Ready,
    Message(String),
    PeerClosed(CloseReason),
    Error(String),
}

/// Sent from the UI thread to the network thread.
enum UiCommand {
    Send(String),
    Close,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let identity = load_identity(&args.profile).map_err(to_io_error)?;
    let trust_store = open_trust_store(&args.profile).map_err(to_io_error)?;

    let (net_tx, ui_rx) = mpsc::channel::<NetEvent>();
    let (ui_tx, net_rx) = mpsc::channel::<UiCommand>();

    let net_handle = thread::spawn(move || match args.mode {
        Mode::Listen { addr } => run_listener(&addr, identity, trust_store, net_tx, net_rx),
        Mode::Connect { addr } => run_dialer(&addr, identity, trust_store, net_tx, net_rx),
    });

    run_ui(ui_rx, ui_tx)?;
    let _ = net_handle.join();
    Ok(())
}

fn to_io_error(error: ruxmsg::Error) -> io::Error {
    io::Error::other(error.to_string())
}

fn config_dir(profile: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".ruxmsg").join(profile)
}

fn load_identity(profile: &str) -> ruxmsg::Result<IdentityKeypair> {
    let secrets = KeyringSecretStore::new(format!("ruxmsg-{profile}"));
    IdentityKeyStore::new(secrets, "identity").load_or_generate()
}

fn open_trust_store(profile: &str) -> ruxmsg::Result<SealedFileTrustStore<KeyringSecretStore>> {
    let dir = config_dir(profile);
    std::fs::create_dir_all(&dir).map_err(|error| ruxmsg::Error::Storage(error.to_string()))?;
    let secrets = KeyringSecretStore::new(format!("ruxmsg-{profile}"));
    SealedFileTrustStore::open(dir.join("trust.sealed"), secrets, "trust-key")
}

fn run_listener(
    addr: &str,
    identity: IdentityKeypair,
    trust_store: SealedFileTrustStore<KeyringSecretStore>,
    net_tx: mpsc::Sender<NetEvent>,
    net_rx: mpsc::Receiver<UiCommand>,
) {
    let listener = match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = net_tx.send(NetEvent::Error(error.to_string()));
            return;
        }
    };
    let stream = match listener.accept() {
        Ok((stream, _)) => stream,
        Err(error) => {
            let _ = net_tx.send(NetEvent::Error(error.to_string()));
            return;
        }
    };
    run_established(stream, identity, trust_store, false, net_tx, net_rx);
}

fn run_dialer(
    addr: &str,
    identity: IdentityKeypair,
    trust_store: SealedFileTrustStore<KeyringSecretStore>,
    net_tx: mpsc::Sender<NetEvent>,
    net_rx: mpsc::Receiver<UiCommand>,
) {
    let stream = match TcpStream::connect(addr) {
        Ok(stream) => stream,
        Err(error) => {
            let _ = net_tx.send(NetEvent::Error(error.to_string()));
            return;
        }
    };
    run_established(stream, identity, trust_store, true, net_tx, net_rx);
}

/// Drives one connection end to end: handshake (with interactive SAS
/// confirmation relayed through `net_tx`/a one-shot answer channel), then
/// splits into a reader loop (this thread) and a writer thread that drains
/// `net_rx`, per the concurrent send/receive design in `connection.rs`.
fn run_established(
    stream: TcpStream,
    identity: IdentityKeypair,
    mut trust_store: SealedFileTrustStore<KeyringSecretStore>,
    as_initiator: bool,
    net_tx: mpsc::Sender<NetEvent>,
    net_rx: mpsc::Receiver<UiCommand>,
) {
    let transport = FramedTransport::new(stream);
    let sas_tx = net_tx.clone();
    let sas_approved = move |words: [&'static str; 3]| -> bool {
        let (answer_tx, answer_rx) = mpsc::channel();
        if sas_tx.send(NetEvent::Sas(words, answer_tx)).is_err() {
            return false;
        }
        answer_rx.recv().unwrap_or(false)
    };
    let trusted_identity = trust_store
        .records()
        .iter()
        .find(|r| r.trust_state == TrustState::Trusted)
        .map(|r| (r.identity, r.trust_state));
    let established = if as_initiator {
        PeerConnection::establish_as_initiator(
            transport,
            identity,
            sas_approved,
            trusted_identity,
            Instant::now(),
        )
    } else {
        PeerConnection::establish_as_responder(
            transport,
            identity,
            sas_approved,
            trusted_identity,
            Instant::now(),
        )
    };
    let connection = match established {
        Ok(connection) => connection,
        Err(error) => {
            let _ = net_tx.send(NetEvent::Error(error.to_string()));
            return;
        }
    };

    // First-contact verification already happened via SAS above; record the
    // peer as trusted for future reference (not yet used to skip SAS again).
    let peer_identity = connection.manager().active().peer_identity();
    let mut record = PeerRecord::new(peer_identity);
    record.trust_state = TrustState::Trusted;
    let _ = trust_store.put(record);

    let (mut reader, writer) = match connection.split_tcp() {
        Ok(halves) => halves,
        Err(error) => {
            let _ = net_tx.send(NetEvent::Error(error.to_string()));
            return;
        }
    };
    let _ = net_tx.send(NetEvent::Ready);

    let writer_net_tx = net_tx.clone();
    let writer_thread = thread::spawn(move || {
        for command in net_rx {
            match command {
                UiCommand::Send(text) => {
                    if let Err(error) = writer.send(text.as_bytes()) {
                        let _ = writer_net_tx.send(NetEvent::Error(error.to_string()));
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
                if net_tx.send(NetEvent::Message(text)).is_err() {
                    break;
                }
            }
            Ok(ConnectionEvent::PeerClosed(reason)) => {
                let _ = net_tx.send(NetEvent::PeerClosed(reason));
                break;
            }
            Err(error) => {
                let _ = net_tx.send(NetEvent::Error(error.to_string()));
                break;
            }
        }
    }
    let _ = writer_thread.join();
}

struct App {
    messages: Vec<String>,
    input: String,
    status: String,
    sas_prompt: Option<([&'static str; 3], mpsc::Sender<bool>)>,
}

fn run_ui(ui_rx: mpsc::Receiver<NetEvent>, ui_tx: mpsc::Sender<UiCommand>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        messages: Vec::new(),
        input: String::new(),
        status: "connecting...".to_string(),
        sas_prompt: None,
    };

    let result = run_ui_loop(&mut terminal, &mut app, &ui_rx, &ui_tx);

    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    result
}

fn run_ui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    ui_rx: &mpsc::Receiver<NetEvent>,
    ui_tx: &mpsc::Sender<UiCommand>,
) -> io::Result<()> {
    loop {
        while let Ok(event) = ui_rx.try_recv() {
            match event {
                NetEvent::Sas(words, answer_tx) => app.sas_prompt = Some((words, answer_tx)),
                NetEvent::Ready => app.status = "connected".to_string(),
                NetEvent::Message(text) => app.messages.push(format!("peer: {text}")),
                NetEvent::PeerClosed(reason) => {
                    app.status = format!("peer closed ({reason:?})");
                }
                NetEvent::Error(message) => app.status = format!("error: {message}"),
            }
        }

        terminal.draw(|frame| draw(frame, app))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if app.sas_prompt.is_some() {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        if let Some((_, answer_tx)) = app.sas_prompt.take() {
                            let _ = answer_tx.send(true);
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        if let Some((_, answer_tx)) = app.sas_prompt.take() {
                            let _ = answer_tx.send(false);
                        }
                    }
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Esc => {
                    let _ = ui_tx.send(UiCommand::Close);
                    return Ok(());
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let _ = ui_tx.send(UiCommand::Close);
                    return Ok(());
                }
                KeyCode::Enter if !app.input.is_empty() => {
                    let text = std::mem::take(&mut app.input);
                    app.messages.push(format!("me: {text}"));
                    let _ = ui_tx.send(UiCommand::Send(text));
                }
                KeyCode::Backspace => {
                    app.input.pop();
                }
                KeyCode::Char(character) => app.input.push(character),
                _ => {}
            }
        }
    }
}

fn draw(frame: &mut ratatui::Frame, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let status = Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::Yellow));
    frame.render_widget(status, layout[0]);

    if let Some((words, _)) = &app.sas_prompt {
        let text = format!(
            "Verify these three words with your peer out-of-band:\n\n  {} {} {}\n\n[y] approve   [n]/[Esc] reject",
            words[0], words[1], words[2]
        );
        let block = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("SAS confirmation"),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(block, layout[1]);
    } else {
        let items: Vec<ListItem> = app
            .messages
            .iter()
            .map(|m| ListItem::new(m.as_str()))
            .collect();
        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Messages"));
        frame.render_widget(list, layout[1]);
    }

    let input = Paragraph::new(app.input.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Message (Enter to send, Esc to quit)"),
    );
    frame.render_widget(input, layout[2]);
}
