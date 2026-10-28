//! Conversation view: one conversation at a time, with a modal for SAS.
//!
//! Everything shown here comes from bounded in-RAM scrollback. Peer text has
//! already been sanitized on ingestion, and rows are drawn as slices of that
//! text so rendering makes no further copies of message bodies.

use std::cell::Cell;
use std::io;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::enable_raw_mode;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ruxmsg_cli::config::{KeyName, KeySpec};
use unicode_width::UnicodeWidthChar;
use zeroize::{Zeroize, Zeroizing};

use ruxmsg::protocol::{MAX_CONTENT, SAS_DECISION_TIMEOUT_SECS};

use crate::app::{App, ChatView, Mode, Peer, PeerStatus, grouped, input_buffer, is_approval};
use crate::scrollback::{Author, Entry};

const MIN_WIDTH: u16 = 30;
const MIN_HEIGHT: u16 = 14;
const GUTTER: &str = "      ";

fn key_matches(spec: &KeySpec, key: &KeyEvent) -> bool {
    let wanted = match spec.key {
        KeyName::Esc => KeyCode::Esc,
        KeyName::Up => KeyCode::Up,
        KeyName::Down => KeyCode::Down,
        KeyName::PageUp => KeyCode::PageUp,
        KeyName::PageDown => KeyCode::PageDown,
        KeyName::Home => KeyCode::Home,
        KeyName::End => KeyCode::End,
        KeyName::Function(number) => KeyCode::F(number),
        KeyName::Letter(letter) => match key.code {
            KeyCode::Char(typed) if typed.eq_ignore_ascii_case(&letter) => key.code,
            _ => return false,
        },
    };

    key.code == wanted
        && key.modifiers.contains(KeyModifiers::CONTROL) == spec.ctrl
        && key.modifiers.contains(KeyModifiers::ALT) == spec.alt
}

/// Splits `text` into rows of at most `width` columns, as slices of `text`.
fn wrap(text: &str, width: usize) -> Vec<&str> {
    let width = width.max(1);
    let mut rows = Vec::new();

    for line in text.split('\n') {
        let mut start = 0;
        let mut used = 0;

        for (index, character) in line.char_indices() {
            let columns = character.width().unwrap_or(0);

            if used + columns > width && index > start {
                rows.push(&line[start..index]);
                start = index;
                used = 0;
            }

            used += columns;
        }

        rows.push(&line[start..]);
    }

    rows
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);

    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

impl App {
    // ---------------------------------------------------------- lifecycle

    pub(crate) fn try_enter_chat(&mut self, label: &str) -> Result<(), String> {
        let peer = self.peer(label)?;

        if peer.status != PeerStatus::Connected {
            return Err(format!("session '{label}' is not connected"));
        }

        let terminal = ratatui::try_init().map_err(|error| error.to_string())?;

        self.terminal = Some(terminal);
        self.default_target = Some(label.to_string());
        self.touched = true;

        if let Some(peer) = self.peers.get_mut(label) {
            peer.unread = 0;
        }

        self.mode = Mode::Chat(ChatView {
            label: label.to_string(),
            input: input_buffer(),
            scroll: 0,
            max_scroll: Cell::new(0),
        });

        self.redraw_chat().map_err(|error| error.to_string())
    }

    /// Returns to the REPL. A closed session is forgotten here, taking its
    /// scrollback with it.
    pub(crate) fn leave_chat(&mut self) {
        self.leave_chat_terminal();

        let _ = enable_raw_mode();

        if let Mode::Chat(view) = std::mem::replace(&mut self.mode, Mode::Repl) {
            let closed = self
                .peers
                .get(&view.label)
                .is_some_and(|peer| peer.status == PeerStatus::Closed);

            if closed {
                self.forget(&view.label);
            }
        }

        let _ = self.redraw_prompt();
        self.announce_sas();
    }

    /// Restores the terminal if a chat holds it. Safe to call repeatedly.
    pub(crate) fn leave_chat_terminal(&mut self) {
        if self.terminal.take().is_some() {
            ratatui::restore();
        }
    }

    // ---------------------------------------------------------------- keys

    pub(crate) fn chat_key(&mut self, key: KeyEvent) -> io::Result<()> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        if !self.sas.is_empty() {
            self.chat_sas_key(key, control);
            return self.redraw_chat();
        }

        if key_matches(&self.keys.leave, &key) || (control && key.code == KeyCode::Char('c')) {
            self.leave_chat();
            return Ok(());
        }

        let keys = self.keys;

        let Mode::Chat(view) = &mut self.mode else {
            return Ok(());
        };

        let label = view.label.clone();

        match key.code {
            KeyCode::Enter => {
                let mut text = Zeroizing::new(view.input.trim().to_string());
                view.input.zeroize();

                if !text.is_empty()
                    && let Err(error) = self.send_text(&label, std::mem::take(&mut *text))
                    && let Some(peer) = self.peers.get_mut(&label)
                {
                    peer.scrollback
                        .push(Author::System, format!("not sent: {error}"));
                }

                if let Mode::Chat(view) = &mut self.mode {
                    view.scroll = 0;
                }
            }
            _ if key_matches(&keys.rekey, &key) => {
                if let Err(error) = self.request_rekey(&label)
                    && let Some(peer) = self.peers.get_mut(&label)
                {
                    peer.scrollback
                        .push(Author::System, format!("rekey: {error}"));
                }
            }
            KeyCode::Backspace => {
                view.input.pop();
            }
            KeyCode::Char(character)
                if !control
                    && !key.modifiers.contains(KeyModifiers::ALT)
                    && view.input.len() + character.len_utf8() <= MAX_CONTENT =>
            {
                view.input.push(character);
            }
            _ if key_matches(&keys.scroll_up, &key) => {
                view.scroll = (view.scroll + 1).min(view.max_scroll.get());
            }
            _ if key_matches(&keys.scroll_down, &key) => {
                view.scroll = view.scroll.saturating_sub(1);
            }
            _ if key_matches(&keys.page_up, &key) => {
                view.scroll = (view.scroll + 10).min(view.max_scroll.get());
            }
            _ if key_matches(&keys.page_down, &key) => {
                view.scroll = view.scroll.saturating_sub(10);
            }
            _ => {}
        }

        self.redraw_chat()
    }

    fn chat_sas_key(&mut self, key: KeyEvent, control: bool) {
        match key.code {
            KeyCode::Enter => {
                let approved = self
                    .sas
                    .front()
                    .is_some_and(|pending| is_approval(&pending.typed));

                self.answer_sas(approved);
            }
            KeyCode::Esc => self.answer_sas(false),
            KeyCode::Char('c') if control => self.answer_sas(false),
            KeyCode::Backspace => {
                if let Some(pending) = self.sas.front_mut() {
                    pending.typed.pop();
                }
            }
            KeyCode::Char(character) if !control => {
                if let Some(pending) = self.sas.front_mut()
                    && pending.typed.len() < 16
                {
                    pending.typed.push(character);
                }
            }
            _ => {}
        }
    }

    // ----------------------------------------------------------- rendering

    pub(crate) fn redraw_chat(&mut self) -> io::Result<()> {
        if !matches!(self.mode, Mode::Chat(_)) {
            return Ok(());
        }

        let Some(mut terminal) = self.terminal.take() else {
            return Ok(());
        };

        let result = terminal.draw(|frame| self.draw(frame)).map(|_| ());

        self.terminal = Some(terminal);

        result
    }

    fn draw(&self, frame: &mut Frame) {
        let area = frame.area();

        let Mode::Chat(view) = &self.mode else {
            return;
        };

        let Some(peer) = self.peers.get(&view.label) else {
            return;
        };

        if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
            frame.render_widget(
                Paragraph::new(format!(
                    "terminal too small (need {MIN_WIDTH}x{MIN_HEIGHT})"
                ))
                .wrap(Wrap { trim: true }),
                area,
            );
            return;
        }

        let header_height = self.header_height(peer, area);

        let [header, body, input, status] = Layout::vertical([
            Constraint::Length(header_height),
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .areas(area);

        self.draw_header(frame, header, view, peer);
        self.draw_messages(frame, body, view, peer);
        self.draw_input(frame, input, view);
        self.draw_status(frame, status, view);

        if let Some(pending) = self.sas.front() {
            self.draw_sas(frame, area, pending);
        }
    }

    fn fingerprint_line(peer: &Peer) -> String {
        match &peer.fingerprint {
            Some(fingerprint) => format!("peer key  {}", grouped(fingerprint)),
            None => "peer key  (handshake in progress)".to_string(),
        }
    }

    /// Tall enough that the whole fingerprint is always visible.
    fn header_height(&self, peer: &Peer, area: Rect) -> u16 {
        let inner = usize::from(area.width.saturating_sub(2)).max(1);
        let rows = Self::fingerprint_line(peer).chars().count().div_ceil(inner);

        u16::try_from(rows)
            .unwrap_or(2)
            .saturating_add(3)
            .min(area.height / 3)
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect, view: &ChatView, peer: &Peer) {
        let theme = &self.theme;

        let (state, state_style) = match peer.status {
            PeerStatus::Closed => (
                format!("CLOSED — {}", peer.close_note.as_deref().unwrap_or("ended")),
                Style::new().fg(theme.warning).add_modifier(Modifier::BOLD),
            ),
            PeerStatus::Handshaking => (
                "UNVERIFIED".to_string(),
                Style::new().fg(theme.warning).add_modifier(Modifier::BOLD),
            ),
            PeerStatus::Connected if peer.rekeying => (
                "ACTIVE · rekeying".to_string(),
                Style::new().fg(theme.system),
            ),
            PeerStatus::Connected => ("ACTIVE".to_string(), Style::new().fg(theme.local)),
        };

        let lines = vec![
            Line::from(vec![
                Span::styled(state, state_style),
                Span::styled(
                    format!(
                        "  ·  {}",
                        if peer.outbound { "outbound" } else { "inbound" }
                    ),
                    Style::new().fg(theme.dim),
                ),
                Span::styled(format!("  ·  {}", peer.remote), Style::new().fg(theme.dim)),
            ]),
            Line::from(Span::styled(
                Self::fingerprint_line(peer),
                Style::new().fg(theme.dim),
            )),
        ];

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.border_type)
            .border_style(Style::new().fg(theme.border))
            .title(Span::styled(
                format!(" RUXMSG · {} ", view.label),
                Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
            ));

        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block),
            area,
        );
    }

    fn draw_messages(&self, frame: &mut Frame, area: Rect, view: &ChatView, peer: &Peer) {
        let theme = &self.theme;

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.border_type)
            .border_style(Style::new().fg(theme.border));

        let inner = block.inner(area);
        let text_width = usize::from(inner.width).saturating_sub(GUTTER.len());

        let mut rows: Vec<Line<'_>> = Vec::new();

        for entry in peer.scrollback.iter() {
            let (tag, color) = Self::tag(entry, theme);

            for (index, row) in wrap(entry.text(), text_width).into_iter().enumerate() {
                let gutter = if index == 0 { tag } else { GUTTER };

                rows.push(Line::from(vec![
                    Span::styled(gutter, Style::new().fg(color)),
                    Span::raw(row),
                ]));
            }
        }

        let height = usize::from(inner.height);
        let max_scroll = rows.len().saturating_sub(height);
        view.max_scroll.set(max_scroll);

        let scroll = view.scroll.min(max_scroll);
        let end = rows.len() - scroll;
        let start = end.saturating_sub(height);

        let title = if scroll > 0 {
            format!(" Messages · {scroll} rows up ")
        } else {
            " Messages ".to_string()
        };

        frame.render_widget(block.title(title), area);
        frame.render_widget(Paragraph::new(rows[start..end].to_vec()), inner);
    }

    fn tag(entry: &Entry, theme: &crate::theme::Theme) -> (&'static str, ratatui::style::Color) {
        match entry.author {
            Author::Local => ("you   ", theme.local),
            Author::Remote => ("peer  ", theme.remote),
            Author::System => ("*     ", theme.system),
        }
    }

    fn draw_input(&self, frame: &mut Frame, area: Rect, view: &ChatView) {
        let theme = &self.theme;

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.border_type)
            .border_style(Style::new().fg(theme.border))
            .title(" Message ")
            .title(
                Line::from(format!(" {}/{} ", view.input.len(), MAX_CONTENT))
                    .alignment(Alignment::Right),
            );

        let inner = block.inner(area);
        let capacity = usize::from(inner.width).saturating_sub(1);

        // Show the tail of the input that fits.
        let mut used = 0;
        let mut start = view.input.len();

        for (index, character) in view.input.char_indices().rev() {
            let columns = character.width().unwrap_or(0);

            if used + columns > capacity {
                break;
            }

            used += columns;
            start = index;
        }

        frame.render_widget(block, area);
        frame.render_widget(Paragraph::new(&view.input[start..]), inner);

        if self.sas.is_empty() {
            let offset = u16::try_from(used).unwrap_or(0);
            frame.set_cursor_position(Position::new(inner.x + offset, inner.y));
        }
    }

    fn draw_status(&self, frame: &mut Frame, area: Rect, view: &ChatView) {
        let others: Vec<String> = self
            .peers
            .iter()
            .filter(|(label, peer)| **label != view.label && peer.unread > 0)
            .take(3)
            .map(|(label, peer)| format!("{label} +{}", peer.unread))
            .collect();

        let mut text = String::from(" Enter send · Esc REPL · Ctrl-R rekey · PgUp/PgDn scroll");

        if !others.is_empty() {
            text.push_str(" · new: ");
            text.push_str(&others.join(", "));
        }

        frame.render_widget(
            Paragraph::new(text).style(Style::new().fg(self.theme.dim)),
            area,
        );
    }

    fn draw_sas(&self, frame: &mut Frame, area: Rect, pending: &crate::app::PendingSas) {
        let theme = &self.theme;

        let remaining = SAS_DECISION_TIMEOUT_SECS.saturating_sub(pending.since.elapsed().as_secs());

        let modal = centered(area, 72, 17);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.border_type)
            .border_style(Style::new().fg(theme.warning))
            .title(Span::styled(
                " VERIFY CONNECTION — Short Authentication String ",
                Style::new().fg(theme.warning).add_modifier(Modifier::BOLD),
            ));

        let inner = block.inner(modal);

        frame.render_widget(Clear, modal);
        frame.render_widget(block, modal);

        let [text_area, input_area] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);

        let lines = vec![
            Line::from(format!(
                "{} ({}) · {remaining} s left",
                pending.label,
                if pending.outbound {
                    "outbound"
                } else {
                    "inbound"
                }
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!(
                    "{}  {}  {}",
                    pending.words[0], pending.words[1], pending.words[2]
                ),
                Style::new().fg(theme.accent).add_modifier(Modifier::BOLD),
            ))
            .alignment(Alignment::Center),
            Line::from(""),
            Line::from("Peer key (claimed until you approve):"),
            Line::from(Span::styled(
                grouped(&pending.fingerprint),
                Style::new().fg(theme.dim),
            )),
            Line::from(""),
            Line::from("Compare the three words with your peer over a separate channel"),
            Line::from("(voice, in person). Do not approve if they differ."),
            Line::from(""),
            Line::from("Type yes and press Enter to approve."),
            Line::from("Anything else, or Esc, rejects."),
        ];

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), text_area);

        let prompt = "> ";

        frame.render_widget(
            Paragraph::new(format!("{prompt}{}", pending.typed)),
            input_area,
        );

        let offset = u16::try_from(prompt.len() + pending.typed.chars().count()).unwrap_or(0);
        frame.set_cursor_position(Position::new(input_area.x + offset, input_area.y));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_by_display_width_and_keeps_slices_of_the_input() {
        assert_eq!(wrap("abcdefgh", 3), vec!["abc", "def", "gh"]);
        assert_eq!(wrap("ab\ncd", 10), vec!["ab", "cd"]);
        assert_eq!(wrap("", 5), vec![""]);
    }

    #[test]
    fn wrap_counts_wide_characters_as_two_columns() {
        assert_eq!(wrap("日本語", 4), vec!["日本", "語"]);
    }

    #[test]
    fn wrap_never_loops_on_a_character_wider_than_the_row() {
        assert_eq!(wrap("日", 1), vec!["日"]);
    }
}
