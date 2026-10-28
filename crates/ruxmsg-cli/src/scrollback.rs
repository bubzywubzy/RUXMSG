//! Bounded, volatile conversation history.
//!
//! Entries live only in RAM, are capped by count and bytes, and are zeroized
//! when evicted or dropped. A session's scrollback dies with the session.

use std::collections::VecDeque;

use zeroize::Zeroize;

const MAX_ENTRIES: usize = 1000;
const MAX_BYTES: usize = 256 * 1024;
const MAX_ENTRY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Author {
    Local,
    Remote,
    System,
}

pub(crate) struct Entry {
    pub(crate) author: Author,
    text: String,
}

impl Entry {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

#[derive(Default)]
pub(crate) struct Scrollback {
    entries: VecDeque<Entry>,
    bytes: usize,
}

impl Scrollback {
    pub(crate) fn push(&mut self, author: Author, mut text: String) {
        if text.len() > MAX_ENTRY_BYTES {
            let mut cut = MAX_ENTRY_BYTES;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }

            let mut shortened = String::with_capacity(cut + 4);
            shortened.push_str(&text[..cut]);
            shortened.push('…');

            text.zeroize();
            text = shortened;
        }

        self.bytes += text.len();
        self.entries.push_back(Entry { author, text });

        while self.entries.len() > MAX_ENTRIES || self.bytes > MAX_BYTES {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };

            self.bytes -= evicted.text.len();
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_count_is_bounded_and_oldest_entries_go_first() {
        let mut scrollback = Scrollback::default();

        for index in 0..(MAX_ENTRIES + 50) {
            scrollback.push(Author::Remote, index.to_string());
        }

        assert_eq!(scrollback.len(), MAX_ENTRIES);
        assert_eq!(scrollback.iter().next().unwrap().text(), "50");
    }

    #[test]
    fn byte_total_is_bounded() {
        let mut scrollback = Scrollback::default();

        for _ in 0..20 {
            scrollback.push(Author::Remote, "x".repeat(MAX_ENTRY_BYTES));
        }

        assert!(scrollback.bytes <= MAX_BYTES);
        assert!(scrollback.len() >= 1);
    }

    #[test]
    fn a_single_oversized_entry_is_truncated_on_a_char_boundary() {
        let mut scrollback = Scrollback::default();

        scrollback.push(Author::Remote, "é".repeat(MAX_ENTRY_BYTES));

        let text = scrollback.iter().next().unwrap().text();
        assert!(text.len() <= MAX_ENTRY_BYTES + 4);
        assert!(text.ends_with('…'));
    }
}
