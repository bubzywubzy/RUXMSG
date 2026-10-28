//! Terminal-safe rendering of peer-supplied text (spec §10.3).

/// Replaces control and bidirectional formatting characters with visible
/// `\u{..}` escapes. Newline and tab pass through.
pub fn sanitize_for_display(input: &str) -> String {
    let mut output = String::with_capacity(input.len());

    for character in input.chars() {
        let unsafe_char = (character.is_control() && character != '\n' && character != '\t')
            || matches!(character, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');

        if unsafe_char {
            output.push_str(&format!("\\u{{{:04x}}}", u32::from(character)));
        } else {
            output.push(character);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_and_bidi_controls() {
        assert_eq!(sanitize_for_display("a\x1b[2Jb"), "a\\u{001b}[2Jb");
        assert_eq!(sanitize_for_display("\u{9b}x"), "\\u{009b}x");
        assert_eq!(sanitize_for_display("\u{202e}evil"), "\\u{202e}evil");
        assert_eq!(
            sanitize_for_display("\u{2066}x\u{2069}"),
            "\\u{2066}x\\u{2069}"
        );
        assert_eq!(sanitize_for_display("\x07\x00"), "\\u{0007}\\u{0000}");
    }

    #[test]
    fn keeps_newline_tab_and_ordinary_text() {
        assert_eq!(sanitize_for_display("héllo\n\tworld ✓"), "héllo\n\tworld ✓");
    }
}
