//! Neutralize terminal control sequences in untrusted text before it is displayed.
//!
//! Everything the harness prints that did not originate in the harness — model prose, tool output,
//! kernel audit targets, skill metadata, file paths — is attacker-reachable text. A terminal reads
//! that text as a command language: `ESC [ 2 J` clears the screen, `ESC ] 0 ; … BEL` retitles the
//! window, `\r` rewrites the line just printed, and a bidi override reorders characters *after* they
//! are drawn. So untrusted content can erase or forge what the operator sees, and the most valuable
//! thing to forge is the y/N consent prompt that stands between a skill and a capability grant.
//!
//! The harness's own coloring is applied *after* sanitization, at the point of painting, so escaping
//! untrusted text costs nothing in fidelity: bee's SGR sequences are added to already-clean text.
//! That ordering is the whole design — sanitize the payload, then style it. Never the reverse.
//!
//! Escapes are rendered as their textual Rust form (`\x1b`, `\u{202e}`): plain ASCII, unambiguous,
//! and legible in a log or a screenshot, with no reliance on a font or a Unicode picture glyph.
//!
//! Two functions, differing only in whether a newline is data or a threat:
//! * [`safe_block`] keeps `\n` and `\t` — for multi-line prose the caller prints as a block.
//! * [`safe_line`] escapes them too — for anything interpolated into a single composed line, where a
//!   newline lets untrusted text start a line of its own and impersonate the harness.

use std::borrow::Cow;

/// Sanitize multi-line untrusted text: `\n` and `\t` survive, every other control character,
/// C1 escape, and bidi/invisible formatting character is replaced by its textual escape.
pub fn safe_block(s: &str) -> Cow<'_, str> {
    sanitize(s, true)
}

/// Sanitize untrusted text destined for a single composed line: as [`safe_block`], and additionally
/// `\n`, `\r`, and `\t` are escaped so the text cannot break out of the line it was placed in.
pub fn safe_line(s: &str) -> Cow<'_, str> {
    sanitize(s, false)
}

/// True if `c` would be interpreted rather than drawn.
///
/// Three classes: C0 controls + DEL (ESC, CR, BEL, …), the C1 range (`U+0080..=U+009F`, which some
/// terminals accept as single-byte CSI/OSC introducers), and the bidi/invisible formatting
/// characters that reorder or hide text after the fact (Trojan Source, CVE-2021-42574).
fn is_dangerous(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
        || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

fn sanitize(s: &str, keep_whitespace: bool) -> Cow<'_, str> {
    let kept = |c: char| keep_whitespace && (c == '\n' || c == '\t');
    if !s.chars().any(|c| is_dangerous(c) && !kept(c)) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            _ if kept(c) => out.push(c),
            _ if !is_dangerous(c) => out.push(c),
            // ASCII controls and DEL read best as the byte escape an author would type.
            '\u{0}'..='\u{1f}' | '\u{7f}' => out.push_str(&format!("\\x{:02x}", c as u32)),
            _ => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_is_borrowed_unchanged() {
        let s = "a normal line — with unicode, punctuation, and 数字";
        assert!(matches!(safe_block(s), Cow::Borrowed(_)));
        assert_eq!(safe_block(s), s);
        assert_eq!(safe_line(s), s);
    }

    #[test]
    fn escape_sequences_are_defanged() {
        // A screen-clear + a cursor-home, the classic "hide what just happened" pair.
        assert_eq!(safe_block("\x1b[2J\x1b[Hgone"), "\\x1b[2J\\x1b[Hgone");
        // OSC window-title set, terminated by BEL.
        assert_eq!(
            safe_line("\x1b]0;pwned\x07"),
            "\\x1b]0;pwned\\x07".to_string()
        );
    }

    #[test]
    fn carriage_return_cannot_rewrite_a_printed_line() {
        // `\r` is the cheapest forgery: print a benign line, then overwrite it in place.
        assert_eq!(
            safe_block("harmless\rDENIED nothing"),
            "harmless\\x0dDENIED nothing"
        );
    }

    #[test]
    fn a_block_keeps_newlines_and_tabs_but_a_line_does_not() {
        assert_eq!(safe_block("one\ttwo\nthree"), "one\ttwo\nthree");
        assert_eq!(safe_line("one\ttwo\nthree"), "one\\x09two\\x0athree");
    }

    #[test]
    fn bidi_overrides_are_escaped() {
        // Trojan Source: RLO reorders the rendered text without changing the bytes.
        assert_eq!(safe_line("safe\u{202e}dnegrous"), "safe\\u{202e}dnegrous");
        assert_eq!(safe_block("zero\u{200b}width"), "zero\\u{200b}width");
    }

    #[test]
    fn c1_introducers_are_escaped() {
        // U+009B is CSI as a single character on terminals that decode C1.
        assert_eq!(safe_line("\u{9b}2J"), "\\u{009b}2J");
    }

    #[test]
    fn sanitized_output_contains_no_dangerous_characters() {
        let nasty: String = (0u32..0x2100)
            .filter_map(char::from_u32)
            .chain("\u{feff}".chars())
            .collect();
        assert!(!safe_line(&nasty).chars().any(is_dangerous));
        assert!(!safe_block(&nasty)
            .chars()
            .any(|c| is_dangerous(c) && c != '\n' && c != '\t'));
    }
}
