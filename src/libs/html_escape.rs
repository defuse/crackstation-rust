//! HTML text escaping that preserves visual appearance.
//!
//! Ported from defuse-rust's `src/libs/html_escape.rs`, which is itself a direct
//! port of the PHP `HtmlEscape` class from defuse.ca. It converts text so that it
//! looks and behaves in HTML exactly as it does in a text editor.
//!
//! The one deliberate difference from the defuse-rust version: the leading-space
//! step is written out by hand instead of using a `Regex`. The pattern there is
//! `(?m)^ `, i.e. a space at the very start of the input or immediately after a
//! `\n` — and notably *not* after a standalone `\r`, which is the quirk of PHP's
//! `/^\x20/m` that the original comment calls out. Reproducing that directly keeps
//! the behaviour identical while not adding the `regex` crate and its four
//! transitive dependencies to a web server that has no other use for them.
//!
//! The processing order is critical and must match the PHP implementation:
//! 1. Tab → spaces (cursor-position-aware)
//! 2. HTML entity escaping
//! 3. Double space → `" &nbsp;"`
//! 4. Leading space → `&nbsp;`
//! 5. Trailing space before line ending → `&nbsp;`
//! 6. Line ending conversion (if `br_tags` is set)
//!
//! **This function's output is inserted into HTML unescaped**, so step 2 is what
//! stands between a wordlist entry and script execution. It must run before any
//! step that introduces markup, and nothing after it may introduce a `<` that came
//! from the input.

/// Escape text for HTML display, preserving visual appearance.
///
/// `br_tags` converts line endings to `<br />`; `tab_width` is the tab stop width.
pub fn escape_text(text: &str, br_tags: bool, tab_width: usize) -> String {
    // Step 1: tabs to spaces, before escaping, because the width depends on the
    // cursor position and escaping changes character counts.
    let esc = tabs_to_spaces(text, tab_width);

    // Step 2: escape everything with meaning in HTML. Everything after this point
    // may only *add* markup of our own.
    let esc = html_special_chars(&esc);

    // Step 3: repeated spaces. They cannot all become &nbsp; or the line would never
    // break, so pairs become " &nbsp;" -- the plain space first, so three spaces give
    // " &nbsp; " rather than "&nbsp;  ", which a browser renders as two.
    let esc = esc.replace("  ", " &nbsp;");

    // Step 4: HTML drops a leading space in block elements, so replace one at the
    // start of each line.
    let esc = replace_leading_spaces(&esc);

    // Step 5: the same at the end of a line, which matters when text is copied.
    let esc = esc.replace(" \r", "&nbsp;\r").replace(" \n", "&nbsp;\n");

    // Step 6: line endings.
    if br_tags {
        // Normalize CRLF first; doing CR first would turn CRLF into two lines.
        let esc = esc.replace("\r\n", "\n");
        let esc = esc.replace('\r', "\n");
        esc.replace('\n', "<br />\n")
    } else {
        esc
    }
}

/// Replace a space at the start of the input or immediately after a `\n`.
///
/// This is PHP's `/^\x20/m`. A standalone `\r` does not start a new line for that
/// pattern, so a space after one is deliberately left alone.
fn replace_leading_spaces(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut at_line_start = true;

    for ch in text.chars() {
        if at_line_start && ch == ' ' {
            result.push_str("&nbsp;");
        } else {
            result.push(ch);
        }
        at_line_start = ch == '\n';
    }

    result
}

/// Convert tabs to spaces based on cursor position, the way a text editor does.
fn tabs_to_spaces(text: &str, tab_width: usize) -> String {
    let mut result = String::with_capacity(text.len() * 2);
    let mut cursor: usize = 0;

    for ch in text.chars() {
        if ch == '\t' {
            // At least one space, then on to the next tab stop -- so a cursor already
            // on a stop advances a full tab_width.
            result.push(' ');
            cursor += 1;
            while cursor % tab_width != 0 {
                result.push(' ');
                cursor += 1;
            }
        } else {
            result.push(ch);
            cursor += 1;
            if ch == '\n' || ch == '\r' {
                cursor = 0;
            }
        }
    }

    result
}

/// Equivalent to PHP's `htmlspecialchars` with `ENT_QUOTES`.
fn html_special_chars(text: &str) -> String {
    let mut result = String::with_capacity(text.len() * 2);

    for ch in text.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#039;"),
            _ => result.push(ch),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: whitespace that HTML would collapse survives.
    #[test]
    fn whitespace_survives_html_collapsing() {
        assert_eq!(escape_text(" leading", false, 8), "&nbsp;leading");
        assert_eq!(escape_text("trailing \n", false, 8), "trailing&nbsp;\n");
        assert_eq!(escape_text("a  b", false, 8), "a &nbsp;b");
        assert_eq!(escape_text("a   b", false, 8), "a &nbsp; b");
        assert_eq!(escape_text("  ", false, 8), "&nbsp;&nbsp;");
    }

    /// Escaping happens before any markup is introduced, so hostile input cannot
    /// produce a tag. This is the property that lets the result be rendered unescaped.
    #[test]
    fn hostile_input_cannot_produce_markup() {
        let out = escape_text(r#"<script>alert('x&y')</script>"#, false, 8);
        assert_eq!(
            out,
            "&lt;script&gt;alert(&#039;x&amp;y&#039;)&lt;/script&gt;"
        );
        assert!(!out.contains('<'), "no raw < may survive");
        assert!(!out.contains('>'), "no raw > may survive");
    }

    /// An input that is already an entity must not be double-decoded into markup.
    #[test]
    fn existing_entities_are_escaped_not_interpreted() {
        assert_eq!(escape_text("&lt;script&gt;", false, 8), "&amp;lt;script&amp;gt;");
    }

    /// PHP's /^\x20/m starts a line after \n but not after a standalone \r.
    #[test]
    fn leading_space_follows_php_line_semantics() {
        assert_eq!(escape_text("a\n b", false, 8), "a\n&nbsp;b");
        assert_eq!(escape_text("a\r b", false, 8), "a\r b");
        assert_eq!(escape_text(" a\n b", false, 8), "&nbsp;a\n&nbsp;b");
    }

    #[test]
    fn tabs_expand_to_the_next_stop() {
        assert_eq!(tabs_to_spaces("\tx", 8), "        x");
        assert_eq!(tabs_to_spaces("ab\tx", 8), "ab      x");
        assert_eq!(tabs_to_spaces("abcdefgh\tx", 8), "abcdefgh        x");
        // The cursor resets on a line ending.
        assert_eq!(tabs_to_spaces("ab\n\tx", 8), "ab\n        x");
    }

    #[test]
    fn br_tags_normalize_line_endings() {
        assert_eq!(escape_text("a\r\nb", true, 8), "a<br />\nb");
        assert_eq!(escape_text("a\rb", true, 8), "a<br />\nb");
        assert_eq!(escape_text("a\nb", true, 8), "a<br />\nb");
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        assert_eq!(escape_text("hunter2", false, 8), "hunter2");
        assert_eq!(escape_text("", false, 8), "");
    }
}
