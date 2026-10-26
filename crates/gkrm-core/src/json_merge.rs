//! Combining two JSON documents by what they say rather than by how they are laid out.
//!
//! A line merge asks "which lines differ". For the locale files a phone script ships that question
//! has no useful answer: between two releases the developer reindented every one of them, so two
//! thousand lines differ and eight are shared. Nothing about that means the operator's Turkish
//! translations and the developer's new strings cannot both be kept — only that lines are the
//! wrong unit to ask about. Keys are the right one.
//!
//! So this reads three versions of the same document and answers per value: the one the operator
//! installed, the one they have now, and the one the update brings. A value they changed is theirs
//! and stays theirs; every other value, every new key, and the entire shape and formatting of the
//! file are the developer's.
//!
//! The output is the update's own bytes with those values spliced in, so a file that was reindented
//! comes out reindented, key order is the developer's, and nothing is re-serialized. Where a value
//! is substituted it is copied verbatim from the operator's file, so no escape is ever rewritten
//! and no number is ever reformatted. Every byte of the result came from one side or the other.
//!
//! Only values both sides express the same way are eligible: a string stays a string, a number a
//! number. Where the operator turned a string into an object the shapes disagree, and this says so
//! by leaving the developer's value alone rather than by splicing one kind of thing into a hole
//! shaped for another.
//!
//! And only values a key names. Inside an array there are no keys, only positions, and positions
//! are the developer's to renumber: reorder a list between releases and the operator's second
//! element lands on whatever is second now, which is a list neither of them ever had. A key means
//! the same thing in both files whatever moved around it. A position does not, so an array is left
//! exactly as the update wrote it.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::{GkrmError, Result};

/// The most bytes either side of a merge may hold.
const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
/// How deeply objects and arrays may nest. Locale files are two or three deep.
const MAX_DEPTH: usize = 64;
/// The most values one document may hold.
const MAX_VALUES: usize = 200_000;
/// Separates path components. No JSON key can hold it unescaped, so no two paths can read alike.
const SEPARATOR: char = '\u{1f}';

/// Where one value sits in a document, and what kind of thing it is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScannedValue {
    /// The path from the root, as the scanner walked it.
    path: String,
    kind: ValueKind,
    span: Range<usize>,
    /// True when anything on the way here was an array, so a position names this rather than a key.
    positional: bool,
}

/// What a value is, coarsely enough to refuse splicing one kind into another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    String,
    Number,
    Bool,
    Null,
}

/// What a merge produced, and which of the operator's values are in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonMerge {
    pub(crate) bytes: Vec<u8>,
    /// The keys whose values came from the operator's file, so the screen can show what was kept
    /// rather than describe it. Empty means the update's document unchanged: they had changed
    /// nothing in it, which is an answer rather than a failure to find one.
    pub(crate) kept: Vec<String>,
}

/// Merge `installed` over `incoming`, keeping only what the operator changed since `baseline`.
///
/// Returns `Ok(None)` when any of the three is not JSON this will merge — malformed, too large,
/// too deep, or holding more values than this will hold in memory. A refusal is not a failure: the
/// file is then answered whole, which is what happened before this existed.
pub(crate) fn merge_json_documents(
    baseline: &[u8],
    installed: &[u8],
    incoming: &[u8],
) -> Result<Option<JsonMerge>> {
    let (Some(baseline_values), Some(installed_values), Some(incoming_values)) =
        (scan(baseline)?, scan(installed)?, scan(incoming)?)
    else {
        return Ok(None);
    };

    let by_path =
        |values: &[ScannedValue], text: &[u8]| -> BTreeMap<String, (ValueKind, Vec<u8>)> {
            values
                .iter()
                .map(|value| {
                    (
                        value.path.clone(),
                        (value.kind, text[value.span.clone()].to_vec()),
                    )
                })
                .collect()
        };
    let baseline_by_path = by_path(&baseline_values, baseline);
    let installed_by_path = by_path(&installed_values, installed);

    // Splice from the end so an earlier span is still where the scanner said it was.
    let mut merged = incoming.to_vec();
    let mut kept: Vec<String> = Vec::new();
    for value in incoming_values.iter().rev() {
        // Named by a position rather than by a key. Whatever is at that position now is the
        // developer's business, and putting the operator's bytes there builds a list neither of
        // them wrote.
        if value.positional {
            continue;
        }
        let (Some((baseline_kind, baseline_raw)), Some((installed_kind, installed_raw))) = (
            baseline_by_path.get(&value.path),
            installed_by_path.get(&value.path),
        ) else {
            // The operator has no value here, or never installed one. Either way there is nothing
            // of theirs to keep and the update's value stands.
            continue;
        };
        // Unchanged since they installed it: the developer is the only one who has touched it.
        if baseline_raw == installed_raw {
            continue;
        }
        // Three kinds that must agree before one is put where another was.
        if *baseline_kind != *installed_kind || *installed_kind != value.kind {
            continue;
        }
        merged.splice(value.span.clone(), installed_raw.iter().copied());
        kept.push(readable_path(&value.path));
    }
    // The document was walked backwards to keep the spans valid; the keys read forwards.
    kept.reverse();

    // The splice only ever replaced whole values with whole values, so the result must still parse.
    // If it does not, something is wrong here rather than with the file, and a document nobody can
    // read is not something to write over an operator's installation.
    if scan(&merged)?.is_none() {
        return Err(GkrmError::JsonMergeResultInvalid);
    }
    Ok(Some(JsonMerge {
        bytes: merged,
        kept,
    }))
}

/// One value's path, as something to show an operator.
///
/// The scanner separates components with a byte no JSON key can hold unescaped, which is what
/// keeps two different paths from reading alike. It is not something to put on a screen.
fn readable_path(path: &str) -> String {
    path.split(SEPARATOR)
        .filter(|part| !part.is_empty())
        .map(|part| part.trim_matches('"'))
        .collect::<Vec<_>>()
        .join(".")
}

/// Walk `text` as JSON, collecting every scalar value with its path and byte span.
///
/// Returns `Ok(None)` for anything this will not merge rather than an error: the caller's fallback
/// is to answer the file whole, which is always available and always correct.
fn scan(text: &[u8]) -> Result<Option<Vec<ScannedValue>>> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Ok(None);
    }
    let mut scanner = Scanner {
        text,
        at: 0,
        values: Vec::new(),
    };
    if scanner.skip_bom().is_err() {
        return Ok(None);
    }
    let mut path = String::new();
    if scanner.value(&mut path, 0, false).is_err() {
        return Ok(None);
    }
    scanner.skip_whitespace();
    if scanner.at != text.len() {
        return Ok(None);
    }
    Ok(Some(scanner.values))
}

struct Scanner<'a> {
    text: &'a [u8],
    at: usize,
    values: Vec<ScannedValue>,
}

/// Anything that stops a scan. The caller turns every one of them into "not mergeable".
struct Malformed;

type ScanResult = std::result::Result<(), Malformed>;

impl Scanner<'_> {
    fn skip_bom(&mut self) -> ScanResult {
        if self.text.starts_with(&[0xEF, 0xBB, 0xBF]) {
            self.at = 3;
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.text.get(self.at) {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                self.at = self.at.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn expect(&mut self, byte: u8) -> ScanResult {
        if self.peek() == Some(byte) {
            self.at = self.at.saturating_add(1);
            Ok(())
        } else {
            Err(Malformed)
        }
    }

    fn record(
        &mut self,
        path: &str,
        kind: ValueKind,
        span: Range<usize>,
        positional: bool,
    ) -> ScanResult {
        if self.values.len() >= MAX_VALUES {
            return Err(Malformed);
        }
        self.values.push(ScannedValue {
            path: path.to_owned(),
            kind,
            span,
            positional,
        });
        Ok(())
    }

    fn value(&mut self, path: &mut String, depth: usize, positional: bool) -> ScanResult {
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        self.skip_whitespace();
        match self.peek().ok_or(Malformed)? {
            b'{' => self.object(path, depth, positional),
            b'[' => self.array(path, depth),
            b'"' => {
                let start = self.at;
                self.string()?;
                let span = start..self.at;
                self.record(path, ValueKind::String, span, positional)
            }
            b't' | b'f' => {
                let start = self.at;
                let word: &[u8] = if self.peek() == Some(b't') {
                    b"true"
                } else {
                    b"false"
                };
                self.literal(word)?;
                let span = start..self.at;
                self.record(path, ValueKind::Bool, span, positional)
            }
            b'n' => {
                let start = self.at;
                self.literal(b"null")?;
                let span = start..self.at;
                self.record(path, ValueKind::Null, span, positional)
            }
            _ => {
                let start = self.at;
                self.number()?;
                let span = start..self.at;
                self.record(path, ValueKind::Number, span, positional)
            }
        }
    }

    fn object(&mut self, path: &mut String, depth: usize, positional: bool) -> ScanResult {
        self.expect(b'{')?;
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at = self.at.saturating_add(1);
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let key_start = self.at;
            self.string()?;
            // The key as written, quotes and all. Two documents that escape the same key
            // differently name different paths here, which is a refusal to guess rather than an
            // error: the value simply keeps the update's side.
            let key = std::str::from_utf8(&self.text[key_start..self.at]).map_err(|_| Malformed)?;
            let restore = path.len();
            path.push(SEPARATOR);
            path.push_str(key);
            self.skip_whitespace();
            self.expect(b':')?;
            self.value(path, depth.saturating_add(1), positional)?;
            path.truncate(restore);
            self.skip_whitespace();
            match self.peek().ok_or(Malformed)? {
                b',' => self.at = self.at.saturating_add(1),
                b'}' => {
                    self.at = self.at.saturating_add(1);
                    return Ok(());
                }
                _ => return Err(Malformed),
            }
        }
    }

    fn array(&mut self, path: &mut String, depth: usize) -> ScanResult {
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at = self.at.saturating_add(1);
            return Ok(());
        }
        let mut index = 0usize;
        loop {
            let restore = path.len();
            path.push(SEPARATOR);
            path.push_str(&index.to_string());
            // Everything under an array is named by a position, however deep.
            self.value(path, depth.saturating_add(1), true)?;
            path.truncate(restore);
            self.skip_whitespace();
            match self.peek().ok_or(Malformed)? {
                b',' => {
                    self.at = self.at.saturating_add(1);
                    index = index.checked_add(1).ok_or(Malformed)?;
                }
                b']' => {
                    self.at = self.at.saturating_add(1);
                    return Ok(());
                }
                _ => return Err(Malformed),
            }
        }
    }

    fn string(&mut self) -> ScanResult {
        self.expect(b'"')?;
        loop {
            let byte = self.peek().ok_or(Malformed)?;
            self.at = self.at.saturating_add(1);
            match byte {
                b'"' => return Ok(()),
                b'\\' => {
                    let escape = self.peek().ok_or(Malformed)?;
                    self.at = self.at.saturating_add(1);
                    match escape {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                let digit = self.peek().ok_or(Malformed)?;
                                if !digit.is_ascii_hexdigit() {
                                    return Err(Malformed);
                                }
                                self.at = self.at.saturating_add(1);
                            }
                        }
                        _ => return Err(Malformed),
                    }
                }
                // A raw control byte is not legal inside a JSON string, and a document holding one
                // is not one this will rewrite.
                0x00..=0x1f => return Err(Malformed),
                _ => {}
            }
        }
    }

    fn literal(&mut self, word: &[u8]) -> ScanResult {
        if self.text[self.at..].starts_with(word) {
            self.at = self.at.saturating_add(word.len());
            Ok(())
        } else {
            Err(Malformed)
        }
    }

    fn number(&mut self) -> ScanResult {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at = self.at.saturating_add(1);
        }
        // JSON allows a single leading zero and nothing after it. Accepting `01` would let this
        // call a document JSON that every other reader refuses, and then write it somewhere.
        match self.peek() {
            Some(b'0') => self.at = self.at.saturating_add(1),
            Some(byte) if byte.is_ascii_digit() => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.at = self.at.saturating_add(1);
                }
            }
            _ => return Err(Malformed),
        }
        if self.peek() == Some(b'.') {
            self.at = self.at.saturating_add(1);
            let mut fraction = 0usize;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at = self.at.saturating_add(1);
                fraction = fraction.saturating_add(1);
            }
            if fraction == 0 {
                return Err(Malformed);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at = self.at.saturating_add(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at = self.at.saturating_add(1);
            }
            let mut exponent = 0usize;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at = self.at.saturating_add(1);
                exponent = exponent.saturating_add(1);
            }
            if exponent == 0 {
                return Err(Malformed);
            }
        }
        if self.at == start {
            return Err(Malformed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn combine(baseline: &str, installed: &str, incoming: &str) -> Option<JsonMerge> {
        merge_json_documents(
            baseline.as_bytes(),
            installed.as_bytes(),
            incoming.as_bytes(),
        )
        .expect("merge")
    }

    /// The merged text, and `None` where nothing of the operator's was kept.
    fn merged(baseline: &str, installed: &str, incoming: &str) -> Option<String> {
        combine(baseline, installed, incoming).and_then(|merge| {
            (!merge.kept.is_empty()).then(|| String::from_utf8(merge.bytes).expect("utf-8"))
        })
    }

    #[test]
    fn a_retranslated_string_survives_the_developer_reindenting_the_file() {
        // The case this exists for. Every line of the update differs from every line the operator
        // has, and none of that has anything to do with the one string they translated.
        let baseline = "{\n  \"HELLO\": \"Hello\",\n  \"BYE\": \"Bye\"\n}\n";
        let installed = "{\n  \"HELLO\": \"Merhaba\",\n  \"BYE\": \"Bye\"\n}\n";
        let incoming =
            "{\r\n    \"HELLO\": \"Hello\",\r\n    \"BYE\": \"Goodbye\",\r\n    \"NEW\": \"New\"\r\n}\r\n";

        let out = merged(baseline, installed, incoming).expect("merged");
        // Their translation is kept.
        assert!(out.contains("\"HELLO\": \"Merhaba\""));
        // The developer's own change to a string the operator never touched is taken.
        assert!(out.contains("\"BYE\": \"Goodbye\""));
        // The new key arrives.
        assert!(out.contains("\"NEW\": \"New\""));
        // And the file is laid out exactly as the developer laid it out.
        assert!(out.starts_with("{\r\n    "));
        assert!(out.ends_with("}\r\n"));
    }

    #[test]
    fn a_document_holding_nothing_of_theirs_is_the_updates_document() {
        // It reads as a file that could not be combined and is in fact one that did not need to
        // be. Keeping theirs because the lines would not line up costs them every string the
        // update added, to protect an edit they never made.
        let same = "{\n  \"A\": \"a\"\n}\n";
        let combined = combine(same, same, "{\n  \"A\": \"b\"\n}\n").expect("combined");
        assert!(combined.kept.is_empty());
        assert_eq!(combined.bytes, b"{\n  \"A\": \"b\"\n}\n");
    }

    #[test]
    fn an_array_is_left_exactly_as_the_update_wrote_it() {
        // Positions are the developer's to renumber. Reorder a list between releases and the
        // operator's second element lands on whatever is second now, which is a list neither of
        // them ever had — and which can put back the value they changed away from.
        let combined = combine(
            "{\"perms\":[\"guest\",\"user\"]}",
            "{\"perms\":[\"owner\",\"user\"]}",
            "{\"perms\":[\"user\",\"guest\"]}",
        )
        .expect("combined");
        assert!(combined.kept.is_empty());
        assert_eq!(combined.bytes, b"{\"perms\":[\"user\",\"guest\"]}");

        // Nor are elements the update dropped brought back.
        let combined =
            combine("{\"a\":[1,2,3]}", "{\"a\":[9]}", "{\"a\":[1,2,3]}").expect("combined");
        assert_eq!(combined.bytes, b"{\"a\":[1,2,3]}");
    }

    #[test]
    fn a_value_under_an_array_is_positional_however_deep_it_is() {
        let combined = combine(
            "{\"rows\":[{\"label\":\"one\"}]}",
            "{\"rows\":[{\"label\":\"MINE\"}]}",
            "{\"rows\":[{\"label\":\"two\"}]}",
        )
        .expect("combined");
        assert_eq!(combined.bytes, b"{\"rows\":[{\"label\":\"two\"}]}");
    }

    #[test]
    fn what_was_kept_is_named_in_the_operators_terms() {
        let combined = combine(
            "{\"a\":{\"b\":\"one\"},\"c\":\"two\"}",
            "{\"a\":{\"b\":\"MINE\"},\"c\":\"ALSO MINE\"}",
            "{\"a\":{\"b\":\"one\"},\"c\":\"two\"}",
        )
        .expect("combined");
        assert_eq!(combined.kept, vec!["a.b".to_owned(), "c".to_owned()]);
    }

    #[test]
    fn a_value_the_operator_never_had_is_left_to_the_developer() {
        let baseline = "{\n  \"A\": \"a\"\n}\n";
        let installed = "{\n  \"A\": \"mine\"\n}\n";
        let incoming = "{\n  \"A\": \"a\",\n  \"B\": \"new\"\n}\n";
        let out = merged(baseline, installed, incoming).expect("merged");
        assert!(out.contains("\"A\": \"mine\""));
        assert!(out.contains("\"B\": \"new\""));
    }

    #[test]
    fn a_value_the_update_no_longer_has_is_not_reintroduced() {
        // The developer removed the key. Splicing the operator's value back would put it in a file
        // that has nowhere for it, and inventing a place for it is not a merge.
        let baseline = "{\n  \"GONE\": \"a\",\n  \"KEPT\": \"k\"\n}\n";
        let installed = "{\n  \"GONE\": \"mine\",\n  \"KEPT\": \"mine too\"\n}\n";
        let incoming = "{\n  \"KEPT\": \"k\"\n}\n";
        let out = merged(baseline, installed, incoming).expect("merged");
        assert!(!out.contains("GONE"));
        assert!(out.contains("\"KEPT\": \"mine too\""));
    }

    #[test]
    fn kinds_must_agree_before_one_is_put_where_another_was() {
        // The operator replaced a string with an object. There is no value of theirs to splice,
        // and splicing the text of one into a hole shaped for the other would produce a document
        // that is neither.
        let baseline = "{\n  \"A\": \"a\"\n}\n";
        let installed = "{\n  \"A\": { \"deep\": \"mine\" }\n}\n";
        let incoming = "{\n  \"A\": \"b\"\n}\n";
        assert_eq!(merged(baseline, installed, incoming), None);
    }

    #[test]
    fn numbers_and_booleans_are_the_operators_too() {
        let baseline = "{\n  \"MAX\": 10,\n  \"ON\": false\n}\n";
        let installed = "{\n  \"MAX\": 25,\n  \"ON\": true\n}\n";
        let incoming = "{\n  \"MAX\": 10,\n  \"ON\": false,\n  \"NEW\": 1\n}\n";
        let out = merged(baseline, installed, incoming).expect("merged");
        assert!(out.contains("\"MAX\": 25"));
        assert!(out.contains("\"ON\": true"));
        assert!(out.contains("\"NEW\": 1"));
    }

    #[test]
    fn nesting_is_walked_by_key_and_arrays_are_not_walked_into() {
        let out = merged(
            "{\"a\":{\"b\":\"y\",\"list\":[\"x\"]}}",
            "{\"a\":{\"b\":\"MINE\",\"list\":[\"THEIRS?\"]}}",
            "{\"a\":{\"b\":\"y\",\"list\":[\"x\",\"z\"]}}",
        )
        .expect("merged");
        assert_eq!(out, "{\"a\":{\"b\":\"MINE\",\"list\":[\"x\",\"z\"]}}");
    }

    #[test]
    fn an_escape_is_copied_rather_than_rewritten() {
        let baseline = "{\"a\":\"plain\"}";
        let installed = "{\"a\":\"line\\u000abreak \\\"quoted\\\"\"}";
        let incoming = "{\"a\":\"plain\",\"b\":1}";
        let out = merged(baseline, installed, incoming).expect("merged");
        assert!(out.contains("\"line\\u000abreak \\\"quoted\\\"\""));
    }

    #[test]
    fn anything_that_is_not_json_is_refused_rather_than_guessed_at() {
        for bad in [
            "{",
            "{\"a\":}",
            "{\"a\":01}",
            "{\"a\":-}",
            "{\"a\":1.}",
            "{\"a\":\"unterminated}",
            "{\"a\":\"raw\tcontrol\"}",
            "{\"a\":1}trailing",
            "[1,]",
        ] {
            assert_eq!(
                merge_json_documents(b"{\"a\":\"a\"}", b"{\"a\":\"b\"}", bad.as_bytes())
                    .expect("merge"),
                None,
                "should have refused {bad}"
            );
        }
    }

    #[test]
    fn a_document_nested_past_the_ceiling_is_refused() {
        let deep = format!(
            "{}1{}",
            "[".repeat(MAX_DEPTH + 2),
            "]".repeat(MAX_DEPTH + 2)
        );
        assert_eq!(
            merge_json_documents(b"{\"a\":\"a\"}", b"{\"a\":\"b\"}", deep.as_bytes())
                .expect("merge"),
            None
        );
    }

    #[test]
    fn a_key_and_a_value_that_read_alike_are_not_confused() {
        // The path separator is a byte no JSON key can hold unescaped, so a key containing the
        // separator's printable neighbours cannot collide with a deeper path.
        let baseline = "{\"a\":{\"b\":\"one\"},\"a.b\":\"two\"}";
        let installed = "{\"a\":{\"b\":\"MINE\"},\"a.b\":\"two\"}";
        let incoming = "{\"a\":{\"b\":\"one\"},\"a.b\":\"CHANGED\"}";
        let out = merged(baseline, installed, incoming).expect("merged");
        assert!(out.contains("{\"b\":\"MINE\"}"));
        assert!(out.contains("\"a.b\":\"CHANGED\""));
    }
}
