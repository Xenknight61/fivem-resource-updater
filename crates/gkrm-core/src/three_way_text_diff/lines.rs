//! Canonical logical-line splitting for Task 17.

use crate::{GkrmError, MergeContentEncoding, MergeNewlineStyle, Result};

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Split `bytes` into logical lines using a previously verified encoding and newline style.
///
/// Returns `(lines, bom_present, terminal_newline)`.
///
/// No Unicode, whitespace, or tab normalization is performed. Line bodies are exact byte
/// slices of the (BOM-stripped) input between verified separators.
pub(crate) fn split_logical_lines(
    bytes: &[u8],
    encoding: MergeContentEncoding,
    newline_style: MergeNewlineStyle,
) -> Result<(Vec<Vec<u8>>, bool, bool)> {
    let (content, bom) = strip_and_validate_encoding(bytes, encoding)?;

    // UTF-8 validity is required for logical text even after BOM handling.
    if std::str::from_utf8(content).is_err() {
        return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText);
    }

    match newline_style {
        MergeNewlineStyle::None => {
            split_none(content).map(|(lines, terminal)| (lines, bom, terminal))
        }
        MergeNewlineStyle::Lf => split_lf(content).map(|(lines, terminal)| (lines, bom, terminal)),
        MergeNewlineStyle::CrLf => {
            split_crlf(content).map(|(lines, terminal)| (lines, bom, terminal))
        }
        MergeNewlineStyle::Cr | MergeNewlineStyle::Mixed => {
            Err(GkrmError::ThreeWayTextDiffMalformedLogicalText)
        }
    }
}

fn strip_and_validate_encoding(
    bytes: &[u8],
    encoding: MergeContentEncoding,
) -> Result<(&[u8], bool)> {
    match encoding {
        MergeContentEncoding::Utf8 => {
            if bytes.starts_with(&UTF8_BOM) {
                return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText);
            }
            Ok((bytes, false))
        }
        MergeContentEncoding::Utf8WithBom => {
            if !bytes.starts_with(&UTF8_BOM) {
                return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText);
            }
            Ok((&bytes[UTF8_BOM.len()..], true))
        }
        MergeContentEncoding::Unsupported => Err(GkrmError::ThreeWayTextDiffMalformedLogicalText),
    }
}

fn split_none(content: &[u8]) -> Result<(Vec<Vec<u8>>, bool)> {
    if content.iter().any(|&b| b == b'\n' || b == b'\r') {
        return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText);
    }
    if content.is_empty() {
        Ok((Vec::new(), false))
    } else {
        Ok((vec![content.to_vec()], false))
    }
}

fn split_lf(content: &[u8]) -> Result<(Vec<Vec<u8>>, bool)> {
    if content.contains(&b'\r') {
        return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText);
    }
    split_on_separator(content, b"\n")
}

fn split_crlf(content: &[u8]) -> Result<(Vec<Vec<u8>>, bool)> {
    // Reject lone LF or lone CR; only CRLF pairs are valid separators.
    let mut i = 0;
    while i < content.len() {
        match content[i] {
            b'\n' => return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText),
            b'\r' => {
                let next = i
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                if next >= content.len() || content[next] != b'\n' {
                    return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText);
                }
                i = next
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }
            _ => {
                i = i
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }
        }
    }
    split_on_separator(content, b"\r\n")
}

fn split_on_separator(content: &[u8], sep: &[u8]) -> Result<(Vec<Vec<u8>>, bool)> {
    if content.is_empty() {
        return Ok((Vec::new(), false));
    }

    let terminal_newline = content.ends_with(sep);
    let mut lines = Vec::new();
    let mut start = 0;

    while start <= content.len() {
        if start == content.len() {
            // Trailing separator already recorded via terminal_newline; no extra empty line.
            break;
        }
        if let Some(rel) = find_separator(&content[start..], sep) {
            let end = start
                .checked_add(rel)
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            lines.push(content[start..end].to_vec());
            start = end
                .checked_add(sep.len())
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            if start == content.len() {
                // Ended exactly on a separator.
                break;
            }
        } else {
            lines.push(content[start..].to_vec());
            break;
        }
    }

    Ok((lines, terminal_newline))
}

fn find_separator(haystack: &[u8], sep: &[u8]) -> Option<usize> {
    haystack.windows(sep.len()).position(|w| w == sep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf8(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn empty_input() {
        let (lines, bom, terminal) =
            split_logical_lines(b"", MergeContentEncoding::Utf8, MergeNewlineStyle::None)
                .expect("empty");
        assert!(lines.is_empty());
        assert!(!bom);
        assert!(!terminal);
    }

    #[test]
    fn single_line_no_newline() {
        let (lines, bom, terminal) =
            split_logical_lines(b"a", MergeContentEncoding::Utf8, MergeNewlineStyle::None)
                .expect("a");
        assert_eq!(lines, vec![utf8("a")]);
        assert!(!bom);
        assert!(!terminal);
    }

    #[test]
    fn single_line_with_lf_terminal() {
        let (lines, _, terminal) =
            split_logical_lines(b"a\n", MergeContentEncoding::Utf8, MergeNewlineStyle::Lf)
                .expect("a\\n");
        assert_eq!(lines, vec![utf8("a")]);
        assert!(terminal);
    }

    #[test]
    fn only_lf() {
        let (lines, _, terminal) =
            split_logical_lines(b"\n", MergeContentEncoding::Utf8, MergeNewlineStyle::Lf)
                .expect("\\n");
        assert_eq!(lines, vec![utf8("")]);
        assert!(terminal);
    }

    #[test]
    fn two_lines_lf_no_terminal() {
        let (lines, _, terminal) =
            split_logical_lines(b"a\nb", MergeContentEncoding::Utf8, MergeNewlineStyle::Lf)
                .expect("a\\nb");
        assert_eq!(lines, vec![utf8("a"), utf8("b")]);
        assert!(!terminal);
    }

    #[test]
    fn two_lines_crlf_terminal() {
        let (lines, _, terminal) = split_logical_lines(
            b"a\r\nb\r\n",
            MergeContentEncoding::Utf8,
            MergeNewlineStyle::CrLf,
        )
        .expect("crlf");
        assert_eq!(lines, vec![utf8("a"), utf8("b")]);
        assert!(terminal);
    }

    #[test]
    fn bom_only_with_none() {
        let (lines, bom, terminal) = split_logical_lines(
            &UTF8_BOM,
            MergeContentEncoding::Utf8WithBom,
            MergeNewlineStyle::None,
        )
        .expect("bom only");
        assert!(lines.is_empty());
        assert!(bom);
        assert!(!terminal);
    }

    #[test]
    fn utf8_must_not_carry_bom() {
        let err = split_logical_lines(
            &UTF8_BOM,
            MergeContentEncoding::Utf8,
            MergeNewlineStyle::None,
        )
        .expect_err("stale bom");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn utf8_with_bom_requires_bom() {
        let err = split_logical_lines(
            b"a",
            MergeContentEncoding::Utf8WithBom,
            MergeNewlineStyle::None,
        )
        .expect_err("missing bom");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn unsupported_encoding_rejected() {
        let err = split_logical_lines(
            b"a",
            MergeContentEncoding::Unsupported,
            MergeNewlineStyle::None,
        )
        .expect_err("unsupported");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn none_rejects_embedded_newlines() {
        let err = split_logical_lines(b"a\nb", MergeContentEncoding::Utf8, MergeNewlineStyle::None)
            .expect_err("lf in none");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn lf_rejects_cr() {
        let err = split_logical_lines(b"a\rb", MergeContentEncoding::Utf8, MergeNewlineStyle::Lf)
            .expect_err("cr in lf");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn crlf_rejects_lone_lf() {
        let err = split_logical_lines(b"a\nb", MergeContentEncoding::Utf8, MergeNewlineStyle::CrLf)
            .expect_err("lone lf");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn crlf_rejects_lone_cr() {
        let err = split_logical_lines(b"a\rb", MergeContentEncoding::Utf8, MergeNewlineStyle::CrLf)
            .expect_err("lone cr");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn cr_and_mixed_rejected() {
        for style in [MergeNewlineStyle::Cr, MergeNewlineStyle::Mixed] {
            let err = split_logical_lines(b"a", MergeContentEncoding::Utf8, style)
                .expect_err("unsupported newline");
            assert!(matches!(
                err,
                GkrmError::ThreeWayTextDiffMalformedLogicalText
            ));
        }
    }

    #[test]
    fn invalid_utf8_rejected() {
        let err = split_logical_lines(
            &[0xFF, 0xFE],
            MergeContentEncoding::Utf8,
            MergeNewlineStyle::None,
        )
        .expect_err("invalid utf8");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        ));
    }

    #[test]
    fn multi_byte_utf8_preserved() {
        let input = "café\n日本";
        let (lines, _, terminal) = split_logical_lines(
            input.as_bytes(),
            MergeContentEncoding::Utf8,
            MergeNewlineStyle::Lf,
        )
        .expect("multi-byte");
        assert_eq!(lines, vec![utf8("café"), utf8("日本")]);
        assert!(!terminal);
    }

    #[test]
    fn tabs_preserved() {
        let (lines, _, terminal) = split_logical_lines(
            b"a\tb\n\tc",
            MergeContentEncoding::Utf8,
            MergeNewlineStyle::Lf,
        )
        .expect("tabs");
        assert_eq!(lines, vec![b"a\tb".to_vec(), b"\tc".to_vec()]);
        assert!(!terminal);
    }

    #[test]
    fn nfc_vs_nfd_remain_distinct() {
        // U+00E9 LATIN SMALL LETTER E WITH ACUTE (NFC) vs e + combining acute (NFD).
        let nfc = "\u{00E9}";
        let nfd = "e\u{0301}";
        assert_ne!(nfc.as_bytes(), nfd.as_bytes());

        let (lines_nfc, _, _) = split_logical_lines(
            nfc.as_bytes(),
            MergeContentEncoding::Utf8,
            MergeNewlineStyle::None,
        )
        .expect("nfc");
        let (lines_nfd, _, _) = split_logical_lines(
            nfd.as_bytes(),
            MergeContentEncoding::Utf8,
            MergeNewlineStyle::None,
        )
        .expect("nfd");

        assert_eq!(lines_nfc, vec![nfc.as_bytes().to_vec()]);
        assert_eq!(lines_nfd, vec![nfd.as_bytes().to_vec()]);
        assert_ne!(lines_nfc, lines_nfd);
    }

    #[test]
    fn bom_stripped_before_lf_split() {
        let mut bytes = UTF8_BOM.to_vec();
        bytes.extend_from_slice(b"a\nb\n");
        let (lines, bom, terminal) = split_logical_lines(
            &bytes,
            MergeContentEncoding::Utf8WithBom,
            MergeNewlineStyle::Lf,
        )
        .expect("bom+lf");
        assert!(bom);
        assert_eq!(lines, vec![utf8("a"), utf8("b")]);
        assert!(terminal);
    }
}
