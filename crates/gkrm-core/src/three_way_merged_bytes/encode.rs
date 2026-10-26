//! Canonical FinalTextEnvelope encoding for Task 19 merged bytes.

use super::{MergedByteArtifact, MergedByteDisposition};
use crate::three_way_merge_synthesis::FinalTextEnvelope;
use crate::three_way_text_diff::{SupportedTextNewlineStyle, TextTerminalNewline};
use crate::{GkrmError, Result, Sha256Digest};
use sha2::{Digest, Sha256};

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

pub(super) trait EncodeSink {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()>;
}

struct LengthSink {
    len: u64,
}

impl EncodeSink for LengthSink {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.len = self
            .len
            .checked_add(bytes.len() as u64)
            .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
        Ok(())
    }
}

struct BufferSink {
    buf: Vec<u8>,
    hasher: Sha256,
    len: u64,
}

impl EncodeSink for BufferSink {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(bytes);
        self.hasher.update(bytes);
        self.len = self
            .len
            .checked_add(bytes.len() as u64)
            .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
        Ok(())
    }
}

struct HasherSink {
    hasher: Sha256,
    len: u64,
}

impl EncodeSink for HasherSink {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.hasher.update(bytes);
        self.len = self
            .len
            .checked_add(bytes.len() as u64)
            .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
        Ok(())
    }
}

fn separator(style: SupportedTextNewlineStyle) -> Result<Option<&'static [u8]>> {
    match style {
        SupportedTextNewlineStyle::None => Ok(None),
        SupportedTextNewlineStyle::Lf => Ok(Some(b"\n")),
        SupportedTextNewlineStyle::CrLf => Ok(Some(b"\r\n")),
    }
}

fn validate_envelope_lines(lines: &[Vec<u8>], envelope: FinalTextEnvelope) -> Result<()> {
    if envelope.terminal_newline() == TextTerminalNewline::Unknown {
        return Err(GkrmError::ThreeWayMergedBytesInvalidEnvelope);
    }
    match envelope.newline_style() {
        SupportedTextNewlineStyle::None => {
            if lines.len() > 1 {
                return Err(GkrmError::ThreeWayMergedBytesEncodeInvariant);
            }
            if envelope.terminal_newline() == TextTerminalNewline::Present {
                return Err(GkrmError::ThreeWayMergedBytesEncodeInvariant);
            }
        }
        SupportedTextNewlineStyle::Lf | SupportedTextNewlineStyle::CrLf => {
            // [""] + Absent is unrepresentable for LF/CRLF (empty Absent is zero lines).
            if lines.len() == 1
                && lines[0].is_empty()
                && envelope.terminal_newline() == TextTerminalNewline::Absent
            {
                return Err(GkrmError::ThreeWayMergedBytesEncodeInvariant);
            }
        }
    }
    Ok(())
}

/// Encode logical lines under `envelope` into `sink`.
pub(super) fn encode_merged_lines(
    lines: &[Vec<u8>],
    envelope: FinalTextEnvelope,
    sink: &mut impl EncodeSink,
) -> Result<()> {
    validate_envelope_lines(lines, envelope)?;
    if envelope.bom() {
        sink.write_all(&UTF8_BOM)?;
    }
    let sep = separator(envelope.newline_style())?;
    match sep {
        None => {
            if let Some(line) = lines.first() {
                sink.write_all(line)?;
            }
        }
        Some(sep) => {
            for (index, line) in lines.iter().enumerate() {
                if index > 0 {
                    sink.write_all(sep)?;
                }
                sink.write_all(line)?;
            }
            if envelope.terminal_newline() == TextTerminalNewline::Present {
                sink.write_all(sep)?;
            }
        }
    }
    Ok(())
}

pub(super) fn exact_encoded_length(lines: &[Vec<u8>], envelope: FinalTextEnvelope) -> Result<u64> {
    let mut sink = LengthSink { len: 0 };
    encode_merged_lines(lines, envelope, &mut sink)?;
    Ok(sink.len)
}

pub(super) enum EncodeOutcome {
    Ready(MergedByteArtifact),
    ManualLimit,
}

/// Preflight exact length; allocate only when within budgets; dual-pass verify.
pub(super) fn synthesize_output_artifact(
    lines: &[Vec<u8>],
    envelope: FinalTextEnvelope,
    max_output_bytes_per_file: u64,
    remaining_total_output_bytes: u64,
) -> Result<(EncodeOutcome, MergedByteDisposition)> {
    let exact = exact_encoded_length(lines, envelope)?;
    if exact > max_output_bytes_per_file || exact > remaining_total_output_bytes {
        return Ok((
            EncodeOutcome::ManualLimit,
            MergedByteDisposition::ManualReviewOutputLimit,
        ));
    }

    let capacity =
        usize::try_from(exact).map_err(|_| GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
    let mut pass1 = BufferSink {
        buf: Vec::with_capacity(capacity),
        hasher: Sha256::new(),
        len: 0,
    };
    encode_merged_lines(lines, envelope, &mut pass1)?;
    if pass1.len != exact || pass1.buf.len() as u64 != exact {
        return Err(GkrmError::ThreeWayMergedBytesEncodeInvariant);
    }
    let digest1 = Sha256Digest::new(pass1.hasher.finalize().into());

    let mut pass2 = HasherSink {
        hasher: Sha256::new(),
        len: 0,
    };
    encode_merged_lines(lines, envelope, &mut pass2)?;
    let digest2 = Sha256Digest::new(pass2.hasher.finalize().into());
    if pass2.len != exact || digest1 != digest2 {
        return Err(GkrmError::ThreeWayMergedBytesEncodeInvariant);
    }

    Ok((
        EncodeOutcome::Ready(MergedByteArtifact::from_verified_parts(
            pass1.buf.into_boxed_slice(),
            digest1,
        )),
        MergedByteDisposition::ReadyForStaging,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::three_way_text_diff::{SupportedTextNewlineStyle, TextTerminalNewline};

    fn env(
        bom: bool,
        style: SupportedTextNewlineStyle,
        terminal: TextTerminalNewline,
    ) -> FinalTextEnvelope {
        // FinalTextEnvelope fields are private; reconstruct via public API if needed.
        // Use encode through synthesize path with a helper in tests via crate construction.
        // Access via synthesizing empty and checking length — build using transmute-free helper.
        test_envelope(bom, style, terminal)
    }

    fn test_envelope(
        bom: bool,
        style: SupportedTextNewlineStyle,
        terminal: TextTerminalNewline,
    ) -> FinalTextEnvelope {
        FinalTextEnvelope::from_parts(bom, style, terminal)
    }

    fn encode_to_vec(lines: &[Vec<u8>], envelope: FinalTextEnvelope) -> Vec<u8> {
        let mut sink = BufferSink {
            buf: Vec::new(),
            hasher: Sha256::new(),
            len: 0,
        };
        encode_merged_lines(lines, envelope, &mut sink).expect("encode");
        sink.buf
    }

    #[test]
    fn zero_lines_absent_no_bom() {
        let out = encode_to_vec(
            &[],
            env(
                false,
                SupportedTextNewlineStyle::Lf,
                TextTerminalNewline::Absent,
            ),
        );
        assert!(out.is_empty());
    }

    #[test]
    fn zero_lines_present_lf() {
        let out = encode_to_vec(
            &[],
            env(
                false,
                SupportedTextNewlineStyle::Lf,
                TextTerminalNewline::Present,
            ),
        );
        assert_eq!(out, b"\n");
    }

    #[test]
    fn zero_lines_present_crlf() {
        let out = encode_to_vec(
            &[],
            env(
                false,
                SupportedTextNewlineStyle::CrLf,
                TextTerminalNewline::Present,
            ),
        );
        assert_eq!(out, b"\r\n");
    }

    #[test]
    fn bom_only() {
        let out = encode_to_vec(
            &[],
            env(
                true,
                SupportedTextNewlineStyle::Lf,
                TextTerminalNewline::Absent,
            ),
        );
        assert_eq!(out, UTF8_BOM);
    }

    #[test]
    fn bom_plus_terminal_lf() {
        let out = encode_to_vec(
            &[],
            env(
                true,
                SupportedTextNewlineStyle::Lf,
                TextTerminalNewline::Present,
            ),
        );
        assert_eq!(out, b"\xEF\xBB\xBF\n");
    }

    #[test]
    fn one_empty_line_present_lf() {
        let lines = vec![Vec::new()];
        let out = encode_to_vec(
            &lines,
            env(
                false,
                SupportedTextNewlineStyle::Lf,
                TextTerminalNewline::Present,
            ),
        );
        assert_eq!(out, b"\n");
    }

    #[test]
    fn one_empty_line_absent_lf_fails() {
        let lines = vec![Vec::new()];
        let err = encode_merged_lines(
            &lines,
            env(
                false,
                SupportedTextNewlineStyle::Lf,
                TextTerminalNewline::Absent,
            ),
            &mut LengthSink { len: 0 },
        )
        .unwrap_err();
        assert!(matches!(err, GkrmError::ThreeWayMergedBytesEncodeInvariant));
    }

    #[test]
    fn one_nonempty_absent_and_present() {
        let lines = vec![b"a".to_vec()];
        assert_eq!(
            encode_to_vec(
                &lines,
                env(
                    false,
                    SupportedTextNewlineStyle::Lf,
                    TextTerminalNewline::Absent
                )
            ),
            b"a"
        );
        assert_eq!(
            encode_to_vec(
                &lines,
                env(
                    false,
                    SupportedTextNewlineStyle::Lf,
                    TextTerminalNewline::Present
                )
            ),
            b"a\n"
        );
    }

    #[test]
    fn crlf_file() {
        let lines = vec![b"a".to_vec(), b"b".to_vec()];
        assert_eq!(
            encode_to_vec(
                &lines,
                env(
                    false,
                    SupportedTextNewlineStyle::CrLf,
                    TextTerminalNewline::Present
                )
            ),
            b"a\r\nb\r\n"
        );
    }

    #[test]
    fn none_style_zero_and_one_line() {
        assert!(encode_to_vec(
            &[],
            env(
                false,
                SupportedTextNewlineStyle::None,
                TextTerminalNewline::Absent
            )
        )
        .is_empty());
        assert_eq!(
            encode_to_vec(
                &[b"hello".to_vec()],
                env(
                    false,
                    SupportedTextNewlineStyle::None,
                    TextTerminalNewline::Absent
                )
            ),
            b"hello"
        );
    }

    #[test]
    fn none_style_rejects_present_and_multiline() {
        assert!(matches!(
            encode_merged_lines(
                &[b"a".to_vec()],
                env(
                    false,
                    SupportedTextNewlineStyle::None,
                    TextTerminalNewline::Present
                ),
                &mut LengthSink { len: 0 },
            ),
            Err(GkrmError::ThreeWayMergedBytesEncodeInvariant)
        ));
        assert!(matches!(
            encode_merged_lines(
                &[b"a".to_vec(), b"b".to_vec()],
                env(
                    false,
                    SupportedTextNewlineStyle::None,
                    TextTerminalNewline::Absent
                ),
                &mut LengthSink { len: 0 },
            ),
            Err(GkrmError::ThreeWayMergedBytesEncodeInvariant)
        ));
    }

    #[test]
    fn embedded_empty_lines() {
        let lines = vec![b"a".to_vec(), Vec::new(), b"b".to_vec()];
        assert_eq!(
            encode_to_vec(
                &lines,
                env(
                    false,
                    SupportedTextNewlineStyle::Lf,
                    TextTerminalNewline::Present
                )
            ),
            b"a\n\nb\n"
        );
    }

    #[test]
    fn dual_pass_artifact_matches_preflight() {
        let lines = vec![b"x".to_vec(), b"y".to_vec()];
        let envelope = env(
            true,
            SupportedTextNewlineStyle::Lf,
            TextTerminalNewline::Present,
        );
        let exact = exact_encoded_length(&lines, envelope).unwrap();
        let (outcome, disposition) =
            synthesize_output_artifact(&lines, envelope, 1024, 1024).unwrap();
        assert_eq!(disposition, MergedByteDisposition::ReadyForStaging);
        match outcome {
            EncodeOutcome::Ready(artifact) => {
                assert_eq!(artifact.byte_length, exact);
                assert_eq!(artifact.bytes.len() as u64, exact);
            }
            EncodeOutcome::ManualLimit => panic!("expected ready"),
        }
    }

    #[test]
    fn output_limit_skips_allocation() {
        let lines = vec![b"abcdef".to_vec()];
        let envelope = env(
            false,
            SupportedTextNewlineStyle::Lf,
            TextTerminalNewline::Absent,
        );
        let (outcome, disposition) = synthesize_output_artifact(&lines, envelope, 2, 1024).unwrap();
        assert_eq!(disposition, MergedByteDisposition::ManualReviewOutputLimit);
        assert!(matches!(outcome, EncodeOutcome::ManualLimit));
    }
}
