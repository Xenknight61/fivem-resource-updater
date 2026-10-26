//! Shared Task 16/17 streaming content analysis and verified text retention.

use sha2::{Digest, Sha256};

use crate::{
    GkrmError, MergeContentAnalysis, MergeContentEncoding, MergeContentKind, MergeNewlineStyle,
    Result, Sha256Digest,
};

pub(crate) const STREAM_BUFFER_SIZE: usize = 64 * 1024;

/// Ephemeral verified merge text: Task-16-compatible metadata plus optional retained bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedMergeText {
    metadata: MergeContentAnalysis,
    retained_bytes: Option<Vec<u8>>,
}

impl VerifiedMergeText {
    pub(crate) fn metadata(&self) -> &MergeContentAnalysis {
        &self.metadata
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn retained_bytes(&self) -> Option<&[u8]> {
        self.retained_bytes.as_deref()
    }

    pub(crate) fn into_parts(self) -> (MergeContentAnalysis, Option<Vec<u8>>) {
        (self.metadata, self.retained_bytes)
    }
}

#[derive(Debug)]
pub(crate) struct StreamingByteBudget {
    limit: u64,
    actual: u64,
}

impl StreamingByteBudget {
    pub(crate) fn new(limit: u64) -> Self {
        Self { limit, actual: 0 }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn actual(&self) -> u64 {
        self.actual
    }

    pub(crate) fn add_task16(&mut self, bytes: u64) -> Result<()> {
        self.actual = self
            .actual
            .checked_add(bytes)
            .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
        if self.actual > self.limit {
            return Err(GkrmError::ThreeWayMergeAnalysisTotalHashBudgetExceeded {
                limit: self.limit,
                actual: self.actual,
            });
        }
        Ok(())
    }

    pub(crate) fn add_task17(&mut self, bytes: u64) -> Result<()> {
        self.actual = self
            .actual
            .checked_add(bytes)
            .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
        if self.actual > self.limit {
            return Err(GkrmError::ThreeWayTextDiffTotalSourceByteLimitExceeded {
                limit: self.limit,
                actual: self.actual,
            });
        }
        Ok(())
    }

    pub(crate) fn add_task18(&mut self, bytes: u64) -> Result<()> {
        self.actual = self
            .actual
            .checked_add(bytes)
            .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
        if self.actual > self.limit {
            return Err(
                GkrmError::ThreeWayMergeSynthesisTotalSourceByteLimitExceeded {
                    limit: self.limit,
                    actual: self.actual,
                },
            );
        }
        Ok(())
    }

    pub(crate) fn add_task19(&mut self, bytes: u64) -> Result<()> {
        self.actual = self
            .actual
            .checked_add(bytes)
            .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
        if self.actual > self.limit {
            return Err(GkrmError::ThreeWayMergedBytesTotalSourceByteLimitExceeded {
                limit: self.limit,
                actual: self.actual,
            });
        }
        Ok(())
    }
}

/// Streams chunks into a Task-16-compatible analyzer and optionally retains bytes up to a limit.
pub(crate) struct VerifiedMergeTextBuilder {
    analyzer: StreamingContentAnalyzer,
    retained: Option<Vec<u8>>,
    max_retain: u64,
    retain_abandoned: bool,
}

impl VerifiedMergeTextBuilder {
    pub(crate) fn new(max_retain_bytes: u64) -> Self {
        Self {
            analyzer: StreamingContentAnalyzer::new(),
            retained: if max_retain_bytes == 0 {
                None
            } else {
                Some(Vec::new())
            },
            max_retain: max_retain_bytes,
            retain_abandoned: max_retain_bytes == 0,
        }
    }

    /// Metadata-only builder used by Task 16 (never retains bytes).
    pub(crate) fn metadata_only() -> Self {
        Self::new(0)
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<()> {
        self.analyzer.push(chunk)?;
        if self.retain_abandoned {
            return Ok(());
        }
        let Some(retained) = self.retained.as_mut() else {
            return Ok(());
        };
        let next_len = (retained.len() as u64)
            .checked_add(chunk.len() as u64)
            .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
        if next_len > self.max_retain {
            self.retained = None;
            self.retain_abandoned = true;
            return Ok(());
        }
        retained.extend_from_slice(chunk);
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<VerifiedMergeText> {
        let metadata = self.analyzer.finish()?;
        let retained_bytes = if self.retain_abandoned {
            None
        } else {
            self.retained
        };
        if let Some(bytes) = retained_bytes.as_ref() {
            if bytes.len() as u64 != metadata.byte_length() {
                return Err(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow);
            }
        }
        Ok(VerifiedMergeText {
            metadata,
            retained_bytes,
        })
    }

    pub(crate) fn finish_metadata(self) -> Result<MergeContentAnalysis> {
        Ok(self.finish()?.metadata)
    }
}

pub(crate) struct StreamingContentAnalyzer {
    hasher: Sha256,
    byte_length: u64,
    has_nul: bool,
    utf8_tail: Vec<u8>,
    utf8_invalid: bool,
    first_bytes: Vec<u8>,
    line_count: usize,
    max_line_bytes: usize,
    current_line_bytes: usize,
    pending_cr: bool,
    ended_with_newline: bool,
    lf_count: usize,
    crlf_count: usize,
    cr_count: usize,
}

impl StreamingContentAnalyzer {
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            byte_length: 0,
            has_nul: false,
            utf8_tail: Vec::new(),
            utf8_invalid: false,
            first_bytes: Vec::new(),
            line_count: 0,
            max_line_bytes: 0,
            current_line_bytes: 0,
            pending_cr: false,
            ended_with_newline: false,
            lf_count: 0,
            crlf_count: 0,
            cr_count: 0,
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<()> {
        self.byte_length = self
            .byte_length
            .checked_add(chunk.len() as u64)
            .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
        self.hasher.update(chunk);
        if self.first_bytes.len() < 3 {
            let needed = 3 - self.first_bytes.len();
            self.first_bytes
                .extend_from_slice(&chunk[..chunk.len().min(needed)]);
        }
        if chunk.contains(&0) {
            self.has_nul = true;
        }
        self.validate_utf8_chunk(chunk);
        for &byte in chunk {
            self.process_line_byte(byte)?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<MergeContentAnalysis> {
        if self.pending_cr {
            self.cr_count = checked_inc(self.cr_count)?;
            self.line_count = checked_inc(self.line_count)?;
            self.pending_cr = false;
            self.ended_with_newline = true;
        }
        if self.byte_length > 0 && !self.ended_with_newline {
            self.line_count = checked_inc(self.line_count)?;
        }
        if !self.utf8_tail.is_empty() {
            self.utf8_invalid = true;
        }
        let sha256 = Sha256Digest::new(self.hasher.finalize().into());
        let newline_style = newline_style(self.lf_count, self.crlf_count, self.cr_count);
        let (content_kind, encoding, line_count, max_line_bytes) = if self.has_nul {
            (
                MergeContentKind::Binary,
                MergeContentEncoding::Unsupported,
                None,
                None,
            )
        } else if self.utf8_invalid {
            (
                MergeContentKind::UnsupportedEncoding,
                MergeContentEncoding::Unsupported,
                None,
                None,
            )
        } else {
            (
                MergeContentKind::Text,
                if self.first_bytes == [0xEF, 0xBB, 0xBF] {
                    MergeContentEncoding::Utf8WithBom
                } else {
                    MergeContentEncoding::Utf8
                },
                Some(self.line_count),
                Some(self.max_line_bytes),
            )
        };
        Ok(MergeContentAnalysis::from_parts(
            sha256,
            self.byte_length,
            content_kind,
            encoding,
            newline_style,
            line_count,
            max_line_bytes,
            self.byte_length == 0,
        ))
    }

    fn validate_utf8_chunk(&mut self, chunk: &[u8]) {
        if self.utf8_invalid {
            return;
        }
        let mut bytes = Vec::with_capacity(self.utf8_tail.len() + chunk.len());
        bytes.extend_from_slice(&self.utf8_tail);
        bytes.extend_from_slice(chunk);
        match std::str::from_utf8(&bytes) {
            Ok(_) => self.utf8_tail.clear(),
            Err(error) => {
                if error.error_len().is_some() {
                    self.utf8_invalid = true;
                    self.utf8_tail.clear();
                } else {
                    self.utf8_tail = bytes[error.valid_up_to()..].to_vec();
                    if self.utf8_tail.len() > 3 {
                        self.utf8_invalid = true;
                        self.utf8_tail.clear();
                    }
                }
            }
        }
    }

    fn process_line_byte(&mut self, byte: u8) -> Result<()> {
        if self.pending_cr {
            if byte == b'\n' {
                self.crlf_count = checked_inc(self.crlf_count)?;
                self.line_count = checked_inc(self.line_count)?;
                self.pending_cr = false;
                self.ended_with_newline = true;
                return Ok(());
            }
            self.cr_count = checked_inc(self.cr_count)?;
            self.line_count = checked_inc(self.line_count)?;
            self.pending_cr = false;
            self.ended_with_newline = true;
        }
        match byte {
            b'\r' => {
                self.max_line_bytes = self.max_line_bytes.max(self.current_line_bytes);
                self.current_line_bytes = 0;
                self.pending_cr = true;
                self.ended_with_newline = true;
            }
            b'\n' => {
                self.max_line_bytes = self.max_line_bytes.max(self.current_line_bytes);
                self.current_line_bytes = 0;
                self.lf_count = checked_inc(self.lf_count)?;
                self.line_count = checked_inc(self.line_count)?;
                self.ended_with_newline = true;
            }
            _ => {
                self.current_line_bytes = checked_inc(self.current_line_bytes)?;
                self.max_line_bytes = self.max_line_bytes.max(self.current_line_bytes);
                self.ended_with_newline = false;
            }
        }
        Ok(())
    }
}

fn checked_inc(value: usize) -> Result<usize> {
    value
        .checked_add(1)
        .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
}

fn newline_style(lf: usize, crlf: usize, cr: usize) -> MergeNewlineStyle {
    let forms = usize::from(lf > 0) + usize::from(crlf > 0) + usize::from(cr > 0);
    match (forms, lf > 0, crlf > 0, cr > 0) {
        (0, _, _, _) => MergeNewlineStyle::None,
        (1, true, _, _) => MergeNewlineStyle::Lf,
        (1, _, true, _) => MergeNewlineStyle::CrLf,
        (1, _, _, true) => MergeNewlineStyle::Cr,
        _ => MergeNewlineStyle::Mixed,
    }
}
