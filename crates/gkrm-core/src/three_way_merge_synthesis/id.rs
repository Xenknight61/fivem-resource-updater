//! Stable enum encodings for merge-synthesis plan fingerprints.

use super::{MergeSynthesisDisposition, MergeSynthesisOperationKind, MergeSynthesisStatus};
use crate::three_way_text_diff::{SupportedTextNewlineStyle, TextTerminalNewline};

pub(super) fn encode_kind(kind: MergeSynthesisOperationKind) -> u8 {
    match kind {
        MergeSynthesisOperationKind::CopyBase => 0,
        MergeSynthesisOperationKind::UseInstalledReplacement => 1,
        MergeSynthesisOperationKind::UseIncomingReplacement => 2,
        MergeSynthesisOperationKind::UseEquivalentReplacement => 3,
    }
}

pub(super) fn encode_disposition(disposition: MergeSynthesisDisposition) -> u8 {
    match disposition {
        MergeSynthesisDisposition::ReadyForByteSynthesis => 0,
        MergeSynthesisDisposition::ManualReviewOperationLimit => 1,
    }
}

pub(super) fn encode_status(status: MergeSynthesisStatus) -> u8 {
    match status {
        MergeSynthesisStatus::ReadyForByteSynthesis => 0,
        MergeSynthesisStatus::HasManualReviewEntries => 1,
    }
}

pub(super) fn encode_newline(style: SupportedTextNewlineStyle) -> u8 {
    match style {
        SupportedTextNewlineStyle::None => 0,
        SupportedTextNewlineStyle::Lf => 1,
        SupportedTextNewlineStyle::CrLf => 2,
    }
}

pub(super) fn encode_terminal_newline(value: TextTerminalNewline) -> u8 {
    match value {
        TextTerminalNewline::Absent => 0,
        TextTerminalNewline::Present => 1,
        TextTerminalNewline::Unknown => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_tags_are_stable() {
        assert_eq!(encode_kind(MergeSynthesisOperationKind::CopyBase), 0);
        assert_eq!(
            encode_kind(MergeSynthesisOperationKind::UseInstalledReplacement),
            1
        );
        assert_eq!(
            encode_kind(MergeSynthesisOperationKind::UseIncomingReplacement),
            2
        );
        assert_eq!(
            encode_kind(MergeSynthesisOperationKind::UseEquivalentReplacement),
            3
        );
        assert_eq!(
            encode_disposition(MergeSynthesisDisposition::ReadyForByteSynthesis),
            0
        );
        assert_eq!(
            encode_disposition(MergeSynthesisDisposition::ManualReviewOperationLimit),
            1
        );
        assert_eq!(
            encode_status(MergeSynthesisStatus::ReadyForByteSynthesis),
            0
        );
        assert_eq!(
            encode_status(MergeSynthesisStatus::HasManualReviewEntries),
            1
        );
        assert_eq!(encode_newline(SupportedTextNewlineStyle::CrLf), 2);
        assert_eq!(encode_terminal_newline(TextTerminalNewline::Absent), 0);
        assert_eq!(encode_terminal_newline(TextTerminalNewline::Present), 1);
        assert_eq!(encode_terminal_newline(TextTerminalNewline::Unknown), 2);
    }
}
