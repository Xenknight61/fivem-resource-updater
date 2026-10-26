//! Stable enum encodings for merged-bytes plan fingerprints.

use super::{MergedByteDisposition, MergedByteStatus};
use crate::three_way_text_diff::{SupportedTextNewlineStyle, TextTerminalNewline};

pub(super) fn encode_disposition(disposition: MergedByteDisposition) -> u8 {
    match disposition {
        MergedByteDisposition::ReadyForStaging => 0,
        MergedByteDisposition::ManualReviewOutputLimit => 1,
    }
}

pub(super) fn encode_status(status: MergedByteStatus) -> u8 {
    match status {
        MergedByteStatus::ReadyForStaging => 0,
        MergedByteStatus::HasManualReviewEntries => 1,
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
        assert_eq!(
            encode_disposition(MergedByteDisposition::ReadyForStaging),
            0
        );
        assert_eq!(
            encode_disposition(MergedByteDisposition::ManualReviewOutputLimit),
            1
        );
        assert_eq!(encode_status(MergedByteStatus::ReadyForStaging), 0);
        assert_eq!(encode_status(MergedByteStatus::HasManualReviewEntries), 1);
        assert_eq!(encode_newline(SupportedTextNewlineStyle::CrLf), 2);
        assert_eq!(encode_terminal_newline(TextTerminalNewline::Absent), 0);
        assert_eq!(encode_terminal_newline(TextTerminalNewline::Present), 1);
    }
}
