//! Stable enum / range encodings for text-diff plan fingerprints.

use super::envelope::{SupportedTextNewlineStyle, ThreeWayTextScalarResolution};
use super::hunks::{LineRange, TextDiffHunkKind, TextDiffSide};
use super::overlap::ThreeWayTextOverlapClassification;
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, Result};

pub(super) fn encode_side(side: TextDiffSide) -> u8 {
    match side {
        TextDiffSide::Installed => 0,
        TextDiffSide::Incoming => 1,
    }
}

pub(super) fn encode_kind(kind: TextDiffHunkKind) -> u8 {
    match kind {
        TextDiffHunkKind::Insert => 0,
        TextDiffHunkKind::Delete => 1,
        TextDiffHunkKind::Replace => 2,
    }
}

pub(super) fn encode_resolution(resolution: ThreeWayTextScalarResolution) -> u8 {
    match resolution {
        ThreeWayTextScalarResolution::KeepBase => 0,
        ThreeWayTextScalarResolution::UseInstalled => 1,
        ThreeWayTextScalarResolution::UseIncoming => 2,
        ThreeWayTextScalarResolution::Converged => 3,
        ThreeWayTextScalarResolution::Conflict => 4,
    }
}

pub(super) fn encode_newline(style: SupportedTextNewlineStyle) -> u8 {
    match style {
        SupportedTextNewlineStyle::None => 0,
        SupportedTextNewlineStyle::Lf => 1,
        SupportedTextNewlineStyle::CrLf => 2,
    }
}

pub(super) fn encode_terminal_newline(value: super::envelope::TextTerminalNewline) -> u8 {
    match value {
        super::envelope::TextTerminalNewline::Absent => 0,
        super::envelope::TextTerminalNewline::Present => 1,
        super::envelope::TextTerminalNewline::Unknown => 2,
    }
}

pub(super) fn encode_envelope_plan_state(
    state: &super::envelope::ThreeWayTextEnvelopePlanState,
) -> u8 {
    match state {
        super::envelope::ThreeWayTextEnvelopePlanState::Planned(_) => 1,
        super::envelope::ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge => 0,
    }
}

pub(super) fn encode_overlap_class(classification: ThreeWayTextOverlapClassification) -> u8 {
    match classification {
        ThreeWayTextOverlapClassification::Equivalent => 0,
        ThreeWayTextOverlapClassification::DivergentInsertion => 1,
        ThreeWayTextOverlapClassification::OverlappingEditConflict => 2,
    }
}

pub(super) fn encode_line_range(
    encoder: &mut CanonicalFingerprintEncoder,
    range: &LineRange,
) -> Result<()> {
    encoder
        .usize(range.start())
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    encoder
        .usize(range.end())
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_tags_are_stable() {
        assert_eq!(encode_side(TextDiffSide::Installed), 0);
        assert_eq!(encode_side(TextDiffSide::Incoming), 1);
        assert_eq!(encode_kind(TextDiffHunkKind::Insert), 0);
        assert_eq!(encode_kind(TextDiffHunkKind::Delete), 1);
        assert_eq!(encode_kind(TextDiffHunkKind::Replace), 2);
        assert_eq!(encode_resolution(ThreeWayTextScalarResolution::KeepBase), 0);
        assert_eq!(encode_resolution(ThreeWayTextScalarResolution::Conflict), 4);
        assert_eq!(encode_newline(SupportedTextNewlineStyle::CrLf), 2);
        assert_eq!(
            encode_terminal_newline(crate::TextTerminalNewline::Absent),
            0
        );
        assert_eq!(
            encode_terminal_newline(crate::TextTerminalNewline::Present),
            1
        );
        assert_eq!(
            encode_terminal_newline(crate::TextTerminalNewline::Unknown),
            2
        );
        assert_eq!(
            encode_envelope_plan_state(
                &crate::ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge
            ),
            0
        );
        let planned = crate::ThreeWayTextEnvelopePlanState::Planned(
            super::super::envelope::plan_envelope(
                &crate::TextEnvelope::new(
                    false,
                    crate::SupportedTextNewlineStyle::Lf,
                    crate::TextTerminalNewline::Absent,
                ),
                &crate::TextEnvelope::new(
                    false,
                    crate::SupportedTextNewlineStyle::Lf,
                    crate::TextTerminalNewline::Absent,
                ),
                &crate::TextEnvelope::new(
                    false,
                    crate::SupportedTextNewlineStyle::Lf,
                    crate::TextTerminalNewline::Absent,
                ),
            )
            .expect("planned"),
        );
        assert_eq!(encode_envelope_plan_state(&planned), 1);
        assert_eq!(
            encode_overlap_class(ThreeWayTextOverlapClassification::DivergentInsertion),
            1
        );
    }

    #[test]
    fn encode_line_range_writes_start_then_end() {
        let mut encoder = CanonicalFingerprintEncoder::new("gkrm-text-diff-test-range-v1").unwrap();
        let range = LineRange::new(3, 7).unwrap();
        encode_line_range(&mut encoder, &range).unwrap();
        let first = encoder.finish();

        let mut encoder = CanonicalFingerprintEncoder::new("gkrm-text-diff-test-range-v1").unwrap();
        encoder.usize(3).unwrap();
        encoder.usize(7).unwrap();
        assert_eq!(first, encoder.finish());
    }
}
