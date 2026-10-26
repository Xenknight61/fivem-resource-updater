#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JournalEvidenceVersion {
    None,
    V1,
    V2,
    Unsupported,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeEvidence {
    None,
    Matching,
    Mismatched,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryEvidenceCompatibility {
    NoCandidate,
    LegacyPackageBacked,
    CompleteV2Authority,
    ManualAttention,
    Malformed,
}

pub(crate) fn classify_recovery_evidence(
    artifact_version: u8,
    journal: JournalEvidenceVersion,
    envelope: EnvelopeEvidence,
    derivation_supported: bool,
) -> RecoveryEvidenceCompatibility {
    if matches!(journal, JournalEvidenceVersion::Malformed)
        || matches!(envelope, EnvelopeEvidence::Malformed)
    {
        return RecoveryEvidenceCompatibility::Malformed;
    }
    if matches!(journal, JournalEvidenceVersion::Unsupported) || !derivation_supported {
        return RecoveryEvidenceCompatibility::ManualAttention;
    }
    match (artifact_version, journal, envelope) {
        (1, JournalEvidenceVersion::V1, EnvelopeEvidence::None) => {
            RecoveryEvidenceCompatibility::LegacyPackageBacked
        }
        (2, JournalEvidenceVersion::None, EnvelopeEvidence::None) => {
            RecoveryEvidenceCompatibility::NoCandidate
        }
        (2, JournalEvidenceVersion::V2, EnvelopeEvidence::Matching) => {
            RecoveryEvidenceCompatibility::CompleteV2Authority
        }
        (1, JournalEvidenceVersion::V2, _)
        | (2, JournalEvidenceVersion::V1, _)
        | (2, JournalEvidenceVersion::V2, EnvelopeEvidence::None | EnvelopeEvidence::Mismatched) => {
            RecoveryEvidenceCompatibility::ManualAttention
        }
        _ => RecoveryEvidenceCompatibility::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_compatibility_matrix_is_explicit() {
        use EnvelopeEvidence::{Matching, Mismatched, None};
        use JournalEvidenceVersion::{Malformed, Unsupported, V1, V2};
        use RecoveryEvidenceCompatibility::{
            CompleteV2Authority, LegacyPackageBacked, Malformed as Bad, ManualAttention,
            NoCandidate,
        };

        assert_eq!(
            classify_recovery_evidence(1, V1, None, true),
            LegacyPackageBacked
        );
        assert_eq!(
            classify_recovery_evidence(2, JournalEvidenceVersion::None, None, true),
            NoCandidate
        );
        assert_eq!(
            classify_recovery_evidence(2, V1, None, true),
            ManualAttention
        );
        assert_eq!(
            classify_recovery_evidence(1, V2, Matching, true),
            ManualAttention
        );
        assert_eq!(
            classify_recovery_evidence(2, V2, None, true),
            ManualAttention
        );
        assert_eq!(
            classify_recovery_evidence(2, V2, Mismatched, true),
            ManualAttention
        );
        assert_eq!(
            classify_recovery_evidence(2, V2, Matching, true),
            CompleteV2Authority
        );
        assert_eq!(
            classify_recovery_evidence(2, V2, Matching, false),
            ManualAttention
        );
        assert_eq!(
            classify_recovery_evidence(2, Unsupported, Matching, true),
            ManualAttention
        );
        assert_eq!(
            classify_recovery_evidence(2, Malformed, Matching, true),
            Bad
        );
    }
}
