//! Stable enum encodings for trusted staging fingerprints.

use super::{StagingContentOrigin, StagingFinalState, TrustedStagingStatus};

pub(super) fn encode_final_state(state: StagingFinalState) -> u8 {
    match state {
        StagingFinalState::Installed => 0,
        StagingFinalState::Incoming => 1,
        StagingFinalState::Merged => 2,
        StagingFinalState::Absent => 3,
    }
}

pub(super) fn encode_origin(origin: StagingContentOrigin) -> u8 {
    match origin {
        StagingContentOrigin::Installed => 0,
        StagingContentOrigin::Incoming => 1,
        StagingContentOrigin::Merged => 2,
        StagingContentOrigin::Absent => 3,
    }
}

pub(super) fn encode_status(status: TrustedStagingStatus) -> u8 {
    match status {
        TrustedStagingStatus::ReadyForApplyPlanning => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_tags_are_stable() {
        assert_eq!(encode_final_state(StagingFinalState::Merged), 2);
        assert_eq!(encode_origin(StagingContentOrigin::Absent), 3);
        assert_eq!(
            encode_status(TrustedStagingStatus::ReadyForApplyPlanning),
            0
        );
    }
}
