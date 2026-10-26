//! Immutable version dispatch for durable recovery reconstruction.

mod v1;

use crate::{GkrmError, Result};

pub(crate) use v1::{
    RecoveryDerivationFromSnapshotRequestV1, RecoveryDerivationRequestV1,
    RecoveryDerivationResultV1,
};

pub(crate) const TASK21_APPLY_DERIVATION_V1: u8 = 1;
pub(crate) const TASK22_TRANSACTION_DERIVATION_V1: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryDerivationContract {
    Task21V1Task22V1,
}

pub(crate) fn dispatch_recovery_derivation(
    apply_version: u8,
    transaction_version: u8,
) -> Result<RecoveryDerivationContract> {
    match (apply_version, transaction_version) {
        (TASK21_APPLY_DERIVATION_V1, TASK22_TRANSACTION_DERIVATION_V1) => {
            Ok(RecoveryDerivationContract::Task21V1Task22V1)
        }
        _ => Err(GkrmError::TrustedRecoveryAuthorityDerivationUnsupported),
    }
}

/// Reconstruct through a closed, typed version branch. No caller-provided
/// executable behavior crosses this boundary.
pub(crate) fn reconstruct_recovery_derivation(
    apply_version: u8,
    transaction_version: u8,
    request: RecoveryDerivationRequestV1<'_>,
) -> Result<RecoveryDerivationResultV1> {
    match dispatch_recovery_derivation(apply_version, transaction_version)? {
        RecoveryDerivationContract::Task21V1Task22V1 => v1::reconstruct(request),
    }
}

pub(crate) fn reconstruct_recovery_derivation_from_snapshot(
    apply_version: u8,
    transaction_version: u8,
    request: RecoveryDerivationFromSnapshotRequestV1<'_>,
) -> Result<RecoveryDerivationResultV1> {
    match dispatch_recovery_derivation(apply_version, transaction_version)? {
        RecoveryDerivationContract::Task21V1Task22V1 => v1::reconstruct_from_snapshot(request),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_closed_and_version_one_is_frozen() {
        assert_eq!(
            dispatch_recovery_derivation(1, 1).unwrap(),
            RecoveryDerivationContract::Task21V1Task22V1
        );
        for versions in [(0, 0), (0, 1), (1, 0), (1, 2), (2, 1), (2, 2), (255, 255)] {
            assert!(matches!(
                dispatch_recovery_derivation(versions.0, versions.1),
                Err(GkrmError::TrustedRecoveryAuthorityDerivationUnsupported)
            ));
        }
    }
}
