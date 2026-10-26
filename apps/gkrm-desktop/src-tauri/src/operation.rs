//! The one-trusted-operation-at-a-time permit, and core failures translated for the frontend.
//!
//! These outlived the three-way plan module they grew up in: an update, a recovery, and a
//! finalization all take the same permit, and all report core failures the same way.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use gkrm_core::GkrmError;

use crate::error::{DesktopFailure, DesktopResult};

/// The most bytes of line-level diff content one preview will retain.
pub const MAX_LINE_VIEW_BYTES: usize = 1024 * 1024;

/// Held for the length of one trusted operation. Dropping it lets the next one start.
pub struct OperationPermit {
    occupied: Arc<AtomicBool>,
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        self.occupied.store(false, Ordering::Release);
    }
}

pub fn acquire_operation_permit(occupied: &Arc<AtomicBool>) -> DesktopResult<OperationPermit> {
    occupied
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| DesktopFailure::PlanningBusy)?;
    Ok(OperationPermit {
        occupied: Arc::clone(occupied),
    })
}

/// Core failures translated for an apply, where "the plan could not be created" would be a lie.
///
/// A transaction is identified by the work it does and the state it does it from, so applying the
/// same update twice from the same starting state produces the same identity. That is not a
/// broken plan and not damaged evidence; it is the operator asking for something that has already
/// happened, and it is worth saying so.
pub(crate) fn map_apply_core_error(error: GkrmError) -> DesktopFailure {
    // The last place the real reason still exists: past here it is a closed code that a dozen
    // different causes share, and the operator is shown the same sentence for all of them.
    crate::diagnostics::note_cause(&error);
    match error {
        GkrmError::TrustedTransactionalApplyExecutionTransactionExists
        | GkrmError::TrustedCliUpdateTransactionAlreadyPublished => {
            DesktopFailure::UpdateAlreadyApplied
        }
        GkrmError::TrustedCliUpdateRecoveryRequired => DesktopFailure::RecoveryRequired,
        // The files moved under the operator between looking and pressing. Nothing was written,
        // and comparing again is the whole of what they have to do about it.
        GkrmError::TwoWayPlanChangedSincePreview => DesktopFailure::SelectionStale,
        other => match map_core_error(other) {
            DesktopFailure::PlanCreationFailed => DesktopFailure::UpdateApplyFailed,
            mapped => mapped,
        },
    }
}

pub(crate) fn map_core_error(error: GkrmError) -> DesktopFailure {
    crate::diagnostics::note_cause(&error);
    match error {
        GkrmError::TrustedCliUpdateRecoveryRequired
        | GkrmError::TrustedCliUpdateTransactionAlreadyPublished => {
            DesktopFailure::RecoveryRequired
        }
        GkrmError::TrustedUpdateWorkspaceLegacyUnsupported => {
            DesktopFailure::WorkspaceLegacyUnsupported
        }
        GkrmError::TrustedUpdateWorkspaceCapacityReached => {
            DesktopFailure::WorkspaceCapacityReached
        }
        GkrmError::TrustedUpdateWorkspaceInvalid
        | GkrmError::TrustedCliUpdateSecurityRejection
        | GkrmError::TrustedCliUpdatePathOverlap
        | GkrmError::TrustedStagingSourceUnavailable
        | GkrmError::TrustedStagingDigestLengthMismatch
        | GkrmError::InstalledEntrySymlink { .. }
        | GkrmError::InstalledFxManifestSymlink { .. }
        | GkrmError::InstalledEntryReparsePoint { .. }
        | GkrmError::ThreeWayMergeAnalysisInstalledPreFingerprintMismatch
        | GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid
        | GkrmError::TrustedApplyPlanningInstalledStale
        | GkrmError::TrustedTransactionalApplyPlanningInstalledStale => {
            DesktopFailure::SecurityRejection
        }
        GkrmError::TrustedCliUpdateDestinationExists | GkrmError::TrustedCliUpdateIo { .. } => {
            DesktopFailure::ArtifactPublicationFailed
        }
        GkrmError::TrustedUpdateSourceChanged => DesktopFailure::SourceChanged,
        GkrmError::BaselineMultipleValidBaselinesRequireExactSelection { .. } => {
            DesktopFailure::BaselineAmbiguous
        }
        GkrmError::BaselineAutoSingleBlockedByCatalogIssues { .. }
        | GkrmError::BaselineNoStoredBaselines
        | GkrmError::BaselineSelectedBaselineNotFound { .. }
        | GkrmError::BaselineStoreMissing { .. } => DesktopFailure::BaselineNotFound,
        GkrmError::TrustedCliUpdateResourceSelectionRequired
        | GkrmError::TrustedCliUpdateResourceNotFound
        | GkrmError::TrustedCliUpdateResourceAmbiguous => DesktopFailure::ResourceSelectionStale,
        GkrmError::TrustedCliUpdateLimitExceeded { .. }
        | GkrmError::ThreeWayPlanEntryLimitExceeded { .. } => DesktopFailure::PlanReviewTooLarge,
        _ => DesktopFailure::PlanCreationFailed,
    }
}
