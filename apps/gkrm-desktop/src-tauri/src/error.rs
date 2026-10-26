use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopErrorCode {
    InvalidRequest,
    DialogFailed,
    InvalidInstalledRoot,
    InvalidPackageFile,
    SelectionLimitReached,
    SelectionNotFound,
    SelectionStale,
    SelectionBusy,
    SecurityRejection,
    Busy,
    ScanBusy,
    ScanLimitReached,
    ScanNotFound,
    ScanFailed,
    InvalidScanSource,
    ResourceNotFound,
    InspectionRejected,
    PlanningBusy,
    PlanLimitReached,
    PlanNotFound,
    PlanNotReady,
    PlanBusy,
    PlanAlreadyApplied,
    PlanChangeNotFound,
    PlanDecisionInvalid,
    PlanDecisionIncomplete,
    PlanPolicyAcknowledgementRequired,
    PlanCreationFailed,
    UpdateAlreadyApplied,
    UpdateApplyFailed,
    UndoUnavailable,
    UndoInstallationMissing,
    UndoFailed,
    ResourceSelectionStale,
    SourceChanged,
    BaselineNotFound,
    BaselineAmbiguous,
    BaselineSessionLimitReached,
    BaselineSessionStale,
    BaselineCandidateStale,
    BaselineCatalogBlocked,
    BaselineCaptureRejected,
    BaselinePackageChanged,
    BaselineBusy,
    WorkspaceCapacityReached,
    PlanReviewTooLarge,
    RecoveryRequired,
    ArtifactPublicationFailed,
    PlanSessionPublicationFailed,
    RecoverySessionLimitReached,
    RecoverySessionStale,
    RecoveryCandidateStale,
    RecoveryBusy,
    RecoveryManualAttention,
    RecoveryAmbiguous,
    RecoveryEvidenceInvalid,
    RecoveryUnsupported,
    WorkspaceLegacyUnsupported,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopErrorCategory {
    Input,
    Selection,
    Filesystem,
    Security,
    Busy,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopError {
    pub code: DesktopErrorCode,
    pub category: DesktopErrorCategory,
    pub message: &'static str,
    pub recoverable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DesktopFailure {
    #[error("invalid request")]
    InvalidRequest,
    #[error("dialog failed")]
    DialogFailed,
    #[error("invalid installed root")]
    InvalidInstalledRoot,
    #[error("invalid package file")]
    InvalidPackageFile,
    #[error("selection limit reached")]
    SelectionLimitReached,
    #[error("selection not found")]
    SelectionNotFound,
    #[error("selection stale")]
    SelectionStale,
    #[error("selection busy")]
    SelectionBusy,
    #[error("security rejection")]
    SecurityRejection,
    #[error("busy")]
    Busy,
    #[error("scan busy")]
    ScanBusy,
    #[error("scan limit reached")]
    ScanLimitReached,
    #[error("scan not found")]
    ScanNotFound,
    #[error("scan failed")]
    ScanFailed,
    #[error("invalid scan source")]
    InvalidScanSource,
    #[error("resource not found")]
    ResourceNotFound,
    #[error("inspection rejected")]
    InspectionRejected,
    #[error("planning busy")]
    PlanningBusy,
    #[error("plan limit reached")]
    PlanLimitReached,
    #[error("plan not found")]
    PlanNotFound,
    #[error("plan not ready")]
    PlanNotReady,
    #[error("plan busy")]
    PlanBusy,
    #[error("plan already applied")]
    PlanAlreadyApplied,
    #[error("plan change not found")]
    PlanChangeNotFound,
    #[error("plan decision invalid")]
    PlanDecisionInvalid,
    #[error("plan decision incomplete")]
    PlanDecisionIncomplete,
    #[error("plan policy acknowledgement required")]
    PlanPolicyAcknowledgementRequired,
    #[error("plan creation failed")]
    PlanCreationFailed,
    #[error("update already applied from this state")]
    UpdateAlreadyApplied,
    #[error("update apply failed")]
    UpdateApplyFailed,
    #[error("nothing on record to undo")]
    UndoUnavailable,
    #[error("installation to undo into is missing")]
    UndoInstallationMissing,
    #[error("undo failed")]
    UndoFailed,
    #[error("resource selection stale")]
    ResourceSelectionStale,
    #[error("source changed")]
    SourceChanged,
    #[error("baseline not found")]
    BaselineNotFound,
    #[error("baseline ambiguous")]
    BaselineAmbiguous,
    #[error("baseline session limit reached")]
    BaselineSessionLimitReached,
    #[error("baseline session stale")]
    BaselineSessionStale,
    #[error("baseline candidate stale")]
    BaselineCandidateStale,
    #[error("baseline catalog blocked")]
    BaselineCatalogBlocked,
    #[error("baseline capture rejected")]
    BaselineCaptureRejected,
    #[error("baseline package changed")]
    BaselinePackageChanged,
    #[error("baseline busy")]
    BaselineBusy,
    #[error("workspace capacity reached")]
    WorkspaceCapacityReached,
    #[error("plan review too large")]
    PlanReviewTooLarge,
    #[error("recovery required")]
    RecoveryRequired,
    #[error("artifact publication failed")]
    ArtifactPublicationFailed,
    #[error("plan session publication failed")]
    PlanSessionPublicationFailed,
    #[error("recovery session limit reached")]
    RecoverySessionLimitReached,
    #[error("recovery session stale")]
    RecoverySessionStale,
    #[error("recovery candidate stale")]
    RecoveryCandidateStale,
    #[error("recovery busy")]
    RecoveryBusy,
    #[error("recovery manual attention")]
    RecoveryManualAttention,
    #[error("recovery ambiguous")]
    RecoveryAmbiguous,
    #[error("recovery evidence invalid")]
    RecoveryEvidenceInvalid,
    #[error("recovery unsupported")]
    RecoveryUnsupported,
    #[error("workspace legacy unsupported")]
    WorkspaceLegacyUnsupported,
    #[error("internal")]
    Internal,
}

pub type DesktopResult<T> = Result<T, DesktopFailure>;

impl DesktopFailure {
    pub fn dto(self) -> DesktopError {
        match self {
            Self::InvalidRequest => DesktopError {
                code: DesktopErrorCode::InvalidRequest,
                category: DesktopErrorCategory::Input,
                message: "The desktop request is invalid.",
                recoverable: true,
            },
            Self::DialogFailed => DesktopError {
                code: DesktopErrorCode::DialogFailed,
                category: DesktopErrorCategory::Filesystem,
                message: "The native selection dialog failed.",
                recoverable: true,
            },
            Self::InvalidInstalledRoot => DesktopError {
                code: DesktopErrorCode::InvalidInstalledRoot,
                category: DesktopErrorCategory::Filesystem,
                message: "The installed root selection is invalid.",
                recoverable: true,
            },
            Self::InvalidPackageFile => DesktopError {
                code: DesktopErrorCode::InvalidPackageFile,
                category: DesktopErrorCategory::Filesystem,
                message: "The package file selection is invalid.",
                recoverable: true,
            },
            Self::SelectionLimitReached => DesktopError {
                code: DesktopErrorCode::SelectionLimitReached,
                category: DesktopErrorCategory::Selection,
                message: "The selection limit has been reached.",
                recoverable: true,
            },
            Self::SelectionNotFound => DesktopError {
                code: DesktopErrorCode::SelectionNotFound,
                category: DesktopErrorCategory::Selection,
                message: "The selection is not available.",
                recoverable: true,
            },
            Self::SelectionStale => DesktopError {
                code: DesktopErrorCode::SelectionStale,
                category: DesktopErrorCategory::Selection,
                message: "The files changed since you compared them. Nothing was written — compare again to see what they are now.",
                recoverable: true,
            },
            Self::SelectionBusy => DesktopError {
                code: DesktopErrorCode::SelectionBusy,
                category: DesktopErrorCategory::Busy,
                message: "The selection is in use.",
                recoverable: true,
            },
            Self::SecurityRejection => DesktopError {
                code: DesktopErrorCode::SecurityRejection,
                category: DesktopErrorCategory::Security,
                message: "The desktop security boundary rejected the request.",
                recoverable: false,
            },
            Self::Busy => DesktopError {
                code: DesktopErrorCode::Busy,
                category: DesktopErrorCategory::Busy,
                message: "The desktop adapter is busy.",
                recoverable: true,
            },
            Self::ScanBusy => DesktopError {
                code: DesktopErrorCode::ScanBusy,
                category: DesktopErrorCategory::Busy,
                message: "A scan is already running.",
                recoverable: true,
            },
            Self::ScanLimitReached => DesktopError {
                code: DesktopErrorCode::ScanLimitReached,
                category: DesktopErrorCategory::Selection,
                message: "The scan session limit has been reached.",
                recoverable: true,
            },
            Self::ScanNotFound => DesktopError {
                code: DesktopErrorCode::ScanNotFound,
                category: DesktopErrorCategory::Selection,
                message: "The scan session is not available.",
                recoverable: true,
            },
            Self::ScanFailed => DesktopError {
                code: DesktopErrorCode::ScanFailed,
                category: DesktopErrorCategory::Filesystem,
                message: "The scan failed.",
                recoverable: true,
            },
            Self::InvalidScanSource => DesktopError {
                code: DesktopErrorCode::InvalidScanSource,
                category: DesktopErrorCategory::Input,
                message: "The scan source is invalid.",
                recoverable: true,
            },
            Self::ResourceNotFound => DesktopError {
                code: DesktopErrorCode::ResourceNotFound,
                category: DesktopErrorCategory::Selection,
                message: "The resource is not available.",
                recoverable: true,
            },
            Self::InspectionRejected => DesktopError {
                code: DesktopErrorCode::InspectionRejected,
                category: DesktopErrorCategory::Filesystem,
                message: "The inspection was rejected.",
                recoverable: true,
            },
            Self::PlanningBusy => DesktopError {
                code: DesktopErrorCode::PlanningBusy,
                category: DesktopErrorCategory::Busy,
                message: "A trusted operation is already running.",
                recoverable: true,
            },
            Self::PlanLimitReached => DesktopError {
                code: DesktopErrorCode::PlanLimitReached,
                category: DesktopErrorCategory::Selection,
                message: "The plan session limit has been reached.",
                recoverable: true,
            },
            Self::PlanNotFound => DesktopError {
                code: DesktopErrorCode::PlanNotFound,
                category: DesktopErrorCategory::Selection,
                message: "The plan session is not available.",
                recoverable: true,
            },
            Self::PlanNotReady => DesktopError {
                code: DesktopErrorCode::PlanNotReady,
                category: DesktopErrorCategory::Selection,
                message: "The plan is not ready to apply.",
                recoverable: true,
            },
            Self::PlanBusy => DesktopError {
                code: DesktopErrorCode::PlanBusy,
                category: DesktopErrorCategory::Busy,
                message: "The plan is in use.",
                recoverable: true,
            },
            Self::PlanAlreadyApplied => DesktopError {
                code: DesktopErrorCode::PlanAlreadyApplied,
                category: DesktopErrorCategory::Selection,
                message: "The plan has already completed apply.",
                recoverable: false,
            },
            Self::PlanChangeNotFound => DesktopError {
                code: DesktopErrorCode::PlanChangeNotFound,
                category: DesktopErrorCategory::Selection,
                message: "The plan change is not available.",
                recoverable: true,
            },
            Self::PlanDecisionInvalid => DesktopError {
                code: DesktopErrorCode::PlanDecisionInvalid,
                category: DesktopErrorCategory::Input,
                message: "The submitted plan decisions are invalid or stale.",
                recoverable: true,
            },
            Self::PlanDecisionIncomplete => DesktopError {
                code: DesktopErrorCode::PlanDecisionIncomplete,
                category: DesktopErrorCategory::Input,
                message: "Choose a valid decision for every required change.",
                recoverable: true,
            },
            Self::PlanPolicyAcknowledgementRequired => DesktopError {
                code: DesktopErrorCode::PlanPolicyAcknowledgementRequired,
                category: DesktopErrorCategory::Input,
                message: "A required policy transition acknowledgement is missing.",
                recoverable: true,
            },
            Self::PlanCreationFailed => DesktopError {
                code: DesktopErrorCode::PlanCreationFailed,
                category: DesktopErrorCategory::Filesystem,
                message: "The update plan could not be created.",
                recoverable: true,
            },
            Self::UpdateAlreadyApplied => DesktopError {
                code: DesktopErrorCode::UpdateAlreadyApplied,
                category: DesktopErrorCategory::Filesystem,
                message: "This update was already applied from exactly this starting state.",
                recoverable: true,
            },
            Self::UpdateApplyFailed => DesktopError {
                code: DesktopErrorCode::UpdateApplyFailed,
                category: DesktopErrorCategory::Filesystem,
                message: "The update could not be applied. Nothing was changed.",
                recoverable: true,
            },
            Self::UndoUnavailable => DesktopError {
                code: DesktopErrorCode::UndoUnavailable,
                category: DesktopErrorCategory::Filesystem,
                message: "There is nothing on record to put this update back from.",
                recoverable: false,
            },
            Self::UndoInstallationMissing => DesktopError {
                code: DesktopErrorCode::UndoInstallationMissing,
                category: DesktopErrorCategory::Filesystem,
                message: "The folder this update was applied to is not there any more.",
                recoverable: true,
            },
            Self::UndoFailed => DesktopError {
                code: DesktopErrorCode::UndoFailed,
                category: DesktopErrorCategory::Filesystem,
                message: "The update could not be put back. Some files may already be restored.",
                recoverable: true,
            },
            Self::ResourceSelectionStale => DesktopError {
                code: DesktopErrorCode::ResourceSelectionStale,
                category: DesktopErrorCategory::Selection,
                message: "The selected resource is no longer valid.",
                recoverable: true,
            },
            Self::SourceChanged => DesktopError {
                code: DesktopErrorCode::SourceChanged,
                category: DesktopErrorCategory::Filesystem,
                message: "The update sources changed before planning completed.",
                recoverable: true,
            },
            Self::BaselineNotFound => DesktopError {
                code: DesktopErrorCode::BaselineNotFound,
                category: DesktopErrorCategory::Filesystem,
                message: "No trusted baseline is available.",
                recoverable: true,
            },
            Self::BaselineAmbiguous => DesktopError {
                code: DesktopErrorCode::BaselineAmbiguous,
                category: DesktopErrorCategory::Filesystem,
                message: "The trusted baseline selection is ambiguous.",
                recoverable: true,
            },
            Self::BaselineSessionLimitReached => DesktopError {
                code: DesktopErrorCode::BaselineSessionLimitReached,
                category: DesktopErrorCategory::Busy,
                message: "The baseline inspection limit has been reached. Refresh after closing an older inspection.",
                recoverable: true,
            },
            Self::BaselineSessionStale => DesktopError {
                code: DesktopErrorCode::BaselineSessionStale,
                category: DesktopErrorCategory::Selection,
                message: "The baseline inspection is no longer current. Refresh official baseline status.",
                recoverable: true,
            },
            Self::BaselineCandidateStale => DesktopError {
                code: DesktopErrorCode::BaselineCandidateStale,
                category: DesktopErrorCategory::Selection,
                message: "The selected official baseline is no longer available. Refresh baseline status.",
                recoverable: true,
            },
            Self::BaselineCatalogBlocked => DesktopError {
                code: DesktopErrorCode::BaselineCatalogBlocked,
                category: DesktopErrorCategory::Security,
                message: "The managed baseline store needs attention before planning can continue.",
                recoverable: true,
            },
            Self::BaselineCaptureRejected => DesktopError {
                code: DesktopErrorCode::BaselineCaptureRejected,
                category: DesktopErrorCategory::Filesystem,
                message: "The previous official package could not be captured as a trusted baseline.",
                recoverable: true,
            },
            Self::BaselinePackageChanged => DesktopError {
                code: DesktopErrorCode::BaselinePackageChanged,
                category: DesktopErrorCategory::Filesystem,
                message: "The previous official package changed after it was inspected. Inspect it again before capturing the baseline.",
                recoverable: true,
            },
            Self::BaselineBusy => DesktopError {
                code: DesktopErrorCode::BaselineBusy,
                category: DesktopErrorCategory::Busy,
                message: "The baseline inspection is in use.",
                recoverable: true,
            },
            Self::WorkspaceCapacityReached => DesktopError {
                code: DesktopErrorCode::WorkspaceCapacityReached,
                category: DesktopErrorCategory::Filesystem,
                message: "The trusted workspace capacity has been reached.",
                recoverable: true,
            },
            Self::PlanReviewTooLarge => DesktopError {
                code: DesktopErrorCode::PlanReviewTooLarge,
                category: DesktopErrorCategory::Filesystem,
                message: "The plan is too large for desktop review.",
                recoverable: true,
            },
            Self::RecoveryRequired => DesktopError {
                code: DesktopErrorCode::RecoveryRequired,
                category: DesktopErrorCategory::Filesystem,
                message: "Recovery is required before planning can continue.",
                recoverable: true,
            },
            Self::ArtifactPublicationFailed => DesktopError {
                code: DesktopErrorCode::ArtifactPublicationFailed,
                category: DesktopErrorCategory::Filesystem,
                message: "The trusted plan artifact could not be published.",
                recoverable: true,
            },
            Self::PlanSessionPublicationFailed => DesktopError {
                code: DesktopErrorCode::PlanSessionPublicationFailed,
                category: DesktopErrorCategory::Internal,
                message: "The desktop plan session could not be published.",
                recoverable: true,
            },
            Self::RecoverySessionLimitReached => DesktopError {
                code: DesktopErrorCode::RecoverySessionLimitReached,
                category: DesktopErrorCategory::Selection,
                message: "The recovery session limit has been reached.",
                recoverable: true,
            },
            Self::RecoverySessionStale => DesktopError {
                code: DesktopErrorCode::RecoverySessionStale,
                category: DesktopErrorCategory::Selection,
                message: "The recovery session is no longer available. Refresh recovery status.",
                recoverable: true,
            },
            Self::RecoveryCandidateStale => DesktopError {
                code: DesktopErrorCode::RecoveryCandidateStale,
                category: DesktopErrorCategory::Selection,
                message: "The recovery candidate changed. Refresh recovery status.",
                recoverable: true,
            },
            Self::RecoveryBusy => DesktopError {
                code: DesktopErrorCode::RecoveryBusy,
                category: DesktopErrorCategory::Busy,
                message: "A trusted recovery operation is already running.",
                recoverable: true,
            },
            Self::RecoveryManualAttention => DesktopError {
                code: DesktopErrorCode::RecoveryManualAttention,
                category: DesktopErrorCategory::Filesystem,
                message: "Recovery evidence requires manual attention.",
                recoverable: false,
            },
            Self::RecoveryAmbiguous => DesktopError {
                code: DesktopErrorCode::RecoveryAmbiguous,
                category: DesktopErrorCategory::Security,
                message: "Recovery evidence is ambiguous and was not selected.",
                recoverable: false,
            },
            Self::RecoveryEvidenceInvalid => DesktopError {
                code: DesktopErrorCode::RecoveryEvidenceInvalid,
                category: DesktopErrorCategory::Security,
                message: "Recovery evidence failed trusted validation.",
                recoverable: false,
            },
            Self::RecoveryUnsupported => DesktopError {
                code: DesktopErrorCode::RecoveryUnsupported,
                category: DesktopErrorCategory::Filesystem,
                message: "This recovery evidence is not supported by the desktop recovery flow.",
                recoverable: false,
            },
            Self::WorkspaceLegacyUnsupported => DesktopError {
                code: DesktopErrorCode::WorkspaceLegacyUnsupported,
                category: DesktopErrorCategory::Filesystem,
                message: "Pre-release workspace layout found. Evidence is preserved, not \
                          damaged. Move the app data folder aside, then reopen to create a \
                          current workspace.",
                recoverable: false,
            },
            Self::Internal => DesktopError {
                code: DesktopErrorCode::Internal,
                category: DesktopErrorCategory::Internal,
                message: "The desktop adapter failed.",
                recoverable: false,
            },
        }
    }
}

impl From<DesktopFailure> for DesktopError {
    fn from(value: DesktopFailure) -> Self {
        value.dto()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// Every `DesktopFailure`, listed once so the message audit below covers all of them.
    /// The exhaustive match is the guard: adding a variant fails to compile until it is
    /// listed here, so a new error can never skip the audit silently.
    fn every_failure() -> Vec<DesktopFailure> {
        use DesktopFailure::*;
        let all = vec![
            InvalidRequest,
            DialogFailed,
            InvalidInstalledRoot,
            InvalidPackageFile,
            SelectionLimitReached,
            SelectionNotFound,
            SelectionStale,
            SelectionBusy,
            SecurityRejection,
            Busy,
            ScanBusy,
            ScanLimitReached,
            ScanNotFound,
            ScanFailed,
            InvalidScanSource,
            ResourceNotFound,
            InspectionRejected,
            PlanningBusy,
            PlanLimitReached,
            PlanNotFound,
            PlanNotReady,
            PlanBusy,
            PlanAlreadyApplied,
            PlanChangeNotFound,
            PlanDecisionInvalid,
            PlanDecisionIncomplete,
            PlanPolicyAcknowledgementRequired,
            PlanCreationFailed,
            ResourceSelectionStale,
            SourceChanged,
            BaselineNotFound,
            BaselineAmbiguous,
            BaselineSessionLimitReached,
            BaselineSessionStale,
            BaselineCandidateStale,
            BaselineCatalogBlocked,
            BaselineCaptureRejected,
            BaselinePackageChanged,
            BaselineBusy,
            WorkspaceCapacityReached,
            PlanReviewTooLarge,
            RecoveryRequired,
            ArtifactPublicationFailed,
            PlanSessionPublicationFailed,
            RecoverySessionLimitReached,
            RecoverySessionStale,
            RecoveryCandidateStale,
            RecoveryBusy,
            RecoveryManualAttention,
            RecoveryAmbiguous,
            RecoveryEvidenceInvalid,
            RecoveryUnsupported,
            WorkspaceLegacyUnsupported,
            Internal,
        ];
        for failure in &all {
            match failure {
                InvalidRequest
                | DialogFailed
                | InvalidInstalledRoot
                | InvalidPackageFile
                | SelectionLimitReached
                | SelectionNotFound
                | SelectionStale
                | SelectionBusy
                | SecurityRejection
                | Busy
                | ScanBusy
                | ScanLimitReached
                | ScanNotFound
                | ScanFailed
                | InvalidScanSource
                | ResourceNotFound
                | InspectionRejected
                | PlanningBusy
                | PlanLimitReached
                | PlanNotFound
                | PlanNotReady
                | PlanBusy
                | PlanAlreadyApplied
                | PlanChangeNotFound
                | PlanDecisionInvalid
                | PlanDecisionIncomplete
                | PlanPolicyAcknowledgementRequired
                | PlanCreationFailed
                | ResourceSelectionStale
                | SourceChanged
                | BaselineNotFound
                | BaselineAmbiguous
                | BaselineSessionLimitReached
                | BaselineSessionStale
                | BaselineCandidateStale
                | BaselineCatalogBlocked
                | BaselineCaptureRejected
                | BaselinePackageChanged
                | BaselineBusy
                | WorkspaceCapacityReached
                | PlanReviewTooLarge
                | RecoveryRequired
                | ArtifactPublicationFailed
                | PlanSessionPublicationFailed
                | RecoverySessionLimitReached
                | RecoverySessionStale
                | RecoveryCandidateStale
                | RecoveryBusy
                | RecoveryManualAttention
                | RecoveryAmbiguous
                | RecoveryEvidenceInvalid
                | RecoveryUnsupported
                | WorkspaceLegacyUnsupported
                | UpdateAlreadyApplied
                | UpdateApplyFailed
                | UndoUnavailable
                | UndoInstallationMissing
                | UndoFailed
                | Internal => {}
            }
        }
        all
    }

    #[test]
    fn every_failure_message_fits_the_frontend_decoder_bound() {
        // `decodeDesktopError` rejects a message longer than 160 characters and substitutes
        // the generic internal error, so an over-long message reaches the operator as
        // "The desktop adapter failed." instead of the explanation it was written to give.
        const FRONTEND_MESSAGE_MAX_CHARS: usize = 160;
        for failure in every_failure() {
            let dto = failure.dto();
            let length = dto.message.chars().count();
            assert!(
                (1..=FRONTEND_MESSAGE_MAX_CHARS).contains(&length),
                "{:?} message is {length} characters: {}",
                dto.code,
                dto.message
            );
        }
    }

    #[test]
    fn every_failure_maps_to_a_distinct_error_code() {
        let mut seen = std::collections::BTreeSet::new();
        for failure in every_failure() {
            let dto = failure.dto();
            assert!(
                seen.insert(format!("{:?}", dto.code)),
                "duplicate error code for {failure:?}"
            );
        }
    }

    #[test]
    fn error_json_does_not_include_paths_or_raw_details() {
        let text = serde_json::to_string(&DesktopFailure::InvalidPackageFile.dto()).unwrap();
        for needle in [
            r"C:\Users\sentinel\package.zip",
            "/tmp/sentinel/package.zip",
            "\\\\server\\share\\package.zip",
            "package.zip",
            "Permission denied",
            &format!("{:?}", PathBuf::from(r"C:\Users\sentinel\package.zip")),
        ] {
            assert!(!text.contains(needle), "error leaked {needle}: {text}");
        }
    }
}
