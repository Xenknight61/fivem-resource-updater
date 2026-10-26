use std::fmt;

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_PLAN_DECISION_SUBMISSIONS: usize = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum SelectionKind {
    InstalledRoot,
    PackageFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub schema_version: u8,
    pub app_version: &'static str,
    pub core_version: &'static str,
    pub platform: Platform,
    pub build_profile: BuildProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BuildProfile {
    Debug,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectionSummary {
    pub handle: String,
    pub kind: SelectionKind,
    pub display_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectionDialogResult {
    pub cancelled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<SelectionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListSelectionsRequest {
    pub kind: Option<SelectionKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSelectionsResponse {
    pub selections: Vec<SelectionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseSelectionRequest {
    pub handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseSelectionResponse {
    pub released: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanSourceKind {
    InstalledRoot,
    PackageFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResourceStatus {
    Available,
    Warnings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ManifestKind {
    Fxmanifest,
    ResourceManifest,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EscrowState {
    NotAvailable,
    None,
    Partial,
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingCode {
    ScanWarningsPresent,
    ManifestWarningsPresent,
    EscrowWarningsPresent,
    PackageEntriesUnassigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingSeverity {
    Info,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub source_kind: ScanSourceKind,
    pub source_label: String,
    pub resource_count: u32,
    pub warning_count: u32,
    pub total_file_count: u32,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSummary {
    pub resource_handle: String,
    pub source_kind: ScanSourceKind,
    pub display_name: String,
    pub status: ResourceStatus,
    pub file_count: u32,
    pub total_bytes: u64,
    pub warning_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSummary {
    pub kind: ManifestKind,
    pub client_script_count: u32,
    pub server_script_count: u32,
    pub shared_script_count: u32,
    pub data_file_count: u32,
    pub has_ui_page: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EscrowSummary {
    pub state: EscrowState,
    pub protected_file_count: u32,
    pub ignored_file_count: u32,
    pub unsupported_file_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceStatistics {
    pub file_count: u32,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSummary {
    pub code: FindingCode,
    pub severity: FindingSeverity,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDetail {
    pub resource_handle: String,
    pub source_kind: ScanSourceKind,
    pub display_name: String,
    pub status: ResourceStatus,
    pub manifest: ManifestSummary,
    pub escrow: EscrowSummary,
    pub statistics: ResourceStatistics,
    pub findings: Vec<FindingSummary>,
    pub omitted_finding_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanInstalledRootRequest {
    pub selection_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectPackageRequest {
    pub selection_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartScanResponse {
    pub scan_handle: String,
    pub source_kind: ScanSourceKind,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanGetSummaryRequest {
    pub scan_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanGetSummaryResponse {
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanListResourcesRequest {
    pub scan_handle: String,
    pub query: Option<String>,
    pub status: Option<ResourceStatus>,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanListResourcesResponse {
    pub total: u32,
    pub offset: u32,
    pub limit: u32,
    pub resources: Vec<ResourceSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanGetResourceDetailRequest {
    pub scan_handle: String,
    pub resource_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanGetResourceDetailResponse {
    pub resource: ResourceDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanReleaseRequest {
    pub scan_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReleaseResponse {
    pub released: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSourceMatchRequest {
    pub installed_selection_handle: String,
    pub installed_scan_handle: String,
    pub installed_resource_handle: String,
    pub package_selection_handle: String,
    pub package_scan_handle: String,
    pub package_resource_handle: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceMatchStatus {
    Matched,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSourceMatchResponse {
    pub status: SourceMatchStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateBaselineStatusRequest {
    pub installed_selection_handle: String,
    pub installed_scan_handle: String,
    pub installed_resource_handle: String,
    pub package_selection_handle: String,
    pub package_scan_handle: String,
    pub package_resource_handle: String,
}

impl From<&UpdateBaselineStatusRequest> for UpdateSourceMatchRequest {
    fn from(value: &UpdateBaselineStatusRequest) -> Self {
        Self {
            installed_selection_handle: value.installed_selection_handle.clone(),
            installed_scan_handle: value.installed_scan_handle.clone(),
            installed_resource_handle: value.installed_resource_handle.clone(),
            package_selection_handle: value.package_selection_handle.clone(),
            package_scan_handle: value.package_scan_handle.clone(),
            package_resource_handle: value.package_resource_handle.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BaselineStatus {
    Missing,
    Ready,
    Multiple,
    Ambiguous,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineCandidateSummary {
    pub candidate_handle: String,
    pub presentation: BaselineCandidatePresentation,
}

/// The complete safe operator-visible tuple used to decide whether baseline
/// candidates may be selected directly. Every field is rendered by the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineCandidatePresentation {
    pub resource_label: String,
    pub version: BaselineVersionPresentation,
    pub file_count: u64,
    pub protected_file_count: u64,
    pub editable_file_count: u64,
    pub retained_blob_count: u64,
    pub retained_blob_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum BaselineVersionPresentation {
    NotDeclared,
    DeclaredEmpty,
    Declared { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBaselineStatusResponse {
    pub baseline_session_handle: String,
    pub status: BaselineStatus,
    pub candidates: Vec<BaselineCandidateSummary>,
    pub catalog_needs_attention: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateBaselineCaptureRequest {
    pub baseline_session_handle: String,
    pub preview_selection_handle: String,
    pub preview_scan_handle: String,
    pub preview_resource_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBaselineCaptureResponse {
    pub baseline: UpdateBaselineStatusResponse,
    pub selected_candidate_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateBaselineReleaseRequest {
    pub baseline_session_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBaselineReleaseResponse {
    pub released: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdatePlanStatus {
    PendingDecisions,
    ManualMergeRequired,
    ReadyToApply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanDisposition {
    NoChange,
    UseIncoming,
    RemoveForIncoming,
    PreserveInstalled,
    PreserveInstalledDeletion,
    AddIncoming,
    PreserveInstalledAddition,
    Converged,
    ConvergedAddition,
    ConvergedDeletion,
    MergeCandidate,
    ConflictReview,
    DeleteVsModifyConflict,
    ModifyVsDeleteConflict,
    AddVsAddConflict,
    PolicyReview,
    PolicyConflictReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanDelta {
    Unchanged,
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanReviewRequirement {
    NoDecisionRequired,
    DecisionRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanReviewedAction {
    NotRequired,
    Pending,
    UseIncomingState,
    PreserveInstalledState,
    QueueMergeAnalysis,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanDecisionChoice {
    AcceptRecommended,
    UseIncomingState,
    PreserveInstalledState,
    QueueMergeAnalysis,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedPlanDecision {
    pub choice: PlanDecisionChoice,
    pub requires_policy_acknowledgement: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyTransitionKind {
    None,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FilePresenceState {
    Absent,
    Present,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanFindingCode {
    DecisionRequired,
    ManualReviewRequired,
    MergeAnalysisQueued,
    ConflictReviewRequired,
    PolicyReviewRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanFinding {
    pub code: PlanFindingCode,
    pub severity: FindingSeverity,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateUpdatePlanRequest {
    pub installed_selection_handle: String,
    pub installed_scan_handle: String,
    pub installed_resource_handle: String,
    pub package_selection_handle: String,
    pub package_scan_handle: String,
    pub package_resource_handle: String,
    pub baseline_session_handle: String,
    pub baseline_candidate_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUpdatePlanResponse {
    pub plan_handle: String,
    pub summary: UpdatePlanSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanSummary {
    pub plan_handle: String,
    pub status: UpdatePlanStatus,
    pub installed_resource_label: String,
    pub incoming_resource_label: String,
    pub total_change_count: u32,
    pub no_change_count: u32,
    pub incoming_action_count: u32,
    pub preserved_local_count: u32,
    pub converged_count: u32,
    pub merge_candidate_count: u32,
    pub conflict_count: u32,
    pub policy_review_count: u32,
    pub decisions_required_count: u32,
    pub pending_decision_count: u32,
    pub manual_review_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePlanGetSummaryRequest {
    pub plan_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanGetSummaryResponse {
    pub summary: UpdatePlanSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePlanListChangesRequest {
    pub plan_handle: String,
    pub query: Option<String>,
    pub disposition: Option<PlanDisposition>,
    pub review_requirement: Option<PlanReviewRequirement>,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanListChangesResponse {
    pub total: u32,
    pub offset: u32,
    pub limit: u32,
    pub changes: Vec<PlanChangeSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanChangeSummary {
    pub change_handle: String,
    pub display_path: String,
    pub disposition: PlanDisposition,
    pub review_requirement: PlanReviewRequirement,
    pub reviewed_action: PlanReviewedAction,
    pub local_delta: PlanDelta,
    pub incoming_delta: PlanDelta,
    pub policy_transition: PolicyTransitionKind,
    pub blocks_automatic_apply: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<PlanReviewedAction>,
    pub allowed_decisions: Vec<AllowedPlanDecision>,
    pub finding_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePlanGetChangeDetailRequest {
    pub plan_handle: String,
    pub change_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanGetChangeDetailResponse {
    pub change: PlanChangeDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePlanGetChangeDiffRequest {
    pub plan_handle: String,
    pub change_handle: String,
}

/// Why a change does or does not carry a line-level view.
///
/// Absence is reported as a named reason rather than an empty list, because "your vendor's file
/// is never shown" and "this change was not merged" call for different explanations on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanDiffAvailability {
    /// Line content is present below.
    Available,
    /// Escrow-protected content. It is not retained by the product and is never displayed.
    ProtectedContent,
    /// No merge produced a result for this change, so there are no merged lines to show.
    NotMerged,
    /// A view existed but was dropped to keep the plan's retained memory bounded.
    Omitted,
}

/// Which side a surviving merged line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanDiffLineOrigin {
    Baseline,
    Installed,
    Incoming,
    Converged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanDiffLine {
    pub origin: PlanDiffLineOrigin,
    /// Sanitized line text: valid UTF-8, control characters removed, bounded length.
    pub text: String,
    /// True when this individual line was longer than the display limit and was cut.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanGetChangeDiffResponse {
    pub availability: PlanDiffAvailability,
    pub lines: Vec<PlanDiffLine>,
    /// True when the file had more lines than the display limit and the tail was dropped.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanChangeDetail {
    pub change_handle: String,
    pub display_path: String,
    pub disposition: PlanDisposition,
    pub review_requirement: PlanReviewRequirement,
    pub reviewed_action: PlanReviewedAction,
    pub local_delta: PlanDelta,
    pub incoming_delta: PlanDelta,
    pub policy_transition: PolicyTransitionKind,
    pub blocks_automatic_apply: bool,
    pub baseline_state: FilePresenceState,
    pub installed_state: FilePresenceState,
    pub incoming_state: FilePresenceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<PlanReviewedAction>,
    pub allowed_decisions: Vec<AllowedPlanDecision>,
    pub findings: Vec<PlanFinding>,
    pub omitted_finding_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanDecisionSubmission {
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub change_handle: String,
    pub choice: PlanDecisionChoice,
    pub policy_acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePlanSubmitDecisionsRequest {
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub plan_handle: String,
    #[serde(deserialize_with = "deserialize_plan_decisions")]
    pub decisions: Vec<PlanDecisionSubmission>,
}

fn deserialize_opaque_handle<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct OpaqueHandleVisitor;

    impl Visitor<'_> for OpaqueHandleVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded opaque handle")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() != 36 {
                return Err(E::custom("invalid opaque handle"));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() != 36 {
                return Err(E::custom("invalid opaque handle"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(OpaqueHandleVisitor)
}

/// An optional handle, checked exactly as a required one is when it is there at all.
fn deserialize_optional_opaque_handle<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        Some(handle) if handle.len() != 36 => {
            Err(serde::de::Error::custom("invalid opaque handle"))
        }
        other => Ok(other),
    }
}

fn deserialize_plan_decisions<'de, D>(
    deserializer: D,
) -> Result<Vec<PlanDecisionSubmission>, D::Error>
where
    D: Deserializer<'de>,
{
    struct DecisionBatchVisitor;

    impl<'de> Visitor<'de> for DecisionBatchVisitor {
        type Value = Vec<PlanDecisionSubmission>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded plan decision batch")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut decisions = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_PLAN_DECISION_SUBMISSIONS),
            );
            while let Some(decision) = sequence.next_element()? {
                if decisions.len() == MAX_PLAN_DECISION_SUBMISSIONS {
                    return Err(A::Error::custom("plan decision batch is too large"));
                }
                decisions.push(decision);
            }
            Ok(decisions)
        }
    }

    deserializer.deserialize_seq(DecisionBatchVisitor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanSubmitDecisionsResponse {
    pub plan_handle: String,
    pub summary: UpdatePlanSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePlanReleaseRequest {
    pub plan_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanReleaseResponse {
    pub released: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePlanApplyRequest {
    pub plan_handle: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcome {
    Committed,
    RolledBack,
    RecoveryRequired,
    PublishedRecoveryUnsealed,
    PublishedRecoveryFailed,
    SafeFailureBeforePublication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlanApplyResponse {
    pub outcome: ApplyOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOverviewDisposition {
    Clear,
    AttentionRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecoveryOverviewResponse {
    pub disposition: RecoveryOverviewDisposition,
    pub active_recovery: bool,
    pub terminal_evidence: bool,
    pub manual_attention: bool,
    pub unsupported_evidence: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRecoveryRetireTerminalRequest {
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecoveryRetireTerminalResponse {
    pub retired_count: u32,
    pub already_retired_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRecoveryStatusRequest {
    pub installed_selection_handle: String,
    pub installed_scan_handle: String,
    pub installed_resource_handle: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Clear,
    RecoveryAvailable,
    Committed,
    RolledBack,
    SafeRestart,
    RecoveryRequired,
    ManualAttention,
    Ambiguous,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecoveryStatusResponse {
    pub recovery_handle: String,
    pub resource_label: String,
    pub status: RecoveryStatus,
    pub candidate_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRecoveryListCandidatesRequest {
    pub recovery_handle: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCandidateState {
    Recoverable,
    Committed,
    RolledBack,
    SafeRestart,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionHint {
    Recover,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCandidateSummary {
    pub candidate_handle: String,
    pub resource_label: String,
    pub state: RecoveryCandidateState,
    pub recoverable: bool,
    pub action_hint: RecoveryActionHint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecoveryListCandidatesResponse {
    pub candidates: Vec<RecoveryCandidateSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRecoveryExecuteRequest {
    pub recovery_handle: String,
    pub candidate_handle: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    RecoveredCommitted,
    RecoveredRolledBack,
    SafeRestart,
    RecoveryStillRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecoveryExecuteResponse {
    pub outcome: RecoveryOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRecoveryReleaseRequest {
    pub recovery_handle: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRecoveryReleaseResponse {
    pub released: bool,
}

// --- The two-way update: a folder, a package, and a list to answer --------------------------

/// The most characters a resource-relative path may carry across the boundary.
///
/// Long enough for any real FiveM resource path, short enough that a hostile package cannot make
/// the frontend render an unbounded string.
const MAX_TWO_WAY_PATH_CHARS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoWayPreviewRequest {
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub installed_selection_handle: String,
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub package_selection_handle: String,
    /// The package the operator installed from, when they still have it.
    #[serde(default, deserialize_with = "deserialize_optional_opaque_handle")]
    pub baseline_selection_handle: Option<String>,
}

/// What the update would do to one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TwoWayFileDisposition {
    /// Identical on both sides.
    Unchanged,
    /// Replaced with the update's version without asking, because it could not have been edited.
    TakeFromUpdate,
    /// Editable and different. This is the only kind the operator has to look at.
    Review,
    /// Present only in the installation, so it stays.
    KeepLocalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoWayFile {
    /// Resource-relative, never a filesystem path.
    pub path: String,
    pub disposition: TwoWayFileDisposition,
    /// True when the incoming manifest declares this path escrow-ignored.
    pub editable: bool,
    /// True when the package the operator installed from holds exactly what they still have.
    ///
    /// This is the whole reason a file the operator could have edited is not being asked about,
    /// and it is worth saying which of the two reasons applied: encrypted and never theirs to
    /// edit, or theirs to edit and left alone. Always false when no baseline was given — there is
    /// then nothing to have compared against.
    pub untouched: bool,
    /// True when this file was combined by key rather than by line.
    ///
    /// It has no per-line decisions and yet leaving it alone is a merge, not a file kept whole.
    /// The list has to know that without the operator opening every row to find out.
    pub merged_by_key: bool,
    /// How many decisions this file holds, or zero when it holds none.
    ///
    /// The count comes from the split itself rather than from the rendered view, so a file whose
    /// lines were too many to draw can still be answered as a whole. A file the operator answers
    /// must carry exactly this many ticks, which is what keeps a decision made against one
    /// preview from being applied to a file that has since changed underneath it.
    pub block_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoWaySummary {
    pub unchanged: u32,
    pub take_from_update: u32,
    pub review: u32,
    pub keep_local_only: u32,
    pub total: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoWayPreviewResponse {
    pub handle: String,
    /// The resource both sides agreed on, by name.
    pub resource: String,
    /// The version each side's manifest declares, when it declares exactly one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incoming_version: Option<String>,
    pub summary: TwoWaySummary,
    pub files: Vec<TwoWayFile>,
    /// Files beyond the listing cap. The update still applies to them.
    pub omitted_file_count: u32,
    /// Editable files that differ but cannot be combined line by line.
    pub unmergeable: Vec<String>,
    /// The version this comparison reached for by itself, when nobody pointed at a package.
    ///
    /// It is what the last update to this installation applied, kept so the operator is not asked
    /// to have held on to a ZIP. The screen says so rather than leaving them wondering where the
    /// evidence came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remembered_baseline_version: Option<String>,
    /// True when the comparison used one it had kept rather than one it was given.
    pub used_remembered_baseline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoWayGetDiffRequest {
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub handle: String,
    #[serde(deserialize_with = "deserialize_two_way_path")]
    pub path: String,
}

/// What one row of a diff is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TwoWayRowKind {
    /// Both sides already have this line. It belongs to no decision.
    Context,
    /// The operator's line: one of the two outcomes of a decision.
    Yours,
    /// The update's line: the other outcome.
    Theirs,
    /// A run of lines both sides agree on, folded away. Carries how many.
    Gap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoWayDiffRow {
    pub kind: TwoWayRowKind,
    /// Which change block this row belongs to, or absent for context and gaps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<u32>,
    pub text: String,
    /// True when the line itself was cut at the display limit.
    pub truncated: bool,
    /// How many identical lines a gap stands in for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<u32>,
    /// Where this line sits in the file as installed, and as the update has it. A line only one
    /// side has carries only that side's number, which is how an operator finds it in the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incoming_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoWayGetDiffResponse {
    pub available: bool,
    pub rows: Vec<TwoWayDiffRow>,
    /// How many separate decisions this file offers.
    pub block_count: u32,
    /// Where each decision starts before the operator touches it.
    pub default_choices: Vec<bool>,
    /// True when the file had more rows than the display limit and the tail was dropped.
    pub truncated: bool,
    /// True when a view existed but was dropped to keep retained memory bounded.
    pub omitted: bool,
    /// True when the two were combined by key instead of by line: a document the developer
    /// reindented, whose values the operator changed, put back into the developer's own file.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub merged_by_key: bool,
    /// The keys whose values were kept from the operator's file, when it was combined by key.
    ///
    /// Two documents combined this way have no diff to show — every line of one differs from every
    /// line of the other, which is why keys were used — so this is what actually happened to the
    /// file, in the terms it happened in. Otherwise the operator approves a document nothing showed
    /// them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kept_keys: Vec<String>,
    /// How many there are in total, when more were kept than are listed.
    pub kept_key_count: u32,
    /// Why this file has no line view, when it has none: `not_text`, `too_far_apart`, `too_large`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whole_file_reason: Option<&'static str>,
    /// The operator's copy, base64, when this is a picture small enough to show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_image: Option<String>,
    /// The update's copy, on the same terms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incoming_image: Option<String>,
    /// The media type both pictures are, when there are pictures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_media_type: Option<&'static str>,
}

/// One file the operator decided by hand, block by block.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoWayFileChoiceDto {
    #[serde(deserialize_with = "deserialize_two_way_path")]
    pub path: String,
    /// One decision per change block, in order. `true` takes the update's lines there.
    #[serde(deserialize_with = "deserialize_two_way_choices")]
    pub take_from_update: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoWayApplyRequestDto {
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub handle: String,
    /// The preset for every reviewed file the operator did not decide by hand: true keeps their
    /// settings, false takes the update's version of everything.
    pub keep_settings: bool,
    /// The files they did decide.
    #[serde(deserialize_with = "deserialize_two_way_file_choices")]
    pub choices: Vec<TwoWayFileChoiceDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoWayApplyResponse {
    pub outcome: String,
    pub summary: TwoWaySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoWayReleaseRequest {
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub handle: String,
}

/// The updates this operator has run, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateHistoryListResponse {
    pub entries: Vec<UpdateHistoryEntryDto>,
}

/// One remembered update, plus whether it can still be put back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateHistoryEntryDto {
    #[serde(flatten)]
    pub entry: crate::history::UpdateHistoryEntry,
    /// True while the record of what this update replaced is still on disk.
    pub undoable: bool,
}

/// Put one remembered update back.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateHistoryUndoRequest {
    #[serde(deserialize_with = "deserialize_opaque_handle")]
    pub id: String,
}

/// What putting it back actually amounted to, counted rather than claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateHistoryUndoResponse {
    #[serde(flatten)]
    pub outcome: crate::undo::UndoOutcome,
}

/// One copy of an official package the store is holding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeldBaselineDto {
    pub resource: String,
    /// The version that package declared, when it declared one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub bytes: u64,
    /// `installation`, `undo`, or absent when nothing reaches for this any more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needed_for: Option<&'static str>,
}

/// What an update leaves behind: the packages kept, and the copies it staged to write from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageReportResponse {
    pub baselines: Vec<HeldBaselineDto>,
    pub held_bytes: u64,
    pub releasable_bytes: u64,
    /// Staged copies, counted and sized. Whether any can go is the workspace's to say, not this.
    pub staged_count: u32,
    pub staged_bytes: u64,
    /// What a release would free of them, measured rather than promised.
    pub staged_releasable_bytes: u64,
}

/// What one release actually let go of.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageReleaseResponse {
    pub released: u32,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoWayReleaseResponse {
    pub released: bool,
}

fn deserialize_two_way_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct TwoWayPathVisitor;

    impl Visitor<'_> for TwoWayPathVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded resource-relative path")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.is_empty() || value.chars().count() > MAX_TWO_WAY_PATH_CHARS {
                return Err(E::custom("invalid path"));
            }
            Ok(value.to_owned())
        }
    }

    deserializer.deserialize_str(TwoWayPathVisitor)
}

/// The most separately decidable changes one file may carry across the boundary.
const MAX_TWO_WAY_CHOICES: usize = 2048;
/// The most files one apply may carry decisions for.
const MAX_TWO_WAY_CHOICE_FILES: usize = 4096;

fn deserialize_two_way_choices<'de, D>(deserializer: D) -> Result<Vec<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let choices = Vec::<bool>::deserialize(deserializer)?;
    if choices.len() > MAX_TWO_WAY_CHOICES {
        return Err(D::Error::custom("too many decisions"));
    }
    Ok(choices)
}

fn deserialize_two_way_file_choices<'de, D>(
    deserializer: D,
) -> Result<Vec<TwoWayFileChoiceDto>, D::Error>
where
    D: Deserializer<'de>,
{
    let choices = Vec::<TwoWayFileChoiceDto>::deserialize(deserializer)?;
    if choices.len() > MAX_TWO_WAY_CHOICE_FILES {
        return Err(D::Error::custom("too many files"));
    }
    Ok(choices)
}

#[cfg(test)]
mod task29_fixture_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const PLAN_HANDLE: &str = "123e4567-e89b-42d3-a456-426614174030";
    const CHANGE_HANDLE: &str = "123e4567-e89b-42d3-a456-426614174031";

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../src/services/tauri/fixtures/task29")
    }

    fn summary(status: UpdatePlanStatus) -> UpdatePlanSummary {
        UpdatePlanSummary {
            plan_handle: PLAN_HANDLE.to_owned(),
            status,
            installed_resource_label: "installed-resource".to_owned(),
            incoming_resource_label: "package-resource".to_owned(),
            total_change_count: 100_000,
            no_change_count: 0,
            incoming_action_count: 1,
            preserved_local_count: 2,
            converged_count: 3,
            merge_candidate_count: 4,
            conflict_count: 5,
            policy_review_count: 6,
            decisions_required_count: 7,
            pending_decision_count: 8,
            manual_review_count: 9,
        }
    }

    fn change_summary(
        index: u32,
        disposition: PlanDisposition,
        review_requirement: PlanReviewRequirement,
        reviewed_action: PlanReviewedAction,
        local_delta: PlanDelta,
        incoming_delta: PlanDelta,
        policy_transition: PolicyTransitionKind,
    ) -> PlanChangeSummary {
        PlanChangeSummary {
            change_handle: format!("123e4567-e89b-42d3-a456-42661417{index:04}"),
            display_path: format!("client/example-{index}.lua"),
            disposition,
            review_requirement,
            reviewed_action,
            local_delta,
            incoming_delta,
            policy_transition,
            blocks_automatic_apply: index.is_multiple_of(2),
            recommended_action: None,
            allowed_decisions: Vec::new(),
            finding_count: if index == 0 { 0 } else { 1 },
        }
    }

    fn detail() -> PlanChangeDetail {
        PlanChangeDetail {
            change_handle: CHANGE_HANDLE.to_owned(),
            display_path: "client/detail.lua".to_owned(),
            disposition: PlanDisposition::PolicyConflictReview,
            review_requirement: PlanReviewRequirement::DecisionRequired,
            reviewed_action: PlanReviewedAction::ManualReview,
            local_delta: PlanDelta::Modified,
            incoming_delta: PlanDelta::Deleted,
            policy_transition: PolicyTransitionKind::Changed,
            blocks_automatic_apply: true,
            baseline_state: FilePresenceState::Absent,
            installed_state: FilePresenceState::Present,
            incoming_state: FilePresenceState::Present,
            recommended_action: Some(PlanReviewedAction::PreserveInstalledState),
            allowed_decisions: vec![
                AllowedPlanDecision {
                    choice: PlanDecisionChoice::AcceptRecommended,
                    requires_policy_acknowledgement: false,
                },
                AllowedPlanDecision {
                    choice: PlanDecisionChoice::UseIncomingState,
                    requires_policy_acknowledgement: true,
                },
                AllowedPlanDecision {
                    choice: PlanDecisionChoice::PreserveInstalledState,
                    requires_policy_acknowledgement: true,
                },
                AllowedPlanDecision {
                    choice: PlanDecisionChoice::ManualReview,
                    requires_policy_acknowledgement: false,
                },
            ],
            findings: vec![
                PlanFinding {
                    code: PlanFindingCode::DecisionRequired,
                    severity: FindingSeverity::Warning,
                    message: "A decision is required before this change can be applied.",
                },
                PlanFinding {
                    code: PlanFindingCode::ManualReviewRequired,
                    severity: FindingSeverity::Warning,
                    message: "Manual review is required before this change can be applied.",
                },
                PlanFinding {
                    code: PlanFindingCode::MergeAnalysisQueued,
                    severity: FindingSeverity::Info,
                    message: "Merge analysis is required before this change can be applied.",
                },
                PlanFinding {
                    code: PlanFindingCode::ConflictReviewRequired,
                    severity: FindingSeverity::Warning,
                    message: "A conflict requires review before this change can be applied.",
                },
                PlanFinding {
                    code: PlanFindingCode::PolicyReviewRequired,
                    severity: FindingSeverity::Warning,
                    message:
                        "A policy transition requires review before this change can be applied.",
                },
            ],
            omitted_finding_count: 2,
        }
    }

    fn fixture<T: Serialize>(value: &T) -> String {
        serde_json::to_string_pretty(value).unwrap() + "\n"
    }

    fn fixtures() -> Vec<(&'static str, String)> {
        vec![
            (
                "update_plan_create_response.json",
                fixture(&CreateUpdatePlanResponse {
                    plan_handle: PLAN_HANDLE.to_owned(),
                    summary: summary(UpdatePlanStatus::PendingDecisions),
                }),
            ),
            (
                "update_plan_get_summary_response.json",
                fixture(&UpdatePlanGetSummaryResponse {
                    summary: summary(UpdatePlanStatus::ManualMergeRequired),
                }),
            ),
            (
                "update_plan_list_changes_response.json",
                fixture(&UpdatePlanListChangesResponse {
                    total: 17,
                    offset: 0,
                    limit: 25,
                    changes: vec![
                        change_summary(
                            0,
                            PlanDisposition::NoChange,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::NotRequired,
                            PlanDelta::Unchanged,
                            PlanDelta::Unchanged,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            1,
                            PlanDisposition::UseIncoming,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::Pending,
                            PlanDelta::Added,
                            PlanDelta::Modified,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            2,
                            PlanDisposition::RemoveForIncoming,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::UseIncomingState,
                            PlanDelta::Deleted,
                            PlanDelta::Added,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            3,
                            PlanDisposition::PreserveInstalled,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::PreserveInstalledState,
                            PlanDelta::Modified,
                            PlanDelta::Deleted,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            4,
                            PlanDisposition::PreserveInstalledDeletion,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::QueueMergeAnalysis,
                            PlanDelta::Deleted,
                            PlanDelta::Unchanged,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            5,
                            PlanDisposition::AddIncoming,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::ManualReview,
                            PlanDelta::Unchanged,
                            PlanDelta::Added,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            6,
                            PlanDisposition::PreserveInstalledAddition,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::NotRequired,
                            PlanDelta::Added,
                            PlanDelta::Unchanged,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            7,
                            PlanDisposition::Converged,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::Pending,
                            PlanDelta::Modified,
                            PlanDelta::Modified,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            8,
                            PlanDisposition::ConvergedAddition,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::UseIncomingState,
                            PlanDelta::Added,
                            PlanDelta::Added,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            9,
                            PlanDisposition::ConvergedDeletion,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::PreserveInstalledState,
                            PlanDelta::Deleted,
                            PlanDelta::Deleted,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            10,
                            PlanDisposition::MergeCandidate,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::QueueMergeAnalysis,
                            PlanDelta::Modified,
                            PlanDelta::Modified,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            11,
                            PlanDisposition::ConflictReview,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::ManualReview,
                            PlanDelta::Modified,
                            PlanDelta::Modified,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            12,
                            PlanDisposition::DeleteVsModifyConflict,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::NotRequired,
                            PlanDelta::Deleted,
                            PlanDelta::Modified,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            13,
                            PlanDisposition::ModifyVsDeleteConflict,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::Pending,
                            PlanDelta::Modified,
                            PlanDelta::Deleted,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            14,
                            PlanDisposition::AddVsAddConflict,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::UseIncomingState,
                            PlanDelta::Added,
                            PlanDelta::Added,
                            PolicyTransitionKind::None,
                        ),
                        change_summary(
                            15,
                            PlanDisposition::PolicyReview,
                            PlanReviewRequirement::DecisionRequired,
                            PlanReviewedAction::PreserveInstalledState,
                            PlanDelta::Modified,
                            PlanDelta::Modified,
                            PolicyTransitionKind::Changed,
                        ),
                        change_summary(
                            16,
                            PlanDisposition::PolicyConflictReview,
                            PlanReviewRequirement::NoDecisionRequired,
                            PlanReviewedAction::ManualReview,
                            PlanDelta::Modified,
                            PlanDelta::Modified,
                            PolicyTransitionKind::None,
                        ),
                    ],
                }),
            ),
            (
                "update_plan_list_changes_empty_response.json",
                fixture(&UpdatePlanListChangesResponse {
                    total: 0,
                    offset: 50,
                    limit: 25,
                    changes: Vec::new(),
                }),
            ),
            (
                "update_plan_get_change_detail_response.json",
                fixture(&UpdatePlanGetChangeDetailResponse { change: detail() }),
            ),
            (
                "update_plan_get_change_detail_absent_optional_response.json",
                fixture(&UpdatePlanGetChangeDetailResponse {
                    change: PlanChangeDetail {
                        recommended_action: None,
                        findings: Vec::new(),
                        omitted_finding_count: 0,
                        ..detail()
                    },
                }),
            ),
            (
                "update_plan_release_response.json",
                fixture(&UpdatePlanReleaseResponse { released: true }),
            ),
            (
                "update_plan_apply_response.json",
                fixture(&UpdatePlanApplyResponse {
                    outcome: ApplyOutcome::Committed,
                }),
            ),
            (
                "update_plan_ready_summary_response.json",
                fixture(&UpdatePlanGetSummaryResponse {
                    summary: summary(UpdatePlanStatus::ReadyToApply),
                }),
            ),
        ]
    }

    #[test]
    fn task29_committed_fixtures_match_rust_serialization() {
        for (name, expected) in fixtures() {
            let path = fixture_dir().join(name);
            let actual = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "read fixture {}: {error}; regenerate Task 29 fixtures from dto::task29_fixture_tests constructors",
                    path.display()
                )
            });
            assert_eq!(
                actual,
                expected,
                "Task 29 DTO fixture drift for {name}; update committed fixtures from Rust serialization intentionally"
            );
        }
    }

    #[test]
    fn task32d_decision_request_deserialization_is_strict_and_bounded() {
        let plan_handle = "123e4567-e89b-42d3-a456-426614174030";
        let decision = serde_json::json!({
            "changeHandle": "123e4567-e89b-42d3-a456-426614174031",
            "choice": "manualReview",
            "policyAcknowledged": false
        });
        let exact = serde_json::json!({
            "planHandle": plan_handle,
            "decisions": vec![decision.clone(); MAX_PLAN_DECISION_SUBMISSIONS]
        });
        let decoded: UpdatePlanSubmitDecisionsRequest = serde_json::from_value(exact).unwrap();
        assert_eq!(decoded.decisions.len(), MAX_PLAN_DECISION_SUBMISSIONS);

        let oversized = serde_json::json!({
            "planHandle": plan_handle,
            "decisions": vec![decision.clone(); MAX_PLAN_DECISION_SUBMISSIONS + 1]
        });
        assert!(serde_json::from_value::<UpdatePlanSubmitDecisionsRequest>(oversized).is_err());
        for invalid in [
            serde_json::json!({ "planHandle": "too-long-or-short", "decisions": [decision.clone()] }),
            serde_json::json!({ "planHandle": plan_handle, "decisions": [{
                "changeHandle": "short",
                "choice": "manualReview",
                "policyAcknowledged": false
            }] }),
            serde_json::json!({ "planHandle": plan_handle, "decisions": [{
                "changeHandle": "123e4567-e89b-42d3-a456-426614174031",
                "choice": "unknown",
                "policyAcknowledged": false
            }] }),
            serde_json::json!({ "planHandle": plan_handle, "decisions": [decision], "path": "forbidden" }),
        ] {
            assert!(serde_json::from_value::<UpdatePlanSubmitDecisionsRequest>(invalid).is_err());
        }
    }
}
