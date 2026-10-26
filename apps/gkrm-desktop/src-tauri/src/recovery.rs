use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use gkrm_core::{
    inspect_trusted_published_update_v2, inspect_trusted_recovery_workspace_overview,
    open_existing_trusted_update_workspace, recover_trusted_published_update_v2,
    resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
    scan_trusted_installed_recovery_resources, GkrmError, SafeResourceKey,
    TrustedPackageFreeUpdateRecoveryOptions, TrustedPackageFreeUpdateRecoveryRequest,
    TrustedPublishedUpdateRecoveryState, TrustedRecoveryCandidateId, TrustedRecoveryResult,
    TrustedTerminalEvidenceRetirementOptions,
};
use uuid::Uuid;

use crate::dto::{
    RecoveryActionHint, RecoveryCandidateState, RecoveryCandidateSummary, RecoveryOutcome,
    RecoveryOverviewDisposition, RecoveryStatus, ScanSourceKind, SelectionKind,
    UpdateRecoveryExecuteRequest, UpdateRecoveryExecuteResponse,
    UpdateRecoveryListCandidatesRequest, UpdateRecoveryListCandidatesResponse,
    UpdateRecoveryOverviewResponse, UpdateRecoveryReleaseRequest, UpdateRecoveryReleaseResponse,
    UpdateRecoveryRetireTerminalRequest, UpdateRecoveryRetireTerminalResponse,
    UpdateRecoveryStatusRequest, UpdateRecoveryStatusResponse,
};
use crate::error::{DesktopFailure, DesktopResult};
use crate::operation::acquire_operation_permit;
use crate::scan::{ResourceHandle, ScanRecord};
use crate::selection::{lease_selections_for_resolution, revalidate_selection};
use crate::state::DesktopAppState;

pub const MAX_RECOVERY_SESSIONS: usize = 2;
pub const MAX_RECOVERY_CANDIDATES_PER_SESSION: usize = 8;
const MAX_LIFETIME_RECOVERY_HANDLES: usize = 1_024;
const MAX_HANDLE_GENERATION_ATTEMPTS: usize = 32;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoverySessionHandle(String);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryCandidateHandle(String);

impl std::fmt::Debug for RecoverySessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverySessionHandle")
    }
}

impl std::fmt::Debug for RecoveryCandidateHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCandidateHandle")
    }
}

impl RecoverySessionHandle {
    fn parse(value: &str) -> DesktopResult<Self> {
        parse_uuid_handle(value).map(Self)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl RecoveryCandidateHandle {
    fn parse(value: &str) -> DesktopResult<Self> {
        parse_uuid_handle(value).map(Self)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_uuid_handle(value: &str) -> DesktopResult<String> {
    if value.len() != 36 {
        return Err(DesktopFailure::InvalidRequest);
    }
    let uuid = Uuid::parse_str(value).map_err(|_| DesktopFailure::InvalidRequest)?;
    if uuid.get_version_num() != 4 || uuid.to_string() != value {
        return Err(DesktopFailure::InvalidRequest);
    }
    Ok(value.to_owned())
}

pub trait RecoveryHandleGenerator {
    fn session(&mut self) -> RecoverySessionHandle;
    fn candidate(&mut self) -> RecoveryCandidateHandle;
}

pub struct UuidRecoveryHandleGenerator;

impl RecoveryHandleGenerator for UuidRecoveryHandleGenerator {
    fn session(&mut self) -> RecoverySessionHandle {
        RecoverySessionHandle(Uuid::new_v4().to_string())
    }

    fn candidate(&mut self) -> RecoveryCandidateHandle {
        RecoveryCandidateHandle(Uuid::new_v4().to_string())
    }
}

#[derive(Clone)]
struct RecoveryIntent {
    installed_selection_handle: String,
    installed_selection_generation: u64,
    installed_scan_handle: String,
    installed_resource_handle: String,
    resource_key: SafeResourceKey,
    resource_label: String,
}

struct RecoveryCandidateRecord {
    handle: RecoveryCandidateHandle,
    authority: TrustedRecoveryCandidateId,
    summary: RecoveryCandidateSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryLifecycle {
    Ready,
    Executing,
    Terminal,
    Released,
    Invalidated,
}

pub struct RecoverySessionRecord {
    handle: RecoverySessionHandle,
    intent: RecoveryIntent,
    status: RecoveryStatus,
    candidates: Vec<RecoveryCandidateRecord>,
    lifecycle: Mutex<RecoveryLifecycle>,
}

impl std::fmt::Debug for RecoverySessionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverySessionRecord")
            .field("status", &self.status)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct RecoveryRegistry {
    records: Vec<Arc<RecoverySessionRecord>>,
    issued_handles: HashSet<String>,
}

impl RecoveryRegistry {
    pub fn has_capacity(&self) -> bool {
        self.records.len() < MAX_RECOVERY_SESSIONS
            && self.issued_handles.len() < MAX_LIFETIME_RECOVERY_HANDLES
    }

    fn insert(
        &mut self,
        built: BuiltRecoveryInspection,
        generator: &mut impl RecoveryHandleGenerator,
    ) -> DesktopResult<Arc<RecoverySessionRecord>> {
        let candidate_count = usize::from(built.candidate.is_some());
        if candidate_count > MAX_RECOVERY_CANDIDATES_PER_SESSION {
            return Err(DesktopFailure::RecoverySessionLimitReached);
        }
        let required_handles = 1usize
            .checked_add(candidate_count)
            .ok_or(DesktopFailure::RecoverySessionLimitReached)?;
        let issued_after = self
            .issued_handles
            .len()
            .checked_add(required_handles)
            .ok_or(DesktopFailure::RecoverySessionLimitReached)?;
        if self.records.len() >= MAX_RECOVERY_SESSIONS
            || issued_after > MAX_LIFETIME_RECOVERY_HANDLES
        {
            return Err(DesktopFailure::RecoverySessionLimitReached);
        }
        let mut reserved_handles = HashSet::with_capacity(required_handles);
        let handle = self.unique_session_handle(generator, &reserved_handles)?;
        reserved_handles.insert(handle.as_str().to_owned());
        let mut candidates = Vec::with_capacity(candidate_count);
        if let Some((authority, state)) = built.candidate {
            let candidate_handle = self.unique_candidate_handle(generator, &reserved_handles)?;
            reserved_handles.insert(candidate_handle.as_str().to_owned());
            let recoverable = matches!(
                state,
                RecoveryCandidateState::Recoverable | RecoveryCandidateState::RecoveryRequired
            );
            candidates.push(RecoveryCandidateRecord {
                handle: candidate_handle.clone(),
                authority,
                summary: RecoveryCandidateSummary {
                    candidate_handle: candidate_handle.as_str().to_owned(),
                    resource_label: built.intent.resource_label.clone(),
                    state,
                    recoverable,
                    action_hint: if recoverable {
                        RecoveryActionHint::Recover
                    } else {
                        RecoveryActionHint::None
                    },
                },
            });
        }
        let record = Arc::new(RecoverySessionRecord {
            handle: handle.clone(),
            intent: built.intent,
            status: built.status,
            candidates,
            lifecycle: Mutex::new(RecoveryLifecycle::Ready),
        });
        self.issued_handles.extend(reserved_handles);
        self.records.push(Arc::clone(&record));
        Ok(record)
    }

    pub fn get(&self, value: &str) -> DesktopResult<Arc<RecoverySessionRecord>> {
        let handle = RecoverySessionHandle::parse(value)
            .map_err(|_| DesktopFailure::RecoverySessionStale)?;
        self.records
            .iter()
            .find(|record| record.handle == handle)
            .cloned()
            .ok_or(DesktopFailure::RecoverySessionStale)
    }

    pub fn release(&mut self, value: &str) -> DesktopResult<()> {
        let handle = RecoverySessionHandle::parse(value)
            .map_err(|_| DesktopFailure::RecoverySessionStale)?;
        let position = self
            .records
            .iter()
            .position(|record| record.handle == handle)
            .ok_or(DesktopFailure::RecoverySessionStale)?;
        let record = Arc::clone(&self.records[position]);
        let mut lifecycle = record
            .lifecycle
            .lock()
            .map_err(|_| DesktopFailure::Internal)?;
        if *lifecycle == RecoveryLifecycle::Executing {
            return Err(DesktopFailure::RecoveryBusy);
        }
        *lifecycle = RecoveryLifecycle::Released;
        drop(lifecycle);
        self.records.remove(position);
        Ok(())
    }

    /// Refuse a durable transition while a recovery session is executing. This
    /// is checked before the durable write so the invalidation that follows it
    /// cannot fail an operation that already committed.
    pub fn ensure_no_executing_session(&self) -> DesktopResult<()> {
        for record in &self.records {
            let lifecycle = record
                .lifecycle
                .lock()
                .map_err(|_| DesktopFailure::Internal)?;
            if *lifecycle == RecoveryLifecycle::Executing {
                return Err(DesktopFailure::RecoveryBusy);
            }
        }
        Ok(())
    }

    /// Drop every process-local recovery session after a durable transition
    /// actually changed the workspace. Sessions and their candidate handles
    /// were minted from evidence that no longer describes it, so they must not
    /// stay acceptable.
    ///
    /// This is infallible by contract: it runs after the durable write, so it
    /// must never turn a committed transition into a reported failure. Callers
    /// hold the exclusive operation permit and check
    /// [`Self::ensure_no_executing_session`] before the write, so no session
    /// can be executing here, and a poisoned lifecycle mutex still leaves its
    /// record dropped from the registry.
    pub fn invalidate_all(&mut self) {
        for record in &self.records {
            *record
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = RecoveryLifecycle::Invalidated;
        }
        self.records.clear();
    }

    fn unique_session_handle(
        &self,
        generator: &mut impl RecoveryHandleGenerator,
        reserved: &HashSet<String>,
    ) -> DesktopResult<RecoverySessionHandle> {
        for _ in 0..MAX_HANDLE_GENERATION_ATTEMPTS {
            let handle = generator.session();
            if !self.issued_handles.contains(handle.as_str()) && !reserved.contains(handle.as_str())
            {
                return Ok(handle);
            }
        }
        Err(DesktopFailure::Internal)
    }

    fn unique_candidate_handle(
        &self,
        generator: &mut impl RecoveryHandleGenerator,
        reserved: &HashSet<String>,
    ) -> DesktopResult<RecoveryCandidateHandle> {
        for _ in 0..MAX_HANDLE_GENERATION_ATTEMPTS {
            let handle = generator.candidate();
            if !self.issued_handles.contains(handle.as_str()) && !reserved.contains(handle.as_str())
            {
                return Ok(handle);
            }
        }
        Err(DesktopFailure::Internal)
    }
}

struct BuiltRecoveryInspection {
    intent: RecoveryIntent,
    status: RecoveryStatus,
    candidate: Option<(TrustedRecoveryCandidateId, RecoveryCandidateState)>,
}

pub async fn recovery_overview(
    state: &DesktopAppState,
    app_data_root: PathBuf,
) -> DesktopResult<UpdateRecoveryOverviewResponse> {
    let _permit = acquire_operation_permit(&state.operation_occupied)
        .map_err(|_| DesktopFailure::RecoveryBusy)?;
    let overview = tauri::async_runtime::spawn_blocking(move || {
        let workspace = open_existing_trusted_update_workspace(&app_data_root)?;
        inspect_trusted_recovery_workspace_overview(
            workspace.as_ref(),
            TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
    })
    .await
    .map_err(|_| DesktopFailure::Internal)?
    .map_err(map_status_core_error)?;
    Ok(UpdateRecoveryOverviewResponse {
        disposition: if overview.is_clear() {
            RecoveryOverviewDisposition::Clear
        } else {
            RecoveryOverviewDisposition::AttentionRequired
        },
        active_recovery: overview.has_active_recovery(),
        terminal_evidence: overview.has_terminal_evidence(),
        manual_attention: overview.has_manual_attention(),
        unsupported_evidence: overview.has_unsupported_evidence(),
    })
}

pub async fn recovery_retire_terminal(
    state: &DesktopAppState,
    request: UpdateRecoveryRetireTerminalRequest,
    app_data_root: PathBuf,
) -> DesktopResult<UpdateRecoveryRetireTerminalResponse> {
    if !request.acknowledged {
        return Err(DesktopFailure::InvalidRequest);
    }
    let _permit = acquire_operation_permit(&state.operation_occupied)
        .map_err(|_| DesktopFailure::RecoveryBusy)?;
    state
        .recoveries
        .lock()
        .map_err(|_| DesktopFailure::Internal)?
        .ensure_no_executing_session()?;
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let Some(workspace) = open_existing_trusted_update_workspace(&app_data_root)? else {
            return Ok(None);
        };
        retire_trusted_terminal_update_evidence(
            &workspace,
            TrustedTerminalEvidenceRetirementOptions {
                acknowledged: true,
                ..TrustedTerminalEvidenceRetirementOptions::default()
            },
        )
        .map(Some)
    })
    .await
    .map_err(|_| DesktopFailure::Internal)?
    .map_err(map_retirement_core_error)?;
    let (retired_count, already_retired_count) = match outcome {
        Some(outcome) => (
            u32::try_from(outcome.retired_count()).map_err(|_| DesktopFailure::Internal)?,
            u32::try_from(outcome.already_retired_count()).map_err(|_| DesktopFailure::Internal)?,
        ),
        None => (0, 0),
    };
    // Only a transition that published new retirement evidence invalidates the
    // sessions built from the previous evidence. A pass that found nothing to
    // retire changed nothing and must not discard live recovery authority.
    if retired_count > 0 {
        state
            .recoveries
            .lock()
            .map_err(|_| DesktopFailure::Internal)?
            .invalidate_all();
    }
    Ok(UpdateRecoveryRetireTerminalResponse {
        retired_count,
        already_retired_count,
    })
}

pub async fn recovery_status(
    state: &DesktopAppState,
    request: UpdateRecoveryStatusRequest,
    app_data_root: PathBuf,
) -> DesktopResult<UpdateRecoveryStatusResponse> {
    let _permit = acquire_operation_permit(&state.operation_occupied)
        .map_err(|_| DesktopFailure::RecoveryBusy)?;
    if !state
        .recoveries
        .lock()
        .map_err(|_| DesktopFailure::Internal)?
        .has_capacity()
    {
        return Err(DesktopFailure::RecoverySessionLimitReached);
    }
    let scan = scan_for_installed_source(
        state,
        &request.installed_scan_handle,
        &request.installed_selection_handle,
    )?;
    let resource = resource_for(&scan, &request.installed_resource_handle)?;
    let resource_key = resource
        .resource_key
        .clone()
        .ok_or(DesktopFailure::ResourceSelectionStale)?;
    let intent = RecoveryIntent {
        installed_selection_handle: request.installed_selection_handle,
        installed_selection_generation: scan.source_selection.generation,
        installed_scan_handle: request.installed_scan_handle,
        installed_resource_handle: request.installed_resource_handle,
        resource_key: resource_key.clone(),
        resource_label: resource.summary.display_name.clone(),
    };
    let (_leases, mut inputs) =
        lease_selections_for_resolution(state, &[intent.installed_selection_handle.as_str()])?;
    let input = inputs.pop().ok_or(DesktopFailure::SelectionNotFound)?;
    if input.kind() != SelectionKind::InstalledRoot
        || input.generation() != intent.installed_selection_generation
    {
        return Err(DesktopFailure::ResourceSelectionStale);
    }
    let installed = revalidate_selection(input)?;
    let built = tauri::async_runtime::spawn_blocking(move || {
        inspect_from_path(app_data_root, installed.path, intent, resource_key)
    })
    .await
    .map_err(|_| DesktopFailure::Internal)??;
    let mut registry = state
        .recoveries
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    let mut generator = UuidRecoveryHandleGenerator;
    let record = registry.insert(built, &mut generator)?;
    Ok(UpdateRecoveryStatusResponse {
        recovery_handle: record.handle.as_str().to_owned(),
        resource_label: record.intent.resource_label.clone(),
        status: record.status,
        candidate_count: u32::try_from(record.candidates.len())
            .map_err(|_| DesktopFailure::Internal)?,
    })
}

fn inspect_from_path(
    app_data_root: PathBuf,
    installed_root: PathBuf,
    intent: RecoveryIntent,
    resource_key: SafeResourceKey,
) -> DesktopResult<BuiltRecoveryInspection> {
    let Some(workspace) =
        open_existing_trusted_update_workspace(&app_data_root).map_err(map_status_core_error)?
    else {
        return Ok(BuiltRecoveryInspection {
            intent,
            status: RecoveryStatus::Clear,
            candidate: None,
        });
    };
    let installed_scan =
        scan_trusted_installed_recovery_resources(&installed_root, Default::default())
            .map_err(map_status_core_error)?;
    let selection = installed_scan
        .select(&resource_key)
        .map_err(map_status_core_error)?;
    // Pointing at an installation is also the moment this can tell whether an update it ran is
    // missing from its own history. The record is written after the commit, so losing it costs
    // the operator the ability to put that update back; the workspace still knows about it.
    // A failure to look, or to write back what was found, costs a row on a screen and nothing
    // else, so it never fails the status this was asked for.
    if let Ok(discovered) = gkrm_core::inspect_trusted_two_way_updates(&workspace, &selection) {
        crate::undo::restore_missing_locators(&app_data_root, &installed_root, &discovered);
    }
    let inspection = inspect_trusted_published_update_v2(
        &workspace,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .map_err(map_status_core_error)?;
    let (status, candidate_state) = adapt_inspection_state(inspection.state());
    let candidate = match (inspection.candidate_id(), candidate_state) {
        (Some(candidate), Some(state)) => Some((*candidate, state)),
        (None, None) => None,
        _ => return Err(DesktopFailure::RecoveryEvidenceInvalid),
    };
    Ok(BuiltRecoveryInspection {
        intent,
        status,
        candidate,
    })
}

pub fn recovery_list_candidates(
    state: &DesktopAppState,
    request: UpdateRecoveryListCandidatesRequest,
) -> DesktopResult<UpdateRecoveryListCandidatesResponse> {
    let record = state
        .recoveries
        .lock()
        .map_err(|_| DesktopFailure::Internal)?
        .get(&request.recovery_handle)?;
    let lifecycle = record
        .lifecycle
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    if matches!(
        *lifecycle,
        RecoveryLifecycle::Released | RecoveryLifecycle::Invalidated
    ) {
        return Err(DesktopFailure::RecoverySessionStale);
    }
    Ok(UpdateRecoveryListCandidatesResponse {
        candidates: record
            .candidates
            .iter()
            .map(|candidate| candidate.summary.clone())
            .collect(),
    })
}

pub async fn recovery_execute(
    state: &DesktopAppState,
    request: UpdateRecoveryExecuteRequest,
    app_data_root: PathBuf,
) -> DesktopResult<UpdateRecoveryExecuteResponse> {
    let _permit = acquire_operation_permit(&state.operation_occupied)
        .map_err(|_| DesktopFailure::RecoveryBusy)?;
    let record = state
        .recoveries
        .lock()
        .map_err(|_| DesktopFailure::Internal)?
        .get(&request.recovery_handle)?;
    let candidate_handle = RecoveryCandidateHandle::parse(&request.candidate_handle)
        .map_err(|_| DesktopFailure::RecoveryCandidateStale)?;
    let candidate = record
        .candidates
        .iter()
        .find(|candidate| candidate.handle == candidate_handle)
        .ok_or(DesktopFailure::RecoveryCandidateStale)?;
    let authority = candidate.authority;
    {
        let mut lifecycle = record
            .lifecycle
            .lock()
            .map_err(|_| DesktopFailure::Internal)?;
        match *lifecycle {
            RecoveryLifecycle::Ready => *lifecycle = RecoveryLifecycle::Executing,
            RecoveryLifecycle::Executing => return Err(DesktopFailure::RecoveryBusy),
            RecoveryLifecycle::Terminal
            | RecoveryLifecycle::Released
            | RecoveryLifecycle::Invalidated => return Err(DesktopFailure::RecoverySessionStale),
        }
    }
    let resolved = resolve_execution_installed(state, &record.intent);
    let (_leases, installed_root) = match resolved {
        Ok(value) => value,
        Err(error) => {
            set_lifecycle(&record, RecoveryLifecycle::Invalidated)?;
            return Err(error);
        }
    };
    let resource_key = record.intent.resource_key.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        execute_from_path(app_data_root, installed_root, resource_key, authority)
    })
    .await;
    match result {
        Ok(Ok(response)) => {
            set_lifecycle(&record, RecoveryLifecycle::Terminal)?;
            Ok(response)
        }
        Ok(Err(DesktopFailure::RecoveryBusy)) => {
            set_lifecycle(&record, RecoveryLifecycle::Ready)?;
            Err(DesktopFailure::RecoveryBusy)
        }
        Ok(Err(error)) => {
            set_lifecycle(&record, RecoveryLifecycle::Invalidated)?;
            Err(error)
        }
        Err(_) => {
            set_lifecycle(&record, RecoveryLifecycle::Invalidated)?;
            Err(DesktopFailure::Internal)
        }
    }
}

fn execute_from_path(
    app_data_root: PathBuf,
    installed_root: PathBuf,
    resource_key: SafeResourceKey,
    expected_candidate: TrustedRecoveryCandidateId,
) -> DesktopResult<UpdateRecoveryExecuteResponse> {
    let workspace =
        resolve_trusted_update_workspace(&app_data_root).map_err(map_execute_core_error)?;
    let installed_scan =
        scan_trusted_installed_recovery_resources(&installed_root, Default::default())
            .map_err(map_execute_core_error)?;
    let selection = installed_scan
        .select(&resource_key)
        .map_err(|_| DesktopFailure::RecoveryCandidateStale)?;
    let inspection = inspect_trusted_published_update_v2(
        &workspace,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .map_err(map_execute_core_error)?;
    if inspection.candidate_id() != Some(&expected_candidate) {
        return Err(match inspection.state() {
            TrustedPublishedUpdateRecoveryState::Ambiguous => DesktopFailure::RecoveryAmbiguous,
            TrustedPublishedUpdateRecoveryState::Unsupported => DesktopFailure::RecoveryUnsupported,
            TrustedPublishedUpdateRecoveryState::ManualAttention => {
                DesktopFailure::RecoveryManualAttention
            }
            _ => DesktopFailure::RecoveryCandidateStale,
        });
    }
    let request = TrustedPackageFreeUpdateRecoveryRequest::try_new(
        &workspace,
        &expected_candidate,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .map_err(map_execute_core_error)?;
    let result = recover_trusted_published_update_v2(request).map_err(map_execute_core_error)?;
    let outcome = match result {
        TrustedRecoveryResult::RecoveredCommitted(_) => RecoveryOutcome::RecoveredCommitted,
        TrustedRecoveryResult::RecoveredRolledBack(_) => RecoveryOutcome::RecoveredRolledBack,
        TrustedRecoveryResult::SafeRestart(_) => RecoveryOutcome::SafeRestart,
        TrustedRecoveryResult::RecoveryStillRequired(_) => RecoveryOutcome::RecoveryStillRequired,
    };
    Ok(UpdateRecoveryExecuteResponse { outcome })
}

pub fn recovery_release(
    state: &DesktopAppState,
    request: UpdateRecoveryReleaseRequest,
) -> DesktopResult<UpdateRecoveryReleaseResponse> {
    state
        .recoveries
        .lock()
        .map_err(|_| DesktopFailure::Internal)?
        .release(&request.recovery_handle)?;
    Ok(UpdateRecoveryReleaseResponse { released: true })
}

fn resolve_execution_installed<'a>(
    state: &'a DesktopAppState,
    intent: &RecoveryIntent,
) -> DesktopResult<(crate::selection::SelectionLeaseGuard<'a>, PathBuf)> {
    let scan = scan_for_installed_source(
        state,
        &intent.installed_scan_handle,
        &intent.installed_selection_handle,
    )
    .map_err(|_| DesktopFailure::RecoveryCandidateStale)?;
    let resource = resource_for(&scan, &intent.installed_resource_handle)
        .map_err(|_| DesktopFailure::RecoveryCandidateStale)?;
    if resource.resource_key.as_ref() != Some(&intent.resource_key) {
        return Err(DesktopFailure::RecoveryCandidateStale);
    }
    let (leases, mut inputs) =
        lease_selections_for_resolution(state, &[intent.installed_selection_handle.as_str()])
            .map_err(|_| DesktopFailure::RecoveryCandidateStale)?;
    let input = inputs.pop().ok_or(DesktopFailure::RecoveryCandidateStale)?;
    if input.kind() != SelectionKind::InstalledRoot
        || input.generation() != intent.installed_selection_generation
    {
        return Err(DesktopFailure::RecoveryCandidateStale);
    }
    let installed =
        revalidate_selection(input).map_err(|_| DesktopFailure::RecoveryCandidateStale)?;
    Ok((leases, installed.path))
}

fn scan_for_installed_source(
    state: &DesktopAppState,
    scan_handle: &str,
    selection_handle: &str,
) -> DesktopResult<Arc<ScanRecord>> {
    let scan = state
        .scans
        .lock()
        .map_err(|_| DesktopFailure::Internal)?
        .get(scan_handle)?;
    if scan.source_kind != ScanSourceKind::InstalledRoot
        || scan.source_selection.kind != ScanSourceKind::InstalledRoot
        || scan.source_selection.selection_handle != selection_handle
    {
        return Err(DesktopFailure::InvalidScanSource);
    }
    Ok(scan)
}

fn resource_for<'a>(
    scan: &'a ScanRecord,
    resource_handle: &str,
) -> DesktopResult<&'a crate::scan::ResourceRecord> {
    let handle =
        ResourceHandle::parse(resource_handle).map_err(|_| DesktopFailure::ResourceNotFound)?;
    scan.resources
        .iter()
        .find(|resource| resource.handle == handle)
        .ok_or(DesktopFailure::ResourceNotFound)
}

fn adapt_inspection_state(
    state: TrustedPublishedUpdateRecoveryState,
) -> (RecoveryStatus, Option<RecoveryCandidateState>) {
    match state {
        TrustedPublishedUpdateRecoveryState::Clear => (RecoveryStatus::Clear, None),
        TrustedPublishedUpdateRecoveryState::Recoverable => (
            RecoveryStatus::RecoveryAvailable,
            Some(RecoveryCandidateState::Recoverable),
        ),
        TrustedPublishedUpdateRecoveryState::Committed => (
            RecoveryStatus::Committed,
            Some(RecoveryCandidateState::Committed),
        ),
        TrustedPublishedUpdateRecoveryState::RolledBack => (
            RecoveryStatus::RolledBack,
            Some(RecoveryCandidateState::RolledBack),
        ),
        TrustedPublishedUpdateRecoveryState::SafeRestart => (
            RecoveryStatus::SafeRestart,
            Some(RecoveryCandidateState::SafeRestart),
        ),
        TrustedPublishedUpdateRecoveryState::RecoveryRequired => (
            RecoveryStatus::RecoveryRequired,
            Some(RecoveryCandidateState::RecoveryRequired),
        ),
        TrustedPublishedUpdateRecoveryState::ManualAttention => {
            (RecoveryStatus::ManualAttention, None)
        }
        TrustedPublishedUpdateRecoveryState::Unsupported => (RecoveryStatus::Unsupported, None),
        TrustedPublishedUpdateRecoveryState::Ambiguous => (RecoveryStatus::Ambiguous, None),
    }
}

fn set_lifecycle(
    record: &RecoverySessionRecord,
    lifecycle: RecoveryLifecycle,
) -> DesktopResult<()> {
    *record
        .lifecycle
        .lock()
        .map_err(|_| DesktopFailure::Internal)? = lifecycle;
    Ok(())
}

fn map_status_core_error(error: GkrmError) -> DesktopFailure {
    match error {
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous => {
            DesktopFailure::RecoveryAmbiguous
        }
        GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported
        | GkrmError::TrustedRecoveryAuthorityDerivationUnsupported => {
            DesktopFailure::RecoveryUnsupported
        }
        GkrmError::TrustedUpdateWorkspaceLegacyUnsupported => {
            DesktopFailure::WorkspaceLegacyUnsupported
        }
        GkrmError::TrustedUpdateWorkspaceCapacityReached => {
            DesktopFailure::WorkspaceCapacityReached
        }
        _ => DesktopFailure::RecoveryEvidenceInvalid,
    }
}

fn map_retirement_core_error(error: GkrmError) -> DesktopFailure {
    match error {
        GkrmError::TrustedUpdateWorkspaceLegacyUnsupported => {
            DesktopFailure::WorkspaceLegacyUnsupported
        }
        GkrmError::TrustedTerminalEvidenceRetirementAcknowledgementRequired => {
            DesktopFailure::InvalidRequest
        }
        GkrmError::TrustedTerminalEvidenceRetirementBlocked => {
            DesktopFailure::RecoveryManualAttention
        }
        GkrmError::TrustedTerminalEvidenceRetirementVersionUnsupported => {
            DesktopFailure::RecoveryUnsupported
        }
        GkrmError::TrustedTerminalEvidenceRetirementInvalid
        | GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded { .. } => {
            DesktopFailure::RecoveryEvidenceInvalid
        }
        GkrmError::TrustedUpdateWorkspaceCapacityReached => {
            DesktopFailure::WorkspaceCapacityReached
        }
        _ => DesktopFailure::RecoveryEvidenceInvalid,
    }
}

fn map_execute_core_error(error: GkrmError) -> DesktopFailure {
    match error {
        GkrmError::TrustedTransactionalApplyExecutionLockContention => DesktopFailure::RecoveryBusy,
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound
        | GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch => {
            DesktopFailure::RecoveryCandidateStale
        }
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous => {
            DesktopFailure::RecoveryAmbiguous
        }
        GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported
        | GkrmError::TrustedRecoveryAuthorityDerivationUnsupported => {
            DesktopFailure::RecoveryUnsupported
        }
        _ => DesktopFailure::RecoveryEvidenceInvalid,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::Ordering;

    use tempfile::tempdir;

    use super::*;

    fn filesystem_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(root: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            let mut entries = fs::read_dir(current)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let metadata = fs::symlink_metadata(&path).unwrap();
                if metadata.file_type().is_dir() {
                    output.insert(relative, None);
                    visit(root, &path, output);
                } else {
                    output.insert(relative, Some(fs::read(&path).unwrap()));
                }
            }
        }

        let mut output = BTreeMap::new();
        if root.is_dir() {
            visit(root, root, &mut output);
        }
        output
    }

    struct CollisionGenerator {
        value: &'static str,
    }

    impl RecoveryHandleGenerator for CollisionGenerator {
        fn session(&mut self) -> RecoverySessionHandle {
            RecoverySessionHandle(self.value.to_owned())
        }

        fn candidate(&mut self) -> RecoveryCandidateHandle {
            RecoveryCandidateHandle(self.value.to_owned())
        }
    }

    #[test]
    fn opaque_handles_require_canonical_uuid_v4() {
        assert!(RecoverySessionHandle::parse("not-a-handle").is_err());
        assert!(RecoveryCandidateHandle::parse("00000000-0000-1000-8000-000000000000").is_err());
        let value = Uuid::new_v4().to_string();
        assert_eq!(
            RecoverySessionHandle::parse(&value).unwrap().as_str(),
            value
        );
    }

    #[test]
    fn handle_collision_exhaustion_fails_closed() {
        let value = "123e4567-e89b-42d3-a456-426614174000";
        let mut registry = RecoveryRegistry::default();
        registry.issued_handles.insert(value.to_owned());
        let mut generator = CollisionGenerator { value };
        assert!(matches!(
            registry.unique_session_handle(&mut generator, &HashSet::new()),
            Err(DesktopFailure::Internal)
        ));
    }

    struct StatusFixture {
        _temp: tempfile::TempDir,
        state: DesktopAppState,
        app_data_root: PathBuf,
        request: UpdateRecoveryStatusRequest,
    }

    fn status_fixture() -> StatusFixture {
        let temp = tempdir().unwrap();
        let app_data_root = temp.path().join("app-data");
        let installed_root = temp.path().join("installed");
        let resource_root = installed_root.join("gksphone");
        fs::create_dir_all(&resource_root).unwrap();
        fs::write(
            resource_root.join("fxmanifest.lua"),
            b"fx_version 'cerulean'\ngame 'gta5'\n",
        )
        .unwrap();
        let state = DesktopAppState::default();
        let mut selection_generator = crate::selection::UuidHandleGenerator;
        let selected = state
            .selections
            .lock()
            .unwrap()
            .insert(
                SelectionKind::InstalledRoot,
                installed_root.clone(),
                &mut selection_generator,
            )
            .unwrap();
        let input =
            crate::selection::clone_selection_for_resolution(&state, &selected.handle).unwrap();
        let selection_reference = crate::scan::SelectionReference {
            selection_handle: selected.handle.clone(),
            generation: input.generation(),
            kind: ScanSourceKind::InstalledRoot,
        };
        let resolved = revalidate_selection(input).unwrap();
        let mut scan_generator = crate::scan::UuidScanHandleGenerator;
        let built = crate::scan::build_installed_scan_record(
            selected.display_label,
            selection_reference,
            resolved.path,
            &mut scan_generator,
        )
        .unwrap();
        let scan = state
            .scans
            .lock()
            .unwrap()
            .insert(built, &mut scan_generator)
            .unwrap();
        let request = UpdateRecoveryStatusRequest {
            installed_selection_handle: selected.handle,
            installed_scan_handle: scan.handle.as_str().to_owned(),
            installed_resource_handle: scan.resources[0].handle.as_str().to_owned(),
        };
        StatusFixture {
            _temp: temp,
            state,
            app_data_root,
            request,
        }
    }

    #[test]
    fn overview_needs_no_handles_keeps_absent_workspace_absent_and_fabricates_no_session() {
        let temp = tempdir().unwrap();
        let app_data_root = temp.path().join("absent-app-data");
        let state = DesktopAppState::default();
        let response =
            tauri::async_runtime::block_on(recovery_overview(&state, app_data_root.clone()))
                .unwrap();
        assert_eq!(response.disposition, RecoveryOverviewDisposition::Clear);
        assert!(!response.active_recovery);
        assert!(!response.terminal_evidence);
        assert!(!response.manual_attention);
        assert!(!response.unsupported_evidence);
        assert!(!app_data_root.exists());
        assert!(state.selections.lock().unwrap().list(None).is_empty());
        assert!(state.recoveries.lock().unwrap().records.is_empty());
    }

    #[test]
    fn terminal_retirement_is_a_noop_for_absent_workspace_and_fabricates_no_session() {
        let temp = tempdir().unwrap();
        let app_data_root = temp.path().join("absent-app-data");
        let state = DesktopAppState::default();
        let response = tauri::async_runtime::block_on(recovery_retire_terminal(
            &state,
            UpdateRecoveryRetireTerminalRequest { acknowledged: true },
            app_data_root.clone(),
        ))
        .unwrap();
        assert_eq!(response.retired_count, 0);
        assert_eq!(response.already_retired_count, 0);
        assert!(!app_data_root.exists());
        assert!(state.recoveries.lock().unwrap().records.is_empty());
    }

    #[test]
    fn overview_is_fail_closed_while_operation_is_busy() {
        let temp = tempdir().unwrap();
        let state = DesktopAppState::default();
        state.operation_occupied.store(true, Ordering::Release);
        let result =
            tauri::async_runtime::block_on(recovery_overview(&state, temp.path().join("app-data")));
        assert!(matches!(result, Err(DesktopFailure::RecoveryBusy)));
        state.operation_occupied.store(false, Ordering::Release);
    }

    #[test]
    fn overview_corrupt_workspace_returns_sanitized_error_without_repair() {
        let temp = tempdir().unwrap();
        let app_data_root = temp.path().join("app-data");
        fs::create_dir(&app_data_root).unwrap();
        fs::write(app_data_root.join("private-transaction-id"), b"unchanged").unwrap();
        let before = filesystem_snapshot(&app_data_root);
        let error = tauri::async_runtime::block_on(recovery_overview(
            &DesktopAppState::default(),
            app_data_root.clone(),
        ))
        .unwrap_err();
        let json = serde_json::to_string(&error.dto()).unwrap();
        assert!(!json.contains("private-transaction-id"));
        assert!(!json.contains(app_data_root.to_string_lossy().as_ref()));
        assert_eq!(filesystem_snapshot(&app_data_root), before);
    }

    #[test]
    fn status_list_and_release_clear_session_without_durable_deletion() {
        let fixture = status_fixture();
        assert!(!fixture.app_data_root.exists());
        let status = tauri::async_runtime::block_on(recovery_status(
            &fixture.state,
            fixture.request.clone(),
            fixture.app_data_root.clone(),
        ))
        .unwrap();
        assert_eq!(status.status, RecoveryStatus::Clear);
        assert_eq!(status.candidate_count, 0);
        assert!(!fixture.app_data_root.exists());
        let listed = recovery_list_candidates(
            &fixture.state,
            UpdateRecoveryListCandidatesRequest {
                recovery_handle: status.recovery_handle.clone(),
            },
        )
        .unwrap();
        assert!(listed.candidates.is_empty());
        recovery_release(
            &fixture.state,
            UpdateRecoveryReleaseRequest {
                recovery_handle: status.recovery_handle.clone(),
            },
        )
        .unwrap();
        assert!(!fixture.app_data_root.exists());
        assert!(matches!(
            recovery_list_candidates(
                &fixture.state,
                UpdateRecoveryListCandidatesRequest {
                    recovery_handle: status.recovery_handle,
                },
            ),
            Err(DesktopFailure::RecoverySessionStale)
        ));
    }

    #[test]
    fn existing_app_data_parent_without_workspace_is_unchanged_by_status() {
        let fixture = status_fixture();
        let parent = fixture.app_data_root.parent().unwrap();
        fs::write(parent.join("unrelated.bin"), b"unchanged").unwrap();
        let before = filesystem_snapshot(parent);
        let status = tauri::async_runtime::block_on(recovery_status(
            &fixture.state,
            fixture.request,
            fixture.app_data_root.clone(),
        ))
        .unwrap();
        assert_eq!(status.status, RecoveryStatus::Clear);
        assert!(!fixture.app_data_root.exists());
        assert_eq!(filesystem_snapshot(parent), before);
    }

    #[test]
    fn existing_empty_workspace_status_and_list_have_zero_filesystem_delta() {
        let fixture = status_fixture();
        resolve_trusted_update_workspace(&fixture.app_data_root).unwrap();
        let before = filesystem_snapshot(&fixture.app_data_root);
        let status = tauri::async_runtime::block_on(recovery_status(
            &fixture.state,
            fixture.request,
            fixture.app_data_root.clone(),
        ))
        .unwrap();
        assert_eq!(status.status, RecoveryStatus::Clear);
        assert!(recovery_list_candidates(
            &fixture.state,
            UpdateRecoveryListCandidatesRequest {
                recovery_handle: status.recovery_handle,
            },
        )
        .unwrap()
        .candidates
        .is_empty());
        assert_eq!(filesystem_snapshot(&fixture.app_data_root), before);
    }

    #[test]
    fn malformed_existing_workspace_is_not_repaired_by_status() {
        let fixture = status_fixture();
        fs::create_dir(&fixture.app_data_root).unwrap();
        fs::write(fixture.app_data_root.join("sentinel.bin"), b"unchanged").unwrap();
        let before = filesystem_snapshot(&fixture.app_data_root);
        assert!(matches!(
            tauri::async_runtime::block_on(recovery_status(
                &fixture.state,
                fixture.request,
                fixture.app_data_root.clone(),
            )),
            Err(DesktopFailure::RecoveryEvidenceInvalid)
        ));
        assert_eq!(filesystem_snapshot(&fixture.app_data_root), before);
    }

    fn test_intent() -> RecoveryIntent {
        RecoveryIntent {
            installed_selection_handle: "selection".to_owned(),
            installed_selection_generation: 1,
            installed_scan_handle: "scan".to_owned(),
            installed_resource_handle: "resource".to_owned(),
            resource_key: SafeResourceKey::parse("gksphone").unwrap(),
            resource_label: "phone".to_owned(),
        }
    }

    fn built_inspection(with_candidate: bool) -> BuiltRecoveryInspection {
        BuiltRecoveryInspection {
            intent: test_intent(),
            status: if with_candidate {
                RecoveryStatus::RecoveryAvailable
            } else {
                RecoveryStatus::Clear
            },
            candidate: with_candidate.then(|| {
                (
                    TrustedRecoveryCandidateId::from_selector_hex(&"11".repeat(32)).unwrap(),
                    RecoveryCandidateState::Recoverable,
                )
            }),
        }
    }

    #[test]
    fn invalidating_sessions_leaves_no_resolvable_handle() {
        let mut registry = RecoveryRegistry::default();
        let mut generator = UuidRecoveryHandleGenerator;
        let record = registry
            .insert(built_inspection(true), &mut generator)
            .unwrap();
        let session_handle = record.handle.as_str().to_owned();

        registry.invalidate_all();

        assert_eq!(
            *record.lifecycle.lock().unwrap(),
            RecoveryLifecycle::Invalidated
        );
        assert!(registry.records.is_empty());
        assert!(matches!(
            registry.get(&session_handle),
            Err(DesktopFailure::RecoverySessionStale)
        ));
    }

    #[test]
    fn terminal_retirement_without_new_evidence_keeps_process_local_sessions() {
        let temp = tempdir().unwrap();
        let app_data_root = temp.path().join("absent-app-data");
        let state = DesktopAppState::default();
        let mut generator = UuidRecoveryHandleGenerator;
        let record = state
            .recoveries
            .lock()
            .unwrap()
            .insert(built_inspection(true), &mut generator)
            .unwrap();
        let session_handle = record.handle.as_str().to_owned();

        let response = tauri::async_runtime::block_on(recovery_retire_terminal(
            &state,
            UpdateRecoveryRetireTerminalRequest { acknowledged: true },
            app_data_root,
        ))
        .unwrap();

        assert_eq!(response.retired_count, 0);
        assert_eq!(*record.lifecycle.lock().unwrap(), RecoveryLifecycle::Ready);
        assert!(state
            .recoveries
            .lock()
            .unwrap()
            .get(&session_handle)
            .is_ok());
    }

    #[test]
    fn shared_lifetime_accounting_counts_sessions_and_candidates_together() {
        let mut registry = RecoveryRegistry::default();
        let mut generator = UuidRecoveryHandleGenerator;
        let record = registry
            .insert(built_inspection(true), &mut generator)
            .unwrap();
        assert_eq!(registry.issued_handles.len(), 2);
        registry.release(record.handle.as_str()).unwrap();
        assert_eq!(registry.issued_handles.len(), 2);
    }

    #[test]
    fn shared_lifetime_ceiling_and_release_do_not_refund_capacity() {
        let mut registry = RecoveryRegistry::default();
        let mut generator = UuidRecoveryHandleGenerator;
        for _ in 0..(MAX_LIFETIME_RECOVERY_HANDLES / 2) {
            let record = registry
                .insert(built_inspection(true), &mut generator)
                .unwrap();
            registry.release(record.handle.as_str()).unwrap();
        }
        assert_eq!(registry.issued_handles.len(), MAX_LIFETIME_RECOVERY_HANDLES);
        assert!(matches!(
            registry.insert(built_inspection(false), &mut generator),
            Err(DesktopFailure::RecoverySessionLimitReached)
        ));
        assert!(registry.records.is_empty());
    }

    #[test]
    fn session_only_issuance_consumes_the_same_lifetime_budget() {
        let mut registry = RecoveryRegistry::default();
        let mut generator = UuidRecoveryHandleGenerator;
        for _ in 0..MAX_LIFETIME_RECOVERY_HANDLES {
            let record = registry
                .insert(built_inspection(false), &mut generator)
                .unwrap();
            registry.release(record.handle.as_str()).unwrap();
        }
        assert_eq!(registry.issued_handles.len(), MAX_LIFETIME_RECOVERY_HANDLES);
        assert!(matches!(
            registry.insert(built_inspection(false), &mut generator),
            Err(DesktopFailure::RecoverySessionLimitReached)
        ));
    }

    #[test]
    fn insufficient_combined_capacity_is_atomic_and_cross_type_collisions_fail_closed() {
        let mut registry = RecoveryRegistry::default();
        for index in 0..(MAX_LIFETIME_RECOVERY_HANDLES - 1) {
            registry.issued_handles.insert(format!("reserved-{index}"));
        }
        let before = registry.issued_handles.clone();
        let mut generator = UuidRecoveryHandleGenerator;
        assert!(matches!(
            registry.insert(built_inspection(true), &mut generator),
            Err(DesktopFailure::RecoverySessionLimitReached)
        ));
        assert_eq!(registry.issued_handles, before);
        assert!(registry.records.is_empty());

        let mut registry = RecoveryRegistry::default();
        let mut collision = CollisionGenerator {
            value: "123e4567-e89b-42d3-a456-426614174000",
        };
        assert!(matches!(
            registry.insert(built_inspection(true), &mut collision),
            Err(DesktopFailure::Internal)
        ));
        assert!(registry.issued_handles.is_empty());
        assert!(registry.records.is_empty());
    }

    #[test]
    fn malformed_durable_peer_is_classified_ambiguous_without_candidate() {
        let fixture = status_fixture();
        let workspace = resolve_trusted_update_workspace(&fixture.app_data_root).unwrap();
        let malformed = workspace
            .transaction_root()
            .join("transactions")
            .join("1111111111111111111111111111111111111111111111111111111111111111");
        fs::create_dir_all(malformed.join("journal")).unwrap();
        fs::write(
            malformed.join("resource-lock-id.bin"),
            b"secret-invalid-binding",
        )
        .unwrap();
        let status = tauri::async_runtime::block_on(recovery_status(
            &fixture.state,
            fixture.request,
            fixture.app_data_root,
        ))
        .unwrap();
        assert_eq!(status.status, RecoveryStatus::Ambiguous);
        assert_eq!(status.candidate_count, 0);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("111111"));
        assert!(!json.contains("secret-invalid-binding"));
        assert!(!json.contains(malformed.to_string_lossy().as_ref()));
    }

    #[test]
    fn registry_capacity_is_hard_bounded_and_recoverable_by_explicit_release() {
        let fixture = status_fixture();
        let first = tauri::async_runtime::block_on(recovery_status(
            &fixture.state,
            fixture.request.clone(),
            fixture.app_data_root.clone(),
        ))
        .unwrap();
        let second = tauri::async_runtime::block_on(recovery_status(
            &fixture.state,
            fixture.request.clone(),
            fixture.app_data_root.clone(),
        ))
        .unwrap();
        assert!(matches!(
            tauri::async_runtime::block_on(recovery_status(
                &fixture.state,
                fixture.request.clone(),
                fixture.app_data_root.clone(),
            )),
            Err(DesktopFailure::RecoverySessionLimitReached)
        ));
        recovery_release(
            &fixture.state,
            UpdateRecoveryReleaseRequest {
                recovery_handle: first.recovery_handle,
            },
        )
        .unwrap();
        assert!(tauri::async_runtime::block_on(recovery_status(
            &fixture.state,
            fixture.request,
            fixture.app_data_root,
        ))
        .is_ok());
        assert!(!second.recovery_handle.is_empty());
    }

    #[test]
    fn every_core_status_has_a_closed_sanitized_desktop_classification() {
        let cases = [
            (
                TrustedPublishedUpdateRecoveryState::Clear,
                RecoveryStatus::Clear,
                None,
            ),
            (
                TrustedPublishedUpdateRecoveryState::Recoverable,
                RecoveryStatus::RecoveryAvailable,
                Some(RecoveryCandidateState::Recoverable),
            ),
            (
                TrustedPublishedUpdateRecoveryState::Committed,
                RecoveryStatus::Committed,
                Some(RecoveryCandidateState::Committed),
            ),
            (
                TrustedPublishedUpdateRecoveryState::RolledBack,
                RecoveryStatus::RolledBack,
                Some(RecoveryCandidateState::RolledBack),
            ),
            (
                TrustedPublishedUpdateRecoveryState::SafeRestart,
                RecoveryStatus::SafeRestart,
                Some(RecoveryCandidateState::SafeRestart),
            ),
            (
                TrustedPublishedUpdateRecoveryState::RecoveryRequired,
                RecoveryStatus::RecoveryRequired,
                Some(RecoveryCandidateState::RecoveryRequired),
            ),
            (
                TrustedPublishedUpdateRecoveryState::ManualAttention,
                RecoveryStatus::ManualAttention,
                None,
            ),
            (
                TrustedPublishedUpdateRecoveryState::Unsupported,
                RecoveryStatus::Unsupported,
                None,
            ),
            (
                TrustedPublishedUpdateRecoveryState::Ambiguous,
                RecoveryStatus::Ambiguous,
                None,
            ),
        ];
        for (core, status, candidate) in cases {
            assert_eq!(adapt_inspection_state(core), (status, candidate));
        }
    }

    #[test]
    fn strict_request_dtos_reject_unknown_missing_empty_and_oversized_handles() {
        assert!(serde_json::from_str::<UpdateRecoveryStatusRequest>(
            r#"{"installedSelectionHandle":"","installedScanHandle":"","installedResourceHandle":"","rawPath":"C:\\\\secret"}"#,
        )
        .is_err());
        assert!(serde_json::from_str::<UpdateRecoveryExecuteRequest>(
            r#"{"recoveryHandle":"only-one-field"}"#,
        )
        .is_err());
        let empty: UpdateRecoveryReleaseRequest =
            serde_json::from_str(r#"{"recoveryHandle":""}"#).unwrap();
        assert!(matches!(
            RecoverySessionHandle::parse(&empty.recovery_handle),
            Err(DesktopFailure::InvalidRequest)
        ));
        let oversized = format!(r#"{{"recoveryHandle":"{}"}}"#, "x".repeat(1_024));
        let parsed: UpdateRecoveryReleaseRequest = serde_json::from_str(&oversized).unwrap();
        assert!(RecoverySessionHandle::parse(&parsed.recovery_handle).is_err());
    }
}
