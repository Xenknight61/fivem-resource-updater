use std::path::PathBuf;

use gkrm_core::resolve_trusted_update_workspace;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::dto::{
    AppInfo, BuildProfile, ListSelectionsRequest, ListSelectionsResponse, Platform,
    ReleaseSelectionRequest, ReleaseSelectionResponse, ScanGetResourceDetailRequest,
    ScanGetResourceDetailResponse, ScanGetSummaryRequest, ScanGetSummaryResponse,
    ScanInstalledRootRequest, ScanListResourcesRequest, ScanListResourcesResponse,
    ScanReleaseRequest, ScanReleaseResponse, ScanSourceKind, SelectionDialogResult, SelectionKind,
    StartScanResponse, UpdateRecoveryExecuteRequest, UpdateRecoveryExecuteResponse,
    UpdateRecoveryListCandidatesRequest, UpdateRecoveryListCandidatesResponse,
    UpdateRecoveryOverviewResponse, UpdateRecoveryReleaseRequest, UpdateRecoveryReleaseResponse,
    UpdateRecoveryRetireTerminalRequest, UpdateRecoveryRetireTerminalResponse,
    UpdateRecoveryStatusRequest, UpdateRecoveryStatusResponse,
};
use crate::dto::{
    HeldBaselineDto, StorageReleaseResponse, StorageReportResponse, TwoWayApplyRequestDto,
    TwoWayApplyResponse, TwoWayGetDiffRequest, TwoWayGetDiffResponse, TwoWayPreviewRequest,
    TwoWayPreviewResponse, TwoWayReleaseRequest, TwoWayReleaseResponse, UpdateHistoryEntryDto,
    UpdateHistoryListResponse, UpdateHistoryUndoRequest, UpdateHistoryUndoResponse,
};
use crate::error::{DesktopError, DesktopFailure, DesktopResult};
use crate::operation::acquire_operation_permit;
use crate::recovery::{
    recovery_execute, recovery_list_candidates, recovery_overview, recovery_release,
    recovery_retire_terminal, recovery_status,
};
use crate::scan::{
    acquire_scan_permit, build_installed_scan_record, build_package_scan_record, list_resources,
    resource_detail, SelectionReference, UuidScanHandleGenerator,
};
use crate::selection::{
    clone_selection_for_resolution, confirm_selection_active, revalidate_selection,
    validate_selection_shape, UuidHandleGenerator,
};
use crate::state::DesktopAppState;
use crate::update::{two_way_apply, two_way_get_diff, two_way_preview, two_way_release};

trait SelectionDialog {
    fn pick_installed_root(&self) -> DesktopResult<Option<PathBuf>>;
    fn pick_package_file(&self) -> DesktopResult<Option<PathBuf>>;
}

struct TauriSelectionDialog<'a> {
    app: &'a AppHandle,
}

impl SelectionDialog for TauriSelectionDialog<'_> {
    fn pick_installed_root(&self) -> DesktopResult<Option<PathBuf>> {
        self.app
            .dialog()
            .file()
            .set_title("Select installed FiveM resource root")
            .blocking_pick_folder()
            .map(|path| path.into_path().map_err(|_| DesktopFailure::DialogFailed))
            .transpose()
    }

    fn pick_package_file(&self) -> DesktopResult<Option<PathBuf>> {
        self.app
            .dialog()
            .file()
            .set_title("Select update package")
            .add_filter("ZIP package", &["zip"])
            .blocking_pick_file()
            .map(|path| path.into_path().map_err(|_| DesktopFailure::DialogFailed))
            .transpose()
    }
}

#[tauri::command]
pub fn app_get_info() -> Result<AppInfo, DesktopError> {
    Ok(AppInfo {
        schema_version: 1,
        app_version: env!("CARGO_PKG_VERSION"),
        core_version: env!("CARGO_PKG_VERSION"),
        platform: platform(),
        build_profile: build_profile(),
    })
}

#[tauri::command]
pub fn select_installed_root(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
) -> Result<SelectionDialogResult, DesktopError> {
    let dialog = TauriSelectionDialog { app: &app };
    select_with_dialog(&dialog, &state, SelectionKind::InstalledRoot).map_err(DesktopFailure::dto)
}

#[tauri::command]
pub fn select_package_file(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
) -> Result<SelectionDialogResult, DesktopError> {
    let dialog = TauriSelectionDialog { app: &app };
    select_with_dialog(&dialog, &state, SelectionKind::PackageFile).map_err(DesktopFailure::dto)
}

#[tauri::command]
pub fn session_list_selections(
    state: State<'_, DesktopAppState>,
    request: ListSelectionsRequest,
) -> Result<ListSelectionsResponse, DesktopError> {
    let registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    Ok(ListSelectionsResponse {
        selections: registry.list(request.kind),
    })
}

#[tauri::command]
pub fn session_release_selection(
    state: State<'_, DesktopAppState>,
    request: ReleaseSelectionRequest,
) -> Result<ReleaseSelectionResponse, DesktopError> {
    let mut registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    registry
        .release(&request.handle)
        .map_err(DesktopFailure::dto)?;
    Ok(ReleaseSelectionResponse { released: true })
}

#[tauri::command]
pub async fn scan_installed_root(
    state: State<'_, DesktopAppState>,
    request: ScanInstalledRootRequest,
) -> Result<StartScanResponse, DesktopError> {
    start_scan(
        &state,
        request.selection_handle,
        SelectionKind::InstalledRoot,
    )
    .await
}

#[tauri::command]
pub fn scan_get_summary(
    state: State<'_, DesktopAppState>,
    request: ScanGetSummaryRequest,
) -> Result<ScanGetSummaryResponse, DesktopError> {
    let record = state
        .scans
        .lock()
        .map_err(|_| DesktopFailure::Internal.dto())?
        .get(&request.scan_handle)
        .map_err(DesktopFailure::dto)?;
    Ok(ScanGetSummaryResponse {
        summary: record.summary.clone(),
    })
}

#[tauri::command]
pub fn scan_list_resources(
    state: State<'_, DesktopAppState>,
    request: ScanListResourcesRequest,
) -> Result<ScanListResourcesResponse, DesktopError> {
    let record = state
        .scans
        .lock()
        .map_err(|_| DesktopFailure::Internal.dto())?
        .get(&request.scan_handle)
        .map_err(DesktopFailure::dto)?;
    list_resources(&record, &request).map_err(DesktopFailure::dto)
}

#[tauri::command]
pub fn scan_get_resource_detail(
    state: State<'_, DesktopAppState>,
    request: ScanGetResourceDetailRequest,
) -> Result<ScanGetResourceDetailResponse, DesktopError> {
    let record = state
        .scans
        .lock()
        .map_err(|_| DesktopFailure::Internal.dto())?
        .get(&request.scan_handle)
        .map_err(DesktopFailure::dto)?;
    let resource =
        resource_detail(&record, &request.resource_handle).map_err(DesktopFailure::dto)?;
    Ok(ScanGetResourceDetailResponse { resource })
}

#[tauri::command]
pub fn scan_release(
    state: State<'_, DesktopAppState>,
    request: ScanReleaseRequest,
) -> Result<ScanReleaseResponse, DesktopError> {
    state
        .scans
        .lock()
        .map_err(|_| DesktopFailure::Internal.dto())?
        .release(&request.scan_handle)
        .map_err(DesktopFailure::dto)?;
    Ok(ScanReleaseResponse { released: true })
}

#[tauri::command]
pub async fn update_recovery_status(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
    request: UpdateRecoveryStatusRequest,
) -> Result<UpdateRecoveryStatusResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    recovery_status(&state, request, app_data_root)
        .await
        .map_err(DesktopFailure::dto)
}

#[tauri::command]
pub async fn update_recovery_overview(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
) -> Result<UpdateRecoveryOverviewResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    recovery_overview(&state, app_data_root)
        .await
        .map_err(DesktopFailure::dto)
}

#[tauri::command]
pub async fn update_recovery_retire_terminal(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
    request: UpdateRecoveryRetireTerminalRequest,
) -> Result<UpdateRecoveryRetireTerminalResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    recovery_retire_terminal(&state, request, app_data_root)
        .await
        .map_err(DesktopFailure::dto)
}

#[tauri::command]
pub fn update_recovery_list_candidates(
    state: State<'_, DesktopAppState>,
    request: UpdateRecoveryListCandidatesRequest,
) -> Result<UpdateRecoveryListCandidatesResponse, DesktopError> {
    recovery_list_candidates(&state, request).map_err(DesktopFailure::dto)
}

#[tauri::command]
pub async fn update_recovery_execute(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
    request: UpdateRecoveryExecuteRequest,
) -> Result<UpdateRecoveryExecuteResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    recovery_execute(&state, request, app_data_root)
        .await
        .map_err(DesktopFailure::dto)
}

#[tauri::command]
pub fn update_recovery_release(
    state: State<'_, DesktopAppState>,
    request: UpdateRecoveryReleaseRequest,
) -> Result<UpdateRecoveryReleaseResponse, DesktopError> {
    recovery_release(&state, request).map_err(DesktopFailure::dto)
}

async fn start_scan(
    state: &DesktopAppState,
    selection_handle: String,
    expected: SelectionKind,
) -> Result<StartScanResponse, DesktopError> {
    start_scan_with_builder(
        state,
        selection_handle,
        expected,
        |expected, source_label, selection_ref, path| {
            let mut generator = UuidScanHandleGenerator;
            match expected {
                SelectionKind::InstalledRoot => {
                    build_installed_scan_record(source_label, selection_ref, path, &mut generator)
                }
                SelectionKind::PackageFile => {
                    build_package_scan_record(source_label, selection_ref, path, &mut generator)
                }
            }
        },
    )
    .await
}

async fn start_scan_with_builder(
    state: &DesktopAppState,
    selection_handle: String,
    expected: SelectionKind,
    builder: impl FnOnce(
            SelectionKind,
            String,
            SelectionReference,
            PathBuf,
        ) -> DesktopResult<crate::scan::ScanRecord>
        + Send
        + 'static,
) -> Result<StartScanResponse, DesktopError> {
    let input =
        clone_selection_for_resolution(state, &selection_handle).map_err(DesktopFailure::dto)?;
    if input.kind() != expected {
        return Err(DesktopFailure::InvalidScanSource.dto());
    }
    let resolved = revalidate_selection(input.clone()).map_err(DesktopFailure::dto)?;
    confirm_selection_active(state, &input).map_err(DesktopFailure::dto)?;
    let source_kind = match expected {
        SelectionKind::InstalledRoot => ScanSourceKind::InstalledRoot,
        SelectionKind::PackageFile => ScanSourceKind::PackageFile,
    };
    let selection_ref = SelectionReference {
        selection_handle: input.handle().as_str().to_owned(),
        generation: input.generation(),
        kind: source_kind,
    };
    let _permit = acquire_scan_permit(&state.operation_occupied).map_err(DesktopFailure::dto)?;
    {
        let scans = state
            .scans
            .lock()
            .map_err(|_| DesktopFailure::Internal.dto())?;
        if !scans.has_capacity() {
            return Err(DesktopFailure::ScanLimitReached.dto());
        }
    }

    let source_label = input.display_label().to_owned();
    let path = resolved.path;
    let built = tauri::async_runtime::spawn_blocking(move || {
        builder(expected, source_label, selection_ref, path)
    })
    .await
    .map_err(|_| DesktopFailure::Internal.dto())?
    .map_err(DesktopFailure::dto)?;
    #[cfg(test)]
    test_hooks::run_post_build_hook();

    confirm_selection_active(state, &input).map_err(DesktopFailure::dto)?;

    let mut scans = state
        .scans
        .lock()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    let mut generator = UuidScanHandleGenerator;
    let record = scans
        .insert(built, &mut generator)
        .map_err(DesktopFailure::dto)?;
    Ok(StartScanResponse {
        scan_handle: record.handle.as_str().to_owned(),
        source_kind: record.source_kind,
        summary: record.summary.clone(),
    })
}

/// Compare the installed resource against a package, and against the one it was installed from.
#[tauri::command]
pub async fn update_two_way_preview(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
    request: TwoWayPreviewRequest,
) -> Result<TwoWayPreviewResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    let started = std::time::Instant::now();
    let result = two_way_preview(
        &state,
        &request.installed_selection_handle,
        &request.package_selection_handle,
        request.baseline_selection_handle.as_deref(),
        app_data_root,
    );
    note("compare", started, &result, |preview| {
        format!(
            "{} files, {} to answer",
            preview.summary.total, preview.summary.review
        )
    });
    result.map_err(DesktopFailure::dto)
}

/// Record one operator-facing operation, whatever became of it.
///
/// The detail describes the work; the duration and, on a failure, the real cause noted while it
/// ran are added here so every line is written the same way.
fn note<T>(
    operation: &str,
    started: std::time::Instant,
    result: &DesktopResult<T>,
    detail: impl FnOnce(&T) -> String,
) {
    use crate::diagnostics::Outcome;
    let took = format!("{:.1}s", started.elapsed().as_secs_f64());
    match result {
        Ok(value) => crate::diagnostics::record(
            operation,
            Outcome::Ok,
            &format!("{} in {took}", detail(value)),
        ),
        // `Internal` is the failure this could not account for; everything else is a refusal the
        // operator can do something about, and the two are worth telling apart at a glance.
        Err(failure) => {
            let outcome = if matches!(failure, DesktopFailure::Internal) {
                Outcome::Failed
            } else {
                Outcome::Refused
            };
            crate::diagnostics::record(operation, outcome, &format!("{failure:?} after {took}"))
        }
    }
}

#[tauri::command]
pub fn update_two_way_get_diff(
    state: State<'_, DesktopAppState>,
    request: TwoWayGetDiffRequest,
) -> Result<TwoWayGetDiffResponse, DesktopError> {
    two_way_get_diff(&state, &request.handle, &request.path).map_err(DesktopFailure::dto)
}

/// Apply the update. This writes to the live installation.
#[tauri::command]
pub async fn update_two_way_apply(
    state: State<'_, DesktopAppState>,
    request: TwoWayApplyRequestDto,
) -> Result<TwoWayApplyResponse, DesktopError> {
    let started = std::time::Instant::now();
    let result = two_way_apply(
        &state,
        &request.handle,
        request.keep_settings,
        &request.choices,
    );
    note("apply", started, &result, |applied| {
        format!(
            "{}, {} replaced, {} reviewed",
            applied.outcome, applied.summary.take_from_update, applied.summary.review
        )
    });
    result.map_err(DesktopFailure::dto)
}

#[tauri::command]
pub fn update_two_way_release(
    state: State<'_, DesktopAppState>,
    request: TwoWayReleaseRequest,
) -> Result<TwoWayReleaseResponse, DesktopError> {
    two_way_release(&state, &request.handle).map_err(DesktopFailure::dto)
}

/// The updates this operator has run. A convenience index, not authority for anything.
#[tauri::command]
pub fn update_history_list(app: AppHandle) -> Result<UpdateHistoryListResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    Ok(UpdateHistoryListResponse {
        entries: crate::history::list(&app_data_root)
            .into_iter()
            .map(|mut entry| {
                let status = crate::undo::history_status(&app_data_root, &entry.id);
                if let crate::undo::UndoHistoryStatus::Completed { preserved } = status {
                    entry.outcome = if preserved == 0 {
                        "undone"
                    } else {
                        "undone_partial"
                    }
                    .to_owned();
                }
                UpdateHistoryEntryDto {
                    undoable: status == crate::undo::UndoHistoryStatus::Available,
                    entry,
                }
            })
            .collect(),
    })
}

/// What is kept so later updates can tell the operator's work from the developer's.
///
/// Read-only, and reads only this application's own workspace: no folder to point at, because
/// nothing here is about the operator's installation.
#[tauri::command]
pub fn storage_report(app: AppHandle) -> Result<StorageReportResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    let workspace = resolve_trusted_update_workspace(&app_data_root)
        .map_err(|_| DesktopFailure::Internal.dto())?;
    let report = crate::storage::report(
        &app_data_root,
        workspace.baseline_store(),
        workspace.staging_root(),
        &crate::storage::releasable_staged_names(&workspace),
    );
    Ok(StorageReportResponse {
        baselines: report
            .baselines
            .into_iter()
            .map(|held| HeldBaselineDto {
                resource: held.resource,
                version: held.version,
                bytes: held.bytes,
                needed_for: held.needed_for.map(crate::storage::NeededFor::as_str),
            })
            .collect(),
        held_bytes: report.held_bytes,
        releasable_bytes: report.releasable_bytes,
        staged_count: report.staged.count,
        staged_bytes: report.staged.bytes,
        staged_releasable_bytes: report.staged.releasable_bytes,
    })
}

/// Let go of every kept package nothing reaches for any more.
///
/// This deletes, so it takes the operation permit: a release running beside an update would be
/// deciding what is still owed to somebody while that answer is being changed underneath it.
#[tauri::command]
pub fn storage_release(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
) -> Result<StorageReleaseResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    let _permit =
        acquire_operation_permit(&state.operation_occupied).map_err(DesktopFailure::dto)?;
    let workspace = resolve_trusted_update_workspace(&app_data_root)
        .map_err(|_| DesktopFailure::Internal.dto())?;
    let started = std::time::Instant::now();
    let released = crate::storage::release(&app_data_root, &workspace);
    note("release", started, &released, |outcome| {
        format!("{} let go of, {} bytes", outcome.released, outcome.bytes)
    });
    let outcome = released.map_err(DesktopFailure::dto)?;
    Ok(StorageReleaseResponse {
        released: outcome.released,
        bytes: outcome.bytes,
    })
}

/// Put one remembered update back, from what the transaction backed up before it wrote.
///
/// This writes into the operator's installation, so it verifies every byte against the digest
/// recorded at apply time and leaves alone any file they have changed since.
#[tauri::command]
pub fn update_history_undo(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
    request: UpdateHistoryUndoRequest,
) -> Result<UpdateHistoryUndoResponse, DesktopError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| DesktopFailure::Internal.dto())?;
    // One durable operation at a time: an undo that ran beside an apply would race it for the
    // same files.
    let _permit =
        acquire_operation_permit(&state.operation_occupied).map_err(DesktopFailure::dto)?;
    let record = crate::undo::read(&app_data_root, &request.id)
        .ok_or_else(|| DesktopFailure::UndoUnavailable.dto())?;
    let workspace = resolve_trusted_update_workspace(&app_data_root)
        .map_err(|_| DesktopFailure::Internal.dto())?;
    let started = std::time::Instant::now();
    let undone = crate::undo::undo(&workspace, &record);
    note("undo", started, &undone, |outcome| {
        format!(
            "restored {}, removed {}, left alone {}, missing {}",
            outcome.restored, outcome.removed, outcome.skipped, outcome.missing
        )
    });
    let outcome = undone.map_err(DesktopFailure::dto)?;

    Ok(UpdateHistoryUndoResponse { outcome })
}

#[cfg(test)]
mod test_hooks {
    use std::sync::{Arc, Mutex, OnceLock};

    type Hook = Arc<dyn Fn() + Send + Sync + 'static>;

    static POST_BUILD_HOOK: OnceLock<Mutex<Option<Hook>>> = OnceLock::new();

    fn hook_slot() -> &'static Mutex<Option<Hook>> {
        POST_BUILD_HOOK.get_or_init(|| Mutex::new(None))
    }

    pub(super) struct PostBuildHookGuard;

    impl Drop for PostBuildHookGuard {
        fn drop(&mut self) {
            *hook_slot().lock().expect("hook lock") = None;
        }
    }

    pub(super) fn set_post_build_hook(hook: Hook) -> PostBuildHookGuard {
        *hook_slot().lock().expect("hook lock") = Some(hook);
        PostBuildHookGuard
    }

    pub(super) fn run_post_build_hook() {
        let hook = hook_slot().lock().expect("hook lock").clone();
        if let Some(hook) = hook {
            hook();
        }
    }
}

fn select_with_dialog(
    dialog: &impl SelectionDialog,
    state: &DesktopAppState,
    kind: SelectionKind,
) -> DesktopResult<SelectionDialogResult> {
    let path = match kind {
        SelectionKind::InstalledRoot => dialog.pick_installed_root()?,
        SelectionKind::PackageFile => dialog.pick_package_file()?,
    };
    let Some(path) = path else {
        return Ok(SelectionDialogResult {
            cancelled: true,
            selection: None,
        });
    };
    let validation = validate_selection_shape(&path, kind)?;
    let mut generator = UuidHandleGenerator;
    let mut registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    let selection = registry.insert_validated(kind, path, validation, &mut generator)?;
    Ok(SelectionDialogResult {
        cancelled: false,
        selection: Some(selection),
    })
}

fn platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Unknown
    }
}

fn build_profile() -> BuildProfile {
    if cfg!(debug_assertions) {
        BuildProfile::Debug
    } else {
        BuildProfile::Release
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{mpsc, Arc, Condvar, Mutex};

    use tempfile::tempdir;

    use super::*;

    struct FakeDialog {
        installed: DesktopResult<Option<PathBuf>>,
        package: DesktopResult<Option<PathBuf>>,
    }

    impl SelectionDialog for FakeDialog {
        fn pick_installed_root(&self) -> DesktopResult<Option<PathBuf>> {
            self.installed.clone()
        }

        fn pick_package_file(&self) -> DesktopResult<Option<PathBuf>> {
            self.package.clone()
        }
    }

    fn empty_scan_record(
        source_label: String,
        selection: SelectionReference,
        source_kind: ScanSourceKind,
    ) -> crate::scan::ScanRecord {
        crate::scan::ScanRecord {
            handle: crate::scan::ScanHandle::parse("123e4567-e89b-42d3-a456-426614174999").unwrap(),
            source_kind,
            source_selection: selection,
            created_sequence: 0,
            package_commitment: None,
            summary: crate::dto::ScanSummary {
                source_kind,
                source_label,
                resource_count: 0,
                warning_count: 0,
                total_file_count: 0,
                total_bytes: 0,
            },
            resources: Vec::new(),
        }
    }

    #[test]
    fn app_info_is_bounded() {
        let info = app_get_info().unwrap();
        assert_eq!(info.schema_version, 1);
        assert!(info.app_version.len() <= 40);
        assert!(info.core_version.len() <= 40);
    }

    #[test]
    fn dialog_cancellation_is_not_error() {
        let state = Arc::new(DesktopAppState::default());
        let dialog = FakeDialog {
            installed: Ok(None),
            package: Ok(None),
        };
        let result = select_with_dialog(&dialog, &state, SelectionKind::InstalledRoot).unwrap();
        assert!(result.cancelled);
        assert!(result.selection.is_none());
    }

    #[test]
    fn dialog_selection_inserts_summary_without_path() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("resources");
        fs::create_dir(&root).unwrap();
        let state = Arc::new(DesktopAppState::default());
        let dialog = FakeDialog {
            installed: Ok(Some(root)),
            package: Ok(None),
        };
        let result = select_with_dialog(&dialog, &state, SelectionKind::InstalledRoot).unwrap();
        assert!(!result.cancelled);
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains(temp.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn invalid_dialog_result_maps_to_sanitized_error() {
        let temp = tempdir().unwrap();
        let file = temp.path().join("not-a-dir.txt");
        fs::write(&file, b"x").unwrap();
        let state = Arc::new(DesktopAppState::default());
        let dialog = FakeDialog {
            installed: Ok(Some(file)),
            package: Ok(None),
        };
        assert!(matches!(
            select_with_dialog(&dialog, &state, SelectionKind::InstalledRoot),
            Err(DesktopFailure::InvalidInstalledRoot)
        ));
    }

    #[test]
    fn state_instances_are_isolated() {
        let one = DesktopAppState::default();
        let two = DesktopAppState::default();
        assert_eq!(one.selections.lock().unwrap().list(None).len(), 0);
        assert_eq!(two.selections.lock().unwrap().list(None).len(), 0);
    }

    #[test]
    fn selection_release_during_scan_prevents_publication() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("resource");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("fxmanifest.lua"),
            b"fx_version 'cerulean'\ngame 'gta5'\n",
        )
        .unwrap();
        let state = Arc::new(DesktopAppState::default());
        let mut generator = UuidHandleGenerator;
        let summary = state
            .selections
            .lock()
            .unwrap()
            .insert(SelectionKind::InstalledRoot, root, &mut generator)
            .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let handle = summary.handle.clone();
        let release_handle = handle.clone();

        let result = tauri::async_runtime::block_on(async {
            let scan_state = Arc::clone(&state);
            let task = tauri::async_runtime::spawn(async move {
                start_scan_with_builder(
                    &scan_state,
                    handle.clone(),
                    SelectionKind::InstalledRoot,
                    move |expected, source_label, selection_ref, path| {
                        started_tx.send(()).unwrap();
                        continue_rx.recv().unwrap();
                        let mut generator = UuidScanHandleGenerator;
                        match expected {
                            SelectionKind::InstalledRoot => build_installed_scan_record(
                                source_label,
                                selection_ref,
                                path,
                                &mut generator,
                            ),
                            SelectionKind::PackageFile => build_package_scan_record(
                                source_label,
                                selection_ref,
                                path,
                                &mut generator,
                            ),
                        }
                    },
                )
                .await
            });
            started_rx.recv().unwrap();
            state
                .selections
                .lock()
                .unwrap()
                .release(&release_handle)
                .unwrap();
            continue_tx.send(()).unwrap();
            task.await.unwrap()
        });

        assert!(matches!(
            result,
            Err(DesktopError {
                code: crate::error::DesktopErrorCode::SelectionStale,
                ..
            })
        ));
        assert!(state.scans.lock().unwrap().records_is_empty_for_test());
    }

    #[test]
    fn scan_permit_remains_held_between_build_and_publication() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("resource");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("fxmanifest.lua"),
            b"fx_version 'cerulean'\ngame 'gta5'\n",
        )
        .unwrap();
        let state = Arc::new(DesktopAppState::default());
        let mut generator = UuidHandleGenerator;
        let summary = state
            .selections
            .lock()
            .unwrap()
            .insert(SelectionKind::InstalledRoot, root, &mut generator)
            .unwrap();
        let reached = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let hook_reached = Arc::clone(&reached);
        let hook_release = Arc::clone(&release);
        let _guard = super::test_hooks::set_post_build_hook(Arc::new(move || {
            let (lock, cv) = &*hook_reached;
            *lock.lock().unwrap() = true;
            cv.notify_one();
            let (lock, cv) = &*hook_release;
            let mut allowed = lock.lock().unwrap();
            while !*allowed {
                allowed = cv.wait(allowed).unwrap();
            }
        }));

        let handle = summary.handle.clone();
        let first_result = tauri::async_runtime::block_on(async {
            let first_state = Arc::clone(&state);
            let first_handle = handle.clone();
            let first = tauri::async_runtime::spawn(async move {
                start_scan_with_builder(
                    &first_state,
                    first_handle,
                    SelectionKind::InstalledRoot,
                    |expected, source_label, selection_ref, _path| {
                        Ok(empty_scan_record(
                            source_label,
                            selection_ref,
                            match expected {
                                SelectionKind::InstalledRoot => ScanSourceKind::InstalledRoot,
                                SelectionKind::PackageFile => ScanSourceKind::PackageFile,
                            },
                        ))
                    },
                )
                .await
            });

            {
                let (lock, cv) = &*reached;
                let mut reached_build = lock.lock().unwrap();
                while !*reached_build {
                    reached_build = cv.wait(reached_build).unwrap();
                }
            }

            let second = start_scan_with_builder(
                &state,
                handle,
                SelectionKind::InstalledRoot,
                |expected, source_label, selection_ref, _path| {
                    Ok(empty_scan_record(
                        source_label,
                        selection_ref,
                        match expected {
                            SelectionKind::InstalledRoot => ScanSourceKind::InstalledRoot,
                            SelectionKind::PackageFile => ScanSourceKind::PackageFile,
                        },
                    ))
                },
            )
            .await;
            assert!(matches!(
                second,
                Err(DesktopError {
                    code: crate::error::DesktopErrorCode::ScanBusy,
                    ..
                })
            ));

            let (lock, cv) = &*release;
            *lock.lock().unwrap() = true;
            cv.notify_one();
            first.await.unwrap()
        });

        assert!(first_result.is_ok());
        let permit = acquire_scan_permit(&state.operation_occupied).unwrap();
        drop(permit);
    }

    #[test]
    fn scan_build_failure_publishes_no_scan_and_releases_permit() {
        let temp = tempdir().unwrap();
        let package = temp.path().join("package.zip");
        fs::write(&package, b"not a zip").unwrap();
        let state = Arc::new(DesktopAppState::default());
        let mut generator = UuidHandleGenerator;
        let summary = state
            .selections
            .lock()
            .unwrap()
            .insert(SelectionKind::PackageFile, package, &mut generator)
            .unwrap();

        let result = tauri::async_runtime::block_on(start_scan_with_builder(
            &state,
            summary.handle,
            SelectionKind::PackageFile,
            |_expected, _source_label, _selection_ref, _path| {
                Err(DesktopFailure::InspectionRejected)
            },
        ));

        assert!(matches!(
            result,
            Err(DesktopError {
                code: crate::error::DesktopErrorCode::InspectionRejected,
                ..
            })
        ));
        assert!(state.scans.lock().unwrap().records_is_empty_for_test());
        let permit = acquire_scan_permit(&state.operation_occupied).unwrap();
        drop(permit);
    }
}
