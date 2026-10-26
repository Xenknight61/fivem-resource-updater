//! The operator's whole sequence, run once against the synthetic fixtures.
//!
//! Every other desktop test exercises one adapter. This runs the order an operator actually
//! works in — choose the two sources and the one they installed from, compare, keep two files,
//! update, close the finished update, put it back, then let go of what nothing needs — and
//! checks the installation on disk at each step.
//!
//! It covers the behaviour of that sequence and not its presentation: native dialogs, the window,
//! keyboard order and screen readers are outside anything this can reach, and the release
//! checklist still asks for a run of the real application for those.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::dto::{
    ScanSourceKind, SelectionKind, UpdateRecoveryRetireTerminalRequest, UpdateRecoveryStatusRequest,
};
use crate::selection::revalidate_selection;
use crate::state::DesktopAppState;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .join("fixtures")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create");
    for entry in fs::read_dir(from).expect("read") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("kind").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// Every file under a root with its bytes, so a whole installation can be compared at once.
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, here: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(here).expect("read") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if entry.file_type().expect("kind").is_dir() {
                visit(root, &path, out);
            } else {
                let relative = path.strip_prefix(root).expect("relative").to_path_buf();
                out.insert(relative, fs::read(&path).expect("bytes"));
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn select(state: &DesktopAppState, kind: SelectionKind, path: &Path) -> String {
    let mut generator = crate::selection::UuidHandleGenerator;
    state
        .selections
        .lock()
        .expect("selections")
        .insert(kind, path.to_path_buf(), &mut generator)
        .expect("selection")
        .handle
}

/// The recovery surface wants a scanned resource rather than a bare folder.
fn recovery_request(
    state: &DesktopAppState,
    installed_handle: &str,
) -> UpdateRecoveryStatusRequest {
    let input =
        crate::selection::clone_selection_for_resolution(state, installed_handle).expect("input");
    let reference = crate::scan::SelectionReference {
        selection_handle: installed_handle.to_owned(),
        generation: input.generation(),
        kind: ScanSourceKind::InstalledRoot,
    };
    let resolved = revalidate_selection(input).expect("resolve");
    let mut generator = crate::scan::UuidScanHandleGenerator;
    let built = crate::scan::build_installed_scan_record(
        "resources".to_owned(),
        reference,
        resolved.path,
        &mut generator,
    )
    .expect("scan record");
    let scan = state
        .scans
        .lock()
        .expect("scans")
        .insert(built, &mut generator)
        .expect("scan");
    UpdateRecoveryStatusRequest {
        installed_selection_handle: installed_handle.to_owned(),
        installed_scan_handle: scan.handle.as_str().to_owned(),
        installed_resource_handle: scan.resources[0].handle.as_str().to_owned(),
    }
}

#[test]
fn the_operators_whole_sequence_against_the_synthetic_fixtures() {
    let temp = tempfile::tempdir().expect("temp");
    let app_data_root = temp.path().join("app-data");
    let installed_root = temp.path().join("installed");
    copy_tree(&fixtures().join("installed"), &installed_root);
    let resource = installed_root.join("gksphone");
    let original = tree(&resource);
    let package = temp.path().join("gksphone-update.zip");
    fs::copy(fixtures().join("packages/gksphone-update.zip"), &package).expect("package");
    let came_from = temp.path().join("gksphone-official-v1.zip");
    fs::copy(
        fixtures().join("packages/gksphone-official-v1.zip"),
        &came_from,
    )
    .expect("baseline package");

    let state = DesktopAppState::default();
    let installed_handle = select(&state, SelectionKind::InstalledRoot, &installed_root);
    let package_handle = select(&state, SelectionKind::PackageFile, &package);
    let came_from_handle = select(&state, SelectionKind::PackageFile, &came_from);

    // 1-3. The two sources, the one it was installed from, and Compare.
    let preview = crate::update::two_way_preview(
        &state,
        &installed_handle,
        &package_handle,
        Some(&came_from_handle),
        app_data_root.clone(),
    )
    .expect("preview");
    assert_eq!(preview.resource, "gksphone");
    assert_eq!(preview.installed_version.as_deref(), Some("1.0.0"));
    assert_eq!(preview.incoming_version.as_deref(), Some("2.0.0"));
    let disposition = |path: &str| {
        preview
            .files
            .iter()
            .find(|file| file.path == path)
            .map(|file| format!("{:?}", file.disposition))
            .unwrap_or_else(|| panic!("{path} is not in the comparison"))
    };
    // The two the customer edited are the two there is anything to decide about.
    assert!(disposition("config.lua").contains("Review"));
    assert!(disposition("client/custom.lua").contains("Review"));
    assert!(disposition("data/customer_notes.txt").contains("KeepLocalOnly"));
    assert!(disposition("server/main.lua").contains("Unchanged"));

    // 4. Update, with both reviewed files kept. No choices means nothing was handed over.
    let applied = crate::update::two_way_apply(&state, &preview.handle, true, &[]).expect("apply");
    assert_eq!(applied.outcome, "committed");

    // config.lua is the product's core promise: the customer's edits survive and the official
    // line arrives in the same file.
    let config = String::from_utf8(fs::read(resource.join("config.lua")).expect("config"))
        .expect("utf-8 config");
    assert!(config.contains("Config.Locale = 'tr'"), "{config}");
    assert!(config.contains("Config.MaxContacts = 250"), "{config}");
    assert!(config.contains("Config.EnableVoiceMail = true"), "{config}");

    // Kept means the customer's own line survives, not that the file is untouched: a kept file
    // is merged, so what the developer added arrives alongside it.
    let custom = String::from_utf8(fs::read(resource.join("client/custom.lua")).expect("custom"))
        .expect("utf-8 custom");
    assert!(
        custom.contains("print('[gksphone] customer hook')"),
        "{custom}"
    );
    assert!(custom.contains("CustomHook = function()"), "{custom}");
    assert!(resource.join("data/customer_notes.txt").is_file());

    // What escrow protects is taken from the update, and what it adds arrives.
    let incoming = fixtures().join("sources/gksphone-v2/gksphone");
    for path in [
        "client/main.lua",
        "fxmanifest.lua",
        "client/new_feature.lua",
    ] {
        assert_eq!(
            fs::read(resource.join(path)).expect("installed"),
            fs::read(incoming.join(path)).expect("incoming"),
            "{path} must be the incoming version"
        );
    }
    assert_eq!(
        fs::read(resource.join("server/main.lua")).expect("server"),
        original[Path::new("server/main.lua")],
        "an identical file is not rewritten"
    );

    // The update is on record, and the record can address it.
    let records = crate::undo::list(&app_data_root);
    assert_eq!(records.len(), 1);
    let record = records.into_iter().next().expect("record");
    assert!(record.transaction_id.is_some());
    assert_eq!(crate::history::list(&app_data_root).len(), 1);

    // 5. A finished update blocks the next one until it is closed.
    // Tauri's own runtime, so the async adapters run here exactly as they do behind a command
    // and no test-only async dependency is added to reach them. Called by path each time: bound
    // to a name it would fix on the first future's type and refuse the next one.
    let overview = tauri::async_runtime::block_on(crate::recovery::recovery_overview(
        &state,
        app_data_root.clone(),
    ))
    .expect("overview");
    assert!(
        overview.terminal_evidence,
        "the finished update must be on record as outstanding: {overview:?}"
    );

    // 6. Close it. Additive: the evidence stays where it is.
    let retired = tauri::async_runtime::block_on(crate::recovery::recovery_retire_terminal(
        &state,
        UpdateRecoveryRetireTerminalRequest { acknowledged: true },
        app_data_root.clone(),
    ))
    .expect("retire");
    assert!(retired.retired_count >= 1, "{retired:?}");
    let after = tauri::async_runtime::block_on(crate::recovery::recovery_overview(
        &state,
        app_data_root.clone(),
    ))
    .expect("overview after closing");
    assert!(!after.terminal_evidence, "closing must unblock: {after:?}");

    // 8. Put it back. The copied package is gone first, because Undo must not need it.
    fs::remove_file(&package).expect("remove the copied package");
    let workspace =
        gkrm_core::resolve_trusted_update_workspace(&app_data_root).expect("reopen workspace");
    let outcome = crate::undo::undo(&workspace, &record).expect("undo");
    assert!(outcome.skipped == 0 && outcome.missing == 0, "{outcome:?}");
    assert_eq!(
        tree(&resource),
        original,
        "undo must put the installation back exactly as it was"
    );

    // 9. What is kept, and letting go of only what nothing reaches for.
    let report = crate::storage::report(
        &app_data_root,
        workspace.baseline_store(),
        workspace.staging_root(),
        &crate::storage::releasable_staged_names(&workspace),
    );
    assert!(
        report.held_bytes > 0,
        "the update left something behind: {report:?}"
    );
    // Putting an update back is itself an update: it commits, it is on record, and it waits to
    // be closed exactly as the one before it did. History is added to, never rewritten.
    let after_undo = tauri::async_runtime::block_on(crate::recovery::recovery_overview(
        &state,
        app_data_root.clone(),
    ))
    .expect("overview after undo");
    assert!(
        after_undo.terminal_evidence,
        "the undo must be on record as outstanding too: {after_undo:?}"
    );
    let closed = tauri::async_runtime::block_on(crate::recovery::recovery_retire_terminal(
        &state,
        UpdateRecoveryRetireTerminalRequest { acknowledged: true },
        app_data_root.clone(),
    ))
    .expect("close the undo");
    assert!(closed.retired_count >= 1, "{closed:?}");
    let settled = tauri::async_runtime::block_on(crate::recovery::recovery_overview(
        &state,
        app_data_root.clone(),
    ))
    .expect("overview once everything is closed");
    assert!(!settled.terminal_evidence, "{settled:?}");

    // Nothing is outstanding, and nothing needs recovering.
    let request = recovery_request(&state, &installed_handle);
    let status = tauri::async_runtime::block_on(crate::recovery::recovery_status(
        &state,
        request,
        app_data_root.clone(),
    ))
    .expect("status");
    assert_eq!(status.candidate_count, 0, "{status:?}");

    // Every read above left the installation as the undo put it back.
    assert_eq!(tree(&resource), original);
}
