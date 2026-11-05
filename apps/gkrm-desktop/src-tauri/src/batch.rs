//! Updating many resources from a folder of packages.
//!
//! The decisions are the core's: which package matches which installed resource, which updates
//! need no answer, and what happens when one fails. This module only carries that across the
//! boundary. Trusted paths stay here; the frontend sees opaque handles, package file names and
//! counts, and names an entry by its position in the plan.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gkrm_core::{
    apply_batch, plan_batch, resolve_trusted_update_workspace, BatchApplyResult, BatchEntryOutcome,
    BatchPlan,
};
use uuid::Uuid;

use crate::dto::{
    BatchApplyResponse, BatchApplyResultKind, BatchEntryDto, BatchEntryKind, BatchEntryResultDto,
    BatchOpenPackageResponse, BatchPlanResponse, BatchReleaseResponse, SelectionKind,
};
use crate::error::{DesktopFailure, DesktopResult};
use crate::operation::map_core_error;
use crate::selection::{
    resolve_selection_for_future_use, validate_selection_shape, UuidHandleGenerator,
};
use crate::state::DesktopAppState;
use crate::update::{manifest_changes_dto, record_applied_update, summarize};

/// The most packages one batch will take from a folder.
///
/// A folder with more is refused rather than cut short: a batch that quietly skipped the
/// packages past some number would look finished while leaving resources out of date.
pub const MAX_BATCH_PACKAGES: usize = 256;

/// The longest package name sent to the screen, in characters.
const MAX_PACKAGE_NAME_CHARS: usize = 128;

struct BatchRecord {
    plan: BatchPlan,
    installed: PathBuf,
    installed_selection: String,
    packages_selection: String,
    packages_folder: PathBuf,
    app_data_root: PathBuf,
    applied: bool,
}

#[derive(Default)]
pub struct BatchRegistry {
    records: BTreeMap<String, BatchRecord>,
}

impl BatchRegistry {
    fn insert(&mut self, record: BatchRecord) -> String {
        let handle = Uuid::new_v4().to_string();
        self.records.insert(handle.clone(), record);
        handle
    }
}

/// The `.zip` files directly inside a folder. Links, directories and everything else are ignored:
/// a package is a regular file the operator can see in that folder.
fn list_packages(folder: &Path) -> DesktopResult<Vec<PathBuf>> {
    let mut packages = Vec::new();
    let entries = fs::read_dir(folder).map_err(|_| DesktopFailure::InvalidRequest)?;
    for entry in entries {
        let entry = entry.map_err(|_| DesktopFailure::InvalidRequest)?;
        let path = entry.path();
        let is_zip = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"));
        if !is_zip {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        if packages.len() >= MAX_BATCH_PACKAGES {
            return Err(DesktopFailure::PlanLimitReached);
        }
        packages.push(path);
    }
    packages.sort();
    Ok(packages)
}

/// A file name that is safe to draw: control characters become spaces and length is bounded.
fn display_name(path: &Path) -> String {
    let raw = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let scrubbed: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let joined = scrubbed.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut shown: String = joined.chars().take(MAX_PACKAGE_NAME_CHARS).collect();
    if shown.chars().count() < joined.chars().count() {
        shown.push('…');
    }
    shown
}

fn entry_kind(outcome: &BatchEntryOutcome) -> BatchEntryKind {
    match outcome {
        BatchEntryOutcome::Ready => BatchEntryKind::Ready,
        BatchEntryOutcome::AlreadyUpToDate => BatchEntryKind::UpToDate,
        BatchEntryOutcome::NeedsReview { .. } => BatchEntryKind::NeedsReview,
        BatchEntryOutcome::NoInstalledResource => BatchEntryKind::NoInstalledResource,
        BatchEntryOutcome::DuplicatePackage => BatchEntryKind::DuplicatePackage,
        BatchEntryOutcome::NotASingleResource => BatchEntryKind::NotASingleResource,
        BatchEntryOutcome::BlockedByEarlierUpdate => BatchEntryKind::BlockedByEarlierUpdate,
        BatchEntryOutcome::Unreadable => BatchEntryKind::Unreadable,
    }
}

fn entry_dto(index: usize, entry: &gkrm_core::BatchPlanEntry) -> BatchEntryDto {
    let (review, unmergeable) = match entry.outcome() {
        BatchEntryOutcome::NeedsReview {
            review,
            unmergeable,
        } => (*review as u32, *unmergeable as u32),
        _ => (0, 0),
    };
    BatchEntryDto {
        id: u32::try_from(index).unwrap_or(u32::MAX),
        package_name: display_name(entry.package()),
        resource: entry.resource().map(|key| key.as_str().to_owned()),
        kind: entry_kind(entry.outcome()),
        review,
        unmergeable,
        installed_version: entry.installed_version().map(str::to_owned),
        incoming_version: entry.incoming_version().map(str::to_owned),
        summary: entry.summary().map(|summary| crate::dto::TwoWaySummary {
            unchanged: summary.unchanged() as u32,
            take_from_update: summary.take_from_update() as u32,
            review: summary.review() as u32,
            keep_local_only: summary.keep_local_only() as u32,
            total: summary.total() as u32,
        }),
        manifest_changes: entry.manifest_changes().map(manifest_changes_dto),
    }
}

/// Compare every package in a folder against the installation. Reads only.
pub fn batch_plan(
    state: &DesktopAppState,
    installed_handle: &str,
    packages_handle: &str,
    app_data_root: PathBuf,
) -> DesktopResult<BatchPlanResponse> {
    let installed = resolve_selection_for_future_use(state, installed_handle)?;
    let folder = resolve_selection_for_future_use(state, packages_handle)?;
    if installed.kind != SelectionKind::InstalledRoot
        || folder.kind != SelectionKind::PackagesFolder
    {
        return Err(DesktopFailure::InvalidRequest);
    }

    let packages = list_packages(&folder.path)?;
    let workspace = resolve_trusted_update_workspace(&app_data_root).map_err(map_core_error)?;
    // What each resource in this folder was last updated from, so a file only the operator changed
    // is not offered back as a question after every update.
    let root = installed.path.to_string_lossy();
    let remembered: BTreeMap<String, gkrm_core::BaselineId> =
        crate::installed_baseline::all(&app_data_root)
            .into_iter()
            .filter(|entry| entry.installed_root == root)
            .filter_map(|entry| {
                gkrm_core::BaselineId::parse(&entry.baseline_id)
                    .ok()
                    .map(|id| (entry.resource, id))
            })
            .collect();
    let plan =
        plan_batch(&installed.path, &packages, &workspace, &remembered).map_err(map_core_error)?;

    let entries: Vec<BatchEntryDto> = plan
        .entries()
        .iter()
        .enumerate()
        .map(|(index, entry)| entry_dto(index, entry))
        .collect();
    let ready_count = u32::try_from(plan.ready_count()).unwrap_or(u32::MAX);

    let mut registry = state.batches.lock().map_err(|_| DesktopFailure::Internal)?;
    let handle = registry.insert(BatchRecord {
        plan,
        installed: installed.path,
        installed_selection: installed_handle.to_owned(),
        packages_selection: packages_handle.to_owned(),
        packages_folder: folder.path,
        app_data_root,
        applied: false,
    });
    Ok(BatchPlanResponse {
        handle,
        entries,
        ready_count,
    })
}

/// Apply the entries that need no answer. This writes to the live installation.
pub fn batch_apply(state: &DesktopAppState, handle: &str) -> DesktopResult<BatchApplyResponse> {
    let (plan, installed, installed_selection, packages_selection, folder, app_data_root) = {
        let mut registry = state.batches.lock().map_err(|_| DesktopFailure::Internal)?;
        let record = registry
            .records
            .get_mut(handle)
            .ok_or(DesktopFailure::PlanNotFound)?;
        if record.applied {
            return Err(DesktopFailure::PlanAlreadyApplied);
        }
        // Claimed before the work starts, so a second request cannot write the same plan twice.
        record.applied = true;
        (
            record.plan.clone(),
            record.installed.clone(),
            record.installed_selection.clone(),
            record.packages_selection.clone(),
            record.packages_folder.clone(),
            record.app_data_root.clone(),
        )
    };

    // Both folders must still be the ones that were compared.
    let live_installed = resolve_selection_for_future_use(state, &installed_selection)?;
    let live_folder = resolve_selection_for_future_use(state, &packages_selection)?;
    if live_installed.path != installed || live_folder.path != folder {
        return Err(DesktopFailure::SelectionStale);
    }

    let workspace = resolve_trusted_update_workspace(&app_data_root).map_err(map_core_error)?;
    let outcome = apply_batch(&plan, &installed, &workspace);

    let mut results = Vec::with_capacity(outcome.results().len());
    for (index, (_, result)) in outcome.results().iter().enumerate() {
        if let Some(applied) = outcome.applied(index) {
            record_applied_update(
                &app_data_root,
                &installed,
                applied,
                &summarize(applied.plan()),
            );
        }
        results.push(BatchEntryResultDto {
            id: u32::try_from(index).unwrap_or(u32::MAX),
            result: match result {
                BatchApplyResult::Committed => BatchApplyResultKind::Committed,
                BatchApplyResult::Skipped => BatchApplyResultKind::Skipped,
                BatchApplyResult::Failed => BatchApplyResultKind::Failed,
                BatchApplyResult::NotAttempted => BatchApplyResultKind::NotAttempted,
            },
        });
    }
    Ok(BatchApplyResponse {
        results,
        committed_count: u32::try_from(outcome.committed_count()).unwrap_or(u32::MAX),
    })
}

/// Make one package of a batch selectable on the single-resource update screen.
///
/// The package's path never leaves this side: the screen gets the same opaque selection it would
/// have got from choosing the file itself, so the review of a package that needs answers happens
/// exactly where every other review does.
pub fn batch_open_package(
    state: &DesktopAppState,
    handle: &str,
    id: u32,
) -> DesktopResult<BatchOpenPackageResponse> {
    let (package, installed) = {
        let registry = state.batches.lock().map_err(|_| DesktopFailure::Internal)?;
        let record = registry
            .records
            .get(handle)
            .ok_or(DesktopFailure::PlanNotFound)?;
        let entry = record
            .plan
            .entries()
            .get(id as usize)
            .ok_or(DesktopFailure::PlanChangeNotFound)?;
        (entry.package().to_path_buf(), record.installed.clone())
    };
    let package_shape = validate_selection_shape(&package, SelectionKind::PackageFile)?;
    let installed_shape = validate_selection_shape(&installed, SelectionKind::InstalledRoot)?;
    let mut generator = UuidHandleGenerator;
    let mut registry = state
        .selections
        .lock()
        .map_err(|_| DesktopFailure::Internal)?;
    let package = registry.insert_validated(
        SelectionKind::PackageFile,
        package,
        package_shape,
        &mut generator,
    )?;
    let installed = match registry.insert_validated(
        SelectionKind::InstalledRoot,
        installed,
        installed_shape,
        &mut generator,
    ) {
        Ok(installed) => installed,
        Err(failure) => {
            // Do not leave the first one behind when the second cannot be made.
            let _ = registry.release(&package.handle);
            return Err(failure);
        }
    };
    Ok(BatchOpenPackageResponse { package, installed })
}

pub fn batch_release(state: &DesktopAppState, handle: &str) -> DesktopResult<BatchReleaseResponse> {
    let mut registry = state.batches.lock().map_err(|_| DesktopFailure::Internal)?;
    registry
        .records
        .remove(handle)
        .map(|_| BatchReleaseResponse { released: true })
        .ok_or(DesktopFailure::PlanNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    struct Fixture {
        _temp: tempfile::TempDir,
        installed: PathBuf,
        app_data: PathBuf,
        state: DesktopAppState,
        installed_handle: String,
        packages_handle: String,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().expect("temp");
        let installed = temp.path().join("installed");
        copy_tree(&fixtures().join("installed"), &installed);
        let packages = temp.path().join("packages");
        fs::create_dir_all(&packages).expect("packages");
        fs::copy(
            fixtures().join("packages/gksphone-update.zip"),
            packages.join("gksphone-update.zip"),
        )
        .expect("package");
        // Things in the folder that are not packages must be ignored, not reported.
        fs::write(packages.join("notes.txt"), b"not a package").expect("notes");
        fs::create_dir_all(packages.join("nested.zip")).expect("directory named like a zip");
        let app_data = temp.path().join("app-data");
        fs::create_dir_all(&app_data).expect("app data");
        let state = DesktopAppState::default();
        let installed_handle = select(&state, SelectionKind::InstalledRoot, &installed);
        let packages_handle = select(&state, SelectionKind::PackagesFolder, &packages);
        Fixture {
            _temp: temp,
            installed,
            app_data,
            state,
            installed_handle,
            packages_handle,
        }
    }

    #[test]
    fn planning_describes_each_package_by_name_without_writing() {
        let fixture = fixture();
        let before = fs::read(fixture.installed.join("gksphone/config.lua")).expect("config");
        let plan = batch_plan(
            &fixture.state,
            &fixture.installed_handle,
            &fixture.packages_handle,
            fixture.app_data.clone(),
        )
        .expect("plan");

        assert_eq!(plan.entries.len(), 1, "only the zip file is a package");
        let entry = &plan.entries[0];
        assert_eq!(entry.package_name, "gksphone-update.zip");
        assert_eq!(entry.resource.as_deref(), Some("gksphone"));
        assert_eq!(
            fs::read(fixture.installed.join("gksphone/config.lua")).expect("config"),
            before,
            "planning writes nothing"
        );
        let json = serde_json::to_string(&plan).expect("json");
        let installed_text =
            serde_json::to_string(&fixture.installed.to_string_lossy()).expect("path as json");
        let installed_text = installed_text.trim_matches('"');
        assert!(
            !json.contains(installed_text),
            "no path crosses the boundary"
        );
    }

    #[test]
    fn a_plan_applies_once_and_leaves_the_same_record_a_single_update_does() {
        let fixture = fixture();
        let plan = batch_plan(
            &fixture.state,
            &fixture.installed_handle,
            &fixture.packages_handle,
            fixture.app_data.clone(),
        )
        .expect("plan");

        let applied = batch_apply(&fixture.state, &plan.handle).expect("apply");
        assert_eq!(applied.results.len(), 1);
        let committed = applied.committed_count as usize;
        assert_eq!(
            committed, plan.ready_count as usize,
            "exactly the ready entries are written"
        );
        if committed == 1 {
            let history = crate::history::list(&fixture.app_data);
            assert_eq!(history.len(), 1, "the update is on the history screen");
        }

        assert_eq!(
            batch_apply(&fixture.state, &plan.handle),
            Err(DesktopFailure::PlanAlreadyApplied),
            "a plan is never written twice"
        );
        assert!(batch_release(&fixture.state, &plan.handle).is_ok());
        assert_eq!(
            batch_release(&fixture.state, &plan.handle),
            Err(DesktopFailure::PlanNotFound)
        );
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        use std::io::Write;
        let file = fs::File::create(path).expect("zip");
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, contents) in entries {
            writer.start_file(*name, options).expect("entry");
            writer.write_all(contents).expect("bytes");
        }
        writer.finish().expect("finish");
    }

    fn manifest(version: &str) -> Vec<u8> {
        format!(
            "fx_version 'cerulean'
version '{version}'
escrow_ignore {{ 'config.lua' }}
client_script 'client.lua'
"
        )
        .into_bytes()
    }

    /// A folder holding several resources is one installation root for all of them, and each was
    /// last updated from its own package. Remembering by root alone gave every resource the
    /// baseline of whichever was updated last, and the next update failed against the wrong one.
    #[test]
    fn each_resource_in_one_folder_reaches_for_its_own_remembered_baseline() {
        let temp = tempfile::tempdir().expect("temp");
        let installed = temp.path().join("resources");
        let packages = temp.path().join("packages");
        fs::create_dir_all(&packages).expect("packages");
        for name in ["alpha", "epsilon"] {
            let dir = installed.join(name);
            fs::create_dir_all(&dir).expect("resource");
            fs::write(dir.join("fxmanifest.lua"), manifest("1.0.0")).expect("manifest");
            fs::write(dir.join("client.lua"), b"v1").expect("client");
            fs::write(
                dir.join("config.lua"),
                b"Config.Mine = true
",
            )
            .expect("config");
            write_zip(
                &packages.join(format!("{name}.zip")),
                &[
                    (&format!("{name}/fxmanifest.lua"), &manifest("2.0.0")),
                    (&format!("{name}/client.lua"), b"v2"),
                    (
                        &format!("{name}/config.lua"),
                        b"Config.Mine = true
",
                    ),
                ],
            );
        }
        let app_data = temp.path().join("app-data");
        fs::create_dir_all(&app_data).expect("app data");
        let state = DesktopAppState::default();
        let installed_handle = select(&state, SelectionKind::InstalledRoot, &installed);
        let packages_handle = select(&state, SelectionKind::PackagesFolder, &packages);

        let plan = batch_plan(
            &state,
            &installed_handle,
            &packages_handle,
            app_data.clone(),
        )
        .expect("plan");
        assert_eq!(plan.ready_count, 2);
        let applied = batch_apply(&state, &plan.handle).expect("apply");
        assert_eq!(applied.committed_count, 2);

        // Close the finished updates, as the operator does, so the next ones may start.
        let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
        gkrm_core::retire_trusted_terminal_update_evidence(
            &workspace,
            gkrm_core::TrustedTerminalEvidenceRetirementOptions {
                acknowledged: true,
                ..Default::default()
            },
        )
        .expect("retire");

        for name in ["alpha", "epsilon"] {
            let next = packages.join(format!("{name}-3.zip"));
            write_zip(
                &next,
                &[
                    (&format!("{name}/fxmanifest.lua"), &manifest("3.0.0")),
                    (&format!("{name}/client.lua"), b"v3"),
                    (
                        &format!("{name}/config.lua"),
                        b"Config.Mine = true
",
                    ),
                ],
            );
            let handle = select(&state, SelectionKind::PackageFile, &next);
            let preview = crate::update::two_way_preview(
                &state,
                &installed_handle,
                &handle,
                None,
                app_data.clone(),
            )
            .unwrap_or_else(|failure| panic!("preview of {name} failed: {failure:?}"));
            assert!(
                preview.used_remembered_baseline,
                "{name} found its baseline"
            );
            assert_eq!(
                preview.remembered_baseline_version.as_deref(),
                Some("2.0.0"),
                "{name} was last updated to 2.0.0"
            );
        }
    }

    #[test]
    fn opening_a_package_for_review_hands_over_selections_of_its_own() {
        let fixture = fixture();
        let plan = batch_plan(
            &fixture.state,
            &fixture.installed_handle,
            &fixture.packages_handle,
            fixture.app_data.clone(),
        )
        .expect("plan");

        let opened = batch_open_package(&fixture.state, &plan.handle, 0).expect("open");
        assert_eq!(opened.package.kind, SelectionKind::PackageFile);
        assert_eq!(opened.installed.kind, SelectionKind::InstalledRoot);
        // New handles, so whoever releases them never lets go of the batch screen's own.
        assert_ne!(opened.installed.handle, fixture.installed_handle);
        assert_ne!(opened.package.handle, fixture.packages_handle);
        assert!(fixture
            .state
            .selections
            .lock()
            .expect("selections")
            .release(&opened.installed.handle)
            .is_ok());
        assert!(
            resolve_selection_for_future_use(&fixture.state, &fixture.installed_handle).is_ok(),
            "the batch screen's selection is untouched"
        );
        assert_eq!(
            batch_open_package(&fixture.state, &plan.handle, 99),
            Err(DesktopFailure::PlanChangeNotFound)
        );
    }

    #[test]
    fn an_updated_resource_with_kept_edits_is_not_offered_again() {
        let temp = tempfile::tempdir().expect("temp");
        let installed = temp.path().join("resources");
        let packages = temp.path().join("packages");
        fs::create_dir_all(&packages).expect("packages");
        let dir = installed.join("phone");
        fs::create_dir_all(&dir).expect("resource");
        fs::write(dir.join("fxmanifest.lua"), manifest("1.0.0")).expect("m");
        fs::write(dir.join("client.lua"), b"v1").expect("c");
        fs::write(
            dir.join("config.lua"),
            b"Config = {}\nConfig.Locale = 'tr'\nConfig.MaxContacts = 250\n",
        )
        .expect("cfg");
        let zip = packages.join("phone.zip");
        write_zip(
            &zip,
            &[
                ("phone/fxmanifest.lua", &manifest("2.0.0")),
                ("phone/client.lua", b"v2"),
                (
                    "phone/config.lua",
                    b"Config = {}\nConfig.Locale = 'en'\nConfig.MaxContacts = 100\nConfig.VoiceMail = true\n",
                ),
            ],
        );
        let app_data = temp.path().join("app-data");
        fs::create_dir_all(&app_data).expect("app");
        let state = DesktopAppState::default();
        let installed_handle = select(&state, SelectionKind::InstalledRoot, &installed);
        let pkg = select(&state, SelectionKind::PackageFile, &zip);
        let packages_handle = select(&state, SelectionKind::PackagesFolder, &packages);
        let before = batch_plan(
            &state,
            &installed_handle,
            &packages_handle,
            app_data.clone(),
        )
        .expect("plan before");
        assert_eq!(
            before.entries[0].kind,
            crate::dto::BatchEntryKind::NeedsReview
        );
        batch_release(&state, &before.handle).expect("release");
        let packages_handle = select(&state, SelectionKind::PackagesFolder, &packages);
        let before = batch_plan(
            &state,
            &installed_handle,
            &packages_handle,
            app_data.clone(),
        )
        .expect("plan before");
        assert_eq!(
            before.entries[0].kind,
            crate::dto::BatchEntryKind::NeedsReview
        );
        batch_release(&state, &before.handle).expect("release");
        let preview =
            crate::update::two_way_preview(&state, &installed_handle, &pkg, None, app_data.clone())
                .expect("first");
        assert_eq!(
            preview.summary.review, 1,
            "the first time it is a real question"
        );
        let applied =
            crate::update::two_way_apply(&state, &preview.handle, true, &[]).expect("apply");
        assert_eq!(applied.outcome, "committed");
        assert_eq!(
            fs::read_to_string(dir.join("config.lua")).expect("config"),
            "Config = {}\nConfig.Locale = 'tr'\nConfig.MaxContacts = 250\nConfig.VoiceMail = true\n",
            "the operator's lines are kept and the developer's new line is added"
        );
        let workspace = resolve_trusted_update_workspace(&app_data).expect("ws");
        gkrm_core::retire_trusted_terminal_update_evidence(
            &workspace,
            gkrm_core::TrustedTerminalEvidenceRetirementOptions {
                acknowledged: true,
                ..Default::default()
            },
        )
        .expect("retire");
        for attempt in 0..2 {
            let again = crate::update::two_way_preview(
                &state,
                &installed_handle,
                &pkg,
                None,
                app_data.clone(),
            )
            .expect("again");
            assert!(again.used_remembered_baseline);
            assert_eq!(
                again.summary.review, 0,
                "nothing is asked again (attempt {attempt})"
            );
            assert_eq!(
                again.summary.take_from_update, 0,
                "nothing to apply (attempt {attempt})"
            );
        }

        // The batch screen knows it too: the same package is not offered for review again.
        let after = batch_plan(
            &state,
            &installed_handle,
            &packages_handle,
            app_data.clone(),
        )
        .expect("plan after");
        assert_eq!(after.entries[0].kind, crate::dto::BatchEntryKind::UpToDate);
        assert_eq!(after.ready_count, 0);

        // The batch screen knows it too: the same package is not offered for review again.
        let after = batch_plan(
            &state,
            &installed_handle,
            &packages_handle,
            app_data.clone(),
        )
        .expect("plan after");
        assert_eq!(after.entries[0].kind, crate::dto::BatchEntryKind::UpToDate);
        assert_eq!(after.ready_count, 0);
    }

    #[test]
    fn a_changed_folder_is_refused_before_anything_is_written() {
        let fixture = fixture();
        let plan = batch_plan(
            &fixture.state,
            &fixture.installed_handle,
            &fixture.packages_handle,
            fixture.app_data.clone(),
        )
        .expect("plan");
        fixture
            .state
            .selections
            .lock()
            .expect("selections")
            .release(&fixture.packages_handle)
            .expect("release");
        assert_eq!(
            batch_apply(&fixture.state, &plan.handle),
            Err(DesktopFailure::SelectionNotFound)
        );
    }
}
