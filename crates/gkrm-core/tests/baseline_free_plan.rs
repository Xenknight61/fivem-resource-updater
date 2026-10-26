use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    create_baseline_free_update_plan, BaselineFreeDisposition, FileComparisonStatus,
    InspectionOptions, InstalledResourceRoot, ResourceMatchKind, UpdatePlanReason,
    UpdatePlanWarning, ZipResourceRoot,
};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = br#"
fx_version 'cerulean'
escrow_ignore {
  'editable.lua',
  'new_editable.lua',
}
"#;

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("test path should have parent"))
        .expect("parent should be created");
    fs::write(path, contents).expect("file should be written");
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("zip should be created");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    for (name, contents) in entries {
        writer
            .start_file(*name, options)
            .expect("entry should start");
        writer.write_all(contents).expect("entry should be written");
    }

    writer.finish().expect("zip should finish");
}

fn inspect_matrix_fixture() -> (tempfile::TempDir, gkrm_core::FullInspectionReport) {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), MANIFEST);
    write_file(
        &installed.join("protected_changed.lua"),
        b"installed protected",
    );
    write_file(&installed.join("editable.lua"), b"installed editable");
    write_file(&installed.join("unsupported.txt"), b"installed unsupported");
    write_file(&installed.join("old.lua"), b"old");

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/protected_changed.lua", b"incoming protected"),
            ("gksphone/editable.lua", b"incoming editable"),
            ("gksphone/unsupported.txt", b"incoming unsupported"),
            ("gksphone/new_protected.lua", b"new protected"),
            ("gksphone/new_editable.lua", b"new editable"),
            ("gksphone/new_unsupported.txt", b"new unsupported"),
        ],
    );

    let report =
        gkrm_core::inspect_installation_update(&installed, &package, InspectionOptions::default())
            .expect("inspection should succeed");
    (temp, report)
}

fn plan_files(
    plan: &gkrm_core::BaselineFreeUpdatePlan,
) -> Vec<(
    &str,
    FileComparisonStatus,
    BaselineFreeDisposition,
    UpdatePlanReason,
)> {
    plan.resources()[0]
        .files()
        .iter()
        .map(|file| {
            (
                file.relative_path().as_str(),
                file.comparison_status(),
                file.disposition(),
                file.reason(),
            )
        })
        .collect()
}

fn file_names(plan: &gkrm_core::BaselineFreeUpdatePlan) -> Vec<&str> {
    plan.resources()[0]
        .files()
        .iter()
        .map(|file| file.relative_path().as_str())
        .collect()
}

fn snapshot_directory(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    snapshot_directory_inner(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn snapshot_directory_inner(root: &Path, directory: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in fs::read_dir(directory).expect("directory should read") {
        let entry = entry.expect("entry should read");
        let path = entry.path();
        let metadata = entry.metadata().expect("metadata should read");
        if metadata.is_dir() {
            snapshot_directory_inner(root, &path, files);
        } else if metadata.is_file() {
            files.push((
                path.strip_prefix(root)
                    .expect("path should be below root")
                    .to_path_buf(),
                fs::read(&path).expect("file should read"),
            ));
        }
    }
}

#[test]
fn decision_matrix_expected_state_counts_and_order_are_deterministic() {
    let (_temp, report) = inspect_matrix_fixture();

    let plan = create_baseline_free_update_plan(&report).expect("plan should be created");

    assert_eq!(plan.resources().len(), 1);
    assert_eq!(
        plan.resources()[0].resource_match().match_kind,
        ResourceMatchKind::ExactName
    );
    assert_eq!(
        plan_files(&plan),
        vec![
            (
                "editable.lua",
                FileComparisonStatus::Changed,
                BaselineFreeDisposition::MergeCandidate,
                UpdatePlanReason::EditableFileChangedWithoutBaseline,
            ),
            (
                "fxmanifest.lua",
                FileComparisonStatus::Unchanged,
                BaselineFreeDisposition::NoChange,
                UpdatePlanReason::HashesMatch,
            ),
            (
                "new_editable.lua",
                FileComparisonStatus::IncomingOnly,
                BaselineFreeDisposition::AddCandidate,
                UpdatePlanReason::IncomingFileHasNoInstalledCounterpart,
            ),
            (
                "new_protected.lua",
                FileComparisonStatus::IncomingOnly,
                BaselineFreeDisposition::AddCandidate,
                UpdatePlanReason::IncomingFileHasNoInstalledCounterpart,
            ),
            (
                "new_unsupported.txt",
                FileComparisonStatus::IncomingOnly,
                BaselineFreeDisposition::AddCandidate,
                UpdatePlanReason::IncomingFileHasNoInstalledCounterpart,
            ),
            (
                "old.lua",
                FileComparisonStatus::InstalledOnly,
                BaselineFreeDisposition::Preserve,
                UpdatePlanReason::InstalledFileHasNoIncomingCounterpart,
            ),
            (
                "protected_changed.lua",
                FileComparisonStatus::Changed,
                BaselineFreeDisposition::ReplaceCandidate,
                UpdatePlanReason::ProtectedFileChanged,
            ),
            (
                "unsupported.txt",
                FileComparisonStatus::Changed,
                BaselineFreeDisposition::ConflictReview,
                UpdatePlanReason::UnsupportedFileChangedWithoutProfile,
            ),
        ]
    );

    let counts = plan.counts();
    assert_eq!(counts.resources_planned(), 1);
    assert_eq!(counts.no_change_files(), 1);
    assert_eq!(counts.replace_candidates(), 1);
    assert_eq!(counts.add_candidates(), 3);
    assert_eq!(counts.merge_candidates(), 1);
    assert_eq!(counts.preserved_files(), 1);
    assert_eq!(counts.conflict_review_files(), 1);
    assert_eq!(counts.unmatched_installed_resources(), 0);
    assert_eq!(counts.unmatched_incoming_resources(), 0);

    for (planned, compared) in plan.resources()[0]
        .files()
        .iter()
        .zip(report.comparison().matched_resources[0].files.iter())
    {
        assert_eq!(planned.relative_path(), &compared.relative_path);
        assert_eq!(
            planned.expected_installed().map(|state| state.size()),
            compared.installed.as_ref().map(|side| side.size)
        );
        assert_eq!(
            planned.expected_installed().map(|state| state.sha256()),
            compared.installed.as_ref().map(|side| &side.sha256)
        );
        assert_eq!(
            planned.expected_incoming().map(|state| state.size()),
            compared.incoming.as_ref().map(|side| side.size)
        );
        assert_eq!(
            planned.expected_incoming().map(|state| state.sha256()),
            compared.incoming.as_ref().map(|side| &side.sha256)
        );
        assert_eq!(
            planned.incoming_escrow_classification(),
            compared
                .incoming
                .as_ref()
                .map(|side| &side.escrow_classification)
        );
    }
}

#[test]
fn baseline_warning_appears_once_and_fallback_warning_is_preserved() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), b"fx_version 'cerulean'");
    write_file(&installed.join("client.lua"), b"same");

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("fxmanifest.lua", b"fx_version 'cerulean'"),
            ("client.lua", b"same"),
        ],
    );

    let report =
        gkrm_core::inspect_installation_update(&installed, &package, InspectionOptions::default())
            .expect("inspection should succeed");
    let plan = create_baseline_free_update_plan(&report).expect("plan should be created");

    assert_eq!(
        plan.warnings(),
        &[
            UpdatePlanWarning::BaselineUnavailable,
            UpdatePlanWarning::SingleResourceFallback {
                installed_resource: InstalledResourceRoot::Root,
                incoming_resource: ZipResourceRoot::Root,
            },
        ]
    );
}

#[test]
fn unmatched_resources_are_retained_without_file_plans() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), b"fx_version 'cerulean'");

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[("other/fxmanifest.lua", b"fx_version 'cerulean'")],
    );

    let report =
        gkrm_core::inspect_installation_update(&installed, &package, InspectionOptions::default())
            .expect("inspection should succeed");
    let plan = create_baseline_free_update_plan(&report).expect("plan should be created");

    assert!(plan.resources().is_empty());
    assert_eq!(plan.unmatched_installed_resources().len(), 1);
    assert_eq!(plan.unmatched_incoming_resources().len(), 1);
    assert_eq!(plan.counts().unmatched_installed_resources(), 1);
    assert_eq!(plan.counts().unmatched_incoming_resources(), 1);
}

#[test]
fn planning_uses_only_trusted_report_and_does_not_touch_filesystem() {
    let (temp, report) = inspect_matrix_fixture();
    let installed = temp.path().join("gksphone");
    let package = temp.path().join("update.zip");
    let before = snapshot_directory(&installed);

    let first = create_baseline_free_update_plan(&report).expect("plan should be created");
    assert_eq!(
        snapshot_directory(&installed),
        before,
        "planning must not modify installed files"
    );
    assert!(
        !installed.join("new_protected.lua").exists(),
        "planning must not extract ZIP entries"
    );

    fs::remove_file(&package).expect("package should be removable after inspection");
    fs::remove_dir_all(&installed)
        .expect("installed resource should be removable after inspection");

    let second = create_baseline_free_update_plan(&report)
        .expect("planning should use trusted report without filesystem access");
    assert_eq!(file_names(&first), file_names(&second));
}
