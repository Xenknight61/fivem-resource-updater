//! Essential Task 25 workflow tests.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};

use sha2::{Digest, Sha256};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

use super::id::encode_operator_merge_set_id;
use super::operator_merge::validate_and_load_operator_merge_root;
use super::publish::{
    publish_bytes_no_replace, set_publish_parent_sync_fault, set_publish_post_verify_fault,
};
use super::test_hooks::{with_hooks, TrustedCliPlanTestHooks};
use super::{
    apply_trusted_cli_update, apply_trusted_desktop_update,
    apply_trusted_desktop_update_with_test_hooks, build_decision_document, encode_cli_artifact,
    parse_cli_artifact, plan_trusted_cli_update, plan_trusted_cli_update_for_review,
    plan_trusted_cli_update_for_review_with_expected_source_commitments,
    plan_trusted_cli_update_for_review_with_test_hooks, prepare_bound_trusted_update_sources,
    resolve_selected_resource, source_commitments_from_report, status_trusted_cli_update,
    TrustedCliApplyRequest, TrustedCliDecisionEntry, TrustedCliPlanRequest,
    TrustedCliPlanReviewReport, TrustedCliReport, TrustedCliStatusRequest,
    TrustedCliUpdateArtifactBody, TrustedCliUpdateOptions, TrustedDesktopApplyAuthority,
    TrustedDesktopApplyRequest,
};
use crate::file_identity::is_windows_reparse_point_std;
use crate::trusted_staging::test_support::{build_mini, MiniFixture};
use crate::trusted_transactional_apply_execution::hooks::{
    authority_verification_events, lock_execution_hooks, set_force_temp_directory_sync_failure,
    set_forward_op_fault, set_journal_fault, set_post_lock_resource_key, set_publication_hook,
    AuthorityVerificationEvent, ForwardOpFault, JournalFault, PublicationPoint,
};
use crate::{
    inspect_installation_update, inspection::inspect_installation_update_from_package_snapshot,
    resolve_trusted_update_workspace_from_explicit_roots, review_three_way_update_plan, GkrmError,
    InspectionOptions, OfficialBaselineSelector, PolicyTransitionAcknowledgement,
    RecoveryAuthorityLimits, ResourceRelativePath, SafeResourceKey, Sha256Digest,
    ThreeWayPlanDecisionChoice, ThreeWayPlanReviewRequest, TrustedTransactionRoot,
};

const SIMPLE_MANIFEST: &[u8] = b"fx_version 'cerulean'\n";

const FIXED_TASK25_ARTIFACT_ID: &str =
    "c7d5d4840df43746676c4cf9e303605d86e0d0ee59ffcedfbddea5118dc6d00b";

const FIXED_EMPTY_OPERATOR_MERGE_SET_ID: &str =
    "a5490df122af7ecda39765b11beb14f5d2f39499f2ec4a4d099531c0569f1e76";

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, contents) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(contents).unwrap();
    }
    writer.finish().unwrap();
}

fn write_simple_resource(root: &Path, client: &[u8]) {
    write_file(
        &root.join("gksphone").join("fxmanifest.lua"),
        SIMPLE_MANIFEST,
    );
    write_file(&root.join("gksphone").join("client.lua"), client);
}

fn fixed_artifact_body() -> TrustedCliUpdateArtifactBody {
    TrustedCliUpdateArtifactBody {
        package_fingerprint: Sha256Digest::new([1; 32]),
        selected_resource_commitment: Sha256Digest::new([2; 32]),
        baseline_id_digest: Sha256Digest::new([3; 32]),
        plan_id: Sha256Digest::new([4; 32]),
        review_id: Sha256Digest::new([5; 32]),
        analysis_id: None,
        text_diff_id: None,
        synthesis_id: None,
        merged_bytes_id: None,
        operator_merge_set_id: Sha256Digest::new([6; 32]),
        staging_manifest_id: Sha256Digest::new([7; 32]),
        staging_bundle_id: Sha256Digest::new([8; 32]),
        apply_plan_id: Sha256Digest::new([9; 32]),
        snapshot_a: Sha256Digest::new([10; 32]),
        transactional_plan_id: Sha256Digest::new([11; 32]),
        recovery_authority_id: None,
        decision_document_id: Sha256Digest::new([12; 32]),
    }
}

#[test]
fn prepared_source_snapshot_commitments_match_unchanged_scan_commitments() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    write_simple_resource(&installed, b"base\n");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"base\n"),
        ],
    );
    let report =
        inspect_installation_update(&installed, &package, InspectionOptions::default()).unwrap();
    let selected =
        resolve_selected_resource(&report, Some(&SafeResourceKey::parse("gksphone").unwrap()))
            .unwrap();
    let accepted = source_commitments_from_report(&report, &selected).unwrap();

    let bound = prepare_bound_trusted_update_sources(
        &installed,
        &package,
        &selected,
        &accepted,
        TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    let sealed_report = inspect_installation_update_from_package_snapshot(
        bound.installed_root(),
        bound.incoming_package.as_ref(),
        InspectionOptions::default(),
    )
    .unwrap();
    let sealed_selected = resolve_selected_resource(
        &sealed_report,
        Some(&SafeResourceKey::parse("gksphone").unwrap()),
    )
    .unwrap();
    let sealed = source_commitments_from_report(&sealed_report, &sealed_selected).unwrap();
    assert_eq!(accepted, sealed);
}

#[test]
fn prepared_installed_snapshot_commitment_rejects_membership_change() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    write_simple_resource(&installed, b"base\n");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"base\n"),
        ],
    );
    let report =
        inspect_installation_update(&installed, &package, InspectionOptions::default()).unwrap();
    let selected =
        resolve_selected_resource(&report, Some(&SafeResourceKey::parse("gksphone").unwrap()))
            .unwrap();
    let accepted = source_commitments_from_report(&report, &selected).unwrap();
    write_file(&installed.join("gksphone").join("extra.lua"), b"extra\n");

    let err = prepare_bound_trusted_update_sources(
        &installed,
        &package,
        &selected,
        &accepted,
        TrustedCliUpdateOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err, GkrmError::TrustedUpdateSourceChanged));
}

#[test]
fn prepared_package_snapshot_commitment_rejects_same_entry_content_change() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    write_simple_resource(&installed, b"base\n");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"base\n"),
        ],
    );
    let report =
        inspect_installation_update(&installed, &package, InspectionOptions::default()).unwrap();
    let selected =
        resolve_selected_resource(&report, Some(&SafeResourceKey::parse("gksphone").unwrap()))
            .unwrap();
    let accepted = source_commitments_from_report(&report, &selected).unwrap();
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"bAse\n"),
        ],
    );

    let err = prepare_bound_trusted_update_sources(
        &installed,
        &package,
        &selected,
        &accepted,
        TrustedCliUpdateOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(err, GkrmError::TrustedUpdateSourceChanged));
}

#[test]
fn prepared_installed_snapshot_rejects_same_content_replacement_before_reopen() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    write_simple_resource(&installed, b"base\n");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"base\n"),
        ],
    );
    let report =
        inspect_installation_update(&installed, &package, InspectionOptions::default()).unwrap();
    let selected =
        resolve_selected_resource(&report, Some(&SafeResourceKey::parse("gksphone").unwrap()))
            .unwrap();
    let accepted = source_commitments_from_report(&report, &selected).unwrap();
    let target = installed.join("gksphone").join("client.lua");
    let hook = TrustedCliPlanTestHooks {
        before_source_child_reopen: Some(Arc::new(move |relative| {
            if relative == Path::new("client.lua") {
                fs::remove_file(&target).unwrap();
                fs::write(&target, b"base\n").unwrap();
            }
        })),
        ..TrustedCliPlanTestHooks::default()
    };

    let err = with_hooks(hook, || {
        prepare_bound_trusted_update_sources(
            &installed,
            &package,
            &selected,
            &accepted,
            TrustedCliUpdateOptions::default(),
        )
    })
    .unwrap_err();
    assert!(matches!(err, GkrmError::TrustedUpdateSourceChanged));
}

#[cfg(unix)]
#[test]
fn prepared_installed_snapshot_rejects_symlink_replacement_before_reopen() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    write_simple_resource(&installed, b"base\n");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"base\n"),
        ],
    );
    let report =
        inspect_installation_update(&installed, &package, InspectionOptions::default()).unwrap();
    let selected =
        resolve_selected_resource(&report, Some(&SafeResourceKey::parse("gksphone").unwrap()))
            .unwrap();
    let accepted = source_commitments_from_report(&report, &selected).unwrap();
    let target = installed.join("gksphone").join("client.lua");
    let link_target = temp.path().join("link-target.lua");
    fs::write(&link_target, b"base\n").unwrap();
    let hook = TrustedCliPlanTestHooks {
        before_source_child_reopen: Some(Arc::new(move |relative| {
            if relative == Path::new("client.lua") {
                fs::remove_file(&target).unwrap();
                std::os::unix::fs::symlink(&link_target, &target).unwrap();
            }
        })),
        ..TrustedCliPlanTestHooks::default()
    };

    let err = with_hooks(hook, || {
        prepare_bound_trusted_update_sources(
            &installed,
            &package,
            &selected,
            &accepted,
            TrustedCliUpdateOptions::default(),
        )
    })
    .unwrap_err();
    assert!(matches!(err, GkrmError::TrustedUpdateSourceChanged));
}

#[cfg(windows)]
#[test]
fn prepared_installed_snapshot_rejects_junction_replacement_before_reopen() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    write_simple_resource(&installed, b"base\n");
    fs::create_dir_all(installed.join("gksphone").join("nested")).unwrap();
    write_file(
        &installed.join("gksphone").join("nested").join("child.lua"),
        b"nested\n",
    );
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"base\n"),
            ("gksphone/nested/child.lua", b"nested\n"),
        ],
    );
    let report =
        inspect_installation_update(&installed, &package, InspectionOptions::default()).unwrap();
    let selected =
        resolve_selected_resource(&report, Some(&SafeResourceKey::parse("gksphone").unwrap()))
            .unwrap();
    let accepted = source_commitments_from_report(&report, &selected).unwrap();
    let target = installed.join("gksphone").join("nested");
    let junction_target = temp.path().join("junction-target");
    fs::create_dir_all(&junction_target).unwrap();
    let hook = TrustedCliPlanTestHooks {
        before_source_child_reopen: Some(Arc::new(move |relative| {
            if relative == Path::new("nested") {
                fs::remove_dir_all(&target).unwrap();
                create_junction(&junction_target, &target);
            }
        })),
        ..TrustedCliPlanTestHooks::default()
    };

    let err = with_hooks(hook, || {
        prepare_bound_trusted_update_sources(
            &installed,
            &package,
            &selected,
            &accepted,
            TrustedCliUpdateOptions::default(),
        )
    })
    .unwrap_err();
    assert!(matches!(err, GkrmError::TrustedUpdateSourceChanged));
}

#[cfg(windows)]
fn create_junction(target: &Path, link: &Path) {
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            link.to_str().unwrap(),
            target.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mklink");
    assert!(status.success(), "directory junction creation must succeed");
}

#[cfg(unix)]
#[test]
fn source_replacement_after_secure_open_copies_opened_handle_or_source_changed() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    write_simple_resource(&installed, b"base\n");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("gksphone/client.lua", b"base\n"),
        ],
    );
    let report =
        inspect_installation_update(&installed, &package, InspectionOptions::default()).unwrap();
    let selected =
        resolve_selected_resource(&report, Some(&SafeResourceKey::parse("gksphone").unwrap()))
            .unwrap();
    let accepted = source_commitments_from_report(&report, &selected).unwrap();
    let target = installed.join("gksphone").join("client.lua");
    let hook = TrustedCliPlanTestHooks {
        after_source_file_opened_before_copy: Some(Arc::new(move |relative| {
            if relative == Path::new("client.lua") {
                fs::remove_file(&target).unwrap();
                fs::write(&target, b"replaced\n").unwrap();
            }
        })),
        ..TrustedCliPlanTestHooks::default()
    };

    match with_hooks(hook, || {
        prepare_bound_trusted_update_sources(
            &installed,
            &package,
            &selected,
            &accepted,
            TrustedCliUpdateOptions::default(),
        )
    }) {
        Ok(bound) => {
            let copied =
                fs::read(bound.installed_root().join("gksphone").join("client.lua")).unwrap();
            assert_eq!(copied, b"base\n");
        }
        Err(error) => assert!(matches!(error, GkrmError::TrustedUpdateSourceChanged)),
    }
}

fn run_ready_plan_with_hook(
    hook: TrustedCliPlanTestHooks,
) -> (
    std::result::Result<super::TrustedCliReport, GkrmError>,
    crate::trusted_staging::test_support::MiniFixture,
    PathBuf,
    PathBuf,
) {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-snapshot-tamper");
    let staging = fixture._temp.path().join("staging-snapshot-tamper");
    let artifact_out = fixture
        ._temp
        .path()
        .join("out-snapshot-tamper")
        .join("plan.bin");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = fixture
        ._temp
        .path()
        .join("dec-snapshot-tamper")
        .join("decisions.bin");
    write_decisions_file(&fixture, &decisions);
    let result = plan_trusted_cli_update_for_review_with_test_hooks(
        TrustedCliPlanRequest {
            package: &fixture.package_v2,
            installed: &fixture.installed_parent,
            baseline_store: &fixture.store,
            baseline_selector: OfficialBaselineSelector::Exact(
                fixture.baseline.baseline_id().clone(),
            ),
            resource: None,
            staging_root: &staging,
            transaction_root: &txn,
            decisions_path: Some(&decisions),
            decisions_out: None,
            operator_merge_root: None,
            artifact_out: &artifact_out,
            workspace: None,
            workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
            options: TrustedCliUpdateOptions::default(),
        },
        hook,
    )
    .map(|report| report.report);
    (result, fixture, artifact_out, staging)
}

#[test]
fn private_installed_snapshot_content_mutation_after_sealing_is_not_source_changed() {
    let hook = TrustedCliPlanTestHooks {
        after_sealed_snapshot_verified_before_staging: Some(Arc::new(|snapshot_root| {
            fs::write(
                snapshot_root.join("gksphone").join("take.lua"),
                b"tampered\n",
            )
            .unwrap();
        })),
        ..TrustedCliPlanTestHooks::default()
    };
    let (result, _fixture, artifact_out, staging) = run_ready_plan_with_hook(hook);
    let err = result.unwrap_err();
    assert_private_snapshot_tamper_failure(&err);
    assert!(!matches!(err, GkrmError::TrustedUpdateSourceChanged));
    assert!(!artifact_out.exists());
    assert!(!staging.join("bundles").exists());
}

#[cfg(unix)]
#[test]
fn private_installed_snapshot_symlink_injection_after_sealing_is_not_source_changed() {
    let hook = TrustedCliPlanTestHooks {
        after_sealed_snapshot_verified_before_staging: Some(Arc::new(|snapshot_root| {
            let target = snapshot_root.join("gksphone").join("take.lua");
            fs::remove_file(&target).unwrap();
            std::os::unix::fs::symlink("/tmp", &target).unwrap();
        })),
        ..TrustedCliPlanTestHooks::default()
    };
    let (result, _fixture, artifact_out, staging) = run_ready_plan_with_hook(hook);
    let err = result.unwrap_err();
    assert_private_snapshot_tamper_failure(&err);
    assert!(!matches!(err, GkrmError::TrustedUpdateSourceChanged));
    assert!(!artifact_out.exists());
    assert!(!staging.join("bundles").exists());
}

#[cfg(windows)]
#[test]
fn private_installed_snapshot_junction_injection_after_sealing_is_not_source_changed() {
    let hook = TrustedCliPlanTestHooks {
        after_sealed_snapshot_verified_before_staging: Some(Arc::new(|snapshot_root| {
            let target = snapshot_root.join("junction-target");
            fs::create_dir_all(&target).unwrap();
            let replaced = snapshot_root.join("gksphone");
            fs::remove_dir_all(&replaced).unwrap();
            create_junction(&target, &replaced);
        })),
        ..TrustedCliPlanTestHooks::default()
    };
    let (result, _fixture, artifact_out, staging) = run_ready_plan_with_hook(hook);
    let err = result.unwrap_err();
    assert_private_snapshot_tamper_failure(&err);
    assert!(!matches!(err, GkrmError::TrustedUpdateSourceChanged));
    assert!(!artifact_out.exists());
    assert!(!staging.join("bundles").exists());
}

fn assert_private_snapshot_tamper_failure(error: &GkrmError) {
    assert!(
        matches!(
            error,
            GkrmError::TrustedCliUpdateSecurityRejection
                | GkrmError::ThreeWayMergeAnalysisInstalledPreFingerprintMismatch
                | GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid
                | GkrmError::TrustedStagingSourceUnavailable
                | GkrmError::TrustedStagingDigestLengthMismatch
                | GkrmError::TrustedStagingUnsafeFilesystemObject
                | GkrmError::InstalledEntrySymlink { .. }
                | GkrmError::InstalledEntryReparsePoint { .. }
        ),
        "unexpected private snapshot tamper error: {error:?}"
    );
}

fn build_decision_entries(
    fixture: &crate::trusted_staging::test_support::MiniFixture,
) -> Vec<TrustedCliDecisionEntry> {
    build_decision_entries_with_take_choice(fixture, ThreeWayPlanDecisionChoice::UseIncomingState)
}

fn build_decision_entries_with_take_choice(
    fixture: &crate::trusted_staging::test_support::MiniFixture,
    take_choice: ThreeWayPlanDecisionChoice,
) -> Vec<TrustedCliDecisionEntry> {
    fixture
        .plan
        .entries()
        .iter()
        .filter_map(|e| {
            let choice = match e.path().as_str() {
                "merge.lua" => ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                "take.lua" => take_choice,
                _ => return None,
            };
            Some(TrustedCliDecisionEntry {
                path: e.path().clone(),
                choice,
                policy_acknowledgement: PolicyTransitionAcknowledgement::NotProvided,
                operator_merge_relpath: None,
            })
        })
        .collect()
}

fn write_decisions_file(fixture: &crate::trusted_staging::test_support::MiniFixture, path: &Path) {
    write_decisions_file_with_take_choice(
        fixture,
        path,
        ThreeWayPlanDecisionChoice::UseIncomingState,
    );
}

fn write_decisions_file_with_take_choice(
    fixture: &crate::trusted_staging::test_support::MiniFixture,
    path: &Path,
    take_choice: ThreeWayPlanDecisionChoice,
) {
    let entries = build_decision_entries_with_take_choice(fixture, take_choice);
    let doc = build_decision_document(&fixture.plan, entries, &TrustedCliUpdateOptions::default())
        .unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, doc.canonical_bytes()).unwrap();
}

struct DirectDesktopApplyFixture {
    mini: MiniFixture,
    txn: PathBuf,
    staging: PathBuf,
    artifact_out: PathBuf,
    review_report: TrustedCliPlanReviewReport,
}

fn copy_test_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_test_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn ready_workspace_desktop_apply(
    name: &str,
) -> (
    MiniFixture,
    crate::TrustedUpdateWorkspace,
    TrustedCliPlanReviewReport,
) {
    ready_workspace_desktop_apply_with_take_choice(
        name,
        ThreeWayPlanDecisionChoice::UseIncomingState,
    )
}

fn ready_workspace_desktop_apply_with_take_choice(
    name: &str,
    take_choice: ThreeWayPlanDecisionChoice,
) -> (
    MiniFixture,
    crate::TrustedUpdateWorkspace,
    TrustedCliPlanReviewReport,
) {
    let mini = build_mini();
    let workspace_root = mini._temp.path().join(format!("workspace-{name}"));
    let workspace = crate::resolve_trusted_update_workspace(&workspace_root).unwrap();
    copy_test_tree(&mini.store, workspace.baseline_store());
    let artifact_out = workspace
        .artifact_root()
        .allocate_plan_artifact_path()
        .unwrap();
    let decisions = mini
        ._temp
        .path()
        .join(format!("dec-workspace-{name}"))
        .join("decisions.bin");
    write_decisions_file_with_take_choice(&mini, &decisions, take_choice);
    let inspection = inspect_installation_update(
        &mini.installed_parent,
        &mini.package_v2,
        InspectionOptions::default(),
    )
    .unwrap();
    let selected = resolve_selected_resource(
        &inspection,
        Some(&SafeResourceKey::parse("gksphone").unwrap()),
    )
    .unwrap();
    let expected = source_commitments_from_report(&inspection, &selected).unwrap();
    let report = plan_trusted_cli_update_for_review_with_expected_source_commitments(
        TrustedCliPlanRequest {
            package: &mini.package_v2,
            installed: &mini.installed_parent,
            baseline_store: workspace.baseline_store(),
            baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
            resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
            staging_root: workspace.staging_root(),
            transaction_root: workspace.transaction_root(),
            decisions_path: Some(&decisions),
            decisions_out: None,
            operator_merge_root: None,
            artifact_out: &artifact_out,
            workspace: Some(&workspace),
            workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
            options: TrustedCliUpdateOptions::default(),
        },
        &expected,
    )
    .unwrap();
    (mini, workspace, report)
}

fn ready_desktop_apply_fixture(name: &str) -> DirectDesktopApplyFixture {
    let mini = build_mini();
    let txn = mini._temp.path().join(format!("txn-{name}"));
    let staging = mini._temp.path().join(format!("staging-{name}"));
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = mini._temp.path().join("out").join(format!("{name}.bin"));
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = mini
        ._temp
        .path()
        .join(format!("dec-{name}"))
        .join("decisions.bin");
    write_decisions_file(&mini, &decisions);

    let inspection = inspect_installation_update(
        &mini.installed_parent,
        &mini.package_v2,
        InspectionOptions::default(),
    )
    .unwrap();
    let selected = resolve_selected_resource(
        &inspection,
        Some(&SafeResourceKey::parse("gksphone").unwrap()),
    )
    .unwrap();
    let expected = source_commitments_from_report(&inspection, &selected).unwrap();
    let review_report = plan_trusted_cli_update_for_review_with_expected_source_commitments(
        TrustedCliPlanRequest {
            package: &mini.package_v2,
            installed: &mini.installed_parent,
            baseline_store: &mini.store,
            baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
            resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
            staging_root: &staging,
            transaction_root: &txn,
            decisions_path: Some(&decisions),
            decisions_out: None,
            operator_merge_root: None,
            artifact_out: &artifact_out,
            workspace: None,
            workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
            options: TrustedCliUpdateOptions::default(),
        },
        &expected,
    )
    .unwrap();
    assert_eq!(review_report.report.outcome, "ready_to_apply");

    DirectDesktopApplyFixture {
        mini,
        txn,
        staging,
        artifact_out,
        review_report,
    }
}

fn apply_direct_desktop(fixture: &DirectDesktopApplyFixture) -> crate::Result<TrustedCliReport> {
    let authority = fixture
        .review_report
        .desktop_apply_authority
        .as_ref()
        .expect("ready desktop plan should retain authority");
    apply_trusted_desktop_update(TrustedDesktopApplyRequest {
        authority,
        options: TrustedCliUpdateOptions::default(),
    })
}

fn apply_direct_desktop_accepting_current_artifact_id(
    fixture: &DirectDesktopApplyFixture,
) -> crate::Result<TrustedCliReport> {
    let base = fixture
        .review_report
        .desktop_apply_authority
        .as_ref()
        .expect("ready desktop plan should retain authority");
    let artifact = parse_cli_artifact(
        &fs::read(&fixture.artifact_out).unwrap(),
        &TrustedCliUpdateOptions::default(),
    )?;
    let authority = TrustedDesktopApplyAuthority {
        workspace: base.workspace.clone(),
        artifact: base.artifact.clone(),
        installed: base.installed.clone(),
        baseline_store: base.baseline_store.clone(),
        staging_root: base.staging_root.clone(),
        transaction_root: base.transaction_root.clone(),
        expected_artifact_id: *artifact.artifact_id(),
        installed_root_identity: base.installed_root_identity.clone(),
        selected_resource_identity: base.selected_resource_identity.clone(),
        resource_key: base.resource_key.clone(),
        selected_installed_root: base.selected_installed_root.clone(),
    };
    apply_trusted_desktop_update(TrustedDesktopApplyRequest {
        authority: &authority,
        options: TrustedCliUpdateOptions::default(),
    })
}

fn apply_direct_desktop_after_bundle_verify_hook(
    fixture: &DirectDesktopApplyFixture,
    hook: Arc<dyn Fn() + Send + Sync>,
) -> crate::Result<TrustedCliReport> {
    let authority = fixture
        .review_report
        .desktop_apply_authority
        .as_ref()
        .expect("ready desktop plan should retain authority");
    apply_trusted_desktop_update_with_test_hooks(
        TrustedDesktopApplyRequest {
            authority,
            options: TrustedCliUpdateOptions::default(),
        },
        TrustedCliPlanTestHooks {
            after_published_bundle_verified_before_descriptor_graph: Some(hook),
            ..TrustedCliPlanTestHooks::default()
        },
    )
}

fn read_artifact_body(fixture: &DirectDesktopApplyFixture) -> TrustedCliUpdateArtifactBody {
    let bytes = fs::read(&fixture.artifact_out).unwrap();
    parse_cli_artifact(&bytes, &TrustedCliUpdateOptions::default())
        .unwrap()
        .body()
        .clone()
}

fn reseal_artifact(bytes: &mut [u8]) {
    let prefix_len = bytes.len() - 32;
    let expected = if bytes.starts_with(super::artifact::ARTIFACT_V2_MAGIC) {
        super::id::encode_cli_artifact_v2_id(&bytes[..prefix_len]).unwrap()
    } else {
        let prefix_hash = Sha256Digest::new(Sha256::digest(&bytes[..prefix_len]).into());
        super::id::encode_cli_artifact_id(&prefix_hash).unwrap()
    };
    bytes[prefix_len..].copy_from_slice(expected.as_bytes());
}

fn descriptor_start(bytes: &[u8]) -> usize {
    let mut offset = if bytes.starts_with(super::artifact::ARTIFACT_V2_MAGIC) {
        super::artifact::ARTIFACT_V2_MAGIC.len() + 1
    } else {
        super::artifact::ARTIFACT_MAGIC.len() + 1
    };
    let field_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8 + field_len;
    if bytes.starts_with(super::artifact::ARTIFACT_V2_MAGIC) {
        assert_eq!(bytes[offset], 1);
        offset += 1;
    }
    let descriptor_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    assert!(descriptor_len > 0);
    offset
}

type DirectDesktopTamperCase = (&'static str, fn(&DirectDesktopApplyFixture));
type StagedMergeMutationCase = (&'static str, SnapshotNode, Arc<dyn Fn(&Path) + Send + Sync>);
type SnapshotPathMutationCase = (&'static str, fn(&Path));
type SnapshotFixtureMutationCase = (&'static str, fn(&DirectDesktopApplyFixture));

fn published_bundle_dir(fixture: &DirectDesktopApplyFixture) -> PathBuf {
    let body = read_artifact_body(fixture);
    fixture
        .staging
        .join("bundles")
        .join(body.staging_manifest_id.to_string())
}

fn try_published_bundle_dir(fixture: &DirectDesktopApplyFixture) -> Option<PathBuf> {
    let bytes = fs::read(&fixture.artifact_out).ok()?;
    let artifact = parse_cli_artifact(&bytes, &TrustedCliUpdateOptions::default()).ok()?;
    Some(
        fixture
            .staging
            .join("bundles")
            .join(artifact.body().staging_manifest_id.to_string()),
    )
}

fn staged_resource_file(fixture: &DirectDesktopApplyFixture, rel: &str) -> PathBuf {
    published_bundle_dir(fixture).join("resource").join(rel)
}

fn bundle_names(fixture: &DirectDesktopApplyFixture) -> Vec<String> {
    let root = fixture.staging.join("bundles");
    let mut names = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SnapshotNode {
    Directory,
    File(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathSnapshot(BTreeMap<String, SnapshotNode>);

#[derive(Debug)]
enum PathSnapshotError {
    Io,
    DuplicatePath,
    InvalidRelativePath,
    Symlink,
    ReparsePoint,
    UnsupportedNode,
}

impl PathSnapshot {
    fn capture(path: &Path) -> Self {
        Self::try_capture(path).expect("capture durable path snapshot")
    }

    fn try_capture(path: &Path) -> std::result::Result<Self, PathSnapshotError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self(BTreeMap::new()));
            }
            Err(_error) => return Err(PathSnapshotError::Io),
        };
        reject_snapshot_node(path, &metadata)?;
        let mut entries = BTreeMap::new();
        if metadata.file_type().is_file() {
            let bytes = fs::read(path).map_err(|_error| PathSnapshotError::Io)?;
            insert_snapshot_node(
                &mut entries,
                "file:__self__".to_owned(),
                SnapshotNode::File(bytes),
            )?;
        } else if metadata.file_type().is_dir() {
            walk_snapshot_dir(path, path, &mut entries)?;
        } else {
            return Err(PathSnapshotError::UnsupportedNode);
        }
        Ok(Self(entries))
    }

    fn key_for_file(root: &Path, path: &Path) -> String {
        let rel = normalize_snapshot_relative(root, path).expect("snapshot-relative staged path");
        format!("file:{rel}")
    }

    fn node(&self, key: &str) -> SnapshotNode {
        self.0.get(key).expect("snapshot node exists").clone()
    }

    fn delta(&self, after: &Self) -> PathSnapshotDelta {
        let before_keys = self.0.keys().cloned().collect::<BTreeSet<_>>();
        let after_keys = after.0.keys().cloned().collect::<BTreeSet<_>>();
        let mut changes = BTreeSet::new();
        for path in after_keys.difference(&before_keys) {
            let inserted = changes.insert(SnapshotChange::Added {
                path: path.clone(),
                after: after.0.get(path).expect("after node exists").clone(),
            });
            assert!(inserted, "duplicate added snapshot change");
        }
        for path in before_keys.difference(&after_keys) {
            let inserted = changes.insert(SnapshotChange::Removed {
                path: path.clone(),
                before: self.0.get(path).expect("before node exists").clone(),
            });
            assert!(inserted, "duplicate removed snapshot change");
        }
        for path in before_keys.intersection(&after_keys) {
            let before = self.0.get(path).expect("before node exists");
            let after = after.0.get(path).expect("after node exists");
            if before != after {
                let inserted = changes.insert(SnapshotChange::Changed {
                    path: path.clone(),
                    before: before.clone(),
                    after: after.clone(),
                });
                assert!(inserted, "duplicate changed snapshot change");
            }
        }
        PathSnapshotDelta { changes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathSnapshotDelta {
    changes: BTreeSet<SnapshotChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SnapshotChange {
    Added {
        path: String,
        after: SnapshotNode,
    },
    Removed {
        path: String,
        before: SnapshotNode,
    },
    Changed {
        path: String,
        before: SnapshotNode,
        after: SnapshotNode,
    },
}

impl PathSnapshotDelta {
    fn none() -> Self {
        Self {
            changes: BTreeSet::new(),
        }
    }

    fn only_changed(path: String, before: SnapshotNode, after: SnapshotNode) -> Self {
        Self {
            changes: BTreeSet::from([SnapshotChange::Changed {
                path,
                before,
                after,
            }]),
        }
    }

    fn from_changes(changes: impl IntoIterator<Item = SnapshotChange>) -> Self {
        let mut deduped = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for change in changes {
            assert!(
                paths.insert(change.path().to_owned()),
                "duplicate expected snapshot change path"
            );
            assert!(
                deduped.insert(change),
                "duplicate expected snapshot change record"
            );
        }
        Self { changes: deduped }
    }
}

impl SnapshotChange {
    fn path(&self) -> &str {
        match self {
            SnapshotChange::Added { path, .. }
            | SnapshotChange::Removed { path, .. }
            | SnapshotChange::Changed { path, .. } => path,
        }
    }
}

fn walk_snapshot_dir(
    root: &Path,
    path: &Path,
    out: &mut BTreeMap<String, SnapshotNode>,
) -> std::result::Result<(), PathSnapshotError> {
    let rel = normalize_snapshot_relative(root, path)?;
    insert_snapshot_node(out, format!("dir:{rel}"), SnapshotNode::Directory)?;
    let mut children = fs::read_dir(path)
        .map_err(|_error| PathSnapshotError::Io)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_error| PathSnapshotError::Io)?;
    children.sort();
    for child in children {
        let metadata = fs::symlink_metadata(&child).map_err(|_error| PathSnapshotError::Io)?;
        reject_snapshot_node(&child, &metadata)?;
        if metadata.file_type().is_dir() {
            walk_snapshot_dir(root, &child, out)?;
        } else if metadata.file_type().is_file() {
            let rel = normalize_snapshot_relative(root, &child)?;
            let bytes = fs::read(&child).map_err(|_error| PathSnapshotError::Io)?;
            insert_snapshot_node(out, format!("file:{rel}"), SnapshotNode::File(bytes))?;
        } else {
            return Err(PathSnapshotError::UnsupportedNode);
        }
    }
    Ok(())
}

fn reject_snapshot_node(
    _path: &Path,
    metadata: &std::fs::Metadata,
) -> std::result::Result<(), PathSnapshotError> {
    let file_type = metadata.file_type();
    if is_windows_reparse_point_std(metadata) {
        return Err(PathSnapshotError::ReparsePoint);
    }
    if file_type.is_symlink() {
        return Err(PathSnapshotError::Symlink);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
        {
            return Err(PathSnapshotError::UnsupportedNode);
        }
    }
    if !file_type.is_dir() && !file_type.is_file() {
        return Err(PathSnapshotError::UnsupportedNode);
    }
    Ok(())
}

fn normalize_snapshot_relative(
    root: &Path,
    path: &Path,
) -> std::result::Result<String, PathSnapshotError> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| PathSnapshotError::InvalidRelativePath)?;
    let normalized = rel.to_str().ok_or(PathSnapshotError::InvalidRelativePath)?;
    Ok(normalized.replace('\\', "/"))
}

fn insert_snapshot_node(
    entries: &mut BTreeMap<String, SnapshotNode>,
    key: String,
    value: SnapshotNode,
) -> std::result::Result<(), PathSnapshotError> {
    if entries.insert(key.clone(), value).is_some() {
        let _ = key;
        return Err(PathSnapshotError::DuplicatePath);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectDurableSnapshot {
    artifact: PathSnapshot,
    staging: PathSnapshot,
    transaction: PathSnapshot,
    baseline: PathSnapshot,
    installed: PathSnapshot,
}

impl DirectDurableSnapshot {
    fn capture(fixture: &DirectDesktopApplyFixture) -> Self {
        Self {
            artifact: PathSnapshot::capture(&fixture.artifact_out),
            staging: PathSnapshot::capture(&fixture.staging),
            transaction: PathSnapshot::capture(&fixture.txn),
            baseline: PathSnapshot::capture(&fixture.mini.store),
            installed: PathSnapshot::capture(&fixture.mini.installed_parent),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum DirectApplyErrorCategory {
    BindingMismatch,
    ArtifactInvalid,
    ArtifactVersionUnsupported,
    RecoveryRequired,
    StagingManifestTreeMismatch,
    StagingDigestLengthMismatch,
    BaselineNotFound,
    BaselineValidationFailed,
    InstalledStale,
}

impl DirectApplyErrorCategory {
    fn matches(self, err: &GkrmError) -> bool {
        matches!(
            (self, err),
            (
                DirectApplyErrorCategory::BindingMismatch,
                GkrmError::TrustedCliUpdateBindingMismatch
            ) | (
                DirectApplyErrorCategory::ArtifactInvalid,
                GkrmError::TrustedCliUpdateArtifactInvalid
            ) | (
                DirectApplyErrorCategory::ArtifactVersionUnsupported,
                GkrmError::TrustedCliUpdateArtifactVersionUnsupported
            ) | (
                DirectApplyErrorCategory::RecoveryRequired,
                GkrmError::TrustedCliUpdateRecoveryRequired
            ) | (
                DirectApplyErrorCategory::StagingManifestTreeMismatch,
                GkrmError::TrustedStagingManifestTreeMismatch
            ) | (
                DirectApplyErrorCategory::StagingDigestLengthMismatch,
                GkrmError::TrustedStagingDigestLengthMismatch
            ) | (
                DirectApplyErrorCategory::BaselineNotFound,
                GkrmError::BaselineSelectedBaselineNotFound { .. }
            ) | (
                DirectApplyErrorCategory::BaselineValidationFailed,
                GkrmError::BaselineSelectedBaselineValidationFailed { .. }
            ) | (
                DirectApplyErrorCategory::InstalledStale,
                GkrmError::TrustedApplyPlanningInstalledStale
            )
        )
    }
}

struct DirectApplyFailureExpectation {
    category: DirectApplyErrorCategory,
    source_changed_allowed: bool,
    staging_delta: PathSnapshotDelta,
}

impl DirectApplyFailureExpectation {
    fn new(category: DirectApplyErrorCategory) -> Self {
        Self {
            category,
            source_changed_allowed: false,
            staging_delta: PathSnapshotDelta::none(),
        }
    }

    fn with_exact_staging_change(
        mut self,
        path: String,
        before: SnapshotNode,
        after: SnapshotNode,
    ) -> Self {
        self.staging_delta = PathSnapshotDelta::only_changed(path, before, after);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SensitiveMatch {
    Contains,
    Token,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SensitiveValue {
    value: String,
    matching: SensitiveMatch,
}

impl SensitiveValue {
    fn contains(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        if value.is_empty() {
            return None;
        }
        Some(Self {
            value,
            matching: SensitiveMatch::Contains,
        })
    }

    fn token(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        if value.len() < 2 {
            return None;
        }
        Some(Self {
            value,
            matching: SensitiveMatch::Token,
        })
    }

    fn matches(&self, text: &str) -> bool {
        match self.matching {
            SensitiveMatch::Contains => text.contains(&self.value),
            SensitiveMatch::Token => contains_token(text, &self.value),
        }
    }
}

fn direct_sensitive_values(fixture: &DirectDesktopApplyFixture) -> Vec<SensitiveValue> {
    let mut values = BTreeSet::new();
    for value in [
        fixture.mini._temp.path().to_string_lossy().into_owned(),
        fixture.mini.installed_parent.to_string_lossy().into_owned(),
        fixture
            .mini
            .installed_resource
            .to_string_lossy()
            .into_owned(),
        fixture.mini.package_v2.to_string_lossy().into_owned(),
        fixture.artifact_out.to_string_lossy().into_owned(),
        fixture.staging.to_string_lossy().into_owned(),
        fixture.txn.to_string_lossy().into_owned(),
        fixture.mini.store.to_string_lossy().into_owned(),
        fixture
            .artifact_out
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        fixture
            .mini
            .package_v2
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        fixture.mini.baseline.baseline_id().as_str().to_owned(),
        "manifest.bin".to_owned(),
        "take-incoming".to_owned(),
        "merge-incoming".to_owned(),
        "source changed".to_owned(),
        "source chain".to_owned(),
    ] {
        if let Some(value) = SensitiveValue::contains(value) {
            values.insert(value);
        }
    }
    values.insert(SensitiveValue::token("gksphone").expect("resource key"));
    if let Ok(bytes) = fs::read(&fixture.artifact_out) {
        let digest = Sha256Digest::new(Sha256::digest(&bytes).into());
        values.insert(SensitiveValue::contains(digest.to_string()).unwrap());
        if let Ok(artifact) = parse_cli_artifact(&bytes, &TrustedCliUpdateOptions::default()) {
            values.insert(SensitiveValue::contains(artifact.artifact_id().to_hex()).unwrap());
            for digest in [
                artifact.body().package_fingerprint,
                artifact.body().selected_resource_commitment,
                artifact.body().baseline_id_digest,
                artifact.body().plan_id,
                artifact.body().review_id,
                artifact.body().operator_merge_set_id,
                artifact.body().staging_manifest_id,
                artifact.body().staging_bundle_id,
                artifact.body().apply_plan_id,
                artifact.body().snapshot_a,
                artifact.body().transactional_plan_id,
                artifact.body().decision_document_id,
            ] {
                values.insert(SensitiveValue::contains(digest.to_string()).unwrap());
            }
            for digest in [
                artifact.body().analysis_id,
                artifact.body().text_diff_id,
                artifact.body().synthesis_id,
                artifact.body().merged_bytes_id,
            ]
            .into_iter()
            .flatten()
            {
                values.insert(SensitiveValue::contains(digest.to_string()).unwrap());
            }
        }
    }
    if let Some(bundle) = try_published_bundle_dir(fixture) {
        let manifest = bundle.join("manifest.bin");
        values.insert(SensitiveValue::contains(manifest.to_string_lossy().into_owned()).unwrap());
        if let Ok(bytes) = fs::read(&manifest) {
            values.insert(
                SensitiveValue::contains(
                    Sha256Digest::new(Sha256::digest(&bytes).into()).to_string(),
                )
                .unwrap(),
            );
        }
    }
    for rel in ["take.lua", "merge.lua", "preserve.lua", "fxmanifest.lua"] {
        let path = fixture.mini.installed_resource.join(rel);
        if let Ok(bytes) = fs::read(path) {
            values.insert(
                SensitiveValue::contains(
                    Sha256Digest::new(Sha256::digest(&bytes).into()).to_string(),
                )
                .unwrap(),
            );
        }
        if let Some(bundle) = try_published_bundle_dir(fixture) {
            let path = bundle.join("resource").join(rel);
            if let Ok(bytes) = fs::read(path) {
                values.insert(
                    SensitiveValue::contains(
                        Sha256Digest::new(Sha256::digest(&bytes).into()).to_string(),
                    )
                    .unwrap(),
                );
            }
        }
    }
    values.into_iter().collect()
}

fn contains_token(text: &str, token: &str) -> bool {
    let mut start = 0;
    while let Some(offset) = text[start..].find(token) {
        let token_start = start + offset;
        let token_end = token_start + token.len();
        let before = text[..token_start]
            .chars()
            .next_back()
            .is_none_or(|ch| !sensitive_token_char(ch));
        let after = text[token_end..]
            .chars()
            .next()
            .is_none_or(|ch| !sensitive_token_char(ch));
        if before && after {
            return true;
        }
        start = token_end;
    }
    false
}

fn sensitive_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

fn assert_sensitive_values_redacted(text: &str, sensitive_values: &[SensitiveValue]) {
    for sensitive in sensitive_values {
        assert!(
            !sensitive.matches(text),
            "private apply error leaked sensitive value `{:?}`: {text}",
            sensitive
        );
    }
}

fn assert_path_snapshot_delta(
    before: &PathSnapshot,
    after: &PathSnapshot,
    expected: &PathSnapshotDelta,
    label: &str,
) {
    assert_eq!(
        before.delta(after),
        *expected,
        "unexpected {label} state delta"
    );
}

fn assert_private_apply_failure(
    result: crate::Result<TrustedCliReport>,
    fixture: &DirectDesktopApplyFixture,
    before: &DirectDurableSnapshot,
    expectation: DirectApplyFailureExpectation,
) -> GkrmError {
    let err = match result {
        Ok(report) => panic!(
            "private apply unexpectedly returned outcome {}",
            report.outcome
        ),
        Err(err) => err,
    };
    assert!(
        expectation.category.matches(&err),
        "expected private apply error category {:?}, got {err:?}",
        expectation.category
    );
    assert_eq!(
        matches!(err, GkrmError::TrustedUpdateSourceChanged),
        expectation.source_changed_allowed,
        "unexpected source_changed classification for {err:?}"
    );
    let after = DirectDurableSnapshot::capture(fixture);
    assert_eq!(after.artifact, before.artifact, "artifact state changed");
    assert_path_snapshot_delta(
        &before.staging,
        &after.staging,
        &expectation.staging_delta,
        "staging",
    );
    assert_eq!(
        after.transaction, before.transaction,
        "transaction state changed"
    );
    assert_eq!(after.baseline, before.baseline, "baseline state changed");
    assert_eq!(after.installed, before.installed, "installed state changed");

    let mut text = format!("{err:?}\n{err}");
    let mut source = Error::source(&err);
    while let Some(err) = source {
        text.push('\n');
        text.push_str(&format!("{err:?}\n{err}"));
        source = err.source();
    }
    assert_sensitive_values_redacted(&text, &direct_sensitive_values(fixture));
    err
}

#[cfg(any(unix, windows))]
fn try_test_symlink_file(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}

#[cfg(any(unix, windows))]
fn try_test_symlink_dir(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }
}

#[test]
fn path_snapshot_rejects_file_symlink_where_supported() {
    let temp = tempdir().unwrap();
    let target = temp.path().join("target.txt");
    let link = temp.path().join("link.txt");
    fs::write(&target, b"target bytes").unwrap();
    if !try_test_symlink_file(&target, &link) {
        return;
    }

    let err = PathSnapshot::try_capture(&link).expect_err("file symlink rejected");
    // Windows makes a symlink out of a reparse point, and the snapshot classifies it as the
    // reparse point it is. Either way it is refused, which is what this is about.
    assert!(matches!(
        err,
        PathSnapshotError::Symlink | PathSnapshotError::ReparsePoint
    ));
}

#[test]
fn path_snapshot_rejects_directory_symlink_where_supported() {
    let temp = tempdir().unwrap();
    let target = temp.path().join("target-dir");
    let link = temp.path().join("link-dir");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("hidden.txt"), b"must not be followed").unwrap();
    if !try_test_symlink_dir(&target, &link) {
        return;
    }

    let err = PathSnapshot::try_capture(&link).expect_err("directory symlink rejected");
    assert!(matches!(
        err,
        PathSnapshotError::Symlink | PathSnapshotError::ReparsePoint
    ));
}

#[cfg(windows)]
#[test]
fn path_snapshot_rejects_windows_junction() {
    let temp = tempdir().unwrap();
    let target = temp.path().join("junction-target");
    let link = temp.path().join("junction");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("hidden.txt"), b"must not be followed").unwrap();
    create_junction(&target, &link);

    let err = PathSnapshot::try_capture(&link).expect_err("junction rejected");
    assert!(matches!(err, PathSnapshotError::ReparsePoint));
}

#[cfg(unix)]
#[test]
fn path_snapshot_rejects_unix_socket_node() {
    use std::os::unix::net::UnixListener;

    let temp = tempdir().unwrap();
    let socket = temp.path().join("socket");
    let _listener = UnixListener::bind(&socket).unwrap();

    let err = PathSnapshot::try_capture(&socket).expect_err("socket rejected");
    assert!(matches!(err, PathSnapshotError::UnsupportedNode));
}

#[cfg(unix)]
#[test]
fn path_snapshot_propagates_unreadable_child_errors() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let unreadable = root.join("unreadable");
    fs::create_dir_all(&unreadable).unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

    let result = PathSnapshot::try_capture(&root);
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700)).unwrap();
    let err = result.expect_err("unreadable child must fail snapshot");
    assert!(matches!(err, PathSnapshotError::Io));
}

#[test]
fn path_snapshot_detects_structural_and_byte_changes() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    fs::create_dir_all(root.join("empty")).unwrap();
    fs::write(root.join("a.txt"), b"one").unwrap();
    let before = PathSnapshot::capture(&root);

    fs::rename(root.join("a.txt"), root.join("renamed.txt")).unwrap();
    fs::remove_dir(root.join("empty")).unwrap();
    fs::create_dir(root.join("new-empty")).unwrap();
    fs::write(root.join("bytes.txt"), b"before").unwrap();
    let after_structure = PathSnapshot::capture(&root);
    let structure_delta = before.delta(&after_structure);
    assert_eq!(
        structure_delta,
        PathSnapshotDelta::from_changes([
            SnapshotChange::Added {
                path: "dir:new-empty".to_owned(),
                after: SnapshotNode::Directory,
            },
            SnapshotChange::Added {
                path: "file:bytes.txt".to_owned(),
                after: SnapshotNode::File(b"before".to_vec()),
            },
            SnapshotChange::Added {
                path: "file:renamed.txt".to_owned(),
                after: SnapshotNode::File(b"one".to_vec()),
            },
            SnapshotChange::Removed {
                path: "dir:empty".to_owned(),
                before: SnapshotNode::Directory,
            },
            SnapshotChange::Removed {
                path: "file:a.txt".to_owned(),
                before: SnapshotNode::File(b"one".to_vec()),
            },
        ])
    );

    let before_bytes = PathSnapshot::capture(&root);
    fs::write(root.join("bytes.txt"), b"after").unwrap();
    let after_bytes = PathSnapshot::capture(&root);
    assert_eq!(
        before_bytes.delta(&after_bytes),
        PathSnapshotDelta::only_changed(
            "file:bytes.txt".to_owned(),
            SnapshotNode::File(b"before".to_vec()),
            SnapshotNode::File(b"after".to_vec()),
        )
    );

    fs::remove_file(root.join("bytes.txt")).unwrap();
    fs::create_dir(root.join("bytes.txt")).unwrap();
    let after_type = PathSnapshot::capture(&root);
    let type_delta = after_bytes.delta(&after_type);
    assert_eq!(
        type_delta,
        PathSnapshotDelta::from_changes([
            SnapshotChange::Added {
                path: "dir:bytes.txt".to_owned(),
                after: SnapshotNode::Directory,
            },
            SnapshotChange::Removed {
                path: "file:bytes.txt".to_owned(),
                before: SnapshotNode::File(b"after".to_vec()),
            },
        ])
    );
}

#[test]
fn exact_staging_delta_assertion_accepts_only_precise_before_after_state() {
    let fixture = ready_desktop_apply_fixture("desktop-exact-delta-helper");
    let target = staged_resource_file(&fixture, "merge.lua");
    let target_key = PathSnapshot::key_for_file(&fixture.staging, &target);
    let before = PathSnapshot::capture(&fixture.staging);
    let before_node = before.node(&target_key);
    fs::write(&target, b"expected mutation").unwrap();
    let after = PathSnapshot::capture(&fixture.staging);
    let expected = PathSnapshotDelta::only_changed(
        target_key,
        before_node,
        SnapshotNode::File(b"expected mutation".to_vec()),
    );

    assert_path_snapshot_delta(&before, &after, &expected, "staging");
}

#[test]
fn exact_staging_delta_assertion_rejects_wrong_content_type_and_removal() {
    let cases: [SnapshotPathMutationCase; 4] = [
        ("wrong-content", |target| {
            fs::write(target, b"wrong mutation").unwrap();
        }),
        ("file-to-directory", |target| {
            fs::remove_file(target).unwrap();
            fs::create_dir(target).unwrap();
        }),
        ("removed", |target| {
            fs::remove_file(target).unwrap();
        }),
        ("recreated-different-bytes", |target| {
            fs::remove_file(target).unwrap();
            fs::write(target, b"recreated wrong mutation").unwrap();
        }),
    ];

    for (name, mutate) in cases {
        let fixture = ready_desktop_apply_fixture(name);
        let target = staged_resource_file(&fixture, "merge.lua");
        let target_key = PathSnapshot::key_for_file(&fixture.staging, &target);
        let before = PathSnapshot::capture(&fixture.staging);
        let before_node = before.node(&target_key);
        let expected = PathSnapshotDelta::only_changed(
            target_key,
            before_node,
            SnapshotNode::File(b"expected mutation".to_vec()),
        );
        mutate(&target);
        let after = PathSnapshot::capture(&fixture.staging);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_path_snapshot_delta(&before, &after, &expected, "staging");
        }));
        assert!(result.is_err(), "{name} must fail exact delta assertion");
    }
}

#[test]
fn exact_staging_delta_rejects_duplicate_expected_change_records() {
    let duplicate_record = std::panic::catch_unwind(|| {
        PathSnapshotDelta::from_changes([
            SnapshotChange::Changed {
                path: "file:merge.lua".to_owned(),
                before: SnapshotNode::File(b"before".to_vec()),
                after: SnapshotNode::File(b"after".to_vec()),
            },
            SnapshotChange::Changed {
                path: "file:merge.lua".to_owned(),
                before: SnapshotNode::File(b"before".to_vec()),
                after: SnapshotNode::File(b"after".to_vec()),
            },
        ]);
    });
    assert!(duplicate_record.is_err());

    let duplicate_path = std::panic::catch_unwind(|| {
        PathSnapshotDelta::from_changes([
            SnapshotChange::Changed {
                path: "file:merge.lua".to_owned(),
                before: SnapshotNode::File(b"before".to_vec()),
                after: SnapshotNode::File(b"after".to_vec()),
            },
            SnapshotChange::Changed {
                path: "file:merge.lua".to_owned(),
                before: SnapshotNode::File(b"before".to_vec()),
                after: SnapshotNode::File(b"different".to_vec()),
            },
        ]);
    });
    assert!(duplicate_path.is_err());
}

#[test]
fn exact_staging_delta_assertion_rejects_unrelated_changes() {
    let cases: [SnapshotFixtureMutationCase; 4] = [
        ("unrelated-added", |fixture| {
            fs::write(staged_resource_file(fixture, "unexpected.txt"), b"extra").unwrap();
        }),
        ("unrelated-modified", |fixture| {
            fs::write(staged_resource_file(fixture, "take.lua"), b"unrelated").unwrap();
        }),
        ("unrelated-removed", |fixture| {
            fs::remove_file(staged_resource_file(fixture, "take.lua")).unwrap();
        }),
        ("unrelated-renamed", |fixture| {
            fs::rename(
                staged_resource_file(fixture, "take.lua"),
                staged_resource_file(fixture, "take-renamed.lua"),
            )
            .unwrap();
        }),
    ];

    for (name, mutate) in cases {
        let fixture = ready_desktop_apply_fixture(name);
        let target = staged_resource_file(&fixture, "merge.lua");
        let target_key = PathSnapshot::key_for_file(&fixture.staging, &target);
        let before = PathSnapshot::capture(&fixture.staging);
        let before_node = before.node(&target_key);
        let expected = PathSnapshotDelta::only_changed(
            target_key,
            before_node,
            SnapshotNode::File(b"expected mutation".to_vec()),
        );
        fs::write(&target, b"expected mutation").unwrap();
        mutate(&fixture);
        let after = PathSnapshot::capture(&fixture.staging);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_path_snapshot_delta(&before, &after, &expected, "staging");
        }));
        assert!(result.is_err(), "{name} must fail exact delta assertion");
    }
}

#[test]
fn short_sensitive_resource_key_redaction_assertion_is_enforced() {
    let values = vec![SensitiveValue::token("gksphone").unwrap()];
    assert_sensitive_values_redacted("The plan is not ready to apply.", &values);
    let leaked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_sensitive_values_redacted("The resource gksphone was rejected.", &values);
    }));
    assert!(
        leaked.is_err(),
        "gksphone leak must fail redaction assertion"
    );
}

fn copy_dir_recursive(src: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let source = entry.path();
        let target = dest.join(entry.file_name());
        if source.is_dir() {
            copy_dir_recursive(&source, &target);
        } else {
            fs::copy(&source, &target).unwrap();
        }
    }
}

fn read_u64_at(bytes: &[u8], offset: usize) -> usize {
    usize::try_from(u64::from_le_bytes(
        bytes[offset..offset + 8].try_into().unwrap(),
    ))
    .unwrap()
}

fn manifest_first_entry_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let mut offset = 0usize;
    let domain_len = read_u64_at(bytes, offset);
    offset += 8 + domain_len + 32;
    let entry_count = read_u64_at(bytes, offset);
    assert!(entry_count > 0);
    offset += 8;
    manifest_entry_range_at(bytes, offset)
}

fn manifest_entry_range_at(bytes: &[u8], mut offset: usize) -> std::ops::Range<usize> {
    let start = offset;
    offset += 32;
    let path_len = read_u64_at(bytes, offset);
    offset += 8 + path_len + 3;
    if bytes[offset - 1] == 1 {
        offset += 32 + 8;
    }
    let binding_tag = bytes[offset];
    offset += 1;
    if matches!(binding_tag, 0 | 1 | 2 | 4) {
        offset += 32;
    }
    start..offset
}

fn mutate_first_manifest_present_digest_preserving_ids(manifest: &Path) {
    let mut bytes = fs::read(manifest).unwrap();
    let range = manifest_first_entry_range(&bytes);
    let mut offset = range.start + 32;
    let path_len = read_u64_at(&bytes, offset);
    offset += 8 + path_len + 2;
    assert_eq!(
        bytes[offset], 1,
        "first test fixture entry should be present"
    );
    offset += 1;
    bytes[offset] ^= 0x44;
    fs::write(manifest, bytes).unwrap();
}

fn duplicate_first_manifest_entry_preserving_ids(manifest: &Path) {
    let mut bytes = fs::read(manifest).unwrap();
    let mut offset = 0usize;
    let domain_len = read_u64_at(&bytes, offset);
    offset += 8 + domain_len + 32;
    let entry_count = read_u64_at(&bytes, offset);
    bytes[offset..offset + 8].copy_from_slice(&(entry_count as u64 + 1).to_le_bytes());
    let first = manifest_first_entry_range(&bytes);
    let entry = bytes[first.clone()].to_vec();
    bytes.splice(first.end..first.end, entry);
    fs::write(manifest, bytes).unwrap();
}

fn reorder_manifest_entries_preserving_ids(manifest: &Path) {
    let mut bytes = fs::read(manifest).unwrap();
    let first = manifest_first_entry_range(&bytes);
    let second = manifest_entry_range_at(&bytes, first.end);
    let first_bytes = bytes[first.clone()].to_vec();
    let second_bytes = bytes[second.clone()].to_vec();
    let mut reordered = Vec::new();
    reordered.extend_from_slice(&bytes[..first.start]);
    reordered.extend_from_slice(&second_bytes);
    reordered.extend_from_slice(&bytes[first.end..second.start]);
    reordered.extend_from_slice(&first_bytes);
    reordered.extend_from_slice(&bytes[second.end..]);
    bytes = reordered;
    fs::write(manifest, bytes).unwrap();
}

#[test]
fn artifact_roundtrip_and_tamper_fails() {
    let body = fixed_artifact_body();
    let art = encode_cli_artifact(&body).unwrap();
    let parsed =
        parse_cli_artifact(art.canonical_bytes(), &TrustedCliUpdateOptions::default()).unwrap();
    assert_eq!(parsed.artifact_id().to_hex(), art.artifact_id().to_hex());
    let mut bad = art.canonical_bytes().to_vec();
    bad.push(0xff);
    assert!(parse_cli_artifact(&bad, &TrustedCliUpdateOptions::default()).is_err());
}

#[test]
fn artifact_id_is_stable_for_fixed_body() {
    let body = fixed_artifact_body();
    let first = encode_cli_artifact(&body).unwrap();
    let second = encode_cli_artifact(&body).unwrap();
    assert_eq!(first.artifact_id().to_hex(), second.artifact_id().to_hex());
    assert_eq!(first.artifact_id().to_hex(), FIXED_TASK25_ARTIFACT_ID);
}

#[test]
fn fixed_empty_operator_merge_set_id_vector() {
    let empty_set_id = encode_operator_merge_set_id(&[]).unwrap();
    assert_eq!(empty_set_id.to_string(), FIXED_EMPTY_OPERATOR_MERGE_SET_ID);
}

#[test]
fn status_read_only_on_empty_root() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-empty");
    fs::create_dir_all(&txn).unwrap();
    let _root = TrustedTransactionRoot::try_open(&txn).unwrap();
    let report = status_trusted_cli_update(TrustedCliStatusRequest {
        transaction_root: &txn,
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(report.outcome, "status");
    assert_eq!(report.bound_candidates, 0);
}

#[test]
fn implicit_single_resource_selection_with_none() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-implicit");
    let staging = fixture._temp.path().join("staging-implicit");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = fixture._temp.path().join("out").join("implicit.bin");
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = fixture._temp.path().join("dec").join("decisions.bin");
    write_decisions_file(&fixture, &decisions);

    let report = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: None,
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(report.outcome, "ready_to_apply");
    assert!(artifact_out.is_file());
}

#[test]
fn workspace_capacity_rejects_before_staging_publication() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-capacity");
    let staging = fixture._temp.path().join("staging-capacity");
    let artifact_root = fixture._temp.path().join("out-capacity");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(&artifact_root).unwrap();
    let artifact_out = artifact_root.join("plan.bin");
    let decisions = fixture
        ._temp
        .path()
        .join("dec-capacity")
        .join("decisions.bin");
    write_decisions_file(&fixture, &decisions);
    let workspace = resolve_trusted_update_workspace_from_explicit_roots(
        crate::ExplicitTrustedUpdateWorkspaceRequest {
            baseline_store: &fixture.store,
            staging_root: &staging,
            transaction_root: &txn,
            artifact_root: &artifact_root,
            artifact_out: &artifact_out,
            installed_root: &fixture.installed_parent,
            package_file: &fixture.package_v2,
        },
    )
    .unwrap();

    let err = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: None,
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: Some(&workspace),
        workspace_options: crate::TrustedUpdateWorkspaceOptions {
            max_regular_file_bytes: 1,
            ..crate::TrustedUpdateWorkspaceOptions::default()
        },
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap_err();

    assert!(matches!(
        err,
        GkrmError::TrustedUpdateWorkspaceCapacityReached
    ));
    assert!(!staging.join(".tmp").exists());
    assert!(!staging.join("bundles").exists());
    assert!(!artifact_out.exists());
}

#[test]
fn ready_plan_rejects_final_artifact_larger_than_configured_limit() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-artifact-limit");
    let staging = fixture._temp.path().join("staging-artifact-limit");
    let artifact_out = fixture
        ._temp
        .path()
        .join("out-artifact-limit")
        .join("plan.bin");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = fixture
        ._temp
        .path()
        .join("dec-artifact-limit")
        .join("decisions.bin");
    write_decisions_file(&fixture, &decisions);
    let err = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: None,
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions {
            max_artifact_bytes: 1,
            ..TrustedCliUpdateOptions::default()
        },
    })
    .unwrap_err();
    assert!(matches!(
        err,
        GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes"
        }
    ));
    assert!(!artifact_out.exists());
}

#[test]
fn multi_resource_requires_explicit_selection() {
    let temp = tempdir().unwrap();
    let installed = temp.path().join("installed");
    let package = temp.path().join("package.zip");
    let store = temp.path().join("store");
    let txn = temp.path().join("txn");
    let staging = temp.path().join("staging");
    let artifact_out = temp.path().join("out").join("plan.bin");
    fs::create_dir_all(&store).unwrap();
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();

    write_file(&installed.join("gksphone/fxmanifest.lua"), SIMPLE_MANIFEST);
    write_file(
        &installed.join("otherphone/fxmanifest.lua"),
        SIMPLE_MANIFEST,
    );
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", SIMPLE_MANIFEST),
            ("otherphone/fxmanifest.lua", SIMPLE_MANIFEST),
        ],
    );

    let err = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &package,
        installed: &installed,
        baseline_store: &store,
        baseline_selector: OfficialBaselineSelector::AutoSingle,
        resource: None,
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: None,
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect_err("multi-resource package should require explicit selection");
    assert!(matches!(
        err,
        GkrmError::TrustedCliUpdateResourceSelectionRequired
    ));
    assert!(!artifact_out.exists());
}

#[test]
fn wrong_resource_selection_is_not_found() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-wrong");
    let staging = fixture._temp.path().join("staging-wrong");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = fixture._temp.path().join("out").join("wrong.bin");
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let wrong = SafeResourceKey::parse("missing-resource").unwrap();

    let err = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&wrong),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: None,
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect_err("unknown resource should not resolve");
    assert!(matches!(err, GkrmError::TrustedCliUpdateResourceNotFound));
}

#[test]
fn plan_ready_to_apply_on_mini_fixture() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-plan");
    let staging = fixture._temp.path().join("staging-plan");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = fixture._temp.path().join("out").join("plan.bin");
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = fixture._temp.path().join("dec").join("decisions.bin");
    write_decisions_file(&fixture, &decisions);

    let report = match plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    }) {
        Ok(r) => r,
        Err(e) => panic!("plan failed: {e:?}"),
    };
    assert_eq!(report.outcome, "ready_to_apply");
    assert!(artifact_out.is_file());
    assert!(report.artifact_id_hex.is_some());
}

#[test]
fn pending_decisions_creates_no_artifact() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-pending");
    fs::create_dir_all(&txn).unwrap();
    let artifact_out = fixture._temp.path().join("pending-art.bin");
    let report = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: None,
        staging_root: &fixture.staging_root,
        transaction_root: &txn,
        decisions_path: None,
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(report.outcome, "pending_decisions");
    assert!(!artifact_out.exists());
}

#[test]
fn destination_exists_rejects_artifact_publish() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-dest");
    let staging = fixture._temp.path().join("staging-dest");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = fixture._temp.path().join("out").join("exists.bin");
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    fs::write(&artifact_out, b"already-there").unwrap();
    let decisions = fixture._temp.path().join("dec").join("decisions.bin");
    write_decisions_file(&fixture, &decisions);

    let err = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect_err("existing artifact destination should be rejected");
    assert!(matches!(err, GkrmError::TrustedCliUpdateDestinationExists));
}

#[test]
fn artifact_out_under_staging_root_is_path_overlap() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-overlap");
    let staging = fixture._temp.path().join("staging-overlap");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = staging.join("nested").join("plan.bin");
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = fixture._temp.path().join("dec").join("decisions.bin");
    write_decisions_file(&fixture, &decisions);

    let err = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect_err("artifact under staging root should overlap");
    assert!(matches!(err, GkrmError::TrustedCliUpdatePathOverlap));
}

#[test]
fn decision_document_derives_review_without_review_id_input() {
    let fixture = build_mini();
    let entries = build_decision_entries(&fixture);
    let doc = build_decision_document(&fixture.plan, entries, &TrustedCliUpdateOptions::default())
        .unwrap();
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&fixture.plan, &doc.to_decision_set().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        review.review_id().digest(),
        fixture.review.review_id().digest()
    );
}

#[test]
fn plan_then_apply_commits_with_shared_roots() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-flow");
    let staging = fixture._temp.path().join("staging-flow");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = fixture._temp.path().join("out").join("flow.bin");
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = fixture._temp.path().join("dec").join("decisions.bin");
    write_decisions_file(&fixture, &decisions);

    let plan_report = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(plan_report.outcome, "ready_to_apply");

    let apply_report = apply_trusted_cli_update(TrustedCliApplyRequest {
        artifact: &artifact_out,
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        operator_merge_root: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(apply_report.outcome, "committed");
}

#[test]
fn package_free_desktop_apply_commits_without_cli_package_request() {
    let fixture = ready_desktop_apply_fixture("desktop-flow");
    let artifact = parse_cli_artifact(
        &fs::read(&fixture.artifact_out).unwrap(),
        &TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    assert_eq!(artifact.version(), 2);
    let authority_id = artifact
        .body()
        .recovery_authority_id
        .expect("desktop artifact v2 must bind recovery authority");
    let transaction_id = artifact.body().transactional_plan_id;
    fs::remove_file(&fixture.mini.package_v2).unwrap();
    let apply_report = apply_direct_desktop(&fixture).unwrap();
    assert_eq!(apply_report.outcome, "committed");

    let transaction = fixture
        .txn
        .join("transactions")
        .join(transaction_id.to_string());
    let envelope = crate::parse_recovery_authority_envelope(
        &fs::read(transaction.join("recovery-authority.bin")).unwrap(),
        RecoveryAuthorityLimits::default(),
    )
    .unwrap();
    assert_eq!(*envelope.authority_id().digest(), authority_id);
    assert_eq!(envelope.body().transactional_plan_id(), &transaction_id);
    let journal = fs::read(transaction.join("journal").join("00000000-prepared.bin")).unwrap();
    assert!(journal.starts_with(b"gkrm-txn-journal-v2\n"));
}

#[test]
fn recovery_workspace_overview_absent_and_empty_are_clear_and_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let absent = temp.path().join("absent-workspace");
    let absent_workspace = crate::open_existing_trusted_update_workspace(&absent).unwrap();
    let overview = crate::inspect_trusted_recovery_workspace_overview(
        absent_workspace.as_ref(),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(overview.is_clear());
    assert!(!absent.exists());

    let workspace =
        crate::resolve_trusted_update_workspace(&temp.path().join("empty-workspace")).unwrap();
    let before = crate::trusted_staging::test_support::hash_tree(workspace.app_root());
    let overview = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(overview.is_clear());
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.app_root()),
        before
    );
}

#[test]
fn recovery_workspace_overview_rediscovers_interrupted_apply_without_installed_authority() {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task32e1-overview-active");
    {
        let _guard = lock_execution_hooks();
        set_publication_hook(PublicationPoint::AfterFilePublish, || {
            panic!("simulated process interruption")
        });
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
                authority: review.desktop_apply_authority.as_ref().unwrap(),
                options: TrustedCliUpdateOptions::default(),
            });
        }));
        assert!(crashed.is_err());
    }
    drop(review);
    let before = crate::trusted_staging::test_support::hash_tree(workspace.app_root());
    let overview = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(overview.has_active_recovery());
    assert!(!overview.is_clear());
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.app_root()),
        before
    );
    drop(mini);
}

#[test]
fn recovery_workspace_overview_reports_committed_as_terminal_and_corruption_as_manual() {
    let (_mini, workspace, _candidate) = committed_workspace_v2("task32e1-overview-terminal");
    let before = crate::trusted_staging::test_support::hash_tree(workspace.app_root());
    let terminal = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(terminal.has_terminal_evidence());
    assert!(!terminal.is_clear());
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.app_root()),
        before
    );
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));

    std::fs::create_dir(
        workspace
            .transaction_root()
            .join("transactions")
            .join("malformed-peer"),
    )
    .unwrap();
    let mixed_before = crate::trusted_staging::test_support::hash_tree(workspace.app_root());
    let mixed = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(mixed.has_terminal_evidence());
    assert!(mixed.has_manual_attention());
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.app_root()),
        mixed_before
    );

    flip_first_byte(&transaction.join("recovery-authority.bin"));
    let corrupt_before = crate::trusted_staging::test_support::hash_tree(workspace.app_root());
    let corrupt = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(corrupt.has_manual_attention());
    assert!(!corrupt.is_clear());
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.app_root()),
        corrupt_before
    );
}

fn retirement_options(acknowledged: bool) -> crate::TrustedTerminalEvidenceRetirementOptions {
    crate::TrustedTerminalEvidenceRetirementOptions {
        acknowledged,
        ..crate::TrustedTerminalEvidenceRetirementOptions::default()
    }
}

fn retirement_records(workspace: &crate::TrustedUpdateWorkspace) -> Vec<PathBuf> {
    let root = workspace.transaction_root().join("terminal-retirements");
    if !root.exists() {
        return Vec::new();
    }
    regular_files_recursive(&root)
}

#[test]
fn terminal_retirement_is_explicit_restart_safe_idempotent_and_preserves_evidence() {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task32e2a-retirement");
    let applied = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
        authority: review.desktop_apply_authority.as_ref().unwrap(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(applied.outcome, "committed");
    drop(review);

    let transactions = workspace.transaction_root().join("transactions");
    let transaction = only_child_directory(&transactions);
    let transaction_before = crate::trusted_staging::test_support::hash_tree(&transaction);
    let artifacts_before =
        crate::trusted_staging::test_support::hash_tree(workspace.artifact_root().path());
    let terminal = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(terminal.has_terminal_evidence());
    assert!(!terminal.is_clear());

    let missing_intent =
        crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(false))
            .unwrap_err();
    assert!(matches!(
        missing_intent,
        GkrmError::TrustedTerminalEvidenceRetirementAcknowledgementRequired
    ));
    assert!(retirement_records(&workspace).is_empty());

    let retired =
        crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true))
            .unwrap();
    assert_eq!(retired.retired_count(), 1);
    assert_eq!(retired.already_retired_count(), 0);
    assert_eq!(retirement_records(&workspace).len(), 1);
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(&transaction),
        transaction_before
    );
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.artifact_root().path()),
        artifacts_before
    );

    crate::trusted_package_free_update_recovery::reset_overview_retirement_catalog_loads();
    let managed_root = crate::TrustedTransactionRoot::try_open_in_workspace(&workspace).unwrap();
    assert!(!crate::trusted_transactional_apply_execution::recovery::same_resource_recovery_blocks_new_work(
        &managed_root,
        &SafeResourceKey::parse("gksphone").unwrap(),
        TrustedCliUpdateOptions::default().max_journal_records,
    )
    .unwrap());
    assert_eq!(
        crate::trusted_package_free_update_recovery::overview_retirement_catalog_loads(),
        1,
        "one recovery-first gate must share one retirement catalog and byte budget"
    );
    let compatibility_root =
        crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    assert!(crate::trusted_transactional_apply_execution::recovery::same_resource_recovery_blocks_new_work(
        &compatibility_root,
        &SafeResourceKey::parse("gksphone").unwrap(),
        TrustedCliUpdateOptions::default().max_journal_records,
    )
    .unwrap());

    let fresh = crate::open_existing_trusted_update_workspace(workspace.app_root())
        .unwrap()
        .unwrap();
    let clear = crate::inspect_trusted_recovery_workspace_overview(
        Some(&fresh),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(clear.is_clear());
    assert!(!clear.has_terminal_evidence());
    let selected = trusted_gksphone_selection(&mini);
    let status = crate::inspect_trusted_published_update_v2(
        &fresh,
        &selected,
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert_eq!(
        status.state(),
        crate::TrustedPublishedUpdateRecoveryState::Clear
    );
    assert!(status.candidate_id().is_none());

    let retry =
        crate::retire_trusted_terminal_update_evidence(&fresh, retirement_options(true)).unwrap();
    assert_eq!(retry.retired_count(), 0);
    assert_eq!(retry.already_retired_count(), 1);
    assert_eq!(retirement_records(&fresh).len(), 1);
}

#[cfg(unix)]
#[test]
fn recovery_first_gate_cannot_mix_retirement_from_replacement_transaction_root() {
    let (_mini, workspace, _candidate) =
        committed_workspace_v2("task32e2a-retained-transaction-root");
    crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true)).unwrap();
    let managed_root = crate::TrustedTransactionRoot::try_open_in_workspace(&workspace).unwrap();
    let transaction_path = workspace.transaction_root().to_path_buf();
    let retained_path = workspace.app_root().join("transactions-retained-a");

    std::fs::rename(&transaction_path, &retained_path).unwrap();
    copy_dir_recursive(&retained_path, &transaction_path);
    std::fs::remove_dir_all(retained_path.join("terminal-retirements")).unwrap();

    crate::trusted_package_free_update_recovery::reset_overview_retirement_catalog_loads();
    let blocked = crate::trusted_transactional_apply_execution::recovery::same_resource_recovery_blocks_new_work(
        &managed_root,
        &SafeResourceKey::parse("gksphone").unwrap(),
        TrustedCliUpdateOptions::default().max_journal_records,
    )
    .unwrap();
    assert!(
        blocked,
        "terminal evidence from retained root A must not be suppressed by retirement from replacement root B"
    );
    assert_eq!(
        crate::trusted_package_free_update_recovery::overview_retirement_catalog_loads(),
        1,
        "the retained-root gate must still instantiate one retirement catalog and budget"
    );
}

#[cfg(windows)]
#[test]
fn retained_transaction_root_prevents_path_replacement_on_windows() {
    let (_mini, workspace, _candidate) =
        committed_workspace_v2("task32e2a-retained-transaction-root-windows");
    crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true)).unwrap();
    let managed_root = crate::TrustedTransactionRoot::try_open_in_workspace(&workspace).unwrap();
    let replacement_attempt = std::fs::rename(
        workspace.transaction_root(),
        workspace
            .app_root()
            .join("transactions-replacement-attempt"),
    );
    assert!(
        replacement_attempt.is_err(),
        "the retained Windows directory capability must prevent namespace replacement"
    );
    assert!(!crate::trusted_transactional_apply_execution::recovery::same_resource_recovery_blocks_new_work(
        &managed_root,
        &SafeResourceKey::parse("gksphone").unwrap(),
        TrustedCliUpdateOptions::default().max_journal_records,
    )
    .unwrap());
}

#[test]
fn terminal_retirement_rejects_active_or_manual_evidence_without_partial_publication() {
    let fixture = two_bound_overview_fixture("task32e2a-retirement-blocked");
    let blocked = crate::retire_trusted_terminal_update_evidence(
        &fixture.workspace,
        retirement_options(true),
    )
    .unwrap_err();
    assert!(matches!(
        blocked,
        GkrmError::TrustedTerminalEvidenceRetirementBlocked
    ));
    assert!(retirement_records(&fixture.workspace).is_empty());

    fs::create_dir(
        fixture
            .workspace
            .transaction_root()
            .join("transactions")
            .join("malformed-peer"),
    )
    .unwrap();
    let still_blocked = crate::retire_trusted_terminal_update_evidence(
        &fixture.workspace,
        retirement_options(true),
    )
    .unwrap_err();
    assert!(matches!(
        still_blocked,
        GkrmError::TrustedTerminalEvidenceRetirementBlocked
    ));
    assert!(retirement_records(&fixture.workspace).is_empty());
}

#[test]
fn corrupt_or_orphan_retirement_and_mutated_original_evidence_fail_closed() {
    for mode in [
        "record",
        "artifact",
        "orphan",
        "unsupported",
        "wrong-binding",
    ] {
        let (_mini, workspace, _candidate) =
            committed_workspace_v2(&format!("task32e2a-retirement-tamper-{mode}"));
        crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true))
            .unwrap();
        let record = retirement_records(&workspace).pop().unwrap();
        match mode {
            "record" => flip_first_byte(&record),
            "artifact" => flip_first_byte(&package_free_artifact_path(
                workspace.artifact_root().path(),
            )),
            "orphan" => fs::remove_dir_all(only_child_directory(
                &workspace.transaction_root().join("transactions"),
            ))
            .unwrap(),
            "unsupported" => {
                let version = b"gkrm-terminal-evidence-retirement\n".len();
                flip_byte_at(&record, version);
            }
            "wrong-binding" => {
                let (_foreign_mini, foreign_workspace, _foreign_candidate) =
                    committed_workspace_v2("task32e2a-retirement-foreign-binding");
                crate::retire_trusted_terminal_update_evidence(
                    &foreign_workspace,
                    retirement_options(true),
                )
                .unwrap();
                let foreign_record = retirement_records(&foreign_workspace).pop().unwrap();
                fs::copy(foreign_record, &record).unwrap();
            }
            _ => unreachable!(),
        }
        let overview = crate::inspect_trusted_recovery_workspace_overview(
            Some(&workspace),
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap();
        assert!(!overview.is_clear(), "{mode} must fail closed");
        if mode == "unsupported" {
            assert!(overview.has_unsupported_evidence());
        } else {
            assert!(overview.has_manual_attention());
        }
        assert!(matches!(
            crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true)),
            Err(GkrmError::TrustedTerminalEvidenceRetirementBlocked)
        ));
    }
}

#[test]
fn fabricated_terminal_retirement_cannot_suppress_nonterminal_recovery() {
    let (_terminal_mini, terminal_workspace, _terminal_candidate) =
        committed_workspace_v2("task32e2a-retirement-marker-source");
    crate::retire_trusted_terminal_update_evidence(&terminal_workspace, retirement_options(true))
        .unwrap();
    let source_record_dir = retirement_records(&terminal_workspace)
        .pop()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let fixture = two_bound_overview_fixture("task32e2a-nonterminal-marker");
    let transactions = fixture.workspace.transaction_root().join("transactions");
    let active_plan_id = fs::read_dir(&transactions)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name().unwrap().to_string_lossy() != fixture.terminal_transaction_name
                && path.is_dir()
        })
        .unwrap()
        .file_name()
        .unwrap()
        .to_owned();
    let retirement_root = fixture
        .workspace
        .transaction_root()
        .join("terminal-retirements");
    fs::create_dir(&retirement_root).unwrap();
    copy_test_tree(&source_record_dir, &retirement_root.join(active_plan_id));

    let overview = crate::inspect_trusted_recovery_workspace_overview(
        Some(&fixture.workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(overview.has_manual_attention());
    assert!(!overview.is_clear());
    assert!(matches!(
        crate::retire_trusted_terminal_update_evidence(
            &fixture.workspace,
            retirement_options(true)
        ),
        Err(GkrmError::TrustedTerminalEvidenceRetirementBlocked)
    ));
}

#[test]
fn terminal_retirement_catalog_enforces_global_count_entry_and_byte_bounds() {
    for (name, limits) in [
        ("records", (4, 1, 1_024, 10 * 1024 * 1024)),
        ("entries", (2, 2, 1_024, 10 * 1024 * 1024)),
        ("single-bytes", (4, 2, 1, 10 * 1024 * 1024)),
        ("total-bytes", (4, 2, 1_024, 1)),
    ] {
        let (_mini, workspace, _candidate) =
            committed_workspace_v2(&format!("task32e2a-retirement-bound-{name}"));
        crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true))
            .unwrap();
        if matches!(name, "records" | "entries") {
            let retirement_root = workspace.transaction_root().join("terminal-retirements");
            let original = fs::read_dir(&retirement_root)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let duplicate_name = "11".repeat(32);
            assert_ne!(
                original.file_name().unwrap().to_string_lossy(),
                duplicate_name
            );
            copy_test_tree(&original, &retirement_root.join(duplicate_name));
        }
        let _limit_guard =
            crate::trusted_package_free_update_recovery::set_retirement_limits_for_test(
                limits.0, limits.1, limits.2, limits.3,
            );
        let overview = crate::inspect_trusted_recovery_workspace_overview(
            Some(&workspace),
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap();
        assert!(overview.has_manual_attention(), "{name} must fail closed");
        assert!(!overview.is_clear(), "{name} must not produce clear");
    }
}

#[test]
fn terminal_retirement_reserves_managed_workspace_capacity_before_publication() {
    let (_mini, workspace, _candidate) = committed_workspace_v2("task32e2a-retirement-capacity");
    let mut options = retirement_options(true);
    options.workspace.max_regular_file_bytes = 1;
    let error = crate::retire_trusted_terminal_update_evidence(&workspace, options).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedUpdateWorkspaceCapacityReached
    ));
    assert!(retirement_records(&workspace).is_empty());
    assert!(crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap()
    .has_terminal_evidence());
}

#[test]
fn retired_t1_allows_successor_t2_which_blocks_independently_and_preserves_history() {
    let (mini, workspace, review_t1) = ready_workspace_desktop_apply("task32e2a-successor");
    assert_eq!(
        apply_trusted_desktop_update(TrustedDesktopApplyRequest {
            authority: review_t1.desktop_apply_authority.as_ref().unwrap(),
            options: TrustedCliUpdateOptions::default(),
        })
        .unwrap()
        .outcome,
        "committed"
    );
    drop(review_t1);
    let transactions = workspace.transaction_root().join("transactions");
    let t1 = only_child_directory(&transactions);
    let t1_before = crate::trusted_staging::test_support::hash_tree(&t1);

    let package_t2 = mini._temp.path().join("successor-v3.zip");
    write_zip(
        &package_t2,
        &[
            (
                "gksphone/fxmanifest.lua",
                &fs::read(mini.installed_resource.join("fxmanifest.lua")).unwrap(),
            ),
            (
                "gksphone/merge.lua",
                &fs::read(mini.installed_resource.join("merge.lua")).unwrap(),
            ),
            ("gksphone/take.lua", b"successor-v3\n"),
            (
                "gksphone/nested/child.lua",
                &fs::read(mini.installed_resource.join("nested/child.lua")).unwrap(),
            ),
        ],
    );
    let artifact_t2 = workspace
        .artifact_root()
        .allocate_plan_artifact_path()
        .unwrap();
    let blocked = plan_trusted_cli_update_for_review(TrustedCliPlanRequest {
        package: &package_t2,
        installed: &mini.installed_parent,
        baseline_store: workspace.baseline_store(),
        baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        decisions_path: None,
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_t2,
        workspace: Some(&workspace),
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap_err();
    assert!(matches!(
        blocked,
        GkrmError::TrustedCliUpdateRecoveryRequired
    ));

    crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true)).unwrap();
    let pending = plan_trusted_cli_update_for_review(TrustedCliPlanRequest {
        package: &package_t2,
        installed: &mini.installed_parent,
        baseline_store: workspace.baseline_store(),
        baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        decisions_path: None,
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_t2,
        workspace: Some(&workspace),
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(pending.report.outcome, "pending_decisions");
    let decisions = pending
        .report
        .pending_paths
        .iter()
        .map(|path| {
            let plan_entry = pending
                .plan
                .entries()
                .iter()
                .find(|entry| entry.path().as_str() == path)
                .unwrap();
            TrustedCliDecisionEntry {
                path: plan_entry.path().clone(),
                choice: ThreeWayPlanDecisionChoice::UseIncomingState,
                policy_acknowledgement: PolicyTransitionAcknowledgement::NotProvided,
                operator_merge_relpath: None,
            }
        })
        .collect();
    let decision_doc = build_decision_document(
        &pending.plan,
        decisions,
        &TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    let decision_path = mini._temp.path().join("successor-decisions.bin");
    fs::write(&decision_path, decision_doc.canonical_bytes()).unwrap();
    drop(pending);

    let t2_inspection = inspect_installation_update(
        &mini.installed_parent,
        &package_t2,
        InspectionOptions::default(),
    )
    .unwrap();
    let t2_selected = resolve_selected_resource(
        &t2_inspection,
        Some(&SafeResourceKey::parse("gksphone").unwrap()),
    )
    .unwrap();
    let t2_expected = source_commitments_from_report(&t2_inspection, &t2_selected).unwrap();
    let ready_t2 = plan_trusted_cli_update_for_review_with_expected_source_commitments(
        TrustedCliPlanRequest {
            package: &package_t2,
            installed: &mini.installed_parent,
            baseline_store: workspace.baseline_store(),
            baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
            resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
            staging_root: workspace.staging_root(),
            transaction_root: workspace.transaction_root(),
            decisions_path: Some(&decision_path),
            decisions_out: None,
            operator_merge_root: None,
            artifact_out: &artifact_t2,
            workspace: Some(&workspace),
            workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
            options: TrustedCliUpdateOptions::default(),
        },
        &t2_expected,
    )
    .unwrap();
    assert_eq!(ready_t2.report.outcome, "ready_to_apply");
    assert_eq!(
        apply_trusted_desktop_update(TrustedDesktopApplyRequest {
            authority: ready_t2.desktop_apply_authority.as_ref().unwrap(),
            options: TrustedCliUpdateOptions::default(),
        })
        .unwrap()
        .outcome,
        "committed"
    );
    drop(ready_t2);
    let transaction_dirs = fs::read_dir(&transactions)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(transaction_dirs.len(), 2);
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(&t1),
        t1_before
    );
    assert_eq!(retirement_records(&workspace).len(), 1);
    assert_eq!(
        regular_files_recursive(workspace.artifact_root().path()).len(),
        2
    );
    let t2_terminal = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(t2_terminal.has_terminal_evidence());
    assert!(!t2_terminal.is_clear());

    let artifact_t3 = workspace
        .artifact_root()
        .allocate_plan_artifact_path()
        .unwrap();
    let t2_blocks = plan_trusted_cli_update_for_review(TrustedCliPlanRequest {
        package: &package_t2,
        installed: &mini.installed_parent,
        baseline_store: workspace.baseline_store(),
        baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        decisions_path: None,
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_t3,
        workspace: Some(&workspace),
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap_err();
    assert!(matches!(
        t2_blocks,
        GkrmError::TrustedCliUpdateRecoveryRequired
    ));

    let retired_t2 =
        crate::retire_trusted_terminal_update_evidence(&workspace, retirement_options(true))
            .unwrap();
    assert_eq!(retired_t2.retired_count(), 1);
    assert_eq!(retired_t2.already_retired_count(), 1);
    assert_eq!(retirement_records(&workspace).len(), 2);
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(&t1),
        t1_before
    );
    assert!(crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap()
    .is_clear());
}

struct TwoBoundOverviewFixture {
    _committed: MiniFixture,
    _active: MiniFixture,
    _target_temp: tempfile::TempDir,
    workspace: crate::TrustedUpdateWorkspace,
    terminal_transaction_name: String,
    active_artifact_name: String,
}

fn two_bound_overview_fixture(name: &str) -> TwoBoundOverviewFixture {
    let (committed, committed_workspace, _committed_candidate) =
        committed_workspace_v2(&format!("{name}-terminal"));
    let (active, active_workspace, review) = ready_workspace_desktop_apply_with_take_choice(
        &format!("{name}-active"),
        ThreeWayPlanDecisionChoice::PreserveInstalledState,
    );
    {
        let _guard = lock_execution_hooks();
        set_publication_hook(PublicationPoint::AfterFilePublish, || {
            panic!("simulated process interruption")
        });
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
                authority: review.desktop_apply_authority.as_ref().unwrap(),
                options: TrustedCliUpdateOptions::default(),
            });
        }));
        assert!(crashed.is_err());
    }
    drop(review);

    let committed_transaction =
        only_child_directory(&committed_workspace.transaction_root().join("transactions"));
    let active_transaction =
        only_child_directory(&active_workspace.transaction_root().join("transactions"));
    assert_ne!(
        committed_transaction.file_name(),
        active_transaction.file_name(),
        "the two overview candidates must have distinct durable plan bindings"
    );
    let committed_artifact = regular_files_recursive(committed_workspace.artifact_root().path());
    let active_artifact = regular_files_recursive(active_workspace.artifact_root().path());
    assert_eq!(committed_artifact.len(), 1);
    assert_eq!(active_artifact.len(), 1);
    assert_ne!(
        committed_artifact[0].file_name(),
        active_artifact[0].file_name(),
        "the two overview candidates must have distinct artifact bindings"
    );

    let target_temp = tempfile::tempdir().unwrap();
    let workspace = crate::resolve_trusted_update_workspace(
        &target_temp.path().join(format!("workspace-{name}")),
    )
    .unwrap();
    copy_test_tree(
        &committed_workspace.transaction_root().join("transactions"),
        &workspace.transaction_root().join("transactions"),
    );
    copy_test_tree(
        &active_workspace.transaction_root().join("transactions"),
        &workspace.transaction_root().join("transactions"),
    );
    copy_test_tree(
        committed_workspace.artifact_root().path(),
        workspace.artifact_root().path(),
    );
    copy_test_tree(
        active_workspace.artifact_root().path(),
        workspace.artifact_root().path(),
    );

    TwoBoundOverviewFixture {
        _committed: committed,
        _active: active,
        _target_temp: target_temp,
        workspace,
        terminal_transaction_name: committed_transaction
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        active_artifact_name: active_artifact[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    }
}

#[test]
fn recovery_workspace_overview_aggregates_mixed_evidence_independent_of_order() {
    let fixture = two_bound_overview_fixture("task32e1-overview-mixed");
    let transactions = fixture.workspace.transaction_root().join("transactions");
    let unsupported_low = transactions.join(format!("{}1", "0".repeat(63)));
    copy_test_tree(
        &transactions.join(&fixture.terminal_transaction_name),
        &unsupported_low,
    );
    mutate_package_free_journal(
        &unsupported_low.join("journal"),
        "journal-unsupported-version",
    );
    fs::create_dir(transactions.join("malformed-peer")).unwrap();

    for unsupported_name in [
        format!("{}1", "0".repeat(63)),
        format!("{}e", "f".repeat(63)),
    ] {
        let current = fs::read_dir(&transactions)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.is_dir()
                    && path.join("journal").is_dir()
                    && fs::read_dir(path.join("journal")).unwrap().any(|entry| {
                        fs::read(entry.unwrap().path())
                            .unwrap()
                            .starts_with(b"gkrm-txn-journal-v9\n")
                    })
            })
            .unwrap();
        let expected = transactions.join(&unsupported_name);
        if current != expected {
            fs::rename(current, &expected).unwrap();
        }
        crate::trusted_package_free_update_recovery::reset_artifact_parse_attempts();
        crate::trusted_package_free_update_recovery::reset_overview_artifact_catalog_loads();
        crate::trusted_package_free_update_recovery::reset_overview_retirement_catalog_loads();
        let before = crate::trusted_staging::test_support::hash_tree(fixture.workspace.app_root());
        let overview = crate::inspect_trusted_recovery_workspace_overview(
            Some(&fixture.workspace),
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap();
        assert!(overview.has_active_recovery());
        assert!(overview.has_terminal_evidence());
        assert!(overview.has_manual_attention());
        assert!(overview.has_unsupported_evidence());
        assert_eq!(
            crate::trusted_package_free_update_recovery::overview_artifact_catalog_loads(),
            1
        );
        assert_eq!(
            crate::trusted_package_free_update_recovery::overview_retirement_catalog_loads(),
            1
        );
        assert_eq!(
            crate::trusted_package_free_update_recovery::artifact_parse_attempts(),
            2
        );
        assert_eq!(
            crate::trusted_staging::test_support::hash_tree(fixture.workspace.app_root()),
            before
        );
    }
}

#[test]
fn recovery_workspace_overview_catalog_enforces_global_limits_and_exact_binding() {
    let fixture = two_bound_overview_fixture("task32e1-overview-catalog");
    let artifact_files = regular_files_recursive(fixture.workspace.artifact_root().path());
    assert_eq!(artifact_files.len(), 2);
    let artifact_lengths = artifact_files
        .iter()
        .map(|path| fs::metadata(path).unwrap().len())
        .collect::<Vec<_>>();
    let total_artifact_bytes = artifact_lengths.iter().sum::<u64>();
    let max_artifact_bytes = *artifact_lengths.iter().max().unwrap();

    let mut at_limit = crate::TrustedPackageFreeUpdateRecoveryOptions::default();
    at_limit.scan.max_transactions = 2;
    at_limit.scan.max_total_scan_entries = 2;
    at_limit.max_artifact_directory_entries = 2;
    at_limit.max_artifacts = 2;
    at_limit.max_artifact_bytes = max_artifact_bytes;
    at_limit.max_total_artifact_bytes = total_artifact_bytes;
    crate::trusted_package_free_update_recovery::reset_artifact_parse_attempts();
    crate::trusted_package_free_update_recovery::reset_overview_artifact_catalog_loads();
    crate::trusted_package_free_update_recovery::reset_overview_retirement_catalog_loads();
    let overview =
        crate::inspect_trusted_recovery_workspace_overview(Some(&fixture.workspace), at_limit)
            .unwrap();
    assert!(overview.has_active_recovery());
    assert!(overview.has_terminal_evidence());
    assert_eq!(
        crate::trusted_package_free_update_recovery::overview_artifact_catalog_loads(),
        1
    );
    assert_eq!(
        crate::trusted_package_free_update_recovery::overview_retirement_catalog_loads(),
        1
    );
    assert_eq!(
        crate::trusted_package_free_update_recovery::artifact_parse_attempts(),
        2
    );

    let mut over_transaction_limit = at_limit;
    over_transaction_limit.scan.max_transactions = 1;
    assert!(crate::inspect_trusted_recovery_workspace_overview(
        Some(&fixture.workspace),
        over_transaction_limit,
    )
    .is_err());

    for over_limit in [
        crate::TrustedPackageFreeUpdateRecoveryOptions {
            max_artifact_directory_entries: 1,
            ..at_limit
        },
        crate::TrustedPackageFreeUpdateRecoveryOptions {
            max_artifacts: 1,
            ..at_limit
        },
        crate::TrustedPackageFreeUpdateRecoveryOptions {
            max_total_artifact_bytes: total_artifact_bytes - 1,
            ..at_limit
        },
    ] {
        let blocked = crate::inspect_trusted_recovery_workspace_overview(
            Some(&fixture.workspace),
            over_limit,
        )
        .unwrap();
        assert!(blocked.has_manual_attention());
        assert!(!blocked.has_active_recovery());
        assert!(!blocked.has_terminal_evidence());
        assert!(!blocked.is_clear());
    }

    let duplicate_artifact = fixture
        .workspace
        .artifact_root()
        .path()
        .join("plan-duplicate-valid-identity.bin");
    fs::copy(&artifact_files[0], &duplicate_artifact).unwrap();
    let ambiguous = crate::inspect_trusted_recovery_workspace_overview(
        Some(&fixture.workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(ambiguous.has_manual_attention());
    assert!(!ambiguous.is_clear());
    fs::remove_file(duplicate_artifact).unwrap();

    fs::remove_file(
        fixture
            .workspace
            .artifact_root()
            .path()
            .join(&fixture.active_artifact_name),
    )
    .unwrap();
    let exact = crate::inspect_trusted_recovery_workspace_overview(
        Some(&fixture.workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(exact.has_terminal_evidence());
    assert!(!exact.has_active_recovery());
    assert!(exact.has_manual_attention());

    let defaults = crate::TrustedPackageFreeUpdateRecoveryOptions::default();
    assert_eq!(defaults.scan.max_transactions, 10_000);
    assert_eq!(defaults.max_artifacts, 1_000);
    assert_eq!(defaults.max_total_artifact_bytes, 8 * 1024 * 1024 * 1024);
}

#[test]
fn real_apply_rejects_post_lock_selected_resource_authority_drift() {
    let fixture = ready_desktop_apply_fixture("post-lock-selected-drift");
    assert_real_apply_rejects_post_lock_key_drift(&fixture, false);
}

#[test]
fn real_apply_with_prebuilt_backend_authority_rejects_post_lock_key_drift() {
    let fixture = ready_desktop_apply_fixture("prebuilt-authority-post-lock-drift");
    assert_real_apply_rejects_post_lock_key_drift(&fixture, true);
}

#[test]
fn package_free_v2_recovery_survives_restart_and_missing_package() {
    let restart = phase_a_publish_for_strict_restart();

    let fresh_workspace = crate::resolve_trusted_update_workspace(&restart.workspace_root).unwrap();
    let root = crate::TrustedTransactionRoot::try_open(fresh_workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    let candidate = *scan
        .candidates()
        .iter()
        .find(|candidate| candidate.kind() == crate::TrustedRecoveryCandidateKind::Bound)
        .unwrap()
        .candidate_id();
    drop(scan);
    drop(root);

    let selected = trusted_gksphone_selection_at(&restart.installed_parent);
    let transaction_before =
        crate::trusted_staging::test_support::hash_tree(fresh_workspace.transaction_root());
    let artifacts_before =
        crate::trusted_staging::test_support::hash_tree(fresh_workspace.artifact_root().path());
    let staging_before =
        crate::trusted_staging::test_support::hash_tree(fresh_workspace.staging_root());
    let baselines_before =
        crate::trusted_staging::test_support::hash_tree(fresh_workspace.baseline_store());
    let package_guard = crate::package_source::package_source_hook_guard();
    crate::package_source::set_before_package_open_hook(|path| {
        panic!(
            "package-free recovery attempted package access: {}",
            path.display()
        )
    });
    let first = crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &fresh_workspace,
            &candidate,
            &selected,
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        first,
        crate::TrustedRecoveryResult::RecoveredCommitted(_)
    ));
    let second_workspace =
        crate::resolve_trusted_update_workspace(fresh_workspace.app_root()).unwrap();
    let second_selection = trusted_gksphone_selection_at(&restart.installed_parent);
    let second = crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &second_workspace,
            &candidate,
            &second_selection,
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        second,
        crate::TrustedRecoveryResult::RecoveredCommitted(_)
    ));
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(second_workspace.transaction_root()),
        transaction_before
    );
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(second_workspace.artifact_root().path()),
        artifacts_before
    );
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(second_workspace.staging_root()),
        staging_before
    );
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(second_workspace.baseline_store()),
        baselines_before
    );
    assert!(restart.installed_resource.is_dir());
    drop(package_guard);
}

struct StrictRestartCoordinates {
    _container: tempfile::TempDir,
    workspace_root: PathBuf,
    installed_parent: PathBuf,
    installed_resource: PathBuf,
}

fn phase_a_publish_for_strict_restart() -> StrictRestartCoordinates {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task31b-strict-restart");
    let applied = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
        authority: review.desktop_apply_authority.as_ref().unwrap(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(applied.outcome, "committed");
    let workspace_root = workspace.app_root().to_path_buf();
    drop(review);
    drop(workspace);

    let MiniFixture {
        _temp,
        installed_parent,
        installed_resource,
        package_v2,
        ..
    } = mini;
    fs::remove_file(&package_v2).unwrap();
    fs::create_dir(&package_v2).unwrap();
    assert!(package_v2.is_dir());
    drop(package_v2);
    StrictRestartCoordinates {
        _container: _temp,
        workspace_root,
        installed_parent,
        installed_resource,
    }
}

#[test]
fn package_free_v2_rejects_legacy_v1_without_weakening_package_backed_apply() {
    let mini = build_mini();
    let workspace = crate::resolve_trusted_update_workspace(
        &mini._temp.path().join("task31b-legacy-workspace"),
    )
    .unwrap();
    copy_test_tree(&mini.store, workspace.baseline_store());
    let artifact_out = workspace
        .artifact_root()
        .allocate_plan_artifact_path()
        .unwrap();
    let decisions = mini._temp.path().join("task31b-legacy-decisions.bin");
    write_decisions_file(&mini, &decisions);
    let planned = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &mini.package_v2,
        installed: &mini.installed_parent,
        baseline_store: workspace.baseline_store(),
        baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: Some(&workspace),
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(planned.outcome, "ready_to_apply");
    let artifact = parse_cli_artifact(
        &fs::read(&artifact_out).unwrap(),
        &TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    assert_eq!(artifact.version(), 1);

    let applied = apply_trusted_cli_update(TrustedCliApplyRequest {
        artifact: &artifact_out,
        package: &mini.package_v2,
        installed: &mini.installed_parent,
        baseline_store: workspace.baseline_store(),
        baseline_selector: OfficialBaselineSelector::Exact(mini.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        decisions_path: Some(&decisions),
        operator_merge_root: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(applied.outcome, "committed");
    fs::remove_file(&mini.package_v2).unwrap();

    let selected = trusted_gksphone_selection(&mini);
    let inspection = crate::inspect_trusted_published_update_v2(
        &workspace,
        &selected,
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert_eq!(
        inspection.state(),
        crate::TrustedPublishedUpdateRecoveryState::ManualAttention
    );
    assert!(inspection.candidate_id().is_none());
    let overview = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(overview.has_unsupported_evidence());
    assert!(!overview.is_clear());

    let root = crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    let candidate = *scan.candidates()[0].candidate_id();
    drop(scan);
    drop(root);
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported
    ));
}

fn recover_workspace_v2(
    mini: &MiniFixture,
    workspace: &crate::TrustedUpdateWorkspace,
) -> crate::TrustedRecoveryResult {
    try_recover_workspace_v2(mini, workspace).unwrap()
}

fn trusted_gksphone_selection(mini: &MiniFixture) -> crate::TrustedInstalledRecoverySelection {
    trusted_gksphone_selection_at(&mini.installed_parent)
}

fn trusted_gksphone_selection_at(
    installed_parent: &Path,
) -> crate::TrustedInstalledRecoverySelection {
    crate::scan_trusted_installed_recovery_resources(
        installed_parent,
        crate::InstalledScanLimits::default(),
    )
    .unwrap()
    .select(&SafeResourceKey::parse("gksphone").unwrap())
    .unwrap()
}

fn try_recover_workspace_v2(
    mini: &MiniFixture,
    workspace: &crate::TrustedUpdateWorkspace,
) -> crate::Result<crate::TrustedRecoveryResult> {
    let fresh_workspace = crate::resolve_trusted_update_workspace(workspace.app_root()).unwrap();
    let root = crate::TrustedTransactionRoot::try_open(fresh_workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    let candidate = *scan
        .candidates()
        .iter()
        .find(|candidate| candidate.kind() == crate::TrustedRecoveryCandidateKind::Bound)
        .unwrap()
        .candidate_id();
    drop(scan);
    drop(root);
    try_recover_workspace_candidate(mini, &fresh_workspace, &candidate)
}

fn try_recover_workspace_candidate(
    mini: &MiniFixture,
    workspace: &crate::TrustedUpdateWorkspace,
    candidate: &crate::TrustedRecoveryCandidateId,
) -> crate::Result<crate::TrustedRecoveryResult> {
    try_recover_workspace_candidate_with_options(
        mini,
        workspace,
        candidate,
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
}

fn try_recover_workspace_candidate_with_options(
    mini: &MiniFixture,
    workspace: &crate::TrustedUpdateWorkspace,
    candidate: &crate::TrustedRecoveryCandidateId,
    options: crate::TrustedPackageFreeUpdateRecoveryOptions,
) -> crate::Result<crate::TrustedRecoveryResult> {
    let selected = trusted_gksphone_selection(mini);
    crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            workspace, candidate, &selected, options,
        )
        .unwrap(),
    )
}

fn committed_workspace_v2(
    name: &str,
) -> (
    MiniFixture,
    crate::TrustedUpdateWorkspace,
    crate::TrustedRecoveryCandidateId,
) {
    let (mini, workspace, review) = ready_workspace_desktop_apply(name);
    let report = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
        authority: review.desktop_apply_authority.as_ref().unwrap(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(report.outcome, "committed");
    drop(review);
    fs::remove_file(&mini.package_v2).unwrap();
    let root = crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    let candidate = *scan
        .candidates()
        .iter()
        .find(|candidate| candidate.kind() == crate::TrustedRecoveryCandidateKind::Bound)
        .unwrap()
        .candidate_id();
    (mini, workspace, candidate)
}

fn fresh_bound_candidate(
    workspace: &crate::TrustedUpdateWorkspace,
) -> crate::TrustedRecoveryCandidateId {
    let root = crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    *scan
        .candidates()
        .iter()
        .find(|candidate| candidate.kind() == crate::TrustedRecoveryCandidateKind::Bound)
        .unwrap()
        .candidate_id()
}

fn durable_binding_digest(path: &Path) -> Sha256Digest {
    let bytes = fs::read(path).unwrap();
    let digest: [u8; 32] = bytes[bytes.len() - 32..].try_into().unwrap();
    Sha256Digest::new(digest)
}

fn reseal_package_free_publication(
    workspace: &crate::TrustedUpdateWorkspace,
    transaction: &Path,
    mut artifact_body: TrustedCliUpdateArtifactBody,
    descriptor: &super::TrustedCliApplyDescriptor,
    authority_body: crate::RecoveryAuthorityBodyV1,
) {
    let limits = RecoveryAuthorityLimits::default();
    let authority_id = crate::trusted_recovery_authority::test_encode_recovery_authority_id(
        &authority_body,
        limits,
    )
    .unwrap();
    artifact_body.recovery_authority_id = Some(*authority_id.digest());
    let artifact =
        super::artifact::encode_cli_artifact_v2_with_apply_descriptor(&artifact_body, descriptor)
            .unwrap();
    let artifact_path = package_free_artifact_path(workspace.artifact_root().path());
    fs::write(&artifact_path, artifact.canonical_bytes()).unwrap();

    let snapshot_a = durable_binding_digest(&transaction.join("snapshot-a.bin"));
    let resource_lock = durable_binding_digest(&transaction.join("resource-lock-id.bin"));
    let plan_id = *authority_body.transactional_plan_id();
    let publication = crate::trusted_recovery_authority::encode_publication_binding_id(
        artifact.artifact_id().digest(),
        &authority_id,
        &plan_id,
        &snapshot_a,
        &resource_lock,
    )
    .unwrap();
    let envelope = crate::RecoveryAuthorityEnvelopeV1::create(
        authority_body,
        authority_id,
        *artifact.artifact_id().digest(),
        publication,
        limits,
    )
    .unwrap();
    let envelope_bytes =
        crate::trusted_recovery_authority::encode_recovery_authority_envelope(&envelope, limits)
            .unwrap();
    fs::write(transaction.join("recovery-authority.bin"), envelope_bytes).unwrap();
    crate::trusted_transactional_apply_execution::journal::reseal_v2_publication_binding_for_test(
        &transaction.join("journal"),
        &plan_id,
        &snapshot_a,
        *publication.digest(),
    )
    .unwrap();

    let reparsed_artifact = parse_cli_artifact(
        &fs::read(artifact_path).unwrap(),
        &TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    let reparsed_envelope = crate::parse_recovery_authority_envelope(
        &fs::read(transaction.join("recovery-authority.bin")).unwrap(),
        limits,
    )
    .unwrap();
    assert_eq!(
        reparsed_artifact.artifact_id().digest(),
        reparsed_envelope.artifact_id()
    );
    assert_eq!(
        reparsed_artifact.body().recovery_authority_id,
        Some(*reparsed_envelope.authority_id().digest())
    );
    assert_eq!(reparsed_envelope.publication_binding_id(), &publication);
}

#[derive(Clone, Copy)]
enum DeepPackageFreeTamper {
    ArtifactSnapshot,
    ArtifactApplyPlan,
    AuthoritySelectedResource,
    UnsupportedDerivation,
}

fn reseal_deep_package_free_tamper(
    workspace: &crate::TrustedUpdateWorkspace,
    transaction: &Path,
    tamper: DeepPackageFreeTamper,
) {
    let artifact = parse_cli_artifact(
        &fs::read(package_free_artifact_path(workspace.artifact_root().path())).unwrap(),
        &TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    let descriptor = artifact.apply_descriptor().unwrap().clone();
    let mut artifact_body = artifact.body().clone();
    let envelope = crate::parse_recovery_authority_envelope(
        &fs::read(transaction.join("recovery-authority.bin")).unwrap(),
        RecoveryAuthorityLimits::default(),
    )
    .unwrap();
    let mut authority_body = envelope.body().clone();
    match tamper {
        DeepPackageFreeTamper::ArtifactSnapshot => {
            artifact_body.snapshot_a = Sha256Digest::new([0x51; 32]);
        }
        DeepPackageFreeTamper::ArtifactApplyPlan => {
            let changed = Sha256Digest::new([0x52; 32]);
            artifact_body.apply_plan_id = changed;
            authority_body.apply_plan_id = changed;
        }
        DeepPackageFreeTamper::AuthoritySelectedResource => {
            let changed = Sha256Digest::new([0x53; 32]);
            artifact_body.selected_resource_commitment = changed;
            authority_body.selected_resource_commitment = changed;
        }
        DeepPackageFreeTamper::UnsupportedDerivation => {
            authority_body.apply_derivation_version = 2;
            authority_body.transaction_derivation_version = 1;
        }
    }
    reseal_package_free_publication(
        workspace,
        transaction,
        artifact_body,
        &descriptor,
        authority_body,
    );
}

#[test]
fn package_free_v2_direct_core_outcomes_cover_safe_restart() {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task31b-safe-restart");
    {
        let _guard = lock_execution_hooks();
        set_publication_hook(PublicationPoint::BeforeBackup, || panic!("simulated crash"));
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
                authority: review.desktop_apply_authority.as_ref().unwrap(),
                options: TrustedCliUpdateOptions::default(),
            });
        }));
        assert!(crashed.is_err());
    }
    drop(review);
    fs::remove_file(&mini.package_v2).unwrap();
    let recovered = recover_workspace_v2(&mini, &workspace);
    assert!(matches!(
        recovered,
        crate::TrustedRecoveryResult::SafeRestart(_)
    ));
    let terminal_before =
        crate::trusted_staging::test_support::hash_tree(workspace.transaction_root());
    assert!(matches!(
        recover_workspace_v2(&mini, &workspace),
        crate::TrustedRecoveryResult::SafeRestart(_)
    ));
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.transaction_root()),
        terminal_before
    );
    let overview = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(overview.has_terminal_evidence());
}

#[test]
fn package_free_v2_direct_core_outcomes_cover_recovered_rolled_back() {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task31b-rolled-back");
    {
        let _guard = lock_execution_hooks();
        set_journal_fault(Some(JournalFault::ForwardStepCompleted));
        let _report = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
            authority: review.desktop_apply_authority.as_ref().unwrap(),
            options: TrustedCliUpdateOptions::default(),
        })
        .unwrap();
    }
    drop(review);
    fs::remove_file(&mini.package_v2).unwrap();
    let recovered = recover_workspace_v2(&mini, &workspace);
    assert!(matches!(
        recovered,
        crate::TrustedRecoveryResult::RecoveredRolledBack(_)
    ));
    let terminal_before =
        crate::trusted_staging::test_support::hash_tree(workspace.transaction_root());
    assert!(matches!(
        recover_workspace_v2(&mini, &workspace),
        crate::TrustedRecoveryResult::RecoveredRolledBack(_)
    ));
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.transaction_root()),
        terminal_before
    );
    let overview = crate::inspect_trusted_recovery_workspace_overview(
        Some(&workspace),
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    assert!(overview.has_terminal_evidence());
}

#[test]
fn package_free_v2_direct_core_outcomes_cover_recovery_still_required() {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task31b-still-required");
    {
        let _guard = lock_execution_hooks();
        set_forward_op_fault(Some(ForwardOpFault::ReplaceFile));
        let _report = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
            authority: review.desktop_apply_authority.as_ref().unwrap(),
            options: TrustedCliUpdateOptions::default(),
        })
        .unwrap();
    }
    drop(review);
    fs::remove_file(&mini.package_v2).unwrap();
    let recovered = recover_workspace_v2(&mini, &workspace);
    assert!(matches!(
        recovered,
        crate::TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    assert!(transaction.join("journal").is_dir());
    assert!(transaction.join("recovery-authority.bin").is_file());
    assert!(transaction.join("snapshot-a.bin").is_file());
    assert!(transaction.join("resource-lock-id.bin").is_file());
}

#[test]
fn package_free_v2_tamper_matrix_fails_closed_without_new_mutation() {
    for label in [
        "artifact-bytes",
        "artifact-self-id",
        "artifact-recovery-authority-id",
        "artifact-selected-resource",
        "artifact-installed-snapshot",
        "artifact-snapshot",
        "artifact-apply-plan",
        "artifact-transactional-plan",
        "authority-magic",
        "authority-canonical-field",
        "authority-node-path",
        "authority-node-digest",
        "authority-node-length",
        "authority-directory-node",
        "authority-id",
        "authority-envelope-artifact-id",
        "authority-publication-binding",
        "authority-unsupported-derivation",
        "snapshot-mismatch",
        "snapshot-missing",
        "resource-lock-mismatch",
        "resource-lock-missing",
        "journal-body",
        "journal-record-id",
        "journal-previous-chain",
        "journal-sequence",
        "journal-publication-binding",
        "journal-truncated",
        "journal-unsupported-version",
        "journal-malformed-version",
        "staging-manifest",
        "staging-bundle-id",
        "staged-file-bytes",
        "staged-file-missing",
        "staging-extra-entry",
        "baseline-manifest",
        "baseline-blob",
        "baseline-missing",
        "backup-manifest",
        "backup-seal",
        "backup-entry-altered",
        "backup-entry-missing",
        "backup-extra-entry",
        "backup-entry-swapped",
    ] {
        let (mini, workspace, candidate) =
            committed_workspace_v2(&format!("task31b-tamper-{label}"));
        let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
        match label {
            label if label.starts_with("artifact-") => {
                mutate_package_free_artifact(workspace.artifact_root().path(), label)
            }
            label if label.starts_with("authority-") => {
                mutate_package_free_authority(&transaction.join("recovery-authority.bin"), label)
            }
            "snapshot-mismatch" => flip_first_byte(&transaction.join("snapshot-a.bin")),
            "snapshot-missing" => fs::remove_file(transaction.join("snapshot-a.bin")).unwrap(),
            "resource-lock-mismatch" => flip_first_byte(&transaction.join("resource-lock-id.bin")),
            "resource-lock-missing" => {
                fs::remove_file(transaction.join("resource-lock-id.bin")).unwrap()
            }
            label if label.starts_with("journal-") => {
                mutate_package_free_journal(&transaction.join("journal"), label)
            }
            "staging-manifest" => {
                let bundle = only_child_directory(&workspace.staging_root().join("bundles"));
                flip_first_byte(&bundle.join("manifest.bin"));
            }
            "staging-bundle-id" => {
                let bundle = only_child_directory(&workspace.staging_root().join("bundles"));
                flip_byte_at(&bundle.join("manifest.bin"), 40);
            }
            "staged-file-bytes" => {
                let bundle = only_child_directory(&workspace.staging_root().join("bundles"));
                flip_first_byte(&bundle.join("resource/take.lua"));
            }
            "staged-file-missing" => {
                let bundle = only_child_directory(&workspace.staging_root().join("bundles"));
                fs::remove_file(bundle.join("resource/take.lua")).unwrap();
            }
            "staging-extra-entry" => {
                let bundle = only_child_directory(&workspace.staging_root().join("bundles"));
                fs::write(bundle.join("resource/uncommitted.lua"), b"extra").unwrap();
            }
            "baseline-manifest" => {
                flip_first_byte(&package_free_baseline_dir(&mini, &workspace).join("baseline.json"))
            }
            "baseline-blob" => {
                let baseline = package_free_baseline_dir(&mini, &workspace);
                let blob = regular_files_recursive(&baseline)
                    .into_iter()
                    .find(|path| {
                        path.file_name().and_then(|name| name.to_str()) != Some("baseline.json")
                    })
                    .unwrap();
                flip_first_byte(&blob);
            }
            "baseline-missing" => {
                fs::remove_file(package_free_baseline_dir(&mini, &workspace).join("baseline.json"))
                    .unwrap();
            }
            "backup-manifest" => flip_first_byte(&transaction.join("backup/manifest.bin")),
            "backup-seal" => flip_first_byte(&transaction.join("backup/seal.bin")),
            "backup-entry-altered" => {
                let entry = regular_files_recursive(&transaction.join("backup/files"))
                    .into_iter()
                    .next()
                    .unwrap();
                flip_first_byte(&entry);
            }
            "backup-entry-missing" => {
                let entry = regular_files_recursive(&transaction.join("backup/files"))
                    .into_iter()
                    .next()
                    .unwrap();
                fs::remove_file(entry).unwrap();
            }
            "backup-extra-entry" => {
                fs::write(transaction.join("backup/extra.bin"), b"extra").unwrap();
            }
            "backup-entry-swapped" => {
                let entries = regular_files_recursive(&transaction.join("backup/files"));
                assert!(entries.len() >= 2);
                let left = fs::read(&entries[0]).unwrap();
                let right = fs::read(&entries[1]).unwrap();
                fs::write(&entries[0], right).unwrap();
                fs::write(&entries[1], left).unwrap();
            }
            _ => unreachable!(),
        }
        let installed_before = PathSnapshot::capture(&mini.installed_resource);
        let transaction_before =
            crate::trusted_staging::test_support::hash_tree(workspace.transaction_root());
        let result = try_recover_workspace_candidate(&mini, &workspace, &candidate);
        assert!(result.is_err(), "{label} must fail closed");
        assert_eq!(
            PathSnapshot::capture(&mini.installed_resource),
            installed_before
        );
        assert_eq!(
            crate::trusted_staging::test_support::hash_tree(workspace.transaction_root()),
            transaction_before,
            "{label} must not append or rewrite evidence"
        );
    }
}

#[test]
fn package_free_v2_exact_selector_and_fresh_installed_selection_fail_closed() {
    let (mini, workspace, _candidate) = committed_workspace_v2("task31b-selector");
    let missing = crate::TrustedRecoveryCandidateId::from_selector_hex(&"00".repeat(32)).unwrap();
    let missing_error = try_recover_workspace_candidate(&mini, &workspace, &missing).unwrap_err();
    assert!(matches!(
        missing_error,
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound
    ));

    assert!(mini.installed_resource.is_dir());
}

#[test]
fn package_free_valid_resource_a_selection_rejects_candidate_b_at_resource_binding() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-resource-a-vs-b");
    let resource_a = mini.installed_parent.join("resource-a");
    write_file(&resource_a.join("fxmanifest.lua"), SIMPLE_MANIFEST);
    write_file(&resource_a.join("client.lua"), b"resource-a\n");
    let selection_a = crate::scan_trusted_installed_recovery_resources(
        &mini.installed_parent,
        crate::InstalledScanLimits::default(),
    )
    .unwrap()
    .select(&SafeResourceKey::parse("resource-a").unwrap())
    .unwrap();
    let installed_a_before = PathSnapshot::capture(&resource_a);
    let installed_b_before = PathSnapshot::capture(&mini.installed_resource);
    let transaction_before = PathSnapshot::capture(workspace.transaction_root());
    let error = crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &workspace,
            &candidate,
            &selection_a,
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
    ));
    assert_eq!(PathSnapshot::capture(&resource_a), installed_a_before);
    assert_eq!(
        PathSnapshot::capture(&mini.installed_resource),
        installed_b_before
    );
    assert_eq!(
        PathSnapshot::capture(workspace.transaction_root()),
        transaction_before,
        "resource crossing must not append journal or write backup evidence"
    );
}

#[test]
fn package_free_changed_safe_resource_key_reaches_fresh_commitment_rejection() {
    let (mini, workspace, _candidate) = committed_workspace_v2("task31b-changed-safe-key");
    let resource_a = mini.installed_parent.join("resource-a");
    write_file(&resource_a.join("fxmanifest.lua"), SIMPLE_MANIFEST);
    write_file(&resource_a.join("client.lua"), b"resource-a\n");
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    let artifact = parse_cli_artifact(
        &fs::read(package_free_artifact_path(workspace.artifact_root().path())).unwrap(),
        &TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    let envelope = crate::parse_recovery_authority_envelope(
        &fs::read(transaction.join("recovery-authority.bin")).unwrap(),
        RecoveryAuthorityLimits::default(),
    )
    .unwrap();
    let key_a = SafeResourceKey::parse("resource-a").unwrap();
    let resource_lock_a =
        crate::trusted_transactional_apply_execution::locks::encode_resource_lock_id(
            key_a.as_str(),
        )
        .unwrap();
    let mut lock_bytes = b"gkrm-txn-resource-lock-id-v1\n".to_vec();
    lock_bytes.extend_from_slice(resource_lock_a.as_bytes());
    fs::write(transaction.join("resource-lock-id.bin"), lock_bytes).unwrap();
    reseal_package_free_publication(
        &workspace,
        &transaction,
        artifact.body().clone(),
        artifact.apply_descriptor().unwrap(),
        envelope.body().clone(),
    );
    let candidate = fresh_bound_candidate(&workspace);
    let selection_a = crate::scan_trusted_installed_recovery_resources(
        &mini.installed_parent,
        crate::InstalledScanLimits::default(),
    )
    .unwrap()
    .select(&key_a)
    .unwrap();
    let installed_before = PathSnapshot::capture(&mini.installed_parent);
    let transaction_before = PathSnapshot::capture(workspace.transaction_root());
    let _observations = crate::trusted_package_free_update_recovery::validation_observation_guard();
    let error = crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &workspace,
            &candidate,
            &selection_a,
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
    ));
    assert_eq!(
        crate::trusted_package_free_update_recovery::validation_observations(),
        vec![
            crate::trusted_package_free_update_recovery::ValidationObservation::AuthoritySelfIdVerified
        ],
        "the changed legitimate key must fail at the fresh selected-resource commitment"
    );
    assert_eq!(
        PathSnapshot::capture(&mini.installed_parent),
        installed_before
    );
    assert_eq!(
        PathSnapshot::capture(workspace.transaction_root()),
        transaction_before
    );
}

#[test]
fn package_free_deep_artifact_snapshot_tamper_passes_self_id_then_cross_binding_rejects() {
    let (mini, workspace, _candidate) = committed_workspace_v2("task31b-deep-snapshot");
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    reseal_deep_package_free_tamper(
        &workspace,
        &transaction,
        DeepPackageFreeTamper::ArtifactSnapshot,
    );
    let candidate = fresh_bound_candidate(&workspace);
    let transaction_before = PathSnapshot::capture(workspace.transaction_root());
    let _observations = crate::trusted_package_free_update_recovery::validation_observation_guard();
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
    ));
    use crate::trusted_package_free_update_recovery::ValidationObservation as Event;
    assert_eq!(
        crate::trusted_package_free_update_recovery::validation_observations(),
        vec![
            Event::AuthoritySelfIdVerified,
            Event::SelectedResourceCommitmentVerified,
            Event::InstalledAuthorityCommitmentVerified,
            Event::ArtifactSelfIdVerified,
        ]
    );
    assert_eq!(
        PathSnapshot::capture(workspace.transaction_root()),
        transaction_before
    );
}

#[test]
fn package_free_deep_apply_plan_tamper_reaches_frozen_task21_comparison() {
    let (mini, workspace, _candidate) = committed_workspace_v2("task31b-deep-apply-plan");
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    reseal_deep_package_free_tamper(
        &workspace,
        &transaction,
        DeepPackageFreeTamper::ArtifactApplyPlan,
    );
    let candidate = fresh_bound_candidate(&workspace);
    let transaction_before = PathSnapshot::capture(workspace.transaction_root());
    let _observations = crate::trusted_package_free_update_recovery::validation_observation_guard();
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
    ));
    use crate::trusted_package_free_update_recovery::ValidationObservation as Event;
    let events = crate::trusted_package_free_update_recovery::validation_observations();
    assert!(events.contains(&Event::ArtifactSelfIdVerified));
    assert!(events.contains(&Event::ArtifactCrossBindingVerified));
    assert!(events.contains(&Event::PublicationBindingVerified));
    assert!(events.contains(&Event::FrozenDerivationDispatchStarted));
    assert!(events.contains(&Event::FrozenDerivationReconstructionCompleted));
    assert!(!events.contains(&Event::UnsupportedDerivationRejected));
    assert_eq!(
        PathSnapshot::capture(workspace.transaction_root()),
        transaction_before
    );
}

#[test]
fn package_free_deep_authority_selected_resource_tamper_reaches_fresh_comparison() {
    let (mini, workspace, _candidate) = committed_workspace_v2("task31b-deep-selected");
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    reseal_deep_package_free_tamper(
        &workspace,
        &transaction,
        DeepPackageFreeTamper::AuthoritySelectedResource,
    );
    let candidate = fresh_bound_candidate(&workspace);
    let transaction_before = PathSnapshot::capture(workspace.transaction_root());
    let _observations = crate::trusted_package_free_update_recovery::validation_observation_guard();
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
    ));
    use crate::trusted_package_free_update_recovery::ValidationObservation as Event;
    assert_eq!(
        crate::trusted_package_free_update_recovery::validation_observations(),
        vec![Event::AuthoritySelfIdVerified]
    );
    assert_eq!(
        PathSnapshot::capture(workspace.transaction_root()),
        transaction_before
    );
}

#[test]
fn package_free_self_consistent_unsupported_derivation_reaches_closed_dispatcher() {
    let (mini, workspace, _candidate) = committed_workspace_v2("task31b-deep-unsupported");
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    reseal_deep_package_free_tamper(
        &workspace,
        &transaction,
        DeepPackageFreeTamper::UnsupportedDerivation,
    );
    let candidate = fresh_bound_candidate(&workspace);
    let transaction_before = PathSnapshot::capture(workspace.transaction_root());
    let _observations = crate::trusted_package_free_update_recovery::validation_observation_guard();
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported
    ));
    use crate::trusted_package_free_update_recovery::ValidationObservation as Event;
    let events = crate::trusted_package_free_update_recovery::validation_observations();
    assert!(events.contains(&Event::AuthoritySelfIdVerified));
    assert!(events.contains(&Event::ArtifactSelfIdVerified));
    assert!(events.contains(&Event::ArtifactCrossBindingVerified));
    assert!(events.contains(&Event::PublicationBindingVerified));
    assert!(events.contains(&Event::FrozenDerivationDispatchStarted));
    assert!(events.contains(&Event::UnsupportedDerivationRejected));
    assert!(!events.contains(&Event::FrozenDerivationReconstructionCompleted));
    assert_eq!(
        PathSnapshot::capture(workspace.transaction_root()),
        transaction_before
    );
}

#[test]
fn package_free_v2_malformed_peer_blocks_exact_candidate() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-ambiguous-peer");
    let transactions = workspace.transaction_root().join("transactions");
    let original = only_child_directory(&transactions);
    let peer = transactions.join("11".repeat(32));
    copy_test_tree(&original, &peer);
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous
    ));
}

#[test]
fn package_free_public_api_rejects_selected_malformed_candidate_intent() {
    let (mini, workspace, _) = committed_workspace_v2("task31b-selected-malformed");
    let malformed_dir = workspace
        .transaction_root()
        .join("transactions")
        .join("22".repeat(32));
    fs::create_dir_all(&malformed_dir).unwrap();
    fs::write(malformed_dir.join("not-journal.bin"), b"malformed").unwrap();
    let root = crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    let malformed = *scan
        .candidates()
        .iter()
        .find(|candidate| candidate.kind() == crate::TrustedRecoveryCandidateKind::Malformed)
        .unwrap()
        .candidate_id();
    drop(scan);
    drop(root);
    assert!(matches!(
        try_recover_workspace_candidate(&mini, &workspace, &malformed).unwrap_err(),
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous
    ));
}

#[test]
fn package_free_v2_public_surfaces_redact_durable_authority() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-redaction");
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    let transaction_id = transaction
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let artifact = fs::read_dir(workspace.artifact_root().path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("bin"))
        .unwrap();
    let parsed = parse_cli_artifact(
        &fs::read(&artifact).unwrap(),
        &TrustedCliUpdateOptions::default(),
    )
    .unwrap();
    let artifact_id = parsed.artifact_id().to_hex();
    flip_first_byte(&transaction.join("recovery-authority.bin"));
    let installed_selection = trusted_gksphone_selection(&mini);
    let request = crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
        &workspace,
        &candidate,
        &installed_selection,
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    let request_debug = format!("{request:?}");
    let error = crate::recover_trusted_published_update_v2(request).unwrap_err();
    let mut surfaces = vec![format!("{error}"), format!("{error:?}"), request_debug];
    let mut source = error.source();
    while let Some(current) = source {
        surfaces.push(format!("{current}"));
        surfaces.push(format!("{current:?}"));
        source = current.source();
    }
    for surface in surfaces {
        for secret in [
            mini.installed_parent.to_string_lossy().as_ref(),
            mini.package_v2.to_string_lossy().as_ref(),
            transaction.to_string_lossy().as_ref(),
            artifact.to_string_lossy().as_ref(),
            workspace.staging_root().to_string_lossy().as_ref(),
            workspace.baseline_store().to_string_lossy().as_ref(),
            candidate.to_selector_hex().as_str(),
            "gksphone",
            artifact_id.as_str(),
            transaction_id.as_str(),
        ] {
            assert!(!surface.contains(secret), "public surface leaked {secret}");
        }
    }
}

#[test]
fn package_free_v2_respects_resource_and_transaction_lock_contention() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-locks");
    let root = crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    {
        let _held = crate::trusted_transactional_apply_execution::locks::acquire_resource_lock(
            root.dir(),
            "gksphone",
        )
        .unwrap();
        let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
        assert!(matches!(
            error,
            GkrmError::TrustedTransactionalApplyExecutionLockContention
        ));
    }

    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    let plan_id =
        Sha256Digest::from_lowercase_hex(transaction.file_name().unwrap().to_str().unwrap())
            .unwrap();
    let transactions =
        crate::baseline::fs_security::open_child_dir(root.dir(), "transactions").unwrap();
    let transaction_cap =
        crate::baseline::fs_security::open_child_dir(&transactions, &plan_id.to_string()).unwrap();
    {
        let _held = crate::trusted_transactional_apply_execution::locks::acquire_transaction_lock(
            &transaction_cap,
            &plan_id,
        )
        .unwrap();
        let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
        assert!(matches!(
            error,
            GkrmError::TrustedTransactionalApplyExecutionLockContention
        ));
    }
    assert!(matches!(
        try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap(),
        crate::TrustedRecoveryResult::RecoveredCommitted(_)
    ));
}

#[test]
fn package_free_public_request_has_no_raw_installed_path_boundary() {
    let source = include_str!("../trusted_package_free_update_recovery.rs");
    let request_start = source
        .find("pub struct TrustedPackageFreeUpdateRecoveryRequest")
        .unwrap();
    let request_end = source[request_start..]
        .find("struct ReconstructedV2Authority")
        .map(|offset| request_start + offset)
        .unwrap();
    let public_boundary = &source[request_start..request_end];
    for forbidden in ["&Path", "PathBuf", "installed_root:", "selected_resource:"] {
        assert!(
            !public_boundary.contains(forbidden),
            "public recovery boundary exposed {forbidden}"
        );
    }
    assert!(public_boundary.contains("&'a TrustedInstalledRecoverySelection"));
    assert!(!public_boundary.contains("&'a InstalledApplyPlanningSource"));
    let accepted_start = source
        .find("pub struct TrustedInstalledRecoverySelection")
        .unwrap();
    let accepted_end = source[accepted_start..]
        .find("impl std::fmt::Debug for TrustedInstalledRecoverySelection")
        .map(|offset| accepted_start + offset)
        .unwrap();
    let accepted_boundary = &source[accepted_start..accepted_end];
    for forbidden in ["&Path", "PathBuf", "try_new(", "InstalledResourceRoot"] {
        assert!(
            !accepted_boundary.contains(forbidden),
            "accepted recovery authority exposed {forbidden}"
        );
    }
    let accepted_impl_start = source
        .find("impl TrustedInstalledRecoverySelection")
        .unwrap();
    let accepted_impl_end = source[accepted_impl_start..]
        .find("impl Default for TrustedPackageFreeUpdateRecoveryOptions")
        .map(|offset| accepted_impl_start + offset)
        .unwrap();
    let accepted_impl = &source[accepted_impl_start..accepted_impl_end];
    for forbidden in [
        "pub fn new(",
        "pub fn try_new(",
        "impl From<",
        "impl TryFrom<",
        "pub fn builder(",
    ] {
        assert!(
            !accepted_impl.contains(forbidden),
            "accepted recovery authority exposed construction route {forbidden}"
        );
    }
}

#[test]
fn package_free_artifact_enumeration_counts_every_entry_before_parsing() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-artifact-entry-cap");
    let root = workspace.artifact_root().path();
    for index in 0..4 {
        fs::write(root.join(format!("unrelated-{index:04}.dat")), b"x").unwrap();
    }
    let options = crate::TrustedPackageFreeUpdateRecoveryOptions {
        max_artifact_directory_entries: 5,
        ..Default::default()
    };
    crate::trusted_package_free_update_recovery::reset_artifact_parse_attempts();
    assert!(
        try_recover_workspace_candidate_with_options(&mini, &workspace, &candidate, options)
            .is_ok()
    );
    assert_eq!(
        crate::trusted_package_free_update_recovery::artifact_parse_attempts(),
        2,
        "pre-lock and post-lock reconstruction each parse the exact artifact once"
    );

    fs::write(root.join("unrelated-over-limit.dat"), b"x").unwrap();
    crate::trusted_package_free_update_recovery::reset_artifact_parse_attempts();
    assert!(
        try_recover_workspace_candidate_with_options(&mini, &workspace, &candidate, options)
            .is_err()
    );
    assert_eq!(
        crate::trusted_package_free_update_recovery::artifact_parse_attempts(),
        0,
        "valid artifact must not be parsed after total-entry budget overflow"
    );
}

#[test]
fn package_free_artifact_enumeration_rejects_unrelated_and_malformed_floods() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-artifact-flood");
    let root = workspace.artifact_root().path();
    for index in 0..2_000 {
        fs::write(root.join(format!("flood-{index:04}.dat")), b"x").unwrap();
    }
    let mut options = crate::TrustedPackageFreeUpdateRecoveryOptions {
        max_artifact_directory_entries: 1_000,
        ..Default::default()
    };
    crate::trusted_package_free_update_recovery::reset_artifact_parse_attempts();
    assert!(
        try_recover_workspace_candidate_with_options(&mini, &workspace, &candidate, options)
            .is_err()
    );
    assert_eq!(
        crate::trusted_package_free_update_recovery::artifact_parse_attempts(),
        0
    );

    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) == Some("dat") {
            fs::remove_file(path).unwrap();
        }
    }
    for index in 0..12 {
        fs::write(root.join(format!("plan-malformed-{index:04}.bin")), b"bad").unwrap();
    }
    options.max_artifact_directory_entries = 64;
    options.max_artifacts = 8;
    crate::trusted_package_free_update_recovery::reset_artifact_parse_attempts();
    assert!(
        try_recover_workspace_candidate_with_options(&mini, &workspace, &candidate, options)
            .is_err()
    );
    assert_eq!(
        crate::trusted_package_free_update_recovery::artifact_parse_attempts(),
        0,
        "candidate-count overflow must fail before parsing any artifact"
    );
}

#[test]
fn package_free_artifact_enumeration_bounds_types_duplicates_and_total_bytes() {
    for kind in ["directories", "symlinks"] {
        let (mini, workspace, candidate) =
            committed_workspace_v2(&format!("task31b-artifact-{kind}"));
        let root = workspace.artifact_root().path();
        let mut substitution_created = true;
        match kind {
            "directories" => {
                for index in 0..64 {
                    fs::create_dir(root.join(format!("dir-{index:03}"))).unwrap();
                }
            }
            "symlinks" => {
                substitution_created = false;
                let target = root.join("symlink-target");
                fs::write(&target, b"target").unwrap();
                for index in 0..64 {
                    let link = root.join(format!("link-{index:03}"));
                    #[cfg(unix)]
                    {
                        std::os::unix::fs::symlink(&target, &link).unwrap();
                        substitution_created = true;
                    }
                    #[cfg(windows)]
                    {
                        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
                            break;
                        }
                        substitution_created = true;
                    }
                }
            }
            _ => unreachable!(),
        }
        if !substitution_created {
            continue;
        }
        crate::trusted_package_free_update_recovery::reset_artifact_parse_attempts();
        assert!(try_recover_workspace_candidate(&mini, &workspace, &candidate).is_err());
        assert_eq!(
            crate::trusted_package_free_update_recovery::artifact_parse_attempts(),
            0
        );
    }

    let (mini, workspace, candidate) = committed_workspace_v2("task31b-artifact-duplicate");
    let artifact = fs::read_dir(workspace.artifact_root().path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("bin"))
        .unwrap();
    fs::copy(
        &artifact,
        workspace.artifact_root().path().join("plan-duplicate.bin"),
    )
    .unwrap();
    assert!(matches!(
        try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err(),
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous
    ));

    let (mini, workspace, candidate) = committed_workspace_v2("task31b-artifact-byte-budget");
    let artifact = fs::read_dir(workspace.artifact_root().path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("bin"))
        .unwrap();
    let artifact_len = fs::metadata(&artifact).unwrap().len();
    fs::write(
        workspace.artifact_root().path().join("plan-malformed.bin"),
        vec![0_u8; 32],
    )
    .unwrap();
    let options = crate::TrustedPackageFreeUpdateRecoveryOptions {
        max_artifact_bytes: artifact_len.max(32),
        max_total_artifact_bytes: artifact_len + 16,
        ..Default::default()
    };
    assert!(
        try_recover_workspace_candidate_with_options(&mini, &workspace, &candidate, options)
            .is_err()
    );
}

#[test]
fn package_free_options_reject_values_above_immutable_core_maxima() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-option-hard-caps");
    let selection = trusted_gksphone_selection(&mini);
    let mut cases = Vec::new();
    cases.push(crate::TrustedPackageFreeUpdateRecoveryOptions {
        max_artifact_directory_entries: 250_001,
        ..Default::default()
    });
    cases.push(crate::TrustedPackageFreeUpdateRecoveryOptions {
        max_artifacts: 1_001,
        ..Default::default()
    });
    cases.push(crate::TrustedPackageFreeUpdateRecoveryOptions {
        max_artifact_bytes: 64 * 1024 * 1024 + 1,
        ..Default::default()
    });
    cases.push(crate::TrustedPackageFreeUpdateRecoveryOptions {
        max_total_artifact_bytes: 8 * 1024 * 1024 * 1024 + 1,
        ..Default::default()
    });
    for options in cases {
        assert!(crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &workspace, &candidate, &selection, options
        )
        .is_err());
    }
}

#[test]
fn package_free_stale_candidate_is_derived_from_a_previously_valid_scan() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-stale-candidate");
    let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
    fs::remove_dir_all(transaction).unwrap();
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound
    ));
}

#[test]
fn package_free_trusted_selection_rejects_replaced_resource_identity() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-selection-replaced");
    let selection = trusted_gksphone_selection(&mini);
    let old = mini.installed_parent.join("gksphone-old");
    fs::rename(&mini.installed_resource, &old).unwrap();
    copy_test_tree(&old, &mini.installed_resource);
    let error = crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &workspace,
            &candidate,
            &selection,
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
    ));
}

#[test]
fn package_free_trusted_selection_rejects_replaced_root_where_os_permits() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-root-replaced");
    let selection = trusted_gksphone_selection(&mini);
    let old = mini._temp.path().join("installed-root-old");
    if fs::rename(&mini.installed_parent, &old).is_err() {
        // Windows can deny renaming a directory with an open capability. That
        // kernel denial is itself fail-closed; replacement is exercised on
        // platforms whose sharing model permits the substitution.
        return;
    }
    copy_test_tree(&old, &mini.installed_parent);
    assert!(crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &workspace,
            &candidate,
            &selection,
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .is_err());
}

#[test]
fn package_free_rejects_installed_and_staging_reparse_substitution() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-reparse-selection");
    let selection = trusted_gksphone_selection(&mini);
    let old = mini.installed_parent.join("gksphone-reparse-old");
    if fs::rename(&mini.installed_resource, &old).is_ok() {
        create_test_directory_link(&old, &mini.installed_resource);
        assert!(crate::recover_trusted_published_update_v2(
            crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
                &workspace,
                &candidate,
                &selection,
                crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
            )
            .unwrap(),
        )
        .is_err());
    }

    let (mini, workspace, candidate) = committed_workspace_v2("task31b-reparse-staging");
    let bundle = only_child_directory(&workspace.staging_root().join("bundles"));
    let old = mini._temp.path().join("staging-bundle-reparse-old");
    fs::rename(&bundle, &old).unwrap();
    create_test_directory_link(&old, &bundle);
    assert!(try_recover_workspace_candidate(&mini, &workspace, &candidate).is_err());
}

#[test]
fn two_package_free_recoveries_never_own_mutation_concurrently() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-concurrent-recovery");
    let installed_parent = mini.installed_parent.clone();
    let workspace_root = workspace.app_root().to_path_buf();
    let installed_before = PathSnapshot::capture(&mini.installed_resource);
    let journal_before =
        crate::trusted_staging::test_support::hash_tree(workspace.transaction_root());
    let (owned_tx, owned_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let _hook_guard = crate::trusted_package_free_update_recovery::test_hooks::lock();
    crate::trusted_package_free_update_recovery::test_hooks::set_after_mutating_locks_acquired(
        workspace.app_root(),
        move || {
            owned_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        },
    );

    let first = std::thread::spawn(move || {
        let workspace = crate::resolve_trusted_update_workspace(&workspace_root).unwrap();
        let selection = trusted_gksphone_selection_at(&installed_parent);
        crate::recover_trusted_published_update_v2(
            crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
                &workspace,
                &candidate,
                &selection,
                crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
            )
            .unwrap(),
        )
    });
    owned_rx.recv().unwrap();

    let second = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        second,
        GkrmError::TrustedTransactionalApplyExecutionLockContention
    ));
    assert_eq!(
        PathSnapshot::capture(&mini.installed_resource),
        installed_before
    );
    release_tx.send(()).unwrap();
    assert!(matches!(
        first.join().unwrap().unwrap(),
        crate::TrustedRecoveryResult::RecoveredCommitted(_)
    ));
    assert_eq!(
        crate::trusted_staging::test_support::hash_tree(workspace.transaction_root()),
        journal_before,
        "terminal first recovery and contending second recovery must not rewrite evidence"
    );
    assert!(matches!(
        try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap(),
        crate::TrustedRecoveryResult::RecoveredCommitted(_)
    ));
}

#[test]
fn package_free_recovery_and_task30_apply_are_resource_lock_exclusive() {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task31b-recovery-vs-apply");
    {
        let _execution_guard = lock_execution_hooks();
        set_publication_hook(PublicationPoint::BeforeBackup, || {
            panic!("publish then stop")
        });
        let published = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
                authority: review.desktop_apply_authority.as_ref().unwrap(),
                options: TrustedCliUpdateOptions::default(),
            });
        }));
        assert!(published.is_err());
    }
    let root = crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    let candidate = *scan
        .candidates()
        .iter()
        .find(|candidate| candidate.kind() == crate::TrustedRecoveryCandidateKind::Bound)
        .unwrap()
        .candidate_id();
    drop(scan);
    drop(root);

    let (owned_tx, owned_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let _hook_guard = crate::trusted_package_free_update_recovery::test_hooks::lock();
    crate::trusted_package_free_update_recovery::test_hooks::set_after_mutating_locks_acquired(
        workspace.app_root(),
        move || {
            owned_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        },
    );
    let workspace_root = workspace.app_root().to_path_buf();
    let installed_parent = mini.installed_parent.clone();
    let recoverer = std::thread::spawn(move || {
        let workspace = crate::resolve_trusted_update_workspace(&workspace_root).unwrap();
        let selection = trusted_gksphone_selection_at(&installed_parent);
        crate::recover_trusted_published_update_v2(
            crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
                &workspace,
                &candidate,
                &selection,
                crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
            )
            .unwrap(),
        )
    });
    owned_rx.recv().unwrap();
    let apply_error = apply_trusted_desktop_update(TrustedDesktopApplyRequest {
        authority: review.desktop_apply_authority.as_ref().unwrap(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap_err();
    assert!(matches!(
        apply_error,
        GkrmError::TrustedCliUpdateRecoveryRequired
    ));
    release_tx.send(()).unwrap();
    recoverer.join().unwrap().unwrap();
}

#[test]
fn task30_apply_ownership_blocks_package_free_recovery() {
    let (mini, workspace, review) = ready_workspace_desktop_apply("task31b-apply-vs-recovery");
    let (owned_tx, owned_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let applier = std::thread::spawn(move || {
        let _execution_guard = lock_execution_hooks();
        set_publication_hook(PublicationPoint::AfterRecoveryLock, move || {
            owned_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        apply_trusted_desktop_update(TrustedDesktopApplyRequest {
            authority: review.desktop_apply_authority.as_ref().unwrap(),
            options: TrustedCliUpdateOptions::default(),
        })
    });
    owned_rx.recv().unwrap();

    let root = crate::TrustedTransactionRoot::try_open(workspace.transaction_root()).unwrap();
    let scan =
        crate::scan_trusted_transactions(&root, crate::TrustedRecoveryScanOptions::default())
            .unwrap();
    let candidate = *scan
        .candidates()
        .iter()
        .find(|candidate| candidate.kind() == crate::TrustedRecoveryCandidateKind::Bound)
        .unwrap()
        .candidate_id();
    drop(scan);
    drop(root);
    let error = try_recover_workspace_candidate(&mini, &workspace, &candidate).unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedTransactionalApplyExecutionLockContention
    ));
    release_tx.send(()).unwrap();
    assert_eq!(applier.join().unwrap().unwrap().outcome, "committed");
}

#[derive(Clone, Copy)]
enum PackageFreeNamespaceTamper {
    TransactionReplace,
    TransactionRemove,
    JournalReplace,
    JournalRemove,
    TransactionLink,
    JournalLink,
}

#[test]
fn package_free_post_lock_reopen_rejects_namespace_substitution() {
    for (label, tamper) in [
        (
            "transaction-replace",
            PackageFreeNamespaceTamper::TransactionReplace,
        ),
        (
            "transaction-remove",
            PackageFreeNamespaceTamper::TransactionRemove,
        ),
        (
            "journal-replace",
            PackageFreeNamespaceTamper::JournalReplace,
        ),
        ("journal-remove", PackageFreeNamespaceTamper::JournalRemove),
        (
            "transaction-link",
            PackageFreeNamespaceTamper::TransactionLink,
        ),
        ("journal-link", PackageFreeNamespaceTamper::JournalLink),
    ] {
        let (mini, workspace, candidate) =
            committed_workspace_v2(&format!("task31b-namespace-{label}"));
        let transaction = only_child_directory(&workspace.transaction_root().join("transactions"));
        let journal = transaction.join("journal");
        let detached = mini._temp.path().join(format!("detached-{label}"));
        let replacement = mini._temp.path().join(format!("replacement-{label}"));
        match tamper {
            PackageFreeNamespaceTamper::TransactionReplace
            | PackageFreeNamespaceTamper::TransactionLink => {
                copy_test_tree(&transaction, &replacement)
            }
            PackageFreeNamespaceTamper::JournalReplace
            | PackageFreeNamespaceTamper::JournalLink => copy_test_tree(&journal, &replacement),
            PackageFreeNamespaceTamper::TransactionRemove
            | PackageFreeNamespaceTamper::JournalRemove => {}
        }
        let installed_before = PathSnapshot::capture(&mini.installed_resource);
        let original_transaction_before = PathSnapshot::capture(&transaction);
        let original_journal_before = PathSnapshot::capture(&journal);
        let backup_before = PathSnapshot::capture(&transaction.join("backup"));
        let authority_before = fs::read(transaction.join("recovery-authority.bin")).unwrap();
        let snapshot_before = fs::read(transaction.join("snapshot-a.bin")).unwrap();
        let resource_lock_before = fs::read(transaction.join("resource-lock-id.bin")).unwrap();
        let replacement_before = replacement
            .exists()
            .then(|| PathSnapshot::capture(&replacement));
        let hook_transaction = transaction.clone();
        let hook_journal = journal.clone();
        let hook_detached = detached.clone();
        let hook_replacement = replacement.clone();
        let _hook_guard = crate::trusted_package_free_update_recovery::test_hooks::lock();
        crate::trusted_package_free_update_recovery::test_hooks::set_after_pre_lock_reconstruction(
            workspace.app_root(),
            move || match tamper {
                PackageFreeNamespaceTamper::TransactionReplace => {
                    fs::rename(&hook_transaction, &hook_detached).unwrap();
                    fs::rename(&hook_replacement, &hook_transaction).unwrap();
                }
                PackageFreeNamespaceTamper::TransactionRemove => {
                    fs::rename(&hook_transaction, &hook_detached).unwrap();
                }
                PackageFreeNamespaceTamper::JournalReplace => {
                    fs::rename(&hook_journal, &hook_detached).unwrap();
                    fs::rename(&hook_replacement, &hook_journal).unwrap();
                }
                PackageFreeNamespaceTamper::JournalRemove => {
                    fs::rename(&hook_journal, &hook_detached).unwrap();
                }
                PackageFreeNamespaceTamper::TransactionLink => {
                    fs::rename(&hook_transaction, &hook_detached).unwrap();
                    create_test_directory_link(&hook_detached, &hook_transaction);
                }
                PackageFreeNamespaceTamper::JournalLink => {
                    fs::rename(&hook_journal, &hook_detached).unwrap();
                    create_test_directory_link(&hook_detached, &hook_journal);
                }
            },
        );
        let result = try_recover_workspace_candidate(&mini, &workspace, &candidate);
        assert!(result.is_err(), "{label} must fail closed");
        let detached_after = PathSnapshot::capture(&detached);
        let expected_detached = match tamper {
            PackageFreeNamespaceTamper::TransactionReplace
            | PackageFreeNamespaceTamper::TransactionRemove
            | PackageFreeNamespaceTamper::TransactionLink => &original_transaction_before,
            PackageFreeNamespaceTamper::JournalReplace
            | PackageFreeNamespaceTamper::JournalRemove
            | PackageFreeNamespaceTamper::JournalLink => &original_journal_before,
        };
        assert_eq!(
            &detached_after, expected_detached,
            "{label} changed detached original durable evidence"
        );
        if let Some(before) = replacement_before {
            let replacement_after_path = match tamper {
                PackageFreeNamespaceTamper::TransactionReplace => &transaction,
                PackageFreeNamespaceTamper::JournalReplace => &journal,
                PackageFreeNamespaceTamper::TransactionLink
                | PackageFreeNamespaceTamper::JournalLink => &replacement,
                PackageFreeNamespaceTamper::TransactionRemove
                | PackageFreeNamespaceTamper::JournalRemove => unreachable!(),
            };
            assert_eq!(
                PathSnapshot::capture(replacement_after_path),
                before,
                "{label} changed byte-identical replacement evidence"
            );
        }
        if matches!(
            tamper,
            PackageFreeNamespaceTamper::JournalReplace
                | PackageFreeNamespaceTamper::JournalRemove
                | PackageFreeNamespaceTamper::JournalLink
        ) {
            assert_eq!(
                PathSnapshot::capture(&transaction.join("backup")),
                backup_before
            );
            assert_eq!(
                fs::read(transaction.join("recovery-authority.bin")).unwrap(),
                authority_before
            );
            assert_eq!(
                fs::read(transaction.join("snapshot-a.bin")).unwrap(),
                snapshot_before
            );
            assert_eq!(
                fs::read(transaction.join("resource-lock-id.bin")).unwrap(),
                resource_lock_before
            );
        }
        assert_eq!(
            PathSnapshot::capture(&mini.installed_resource),
            installed_before,
            "{label} changed installed content"
        );
    }
}

#[test]
fn package_free_trusted_selection_is_freshly_revalidated_after_both_locks() {
    let (mini, workspace, candidate) = committed_workspace_v2("task31b-post-lock-selection");
    let selection = trusted_gksphone_selection(&mini);
    let installed = mini.installed_resource.clone();
    let old = mini.installed_parent.join("gksphone-post-lock-old");
    let _hook_guard = crate::trusted_package_free_update_recovery::test_hooks::lock();
    crate::trusted_package_free_update_recovery::test_hooks::set_after_mutating_locks_acquired(
        workspace.app_root(),
        move || {
            fs::rename(&installed, &old).unwrap();
            copy_test_tree(&old, &installed);
        },
    );
    let error = crate::recover_trusted_published_update_v2(
        crate::TrustedPackageFreeUpdateRecoveryRequest::try_new(
            &workspace,
            &candidate,
            &selection,
            crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
    ));
}

fn assert_real_apply_rejects_post_lock_key_drift(
    fixture: &DirectDesktopApplyFixture,
    use_prebuilt_backend_authority: bool,
) {
    let installed_before = PathSnapshot::capture(&fixture.mini.installed_resource);
    let artifact_before = fs::read(&fixture.artifact_out).unwrap();
    let artifact =
        parse_cli_artifact(&artifact_before, &TrustedCliUpdateOptions::default()).unwrap();
    let artifact_id_hex = artifact.artifact_id().to_hex();
    let base_authority = fixture
        .review_report
        .desktop_apply_authority
        .as_ref()
        .expect("ready desktop authority");
    assert_eq!(
        artifact.artifact_id().digest(),
        base_authority.expected_artifact_id.digest(),
        "backend authority must pin the exact artifact before apply"
    );
    assert_eq!(
        artifact.body().selected_resource_commitment.to_string(),
        "d4cb61c60acc007ac3d376e4242c8e062c6047c382abf96dd3ab231540a183f9"
    );
    let post_lock_key = SafeResourceKey::parse("gksphone-next").unwrap();
    assert_eq!(
        crate::trusted_recovery_authority::selected_resource_commitment(&post_lock_key)
            .unwrap()
            .to_string(),
        "7d2da71f2f9c8e19133753892897aa58d5a2c10b8a1e2de921eaa8a4b6006ca1"
    );
    fs::remove_file(&fixture.mini.package_v2).unwrap();

    let events = {
        let _guard = lock_execution_hooks();
        set_post_lock_resource_key(Some(post_lock_key));
        let report = if use_prebuilt_backend_authority {
            apply_direct_desktop_accepting_current_artifact_id(fixture)
        } else {
            apply_direct_desktop(fixture)
        }
        .unwrap();
        assert_eq!(report.outcome, "published_recovery_unsealed");
        assert_eq!(
            report.artifact_id_hex.as_deref(),
            Some(artifact_id_hex.as_str())
        );
        authority_verification_events()
    };
    assert_eq!(
        events,
        [
            AuthorityVerificationEvent::InitialDesktopAuthorityValidationPassed,
            AuthorityVerificationEvent::EarlySelectedResourceCommitmentVerified,
            AuthorityVerificationEvent::ResourceLockAcquired,
            AuthorityVerificationEvent::PreMutationArtifactRevalidationPassed,
            AuthorityVerificationEvent::RecoveryLockAcquired,
            AuthorityVerificationEvent::PostLockArtifactRevalidationPassed,
            AuthorityVerificationEvent::FinalSelectedResourceCommitmentVerificationStarted,
            AuthorityVerificationEvent::FinalSelectedResourceCommitmentMismatch,
        ]
    );

    assert_eq!(fs::read(&fixture.artifact_out).unwrap(), artifact_before);
    assert_eq!(
        PathSnapshot::capture(&fixture.mini.installed_resource),
        installed_before
    );
    assert!(!fixture.mini.package_v2.exists());
    let transaction = only_child_directory(&fixture.txn.join("transactions"));
    assert!(!transaction.join("backup").exists());
    let envelope = crate::parse_recovery_authority_envelope(
        &fs::read(transaction.join("recovery-authority.bin")).unwrap(),
        RecoveryAuthorityLimits::default(),
    )
    .unwrap();
    assert_eq!(envelope.artifact_id(), artifact.artifact_id().digest());
    assert_eq!(
        envelope.body().selected_resource_commitment,
        artifact.body().selected_resource_commitment
    );
}

#[test]
fn package_free_desktop_apply_ignores_replaced_package_location() {
    let fixture = ready_desktop_apply_fixture("desktop-package-replaced");
    fs::write(&fixture.mini.package_v2, b"not a package").unwrap();
    let apply_report = apply_direct_desktop(&fixture).unwrap();
    assert_eq!(apply_report.outcome, "committed");
}

#[test]
fn package_free_desktop_apply_never_reopens_or_restages_package() {
    let fixture = ready_desktop_apply_fixture("desktop-no-package-access");
    let bundle_names_before = bundle_names(&fixture);
    fs::remove_file(&fixture.mini.package_v2).unwrap();
    fs::create_dir(&fixture.mini.package_v2).unwrap();
    crate::trusted_staging::reset_source_read_count();

    let apply_report = apply_direct_desktop(&fixture).unwrap();

    assert_eq!(apply_report.outcome, "committed");
    assert_eq!(crate::trusted_staging::source_read_count(), 0);
    assert_eq!(bundle_names(&fixture), bundle_names_before);
}

#[test]
fn direct_desktop_apply_rejects_post_verify_staged_merge_byte_replacements() {
    let cases: Vec<StagedMergeMutationCase> = vec![
        (
            "larger-than-expected",
            SnapshotNode::File(b"L1x\nL2\nL3\nL4\nextra\n".to_vec()),
            Arc::new(|path| fs::write(path, b"L1x\nL2\nL3\nL4\nextra\n").unwrap()),
        ),
        (
            "large-sparse-replacement",
            SnapshotNode::File(vec![0; 10 * 1024 * 1024]),
            Arc::new(|path| {
                let file = fs::File::create(path).unwrap();
                file.set_len(10 * 1024 * 1024).unwrap();
            }),
        ),
        (
            "truncated",
            SnapshotNode::File(b"L1x\n".to_vec()),
            Arc::new(|path| fs::write(path, b"L1x\n").unwrap()),
        ),
        (
            "same-length-digest-mismatch",
            SnapshotNode::File(b"ZZZ\nL2\nL3\nL4\n".to_vec()),
            Arc::new(|path| fs::write(path, b"ZZZ\nL2\nL3\nL4\n").unwrap()),
        ),
        (
            "digest-mismatch",
            SnapshotNode::File(b"L1x\nL2\nL3\nL?\n".to_vec()),
            Arc::new(|path| fs::write(path, b"L1x\nL2\nL3\nL?\n").unwrap()),
        ),
    ];

    for (name, expected_after, mutate) in cases {
        let fixture = ready_desktop_apply_fixture(name);
        let target = staged_resource_file(&fixture, "merge.lua");
        let expected_changed = PathSnapshot::key_for_file(&fixture.staging, &target);
        let hook = Arc::new(move || mutate(&target));
        let before = DirectDurableSnapshot::capture(&fixture);
        let expected_before = before.staging.node(&expected_changed);

        assert_private_apply_failure(
            apply_direct_desktop_after_bundle_verify_hook(&fixture, hook),
            &fixture,
            &before,
            DirectApplyFailureExpectation::new(DirectApplyErrorCategory::BindingMismatch)
                .with_exact_staging_change(expected_changed, expected_before, expected_after),
        );
    }
}

#[test]
fn direct_desktop_apply_accepts_exact_expected_staged_merge_bytes() {
    let fixture = ready_desktop_apply_fixture("desktop-exact-merge");
    let apply_report = apply_direct_desktop(&fixture).unwrap();
    assert_eq!(apply_report.outcome, "committed");
}

#[test]
fn direct_desktop_apply_rejects_durable_artifact_and_binding_tamper() {
    let cases: [DirectDesktopTamperCase; 5] = [
        ("artifact-body", |fixture: &DirectDesktopApplyFixture| {
            let mut bytes = fs::read(&fixture.artifact_out).unwrap();
            bytes[super::artifact::ARTIFACT_MAGIC.len() + 9] ^= 0x55;
            fs::write(&fixture.artifact_out, bytes).unwrap();
        }),
        (
            "descriptor-trailing",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let descriptor = descriptor_start(&bytes);
                let offset = descriptor - 8;
                let descriptor_len = read_u64_at(&bytes, offset);
                let new_len = (descriptor_len as u64 + 1).to_le_bytes();
                bytes[offset..offset + 8].copy_from_slice(&new_len);
                let insert_at = descriptor + descriptor_len;
                bytes.insert(insert_at, 0);
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
            },
        ),
        (
            "unsupported-descriptor-version",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let start = descriptor_start(&bytes);
                let version_at = start + b"gkrm-cli-apply-descriptor-bin-v1\n".len();
                bytes[version_at] = 99;
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
            },
        ),
        (
            "resource-key-drift",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let start = descriptor_start(&bytes);
                let resource_key_at = start + b"gkrm-cli-apply-descriptor-bin-v1\n".len() + 1 + 8;
                bytes[resource_key_at] = b'x';
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
                copy_dir_recursive(
                    &fixture
                        .mini
                        .store
                        .join("baselines")
                        .join("gksphone")
                        .join(fixture.mini.baseline.baseline_id().as_str()),
                    &fixture
                        .mini
                        .store
                        .join("baselines")
                        .join("xksphone")
                        .join(fixture.mini.baseline.baseline_id().as_str()),
                );
                copy_dir_recursive(
                    &fixture.mini.installed_resource,
                    &fixture.mini.installed_parent.join("xksphone"),
                );
            },
        ),
        (
            "artifact-to-staging-mismatch",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let mut offset = super::artifact::ARTIFACT_MAGIC.len() + 1;
                let field_len =
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
                offset += 8;
                let staging_manifest_at = offset + (5 * 32) + 4 + 32;
                assert!(staging_manifest_at + 32 <= offset + field_len);
                bytes[staging_manifest_at] ^= 0x33;
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
            },
        ),
    ];
    for (name, mutate) in cases {
        let fixture = ready_desktop_apply_fixture(name);
        mutate(&fixture);
        let before = DirectDurableSnapshot::capture(&fixture);
        let (result, category) = match name {
            "artifact-body" => (
                apply_direct_desktop(&fixture),
                DirectApplyErrorCategory::ArtifactInvalid,
            ),
            "descriptor-trailing" => (
                apply_direct_desktop_accepting_current_artifact_id(&fixture),
                DirectApplyErrorCategory::ArtifactInvalid,
            ),
            "unsupported-descriptor-version" => (
                apply_direct_desktop_accepting_current_artifact_id(&fixture),
                DirectApplyErrorCategory::ArtifactVersionUnsupported,
            ),
            "resource-key-drift" => (
                apply_direct_desktop_accepting_current_artifact_id(&fixture),
                DirectApplyErrorCategory::BindingMismatch,
            ),
            "artifact-to-staging-mismatch" => (
                apply_direct_desktop_accepting_current_artifact_id(&fixture),
                DirectApplyErrorCategory::StagingManifestTreeMismatch,
            ),
            _ => unreachable!("unknown case"),
        };
        assert_private_apply_failure(
            result,
            &fixture,
            &before,
            DirectApplyFailureExpectation::new(category),
        );
    }
}

#[test]
fn direct_desktop_apply_rejects_staging_baseline_and_installed_tamper() {
    let cases: [DirectDesktopTamperCase; 7] = [
        (
            "staging-manifest-id",
            |fixture: &DirectDesktopApplyFixture| {
                let manifest = published_bundle_dir(fixture).join("manifest.bin");
                let mut bytes = fs::read(&manifest).unwrap();
                bytes[40] ^= 0x11;
                fs::write(manifest, bytes).unwrap();
            },
        ),
        (
            "staged-file-content",
            |fixture: &DirectDesktopApplyFixture| {
                fs::write(
                    published_bundle_dir(fixture)
                        .join("resource")
                        .join("take.lua"),
                    b"tampered staged bytes\n",
                )
                .unwrap();
            },
        ),
        ("baseline-content", |fixture: &DirectDesktopApplyFixture| {
            fs::write(
                fixture
                    .mini
                    .store
                    .join("baselines")
                    .join("gksphone")
                    .join(fixture.mini.baseline.baseline_id().as_str())
                    .join("baseline.json"),
                b"not json",
            )
            .unwrap();
        }),
        (
            "baseline-id-substitution",
            |fixture: &DirectDesktopApplyFixture| {
                fs::rename(
                    fixture
                        .mini
                        .store
                        .join("baselines")
                        .join("gksphone")
                        .join(fixture.mini.baseline.baseline_id().as_str()),
                    fixture
                        .mini
                        .store
                        .join("baselines")
                        .join("gksphone")
                        .join("11".repeat(32)),
                )
                .unwrap();
            },
        ),
        (
            "installed-root-identity-replacement",
            |fixture: &DirectDesktopApplyFixture| {
                let original = &fixture.mini.installed_parent;
                let backup = original.with_file_name("installed-original-identity");
                fs::rename(original, &backup).unwrap();
                copy_dir_recursive(&backup, original);
            },
        ),
        (
            "installed-resource-identity-replacement",
            |fixture: &DirectDesktopApplyFixture| {
                let original = &fixture.mini.installed_resource;
                let backup = original.with_file_name("gksphone-original-identity");
                fs::rename(original, &backup).unwrap();
                copy_dir_recursive(&backup, original);
            },
        ),
        (
            "installed-resource-drift",
            |fixture: &DirectDesktopApplyFixture| {
                fs::write(
                    fixture.mini.installed_resource.join("take.lua"),
                    b"customer drift\n",
                )
                .unwrap();
            },
        ),
    ];
    for (name, mutate) in cases {
        let fixture = ready_desktop_apply_fixture(name);
        mutate(&fixture);
        let before = DirectDurableSnapshot::capture(&fixture);
        let category = match name {
            "staging-manifest-id" => DirectApplyErrorCategory::StagingManifestTreeMismatch,
            "staged-file-content" => DirectApplyErrorCategory::StagingDigestLengthMismatch,
            "baseline-content" => DirectApplyErrorCategory::BaselineValidationFailed,
            "baseline-id-substitution" => DirectApplyErrorCategory::BaselineNotFound,
            "installed-root-identity-replacement" | "installed-resource-identity-replacement" => {
                DirectApplyErrorCategory::InstalledStale
            }
            "installed-resource-drift" => DirectApplyErrorCategory::InstalledStale,
            _ => unreachable!("unknown case"),
        };
        assert_private_apply_failure(
            apply_direct_desktop(&fixture),
            &fixture,
            &before,
            DirectApplyFailureExpectation::new(category),
        );
    }
}

#[test]
fn direct_desktop_apply_rejects_staging_authority_substitution_and_manifest_mutations() {
    let cases: [DirectDesktopTamperCase; 5] = [
        (
            "staging-locator-substitution",
            |fixture: &DirectDesktopApplyFixture| {
                let expected = published_bundle_dir(fixture);
                let backup = expected.with_file_name("original-bundle-backup");
                fs::rename(&expected, &backup).unwrap();
                fs::create_dir_all(expected.join("resource")).unwrap();
                fs::write(expected.join("manifest.bin"), b"substituted").unwrap();
            },
        ),
        (
            "manifest-binding-field",
            |fixture: &DirectDesktopApplyFixture| {
                mutate_first_manifest_present_digest_preserving_ids(
                    &published_bundle_dir(fixture).join("manifest.bin"),
                );
            },
        ),
        (
            "manifest-entry-duplication",
            |fixture: &DirectDesktopApplyFixture| {
                duplicate_first_manifest_entry_preserving_ids(
                    &published_bundle_dir(fixture).join("manifest.bin"),
                );
            },
        ),
        (
            "manifest-entry-reorder",
            |fixture: &DirectDesktopApplyFixture| {
                reorder_manifest_entries_preserving_ids(
                    &published_bundle_dir(fixture).join("manifest.bin"),
                );
            },
        ),
        (
            "baseline-id-mutation",
            |fixture: &DirectDesktopApplyFixture| {
                let manifest = published_bundle_dir(fixture).join("manifest.bin");
                let mut bytes = fs::read(&manifest).unwrap();
                bytes[12] ^= 0x19;
                fs::write(manifest, bytes).unwrap();
            },
        ),
    ];

    for (name, mutate) in cases {
        let fixture = ready_desktop_apply_fixture(name);
        mutate(&fixture);
        let before = DirectDurableSnapshot::capture(&fixture);
        let category = match name {
            "staging-locator-substitution"
            | "manifest-binding-field"
            | "manifest-entry-duplication"
            | "manifest-entry-reorder"
            | "baseline-id-mutation" => DirectApplyErrorCategory::StagingManifestTreeMismatch,
            _ => unreachable!("unknown case"),
        };

        assert_private_apply_failure(
            apply_direct_desktop(&fixture),
            &fixture,
            &before,
            DirectApplyFailureExpectation::new(category),
        );
    }
}

#[test]
fn direct_desktop_apply_rejects_descriptor_and_fingerprint_drift_after_artifact_reseal() {
    let cases: [DirectDesktopTamperCase; 4] = [
        (
            "installed-fingerprint-drift",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let start = descriptor_start(&bytes);
                let mut offset = start + b"gkrm-cli-apply-descriptor-bin-v1\n".len() + 1;
                for _ in 0..3 {
                    let len = read_u64_at(&bytes, offset);
                    offset += 8 + len;
                }
                bytes[offset] ^= 0x61;
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
            },
        ),
        (
            "package-fingerprint-drift",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let start = descriptor_start(&bytes);
                let mut offset = start + b"gkrm-cli-apply-descriptor-bin-v1\n".len() + 1;
                for _ in 0..3 {
                    let len = read_u64_at(&bytes, offset);
                    offset += 8 + len;
                }
                offset += 32;
                bytes[offset] ^= 0x62;
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
            },
        ),
        (
            "resource-fingerprint-drift",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let start = descriptor_start(&bytes);
                let mut offset = start + b"gkrm-cli-apply-descriptor-bin-v1\n".len() + 1;
                for _ in 0..3 {
                    let len = read_u64_at(&bytes, offset);
                    offset += 8 + len;
                }
                offset += 64;
                bytes[offset] ^= 0x63;
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
            },
        ),
        (
            "options-version-tag-mutation",
            |fixture: &DirectDesktopApplyFixture| {
                let mut bytes = fs::read(&fixture.artifact_out).unwrap();
                let start = descriptor_start(&bytes);
                let version_at = start + b"gkrm-cli-apply-descriptor-bin-v1\n".len();
                bytes[version_at] = 2;
                reseal_artifact(&mut bytes);
                fs::write(&fixture.artifact_out, bytes).unwrap();
            },
        ),
    ];

    for (name, mutate) in cases {
        let fixture = ready_desktop_apply_fixture(name);
        mutate(&fixture);
        let before = DirectDurableSnapshot::capture(&fixture);
        let category = match name {
            "installed-fingerprint-drift" | "resource-fingerprint-drift" => {
                DirectApplyErrorCategory::StagingManifestTreeMismatch
            }
            "package-fingerprint-drift" => DirectApplyErrorCategory::BindingMismatch,
            "options-version-tag-mutation" => DirectApplyErrorCategory::ArtifactVersionUnsupported,
            _ => unreachable!("unknown case"),
        };

        assert_private_apply_failure(
            apply_direct_desktop_accepting_current_artifact_id(&fixture),
            &fixture,
            &before,
            DirectApplyFailureExpectation::new(category),
        );
    }
}

#[test]
fn direct_desktop_apply_recovery_first_blocks_without_executing_recovery() {
    let fixture = ready_desktop_apply_fixture("desktop-recovery-first");
    {
        let _guard = lock_execution_hooks();
        set_journal_fault(Some(JournalFault::ForwardStepCompleted));
        let _ = apply_direct_desktop(&fixture);
        set_journal_fault(None);
    }
    let before = DirectDurableSnapshot::capture(&fixture);
    assert_private_apply_failure(
        apply_direct_desktop(&fixture),
        &fixture,
        &before,
        DirectApplyFailureExpectation::new(DirectApplyErrorCategory::RecoveryRequired),
    );
}

fn only_child_directory(parent: &Path) -> PathBuf {
    let children = fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(
        children.len(),
        1,
        "expected exactly one transaction directory"
    );
    children[0].clone()
}

fn flip_first_byte(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    assert!(!bytes.is_empty());
    bytes[0] ^= 0x5a;
    fs::write(path, bytes).unwrap();
}

fn flip_byte_at(path: &Path, offset: usize) {
    let mut bytes = fs::read(path).unwrap();
    assert!(offset < bytes.len());
    bytes[offset] ^= 0x5a;
    fs::write(path, bytes).unwrap();
}

fn package_free_artifact_path(root: &Path) -> PathBuf {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("bin"))
        .unwrap()
}

fn mutate_package_free_artifact(root: &Path, label: &str) {
    let path = package_free_artifact_path(root);
    let mut bytes = fs::read(&path).unwrap();
    if label == "artifact-bytes" {
        bytes[0] ^= 0x5a;
    } else if label == "artifact-self-id" {
        let last = bytes.len() - 1;
        bytes[last] ^= 0x5a;
    } else {
        let fields_start = super::artifact::ARTIFACT_V2_MAGIC.len() + 1 + 8;
        let mut after_optionals = fields_start + (5 * 32);
        for _ in 0..4 {
            let present = bytes[after_optionals];
            after_optionals += 1;
            if present == 1 {
                after_optionals += 32;
            }
        }
        let offset = match label {
            "artifact-selected-resource" => fields_start + 32,
            "artifact-apply-plan" => after_optionals + (3 * 32),
            "artifact-snapshot" => after_optionals + (4 * 32),
            "artifact-transactional-plan" => after_optionals + (5 * 32),
            "artifact-recovery-authority-id" => after_optionals + (6 * 32),
            "artifact-installed-snapshot" => {
                let descriptor = descriptor_start(&bytes);
                let mut cursor = descriptor + b"gkrm-cli-apply-descriptor-bin-v1\n".len() + 1;
                for _ in 0..3 {
                    cursor += 8 + read_u64_at(&bytes, cursor);
                }
                cursor
            }
            _ => unreachable!(),
        };
        bytes[offset] ^= 0x5a;
    }
    fs::write(path, bytes).unwrap();
}

fn mutate_package_free_authority(path: &Path, label: &str) {
    let mut bytes = fs::read(path).unwrap();
    const ENVELOPE_MAGIC_LEN: usize = b"gkrm-recovery-authority-envelope-v1\n".len();
    const BODY_MAGIC_LEN: usize = b"gkrm-recovery-authority-body-v1\n".len();
    let body_start = ENVELOPE_MAGIC_LEN + 1 + 8;
    let body_len = u64::from_le_bytes(
        bytes[ENVELOPE_MAGIC_LEN + 1..body_start]
            .try_into()
            .unwrap(),
    ) as usize;
    let body_end = body_start + body_len;
    let digest_start = body_start + BODY_MAGIC_LEN + 3;
    let nodes_start = digest_start + (8 * 32) + 8;
    let offset = match label {
        "authority-magic" => 0,
        "authority-canonical-field" => digest_start + 32,
        "authority-id" => body_end,
        "authority-envelope-artifact-id" => body_end + 32,
        "authority-publication-binding" => body_end + 64,
        "authority-unsupported-derivation" => body_start + BODY_MAGIC_LEN + 1,
        "authority-node-path" => nodes_start + 8,
        "authority-node-digest" | "authority-node-length" | "authority-directory-node" => {
            let mut cursor = nodes_start;
            let mut found = None;
            while cursor < body_end {
                let path_len =
                    u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
                let tag_at = cursor + 8 + path_len;
                let tag = bytes[tag_at];
                if label == "authority-directory-node" && tag == 2 {
                    found = Some(tag_at);
                    break;
                }
                if tag == 1 {
                    if label == "authority-node-digest" {
                        found = Some(tag_at + 1);
                        break;
                    }
                    if label == "authority-node-length" {
                        found = Some(tag_at + 1 + 32);
                        break;
                    }
                    cursor = tag_at + 1 + 32 + 8;
                } else {
                    cursor = tag_at + 1;
                }
            }
            found.unwrap()
        }
        _ => unreachable!(),
    };
    if label == "authority-unsupported-derivation" {
        bytes[offset] = 0xff;
    } else {
        bytes[offset] ^= 0x5a;
    }
    fs::write(path, bytes).unwrap();
}

fn mutate_package_free_journal(journal: &Path, label: &str) {
    let mut records = fs::read_dir(journal)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    records.sort();
    let path = if label == "journal-previous-chain" {
        records.last().unwrap()
    } else {
        records.first().unwrap()
    };
    let mut bytes = fs::read(path).unwrap();
    let magic_len = b"gkrm-txn-journal-v2\n".len();
    match label {
        "journal-body" => bytes[magic_len + 1 + 4 + 32 + 32 + 32] ^= 0x5a,
        "journal-record-id" => bytes[magic_len + 1 + 4 + 32 + 32] ^= 0x5a,
        "journal-sequence" => bytes[magic_len + 1] ^= 0x5a,
        "journal-publication-binding" => bytes[magic_len + 1 + 4 + 32] ^= 0x5a,
        "journal-previous-chain" => {
            let optional_start = magic_len + 1 + 4 + 32 + 32 + 32 + 32;
            let tag = bytes[optional_start];
            bytes[optional_start + usize::from(tag == 1)] ^= 0x5a;
        }
        "journal-truncated" => bytes.truncate(bytes.len() / 2),
        "journal-unsupported-version" => {
            let version = bytes.windows(2).position(|window| window == b"v2").unwrap();
            bytes[version + 1] = b'9';
        }
        "journal-malformed-version" => bytes[0] ^= 0x5a,
        _ => unreachable!(),
    }
    fs::write(path, bytes).unwrap();
}

fn package_free_baseline_dir(
    mini: &MiniFixture,
    workspace: &crate::TrustedUpdateWorkspace,
) -> PathBuf {
    workspace
        .baseline_store()
        .join("baselines")
        .join("gksphone")
        .join(mini.baseline.baseline_id().as_str())
}

fn regular_files_recursive(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(regular_files_recursive(&path));
        } else if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files
}

#[test]
fn temp_transaction_directory_sync_precedes_publication_and_installed_mutation() {
    let fixture = ready_desktop_apply_fixture("desktop-temp-dir-sync-failure");
    let installed_before = PathSnapshot::capture(&fixture.mini.installed_resource);
    {
        let _guard = lock_execution_hooks();
        set_force_temp_directory_sync_failure(true);
        if let Ok(report) = apply_direct_desktop(&fixture) {
            assert_ne!(report.outcome, "committed");
        }
    }
    assert_eq!(
        PathSnapshot::capture(&fixture.mini.installed_resource),
        installed_before
    );
    let published = fixture.txn.join("transactions");
    assert!(
        !published.exists() || fs::read_dir(&published).unwrap().next().is_none(),
        "a temp-directory sync failure must not publish authority"
    );
    let unpublished = only_child_directory(&fixture.txn.join(".tmp"));
    for relative in [
        "recovery-authority.bin",
        "snapshot-a.bin",
        "resource-lock-id.bin",
        "journal/00000000-prepared.bin",
    ] {
        assert!(unpublished.join(relative).is_file(), "missing {relative}");
    }

    let fixture = ready_desktop_apply_fixture("desktop-temp-dir-sync-success");
    assert_eq!(apply_direct_desktop(&fixture).unwrap().outcome, "committed");
    let published = only_child_directory(&fixture.txn.join("transactions"));
    for relative in [
        "recovery-authority.bin",
        "snapshot-a.bin",
        "resource-lock-id.bin",
        "journal/00000000-prepared.bin",
    ] {
        assert!(published.join(relative).is_file(), "missing {relative}");
    }
}

#[derive(Clone, Copy)]
enum PostLockTamper {
    Artifact,
    Envelope,
    Snapshot,
    ResourceLock,
    Journal,
    StagingManifest,
    StagedResource,
    Baseline,
    InstalledIdentity,
    TransactionDirectoryReplacement,
    JournalDirectoryReplacement,
    TransactionNamespaceRemoval,
    JournalNamespaceRemoval,
    TransactionDirectoryLink,
    JournalDirectoryLink,
}

#[test]
fn post_recovery_lock_revalidation_reopens_every_durable_authority_input_before_backup() {
    let cases = [
        ("artifact", PostLockTamper::Artifact),
        ("envelope", PostLockTamper::Envelope),
        ("snapshot", PostLockTamper::Snapshot),
        ("resource-lock", PostLockTamper::ResourceLock),
        ("journal", PostLockTamper::Journal),
        ("staging-manifest", PostLockTamper::StagingManifest),
        ("staged-resource", PostLockTamper::StagedResource),
        ("baseline", PostLockTamper::Baseline),
        ("installed-identity", PostLockTamper::InstalledIdentity),
        (
            "transaction-directory-byte-identical-replacement",
            PostLockTamper::TransactionDirectoryReplacement,
        ),
        (
            "journal-directory-byte-identical-replacement",
            PostLockTamper::JournalDirectoryReplacement,
        ),
        (
            "transaction-namespace-removal",
            PostLockTamper::TransactionNamespaceRemoval,
        ),
        (
            "journal-namespace-removal",
            PostLockTamper::JournalNamespaceRemoval,
        ),
        (
            "transaction-directory-link",
            PostLockTamper::TransactionDirectoryLink,
        ),
        (
            "journal-directory-link",
            PostLockTamper::JournalDirectoryLink,
        ),
    ];
    for (label, tamper) in cases {
        #[cfg(windows)]
        if matches!(
            tamper,
            PostLockTamper::TransactionDirectoryReplacement
                | PostLockTamper::JournalDirectoryReplacement
                | PostLockTamper::TransactionNamespaceRemoval
                | PostLockTamper::JournalNamespaceRemoval
                | PostLockTamper::TransactionDirectoryLink
                | PostLockTamper::JournalDirectoryLink
        ) {
            // Windows opens these capability directories without delete sharing, so
            // the kernel rejects the deterministic rename/remove substitution itself.
            continue;
        }
        let fixture = ready_desktop_apply_fixture(&format!("post-lock-{label}"));
        let installed_before = PathSnapshot::capture(&fixture.mini.installed_resource);
        let artifact = fixture.artifact_out.clone();
        let transactions = fixture.txn.join("transactions");
        let manifest = published_bundle_dir(&fixture).join("manifest.bin");
        let staged = staged_resource_file(&fixture, "take.lua");
        let baseline = fixture
            .mini
            .store
            .join("baselines")
            .join("gksphone")
            .join(fixture.mini.baseline.baseline_id().as_str())
            .join("baseline.json");
        let installed = fixture.mini.installed_resource.clone();
        let detached_original = Arc::new(Mutex::new(None::<(PathBuf, PathSnapshot)>));
        {
            let _guard = lock_execution_hooks();
            let detached_for_hook = Arc::clone(&detached_original);
            set_publication_hook(PublicationPoint::AfterRecoveryLock, move || {
                match tamper {
                    PostLockTamper::Artifact => flip_first_byte(&artifact),
                    PostLockTamper::Envelope => flip_first_byte(
                        &only_child_directory(&transactions).join("recovery-authority.bin"),
                    ),
                    PostLockTamper::Snapshot => {
                        flip_first_byte(&only_child_directory(&transactions).join("snapshot-a.bin"))
                    }
                    PostLockTamper::ResourceLock => flip_first_byte(
                        &only_child_directory(&transactions).join("resource-lock-id.bin"),
                    ),
                    PostLockTamper::Journal => flip_first_byte(
                        &only_child_directory(&transactions)
                            .join("journal")
                            .join("00000000-prepared.bin"),
                    ),
                    PostLockTamper::StagingManifest => flip_first_byte(&manifest),
                    PostLockTamper::StagedResource => flip_first_byte(&staged),
                    PostLockTamper::Baseline => flip_first_byte(&baseline),
                    PostLockTamper::InstalledIdentity => {
                        let old = installed.with_file_name("gksphone-hook-old");
                        fs::rename(&installed, &old).unwrap();
                        copy_dir_recursive(&old, &installed);
                    }
                    PostLockTamper::TransactionDirectoryReplacement => {
                        let original = only_child_directory(&transactions);
                        let old = transactions.join("renamed-original");
                        fs::rename(&original, &old).unwrap();
                        copy_dir_recursive(&old, &original);
                    }
                    PostLockTamper::JournalDirectoryReplacement => {
                        let transaction = only_child_directory(&transactions);
                        let original = transaction.join("journal");
                        let old = transaction.join("journal-renamed-original");
                        fs::rename(&original, &old).unwrap();
                        copy_dir_recursive(&old, &original);
                    }
                    PostLockTamper::TransactionNamespaceRemoval => {
                        let original = only_child_directory(&transactions);
                        fs::rename(&original, transactions.join("renamed-original")).unwrap();
                    }
                    PostLockTamper::JournalNamespaceRemoval => {
                        let transaction = only_child_directory(&transactions);
                        fs::rename(
                            transaction.join("journal"),
                            transaction.join("journal-renamed-original"),
                        )
                        .unwrap();
                    }
                    PostLockTamper::TransactionDirectoryLink => {
                        let original = only_child_directory(&transactions);
                        let old = transactions.join("renamed-original");
                        fs::rename(&original, &old).unwrap();
                        create_test_directory_link(&old, &original);
                    }
                    PostLockTamper::JournalDirectoryLink => {
                        let transaction = only_child_directory(&transactions);
                        let original = transaction.join("journal");
                        let old = transaction.join("journal-renamed-original");
                        fs::rename(&original, &old).unwrap();
                        create_test_directory_link(&old, &original);
                    }
                }
                let detached_journal = match tamper {
                    PostLockTamper::TransactionDirectoryReplacement
                    | PostLockTamper::TransactionNamespaceRemoval
                    | PostLockTamper::TransactionDirectoryLink => {
                        Some(transactions.join("renamed-original").join("journal"))
                    }
                    PostLockTamper::JournalDirectoryReplacement
                    | PostLockTamper::JournalNamespaceRemoval
                    | PostLockTamper::JournalDirectoryLink => {
                        Some(only_child_directory(&transactions).join("journal-renamed-original"))
                    }
                    _ => None,
                };
                if let Some(path) = detached_journal {
                    *detached_for_hook.lock().unwrap() =
                        Some((path.clone(), PathSnapshot::capture(&path)));
                }
            });
            if let Ok(report) = apply_direct_desktop(&fixture) {
                assert_ne!(report.outcome, "committed", "case {label}");
            }
        }
        if let Some((path, before)) = detached_original.lock().unwrap().clone() {
            assert_eq!(
                PathSnapshot::capture(&path),
                before,
                "case {label} wrote evidence through the detached pre-lock journal"
            );
        }
        for entry in fs::read_dir(fixture.txn.join("transactions")).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert!(!path.join("backup").exists(), "case {label} reached backup");
            }
        }
        assert_eq!(
            PathSnapshot::capture(&fixture.mini.installed_resource),
            installed_before,
            "case {label} changed installed content"
        );
    }
}

#[cfg(unix)]
fn create_test_directory_link(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(windows)]
fn create_test_directory_link(target: &Path, link: &Path) {
    create_junction(target, link);
}

#[test]
fn task31a_publication_crash_boundary_matrix_is_deterministic_and_prebackup_safe() {
    let points = [
        PublicationPoint::AfterResourceLock,
        PublicationPoint::BeforeAuthorityWrite,
        PublicationPoint::DuringAuthorityWrite,
        PublicationPoint::AfterAuthorityFsync,
        PublicationPoint::AfterAuthorityVerify,
        PublicationPoint::AfterSnapshotFsync,
        PublicationPoint::AfterResourceLockFsync,
        PublicationPoint::AfterPreparedAppend,
        PublicationPoint::BeforeTempDirectorySync,
        PublicationPoint::AfterTempDirectorySync,
        PublicationPoint::BeforeRename,
        PublicationPoint::AfterRename,
        PublicationPoint::AfterParentSync,
        PublicationPoint::AfterPublishedReopen,
        PublicationPoint::AfterRecoveryLock,
        PublicationPoint::DuringFinalRevalidation,
        PublicationPoint::BeforeBackup,
    ];
    for point in points {
        let fixture = ready_desktop_apply_fixture(&format!("crash-{point:?}"));
        let installed_before = PathSnapshot::capture(&fixture.mini.installed_resource);
        {
            let _guard = lock_execution_hooks();
            set_publication_hook(point, || panic!("deterministic Task 31A crash"));
            let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = apply_direct_desktop(&fixture);
            }));
            assert!(crashed.is_err(), "hook {point:?} was not reached");
        }
        assert_eq!(
            PathSnapshot::capture(&fixture.mini.installed_resource),
            installed_before,
            "hook {point:?} changed installed content"
        );

        let after_rename = matches!(
            point,
            PublicationPoint::AfterRename
                | PublicationPoint::AfterParentSync
                | PublicationPoint::AfterPublishedReopen
                | PublicationPoint::AfterRecoveryLock
                | PublicationPoint::DuringFinalRevalidation
                | PublicationPoint::BeforeBackup
        );
        let authoritative = fixture.txn.join("transactions");
        if after_rename {
            let published = only_child_directory(&authoritative);
            for relative in [
                "recovery-authority.bin",
                "snapshot-a.bin",
                "resource-lock-id.bin",
                "journal/00000000-prepared.bin",
            ] {
                assert!(published.join(relative).is_file(), "{point:?}: {relative}");
            }
            assert!(
                !published.join("backup").exists(),
                "{point:?} reached backup"
            );
        } else {
            assert!(
                !authoritative.exists() || fs::read_dir(&authoritative).unwrap().next().is_none(),
                "{point:?} published incomplete authority"
            );
        }

        if !matches!(point, PublicationPoint::AfterResourceLock) && !after_rename {
            let unpublished = only_child_directory(&fixture.txn.join(".tmp"));
            let authority_exists = !matches!(point, PublicationPoint::BeforeAuthorityWrite);
            let snapshot_exists = matches!(
                point,
                PublicationPoint::AfterSnapshotFsync
                    | PublicationPoint::AfterResourceLockFsync
                    | PublicationPoint::AfterPreparedAppend
                    | PublicationPoint::BeforeTempDirectorySync
                    | PublicationPoint::AfterTempDirectorySync
                    | PublicationPoint::BeforeRename
            );
            let lock_exists = matches!(
                point,
                PublicationPoint::AfterResourceLockFsync
                    | PublicationPoint::AfterPreparedAppend
                    | PublicationPoint::BeforeTempDirectorySync
                    | PublicationPoint::AfterTempDirectorySync
                    | PublicationPoint::BeforeRename
            );
            let journal_exists = matches!(
                point,
                PublicationPoint::AfterPreparedAppend
                    | PublicationPoint::BeforeTempDirectorySync
                    | PublicationPoint::AfterTempDirectorySync
                    | PublicationPoint::BeforeRename
            );
            assert_eq!(
                unpublished.join("recovery-authority.bin").is_file(),
                authority_exists,
                "{point:?} authority state"
            );
            assert_eq!(
                unpublished.join("snapshot-a.bin").is_file(),
                snapshot_exists,
                "{point:?} snapshot state"
            );
            assert_eq!(
                unpublished.join("resource-lock-id.bin").is_file(),
                lock_exists,
                "{point:?} lock state"
            );
            assert_eq!(
                unpublished.join("journal/00000000-prepared.bin").is_file(),
                journal_exists,
                "{point:?} journal state"
            );
        }
    }
}

#[test]
fn recovery_first_precedence_wins_over_damaged_reconstruction_inputs() {
    for label in ["artifact", "staging", "baseline"] {
        let fixture = ready_desktop_apply_fixture(&format!("recovery-first-{label}"));
        {
            let _guard = lock_execution_hooks();
            set_journal_fault(Some(JournalFault::ForwardStepCompleted));
            let _ = apply_direct_desktop(&fixture);
        }
        match label {
            "artifact" => flip_first_byte(&fixture.artifact_out),
            "staging" => flip_first_byte(&published_bundle_dir(&fixture).join("manifest.bin")),
            "baseline" => flip_first_byte(
                &fixture
                    .mini
                    .store
                    .join("baselines")
                    .join("gksphone")
                    .join(fixture.mini.baseline.baseline_id().as_str())
                    .join("baseline.json"),
            ),
            _ => unreachable!(),
        }
        let before = DirectDurableSnapshot::capture(&fixture);
        assert_private_apply_failure(
            apply_direct_desktop(&fixture),
            &fixture,
            &before,
            DirectApplyFailureExpectation::new(DirectApplyErrorCategory::RecoveryRequired),
        );
    }
}

#[test]
fn operator_merge_unknown_extra_file_in_root_fails() {
    let fixture = build_mini();
    let merge_root = fixture._temp.path().join("operator");
    fs::create_dir_all(&merge_root).unwrap();
    write_file(&merge_root.join("expected.lua"), b"expected content");
    write_file(&merge_root.join("unknown.lua"), b"extra unexpected content");

    let expected = vec![ResourceRelativePath::try_from_slash_str("expected.lua").unwrap()];

    let err = validate_and_load_operator_merge_root(
        &merge_root,
        &expected,
        fixture.plan.plan_id(),
        fixture.review.review_id(),
        &TrustedCliUpdateOptions::default(),
    )
    .expect_err("unknown extra file under operator merge root must fail");
    assert!(matches!(
        err,
        GkrmError::TrustedCliUpdateOperatorMergeInvalid
    ));
}

#[test]
fn publish_bytes_fault_injection_cleans_up_file() {
    let temp = tempdir().unwrap();
    let dest = temp.path().join("fault_out.bin");

    set_publish_parent_sync_fault(true);
    let _ = publish_bytes_no_replace(&dest, b"payload");
    set_publish_parent_sync_fault(false);
    assert!(!dest.exists());

    set_publish_post_verify_fault(true);
    let _ = publish_bytes_no_replace(&dest, b"payload");
    set_publish_post_verify_fault(false);
    assert!(!dest.exists());
}

#[test]
fn decision_document_mutation_fails_apply() {
    let fixture = build_mini();
    let txn = fixture._temp.path().join("txn-mut-dec");
    let staging = fixture._temp.path().join("staging-mut-dec");
    fs::create_dir_all(&txn).unwrap();
    fs::create_dir_all(&staging).unwrap();
    let artifact_out = fixture._temp.path().join("out").join("flow.bin");
    fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
    let decisions = fixture._temp.path().join("dec").join("decisions.bin");
    write_decisions_file(&fixture, &decisions);

    let plan_report = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: crate::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(plan_report.outcome, "ready_to_apply");

    // Mutate decision document after plan
    let mut bytes = fs::read(&decisions).unwrap();
    if let Some(last) = bytes.last_mut() {
        *last ^= 0xff;
    }
    fs::write(&decisions, &bytes).unwrap();

    let err = apply_trusted_cli_update(TrustedCliApplyRequest {
        artifact: &artifact_out,
        package: &fixture.package_v2,
        installed: &fixture.installed_parent,
        baseline_store: &fixture.store,
        baseline_selector: OfficialBaselineSelector::Exact(fixture.baseline.baseline_id().clone()),
        resource: Some(&SafeResourceKey::parse("gksphone").unwrap()),
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        operator_merge_root: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect_err("mutated decision document should be rejected");
    assert!(matches!(
        err,
        GkrmError::TrustedCliUpdateDecisionsInvalid | GkrmError::TrustedCliUpdateBindingMismatch
    ));
}

#[test]
fn two_way_interrupted_apply_recovers_original_tree_after_reopen_without_zip() {
    let mini = build_mini();
    let appdata = mini._temp.path().join("two-way-recovery-appdata");
    fs::create_dir(&appdata).unwrap();
    let workspace = crate::resolve_trusted_update_workspace(&appdata).unwrap();
    let before = PathSnapshot::capture(&mini.installed_resource);
    {
        let _hooks = lock_execution_hooks();
        set_publication_hook(PublicationPoint::AfterFilePublish, || {
            panic!("simulated process interruption after durable publication")
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::apply_two_way_update(crate::TwoWayApplyRequest {
                expected_plan_id: None,
                baseline: None,
                package: &mini.package_v2,
                installed: &mini.installed_parent,
                resource: None,
                staging_root: workspace.staging_root(),
                transaction_root: workspace.transaction_root(),
                mode: crate::TwoWayUpdateMode::ReplaceWithIncoming,
                choices: &[],
                workspace: Some(&workspace),
                options: TrustedCliUpdateOptions::default(),
            })
        }));
        assert!(
            result.is_err(),
            "interruption must occur after a real file publication"
        );
    }
    assert_ne!(
        PathSnapshot::capture(&mini.installed_resource),
        before,
        "the injected interruption must leave an actual partial write"
    );
    drop(workspace);
    fs::remove_file(&mini.package_v2).unwrap();
    let reopened = crate::resolve_trusted_update_workspace(&appdata).unwrap();
    let result = try_recover_workspace_v2(&mini, &reopened).unwrap();
    assert!(
        matches!(result, crate::TrustedRecoveryResult::RecoveredRolledBack(_)),
        "{result:?}"
    );
    assert_eq!(PathSnapshot::capture(&mini.installed_resource), before);
}

#[test]
fn interrupted_trusted_undo_rolls_back_to_the_applied_tree_after_reopen_without_zip() {
    let mini = build_mini();
    let appdata = mini._temp.path().join("undo-recovery-appdata");
    fs::create_dir(&appdata).unwrap();
    let workspace = crate::resolve_trusted_update_workspace(&appdata).unwrap();
    let original = PathSnapshot::capture(&mini.installed_resource);
    let outcome = crate::apply_two_way_update(crate::TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &mini.package_v2,
        installed: &mini.installed_parent,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: crate::TwoWayUpdateMode::ReplaceWithIncoming,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(outcome.outcome(), "committed");
    let parent = *outcome.transaction_id().unwrap();
    let applied = PathSnapshot::capture(&mini.installed_resource);
    let selection = crate::scan_trusted_installed_recovery_resources(
        &mini.installed_parent,
        crate::InstalledScanLimits::default(),
    )
    .unwrap()
    .select(&SafeResourceKey::parse("gksphone").unwrap())
    .unwrap();
    let source = crate::TrustedUndoSource::try_open(&workspace, &selection, &parent).unwrap();
    let plan = source.plan(&selection).unwrap();
    assert!(plan.previous_attempt().is_none());
    let staged = source.stage(&selection, &plan).unwrap();
    let reverse_apply = staged.plan_apply(&selection).unwrap();
    let first_attempt = *staged
        .plan_transaction(&selection, &reverse_apply)
        .unwrap()
        .plan_id()
        .digest();
    drop(staged);
    {
        let _hooks = lock_execution_hooks();
        set_publication_hook(PublicationPoint::AfterFilePublish, || {
            panic!("simulated interruption after actual Undo file publication")
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            source.execute(&selection, &plan)
        }));
        assert!(
            result.is_err(),
            "Undo must reach an actual file publication"
        );
    }
    assert_ne!(
        PathSnapshot::capture(&mini.installed_resource),
        applied,
        "Undo must leave an actual partial reverse write"
    );
    assert!(workspace
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .join("backup")
        .is_dir());
    drop(source);
    drop(workspace);
    fs::remove_file(&mini.package_v2).unwrap();
    let reopened = crate::resolve_trusted_update_workspace(&appdata).unwrap();
    // Both the retained, retired forward parent and the interrupted Undo are
    // present. The generic one-transaction fixture helper takes the first bound
    // candidate; use production discovery to select the actual outstanding Undo.
    let selection = trusted_gksphone_selection(&mini);
    let inspection = crate::inspect_trusted_published_update_v2(
        &reopened,
        &selection,
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    let result = try_recover_workspace_candidate(
        &mini,
        &reopened,
        inspection
            .candidate_id()
            .expect("outstanding Undo candidate"),
    )
    .unwrap();
    assert!(
        matches!(result, crate::TrustedRecoveryResult::RecoveredRolledBack(_)),
        "{result:?}"
    );
    assert_eq!(PathSnapshot::capture(&mini.installed_resource), applied);
    assert!(reopened
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .join("backup")
        .is_dir());
    let selection = trusted_gksphone_selection(&mini);
    let retry = crate::TrustedUndoSource::try_open(&reopened, &selection, &parent).unwrap();
    let retry_plan = retry.plan(&selection).unwrap();
    assert_eq!(retry_plan.previous_attempt(), Some(&first_attempt));
    assert_eq!(retry_plan.current_fingerprint(), plan.current_fingerprint());
    assert_eq!(retry_plan.entries(), plan.entries());
    assert_ne!(retry_plan.plan_id(), plan.plan_id());
    let artifact_count = fs::read_dir(reopened.artifact_root().path())
        .unwrap()
        .count();
    assert!(
        retry.execute(&selection, &plan).is_err(),
        "the earlier reviewed attempt must be stale"
    );
    assert_eq!(
        fs::read_dir(reopened.artifact_root().path())
            .unwrap()
            .count(),
        artifact_count
    );
    assert_eq!(PathSnapshot::capture(&mini.installed_resource), applied);
    let completed = retry.execute(&selection, &retry_plan).unwrap();
    assert!(
        matches!(
            completed.result(),
            Some(crate::TrustedTransactionResult::Committed(_))
        ),
        "{completed:?}"
    );
    let retry_id = *completed.transaction_id().unwrap();
    assert_ne!(retry_id, first_attempt);
    assert_ne!(retry_id, parent);
    assert_eq!(PathSnapshot::capture(&mini.installed_resource), original);
    let receipts = crate::inspect_trusted_undo_receipts(&reopened, &selection).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].transaction_id(), &retry_id);
    for id in [parent, first_attempt, retry_id] {
        assert!(reopened
            .transaction_root()
            .join("transactions")
            .join(id.to_string())
            .join("backup")
            .is_dir());
    }
}

/// The boundary before Undo has a backup to fall back on. Nothing has been written yet, so
/// recovery has to leave the installation exactly as the update left it, and the forward
/// parent's own evidence has to survive being interrupted by a successor.
#[test]
fn interrupted_trusted_undo_before_its_backup_leaves_the_applied_tree_untouched() {
    let mini = build_mini();
    let appdata = mini._temp.path().join("undo-before-backup-appdata");
    fs::create_dir(&appdata).unwrap();
    let workspace = crate::resolve_trusted_update_workspace(&appdata).unwrap();
    let outcome = crate::apply_two_way_update(crate::TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &mini.package_v2,
        installed: &mini.installed_parent,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: crate::TwoWayUpdateMode::ReplaceWithIncoming,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(outcome.outcome(), "committed");
    let parent = *outcome.transaction_id().unwrap();
    let applied = PathSnapshot::capture(&mini.installed_resource);
    let selection = trusted_gksphone_selection(&mini);
    let source = crate::TrustedUndoSource::try_open(&workspace, &selection, &parent).unwrap();
    let plan = source.plan(&selection).unwrap();
    {
        let _hooks = lock_execution_hooks();
        set_publication_hook(PublicationPoint::BeforeBackup, || {
            panic!("simulated interruption before the Undo backup exists")
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            source.execute(&selection, &plan)
        }));
        assert!(result.is_err(), "Undo must reach its backup boundary");
    }
    assert_eq!(
        PathSnapshot::capture(&mini.installed_resource),
        applied,
        "nothing was written, so nothing may have changed"
    );
    drop(source);
    drop(workspace);
    fs::remove_file(&mini.package_v2).unwrap();

    let reopened = crate::resolve_trusted_update_workspace(&appdata).unwrap();
    let selection = trusted_gksphone_selection(&mini);
    let inspection = crate::inspect_trusted_published_update_v2(
        &reopened,
        &selection,
        crate::TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .unwrap();
    if let Some(candidate) = inspection.candidate_id() {
        let result = try_recover_workspace_candidate(&mini, &reopened, candidate).unwrap();
        // Nothing was mutated, so there is nothing to undo and nothing to finish: the
        // transaction is simply safe to start again. A rollback here would be work invented to
        // match a shape rather than to repair anything.
        assert!(
            matches!(result, crate::TrustedRecoveryResult::SafeRestart(_)),
            "{result:?}"
        );
    }
    assert_eq!(PathSnapshot::capture(&mini.installed_resource), applied);
    assert!(reopened
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .join("backup")
        .is_dir());
    // The forward parent is still exactly what an explicit retry binds to.
    let selection = trusted_gksphone_selection(&mini);
    crate::TrustedUndoSource::try_open(&reopened, &selection, &parent).unwrap();
}

/// Completion is a durable record, not an inference. If the record cannot be written, the Undo
/// did not complete, and nothing may read as though it had.
#[test]
fn an_undo_that_cannot_record_completion_is_never_read_as_completed() {
    let mini = build_mini();
    let appdata = mini._temp.path().join("undo-no-completion-appdata");
    fs::create_dir(&appdata).unwrap();
    let workspace = crate::resolve_trusted_update_workspace(&appdata).unwrap();
    let original = PathSnapshot::capture(&mini.installed_resource);
    let outcome = crate::apply_two_way_update(crate::TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &mini.package_v2,
        installed: &mini.installed_parent,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: crate::TwoWayUpdateMode::ReplaceWithIncoming,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(outcome.outcome(), "committed");
    let parent = *outcome.transaction_id().unwrap();
    let applied = PathSnapshot::capture(&mini.installed_resource);
    let selection = trusted_gksphone_selection(&mini);
    let source = crate::TrustedUndoSource::try_open(&workspace, &selection, &parent).unwrap();
    let plan = source.plan(&selection).unwrap();
    {
        let _hooks = lock_execution_hooks();
        set_journal_fault(Some(JournalFault::Committed));
        let attempted = source.execute(&selection, &plan);
        let committed = matches!(
            attempted.as_ref().ok().and_then(|outcome| outcome.result()),
            Some(crate::TrustedTransactionResult::Committed(_))
        );
        assert!(
            !committed,
            "an Undo whose completion record failed must not report completion: {attempted:?}"
        );
    }
    // Whichever way it went, the installation is one of the two whole trees and never a mixture.
    let after = PathSnapshot::capture(&mini.installed_resource);
    assert!(
        after == applied || after == original,
        "the installation must be a whole tree, not a partial reversal"
    );
    // Completion is derived from durable evidence, and that evidence was never written.
    let selection = trusted_gksphone_selection(&mini);
    let receipts = crate::inspect_trusted_undo_receipts(&workspace, &selection).unwrap();
    assert!(
        !receipts
            .iter()
            .any(|receipt| receipt.parent_transaction_id() == &parent),
        "no completed Undo may be derived for a parent whose Undo never committed"
    );
    assert!(workspace
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .join("backup")
        .is_dir());
}
