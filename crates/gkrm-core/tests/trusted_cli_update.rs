//! Integration smoke tests for Task 25 trusted CLI update public APIs.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    apply_trusted_cli_update, apply_trusted_cli_update_in_workspace, build_decision_document,
    capture_official_baseline_in_standalone_store, plan_trusted_cli_update,
    plan_trusted_cli_update_for_review, plan_trusted_cli_update_in_workspace,
    resolve_official_baseline, resolve_trusted_update_workspace_from_explicit_roots,
    retire_trusted_terminal_update_evidence, status_trusted_cli_update, BaselineCaptureOptions,
    BaselineCaptureRequest, BaselineResolutionOptions, BaselineResolutionRequest,
    ExplicitTrustedUpdateWorkspaceRequest, IncomingResourceSelector, OfficialBaselineSelector,
    PolicyTransitionAcknowledgement, SafeResourceKey, ThreeWayPlanDecisionChoice,
    TrustedCliApplyRequest, TrustedCliDecisionEntry, TrustedCliPlanRequest,
    TrustedCliStatusRequest, TrustedCliUpdateOptions, TrustedTerminalEvidenceRetirementOptions,
    TrustedTransactionRoot,
};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'merge.lua',\n  'take.lua',\n}\n";
const MERGE_BASE: &[u8] = b"L1\nL2\nL3\nL4\n";
const MERGE_INSTALLED: &[u8] = b"L1x\nL2\nL3\nL4\n";
const MERGE_INCOMING: &[u8] = b"L1\nL2\nL3\nL4y\n";
const TAKE_INSTALLED: &[u8] = b"take-installed\n";
const TAKE_INCOMING: &[u8] = b"take-incoming\n";
const TAKE_BASE: &[u8] = b"take-base\n";

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    fs::write(path, contents).expect("write file");
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, contents) in entries {
        writer.start_file(*name, options).expect("start zip entry");
        writer
            .write_all(contents)
            .expect("write zip entry contents");
    }
    writer.finish().expect("finish zip");
}

fn snapshot_regular_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, current: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("snapshot entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(root, &path, files);
            } else if path.is_file() {
                files.push((
                    path.strip_prefix(root)
                        .expect("relative snapshot path")
                        .to_path_buf(),
                    fs::read(&path).expect("snapshot file"),
                ));
            }
        }
    }
    let mut files = Vec::new();
    visit(root, root, &mut files);
    files
}

struct MiniPaths {
    _temp: tempfile::TempDir,
    store: PathBuf,
    installed_parent: PathBuf,
    package_v2: PathBuf,
    baseline_id: gkrm_core::BaselineId,
    plan: gkrm_core::ThreeWayUpdatePlan,
}

fn build_mini_paths() -> MiniPaths {
    let temp = tempdir().expect("tempdir");
    let capture_installed = temp.path().join("capture-installed");
    let installed_parent = temp.path().join("installed");
    let installed_resource = installed_parent.join("gksphone");
    let store = temp.path().join("store");
    let package_v1 = temp.path().join("v1.zip");
    let package_v2 = temp.path().join("v2.zip");
    fs::create_dir_all(&capture_installed).expect("capture dir");
    fs::create_dir_all(&store).expect("store dir");

    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/merge.lua", MERGE_BASE),
            ("gksphone/take.lua", TAKE_BASE),
        ],
    );
    let capture = capture_official_baseline_in_standalone_store(
        &gkrm_core::resolve_standalone_baseline_store(&store).expect("standalone store"),
        BaselineCaptureRequest::try_new(
            &capture_installed,
            &store,
            &package_v1,
            SafeResourceKey::parse("gksphone").expect("resource key"),
            IncomingResourceSelector::AutoSingle,
            BaselineCaptureOptions::default(),
        )
        .expect("capture request"),
    )
    .expect("capture baseline");
    let baseline_id = capture.baseline_id().clone();
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &store,
            &SafeResourceKey::parse("gksphone").expect("resource key"),
            OfficialBaselineSelector::Exact(baseline_id.clone()),
            BaselineResolutionOptions::default(),
        )
        .expect("resolve request"),
    )
    .expect("resolve baseline");

    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("merge.lua"), MERGE_INSTALLED);
    write_file(&installed_resource.join("take.lua"), TAKE_INSTALLED);
    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/merge.lua", MERGE_INCOMING),
            ("gksphone/take.lua", TAKE_INCOMING),
        ],
    );

    let report = gkrm_core::inspect_installation_update(
        &installed_parent,
        &package_v2,
        gkrm_core::InspectionOptions::default(),
    )
    .expect("inspect");
    let installed_snapshot = gkrm_core::InstalledResourceSnapshot::try_from_inspection(
        &report,
        &gkrm_core::InstalledResourceRoot::Path(
            gkrm_core::InstallationRelativePath::from_path(Path::new("gksphone")).expect("path"),
        ),
        &SafeResourceKey::parse("gksphone").expect("resource key"),
    )
    .expect("installed snapshot");
    let incoming_snapshot = gkrm_core::IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &gkrm_core::ZipResourceRoot::Path(
            gkrm_core::ZipRelativePath::parse_canonical("gksphone").expect("zip path"),
        ),
        &SafeResourceKey::parse("gksphone").expect("resource key"),
    )
    .expect("incoming snapshot");
    let plan = gkrm_core::create_three_way_update_plan(
        gkrm_core::ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            gkrm_core::ThreeWayPlannerOptions::default(),
        )
        .expect("plan request"),
    )
    .expect("create plan");

    MiniPaths {
        _temp: temp,
        store,
        installed_parent,
        package_v2,
        baseline_id,
        plan,
    }
}

fn write_decisions(mini: &MiniPaths, path: &Path) {
    let entries = mini
        .plan
        .entries()
        .iter()
        .filter_map(|entry| {
            let choice = match entry.path().as_str() {
                "merge.lua" => ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                "take.lua" => ThreeWayPlanDecisionChoice::UseIncomingState,
                _ => return None,
            };
            Some(TrustedCliDecisionEntry {
                path: entry.path().clone(),
                choice,
                policy_acknowledgement: PolicyTransitionAcknowledgement::NotProvided,
                operator_merge_relpath: None,
            })
        })
        .collect::<Vec<_>>();
    let doc = build_decision_document(&mini.plan, entries, &TrustedCliUpdateOptions::default())
        .expect("decision document");
    write_file(path, doc.canonical_bytes());
}

#[test]
fn status_smoke_on_empty_transaction_root() {
    let temp = tempdir().expect("tempdir");
    let txn = temp.path().join("txn");
    fs::create_dir_all(&txn).expect("txn dir");
    TrustedTransactionRoot::try_open(&txn).expect("open txn root");

    let report = status_trusted_cli_update(TrustedCliStatusRequest {
        transaction_root: &txn,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("status");

    assert_eq!(report.outcome, "status");
}

#[test]
fn plan_and_apply_smoke_commits() {
    let mini = build_mini_paths();
    let txn = mini._temp.path().join("txn");
    let staging = mini._temp.path().join("staging");
    let artifact_out = mini._temp.path().join("out").join("artifact.bin");
    let decisions = mini._temp.path().join("dec").join("decisions.bin");
    fs::create_dir_all(&txn).expect("txn");
    fs::create_dir_all(&staging).expect("staging");
    fs::create_dir_all(artifact_out.parent().expect("artifact parent")).expect("artifact parent");
    write_decisions(&mini, &decisions);

    let plan_report = plan_trusted_cli_update(TrustedCliPlanRequest {
        package: &mini.package_v2,
        installed: &mini.installed_parent,
        baseline_store: &mini.store,
        baseline_selector: OfficialBaselineSelector::Exact(mini.baseline_id.clone()),
        resource: None,
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        decisions_out: None,
        operator_merge_root: None,
        artifact_out: &artifact_out,
        workspace: None,
        workspace_options: gkrm_core::TrustedUpdateWorkspaceOptions::default(),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("plan");
    assert_eq!(plan_report.outcome, "ready_to_apply");

    let apply_report = apply_trusted_cli_update(TrustedCliApplyRequest {
        artifact: &artifact_out,
        package: &mini.package_v2,
        installed: &mini.installed_parent,
        baseline_store: &mini.store,
        baseline_selector: OfficialBaselineSelector::Exact(mini.baseline_id),
        resource: None,
        staging_root: &staging,
        transaction_root: &txn,
        decisions_path: Some(&decisions),
        operator_merge_root: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(apply_report.outcome, "committed");
}

#[test]
fn managed_cli_terminal_finalize_allows_successor_without_weakening_next_gate() {
    let mini = build_mini_paths();
    let txn = mini._temp.path().join("managed-txn");
    let staging = mini._temp.path().join("managed-staging");
    let artifact_root = mini._temp.path().join("managed-out");
    let artifact_t1 = artifact_root.join("plan-t1.bin");
    let decisions_t1 = mini._temp.path().join("managed-decisions-t1.bin");
    write_decisions(&mini, &decisions_t1);
    let workspace = resolve_trusted_update_workspace_from_explicit_roots(
        ExplicitTrustedUpdateWorkspaceRequest {
            baseline_store: &mini.store,
            staging_root: &staging,
            transaction_root: &txn,
            artifact_root: &artifact_root,
            artifact_out: &artifact_t1,
            installed_root: &mini.installed_parent,
            package_file: &mini.package_v2,
        },
    )
    .expect("managed workspace");

    macro_rules! plan_request {
        ($artifact:expr, $decisions:expr) => {
            TrustedCliPlanRequest {
                package: &mini.package_v2,
                installed: &mini.installed_parent,
                baseline_store: &mini.store,
                baseline_selector: OfficialBaselineSelector::Exact(mini.baseline_id.clone()),
                resource: None,
                staging_root: &staging,
                transaction_root: &txn,
                decisions_path: $decisions,
                decisions_out: None,
                operator_merge_root: None,
                artifact_out: $artifact,
                workspace: Some(&workspace),
                workspace_options: gkrm_core::TrustedUpdateWorkspaceOptions::default(),
                options: TrustedCliUpdateOptions::default(),
            }
        };
    }
    assert_eq!(
        plan_trusted_cli_update_in_workspace(plan_request!(
            &artifact_t1,
            Some(decisions_t1.as_path())
        ))
        .expect("T1 plan")
        .outcome,
        "ready_to_apply"
    );
    assert_eq!(
        apply_trusted_cli_update_in_workspace(
            TrustedCliApplyRequest {
                artifact: &artifact_t1,
                package: &mini.package_v2,
                installed: &mini.installed_parent,
                baseline_store: &mini.store,
                baseline_selector: OfficialBaselineSelector::Exact(mini.baseline_id.clone()),
                resource: None,
                staging_root: &staging,
                transaction_root: &txn,
                decisions_path: Some(&decisions_t1),
                operator_merge_root: None,
                options: TrustedCliUpdateOptions::default(),
            },
            &workspace,
        )
        .expect("T1 apply")
        .outcome,
        "committed"
    );
    let t1_transaction = fs::read_dir(txn.join("transactions"))
        .expect("transactions")
        .next()
        .expect("T1")
        .expect("T1 entry")
        .path();
    let t1_before = snapshot_regular_files(&t1_transaction);
    let artifact_t2 = artifact_root.join("plan-t2.bin");
    assert!(matches!(
        plan_trusted_cli_update_in_workspace(plan_request!(&artifact_t2, None)),
        Err(gkrm_core::GkrmError::TrustedCliUpdateRecoveryRequired)
    ));

    let finalized = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    )
    .expect("finalize T1");
    assert_eq!(finalized.retired_count(), 1);
    let successor = plan_trusted_cli_update_in_workspace(plan_request!(&artifact_t2, None))
        .expect("successor planning must pass recovery-first gate");
    assert!(matches!(
        successor.outcome,
        "pending_decisions" | "ready_to_apply"
    ));
    let decisions_t2 = if successor.outcome == "pending_decisions" {
        let pending = plan_trusted_cli_update_for_review(plan_request!(&artifact_t2, None))
            .expect("inspect T2 pending decisions");
        let decisions = pending
            .report
            .pending_paths
            .iter()
            .map(|path| {
                let entry = pending
                    .plan
                    .entries()
                    .iter()
                    .find(|entry| entry.path().as_str() == path)
                    .expect("pending plan entry");
                TrustedCliDecisionEntry {
                    path: entry.path().clone(),
                    choice: ThreeWayPlanDecisionChoice::UseIncomingState,
                    policy_acknowledgement: PolicyTransitionAcknowledgement::NotProvided,
                    operator_merge_relpath: None,
                }
            })
            .collect();
        let document = build_decision_document(
            &pending.plan,
            decisions,
            &TrustedCliUpdateOptions::default(),
        )
        .expect("T2 decisions");
        let path = mini._temp.path().join("managed-decisions-t2.bin");
        write_file(&path, document.canonical_bytes());
        drop(pending);
        assert_eq!(
            plan_trusted_cli_update_in_workspace(plan_request!(&artifact_t2, Some(path.as_path())))
                .expect("T2 ready plan")
                .outcome,
            "ready_to_apply"
        );
        Some(path)
    } else {
        None
    };
    assert_eq!(
        apply_trusted_cli_update_in_workspace(
            TrustedCliApplyRequest {
                artifact: &artifact_t2,
                package: &mini.package_v2,
                installed: &mini.installed_parent,
                baseline_store: &mini.store,
                baseline_selector: OfficialBaselineSelector::Exact(mini.baseline_id.clone()),
                resource: None,
                staging_root: &staging,
                transaction_root: &txn,
                decisions_path: decisions_t2.as_deref(),
                operator_merge_root: None,
                options: TrustedCliUpdateOptions::default(),
            },
            &workspace,
        )
        .expect("T2 apply")
        .outcome,
        "committed"
    );
    assert_eq!(snapshot_regular_files(&t1_transaction), t1_before);
    assert_eq!(
        fs::read_dir(txn.join("terminal-retirements"))
            .expect("retirement root")
            .count(),
        1
    );
    let artifact_t3 = artifact_root.join("plan-t3.bin");
    assert!(matches!(
        plan_trusted_cli_update_in_workspace(plan_request!(&artifact_t3, None)),
        Err(gkrm_core::GkrmError::TrustedCliUpdateRecoveryRequired)
    ));
    let finalized_t2 = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    )
    .expect("finalize T2");
    assert_eq!(finalized_t2.retired_count(), 1);
    assert_eq!(finalized_t2.already_retired_count(), 1);
    assert!(plan_trusted_cli_update_in_workspace(plan_request!(&artifact_t3, None)).is_ok());
    assert_eq!(snapshot_regular_files(&t1_transaction), t1_before);
    assert_eq!(
        fs::read_dir(txn.join("terminal-retirements"))
            .expect("retirement root")
            .count(),
        2
    );
}
