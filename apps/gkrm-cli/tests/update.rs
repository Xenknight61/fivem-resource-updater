use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'merge.lua',\n  'take.lua',\n}\n";

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
        writer.start_file(*name, options).expect("zip entry");
        writer.write_all(contents).expect("zip bytes");
    }
    writer.finish().expect("finish zip");
}

fn snapshot_regular_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries: Vec<_> = fs::read_dir(current)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("snapshot entry"))
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().expect("snapshot file type");
            if file_type.is_dir() {
                visit(root, &path, snapshot);
            } else if file_type.is_file() {
                snapshot.insert(
                    path.strip_prefix(root)
                        .expect("snapshot relative path")
                        .to_owned(),
                    fs::read(path).expect("snapshot bytes"),
                );
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

struct CliLifecycleFixture {
    _temp: tempfile::TempDir,
    baseline_store: PathBuf,
    staging_root: PathBuf,
    transaction_root: PathBuf,
    artifact_root: PathBuf,
    installed_root: PathBuf,
    package: PathBuf,
    decisions: PathBuf,
    baseline_id: String,
}

fn cli_lifecycle_fixture() -> CliLifecycleFixture {
    use gkrm_core::{
        build_decision_document, capture_official_baseline_in_standalone_store,
        create_three_way_update_plan, inspect_installation_update, resolve_official_baseline,
        BaselineCaptureOptions, BaselineCaptureRequest, BaselineResolutionOptions,
        BaselineResolutionRequest, IncomingOfficialResourceSnapshot, IncomingResourceSelector,
        InstalledResourceRoot, InstalledResourceSnapshot, OfficialBaselineSelector,
        PolicyTransitionAcknowledgement, SafeResourceKey, ThreeWayPlanDecisionChoice,
        ThreeWayPlannerOptions, ThreeWayUpdatePlanRequest, TrustedCliDecisionEntry,
        TrustedCliUpdateOptions, ZipRelativePath, ZipResourceRoot,
    };
    let temp = tempdir().expect("tempdir");
    let capture_root = temp.path().join("capture");
    let installed_root = temp.path().join("installed");
    let installed_resource = installed_root.join("gksphone");
    let baseline_store = temp.path().join("baselines");
    let staging_root = temp.path().join("staging");
    let transaction_root = temp.path().join("transactions");
    let artifact_root = temp.path().join("artifacts");
    let package_v1 = temp.path().join("v1.zip");
    let package = temp.path().join("v2.zip");
    let decisions = temp.path().join("decisions").join("t1.bin");
    fs::create_dir(&capture_root).expect("capture root");
    fs::create_dir(&baseline_store).expect("baseline store");
    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/merge.lua", b"L1\nL2\nL3\nL4\n"),
            ("gksphone/take.lua", b"take-base\n"),
        ],
    );
    let capture = capture_official_baseline_in_standalone_store(
        &gkrm_core::resolve_standalone_baseline_store(&baseline_store).expect("store"),
        BaselineCaptureRequest::try_new(
            &capture_root,
            &baseline_store,
            &package_v1,
            SafeResourceKey::parse("gksphone").expect("key"),
            IncomingResourceSelector::AutoSingle,
            BaselineCaptureOptions::default(),
        )
        .expect("capture request"),
    )
    .expect("capture");
    let baseline_id = capture.baseline_id().clone();
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &baseline_store,
            &SafeResourceKey::parse("gksphone").expect("key"),
            OfficialBaselineSelector::Exact(baseline_id.clone()),
            BaselineResolutionOptions::default(),
        )
        .expect("baseline request"),
    )
    .expect("baseline");
    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("merge.lua"), b"L1x\nL2\nL3\nL4\n");
    write_file(&installed_resource.join("take.lua"), b"take-installed\n");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/merge.lua", b"L1\nL2\nL3\nL4y\n"),
            ("gksphone/take.lua", b"take-incoming\n"),
        ],
    );
    let inspection = inspect_installation_update(
        &installed_root,
        &package,
        gkrm_core::InspectionOptions::default(),
    )
    .expect("inspection");
    let key = SafeResourceKey::parse("gksphone").expect("key");
    let installed = InstalledResourceSnapshot::try_from_inspection(
        &inspection,
        &InstalledResourceRoot::Path(
            gkrm_core::InstallationRelativePath::from_path(Path::new("gksphone"))
                .expect("installed relative path"),
        ),
        &key,
    )
    .expect("installed snapshot");
    let incoming = IncomingOfficialResourceSnapshot::try_from_inspection(
        &inspection,
        &ZipResourceRoot::Path(ZipRelativePath::parse_canonical("gksphone").expect("zip root")),
        &key,
    )
    .expect("incoming snapshot");
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed,
            &incoming,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan request"),
    )
    .expect("plan");
    let entries = plan
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
        .collect();
    let document = build_decision_document(&plan, entries, &TrustedCliUpdateOptions::default())
        .expect("decisions");
    write_file(&decisions, document.canonical_bytes());
    CliLifecycleFixture {
        _temp: temp,
        baseline_store,
        staging_root,
        transaction_root,
        artifact_root,
        installed_root,
        package,
        decisions,
        baseline_id: baseline_id.to_string(),
    }
}

fn write_current_decisions(fixture: &CliLifecycleFixture, path: &Path) {
    use gkrm_core::{
        build_decision_document, create_three_way_update_plan, inspect_installation_update,
        resolve_official_baseline, review_three_way_update_plan, BaselineId,
        BaselineResolutionOptions, BaselineResolutionRequest, IncomingOfficialResourceSnapshot,
        InstalledResourceRoot, InstalledResourceSnapshot, OfficialBaselineSelector,
        PolicyTransitionAcknowledgement, SafeResourceKey, ThreeWayPlanDecisionChoice,
        ThreeWayPlanReviewRequest, ThreeWayPlannerOptions, ThreeWayReviewedAction,
        ThreeWayUpdatePlanRequest, TrustedCliDecisionEntry, TrustedCliUpdateOptions,
        ZipRelativePath, ZipResourceRoot,
    };

    let key = SafeResourceKey::parse("gksphone").expect("key");
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &fixture.baseline_store,
            &key,
            OfficialBaselineSelector::Exact(
                BaselineId::parse(&fixture.baseline_id).expect("baseline identifier"),
            ),
            BaselineResolutionOptions::default(),
        )
        .expect("baseline request"),
    )
    .expect("baseline");
    let inspection = inspect_installation_update(
        &fixture.installed_root,
        &fixture.package,
        gkrm_core::InspectionOptions::default(),
    )
    .expect("inspection");
    let installed = InstalledResourceSnapshot::try_from_inspection(
        &inspection,
        &InstalledResourceRoot::Path(
            gkrm_core::InstallationRelativePath::from_path(Path::new("gksphone"))
                .expect("installed relative path"),
        ),
        &key,
    )
    .expect("installed snapshot");
    let incoming = IncomingOfficialResourceSnapshot::try_from_inspection(
        &inspection,
        &ZipResourceRoot::Path(ZipRelativePath::parse_canonical("gksphone").expect("zip root")),
        &key,
    )
    .expect("incoming snapshot");
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed,
            &incoming,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan request"),
    )
    .expect("plan");
    let empty = build_decision_document(&plan, Vec::new(), &TrustedCliUpdateOptions::default())
        .expect("empty decisions");
    let empty_set = empty.to_decision_set().expect("empty decision set");
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &empty_set).expect("review request"),
    )
    .expect("review");
    let entries = plan
        .entries()
        .iter()
        .filter(|entry| {
            review.entries().iter().any(|reviewed| {
                reviewed.path() == entry.path()
                    && reviewed.action() == ThreeWayReviewedAction::Pending
            })
        })
        .filter_map(|entry| match entry.path().as_str() {
            "merge.lua" => Some(TrustedCliDecisionEntry {
                path: entry.path().clone(),
                choice: ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                policy_acknowledgement: PolicyTransitionAcknowledgement::NotProvided,
                operator_merge_relpath: None,
            }),
            "take.lua" => Some(TrustedCliDecisionEntry {
                path: entry.path().clone(),
                choice: ThreeWayPlanDecisionChoice::UseIncomingState,
                policy_acknowledgement: PolicyTransitionAcknowledgement::NotProvided,
                operator_merge_relpath: None,
            }),
            _ => None,
        })
        .collect();
    let document = build_decision_document(&plan, entries, &TrustedCliUpdateOptions::default())
        .expect("current decisions");
    write_file(path, document.canonical_bytes());
}

fn gkrm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gkrm"))
}

fn run(args: &[&str]) -> Output {
    Command::new(gkrm())
        .args(args)
        .output()
        .expect("gkrm should run")
}

#[test]
fn status_json_on_empty_transaction_root_succeeds() {
    let temp = tempdir().expect("temp dir");
    let txn = temp.path().join("txn-empty");
    fs::create_dir_all(&txn).expect("create txn dir");

    let output = run(&[
        "update",
        "status",
        "--transaction-root",
        txn.to_str().expect("utf-8 path"),
        "--format",
        "json",
    ]);

    assert!(output.status.success(), "stderr={}", stderr(&output));
    assert!(output.stderr.is_empty());

    let json: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["outcome"], "status");
}

#[test]
fn update_plan_without_required_args_exits_usage() {
    let output = run(&["update", "plan"]);

    assert_eq!(output.status.code(), Some(20));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn status_json_redacts_absolute_windows_paths() {
    let temp = tempdir().expect("temp dir");
    let txn = temp.path().join("txn-redact");
    fs::create_dir_all(&txn).expect("create txn dir");

    let output = run(&[
        "update",
        "status",
        "--transaction-root",
        txn.to_str().expect("utf-8 path"),
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(!stdout.contains("C:\\"));
    assert!(!stdout.contains("C:/"));
    assert!(!stdout.contains(temp.path().to_str().expect("temp path")));
}

#[test]
fn exit_code_mapping_smoke_for_status_and_usage() {
    let temp = tempdir().expect("temp dir");
    let txn = temp.path().join("txn-exit");
    fs::create_dir_all(&txn).expect("create txn dir");

    let status = run(&[
        "update",
        "status",
        "--transaction-root",
        txn.to_str().expect("utf-8 path"),
        "--format",
        "json",
    ]);
    assert_eq!(status.status.code(), Some(0));

    let usage = run(&["update", "apply"]);
    assert_eq!(usage.status.code(), Some(20));
}

#[test]
fn exit_for_outcome_stable_codes() {
    use gkrm_cli::{
        exit_for_outcome, EXIT_INTERNAL, EXIT_MANUAL, EXIT_PENDING, EXIT_RECOVERY,
        EXIT_ROLLED_BACK, EXIT_SUCCESS,
    };
    assert_eq!(exit_for_outcome("committed"), EXIT_SUCCESS);
    assert_eq!(exit_for_outcome("ready_to_apply"), EXIT_SUCCESS);
    assert_eq!(exit_for_outcome("status"), EXIT_SUCCESS);
    assert_eq!(exit_for_outcome("safe_restart"), EXIT_SUCCESS);
    assert_eq!(exit_for_outcome("recovered_committed"), EXIT_SUCCESS);
    assert_eq!(exit_for_outcome("recovered_rolled_back"), EXIT_SUCCESS);
    assert_eq!(exit_for_outcome("pending_decisions"), EXIT_PENDING);
    assert_eq!(exit_for_outcome("manual_merge_required"), EXIT_MANUAL);
    assert_eq!(exit_for_outcome("rolled_back"), EXIT_ROLLED_BACK);
    assert_eq!(exit_for_outcome("recovery_required"), EXIT_RECOVERY);
    assert_eq!(exit_for_outcome("recovery_still_required"), EXIT_RECOVERY);
    assert_eq!(
        exit_for_outcome("published_recovery_unsealed"),
        EXIT_RECOVERY
    );
    assert_eq!(exit_for_outcome("published_recovery_failed"), EXIT_RECOVERY);
    assert_eq!(
        exit_for_outcome("safe_failure_before_publication"),
        EXIT_INTERNAL
    );
}

#[test]
fn map_update_error_stable_codes() {
    use gkrm_cli::{
        map_update_error, EXIT_INVALID, EXIT_LOCK, EXIT_REBIND, EXIT_RECOVERY, EXIT_SECURITY,
    };
    use gkrm_core::GkrmError;
    assert_eq!(
        map_update_error(GkrmError::TrustedCliUpdateResourceSelectionRequired).exit_code(),
        EXIT_INVALID
    );
    assert_eq!(
        map_update_error(GkrmError::TrustedCliUpdateBindingMismatch).exit_code(),
        EXIT_REBIND
    );
    assert_eq!(
        map_update_error(GkrmError::TrustedTransactionalApplyExecutionLockContention).exit_code(),
        EXIT_LOCK
    );
    assert_eq!(
        map_update_error(GkrmError::TrustedCliUpdateSecurityRejection).exit_code(),
        EXIT_SECURITY
    );
    assert_eq!(
        map_update_error(GkrmError::TrustedCliUpdateRecoveryRequired).exit_code(),
        EXIT_RECOVERY
    );
    assert_eq!(
        map_update_error(
            GkrmError::TrustedTransactionalApplyExecutionFailedCompound {
                primary: Box::new(GkrmError::TrustedTransactionalApplyExecutionForwardFailed),
                rollback: Box::new(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed),
                journal: Box::new(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid),
                cleanup: Box::new(GkrmError::TrustedTransactionalApplyExecutionRecoveryRequired),
            }
        )
        .exit_code(),
        EXIT_RECOVERY
    );
}

#[test]
fn invalid_subcommand_exits_usage() {
    let output = run(&["update", "nope"]);
    assert_eq!(output.status.code(), Some(20));
}

#[test]
fn help_exits_zero() {
    let output = run(&["update", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf-8 help");
    assert!(stdout.contains("finalize"));
}

#[test]
fn finalize_requires_complete_managed_workspace_authority() {
    let output = run(&["update", "finalize"]);
    assert_eq!(output.status.code(), Some(20));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn finalize_empty_workspace_is_private_deterministic_noop() {
    let temp = tempdir().expect("temp dir");
    let workspace = gkrm_core::resolve_trusted_update_workspace(temp.path())
        .expect("initialize managed workspace");
    let output = run(&[
        "update",
        "finalize",
        "--baseline-store",
        workspace.baseline_store().to_str().expect("baseline path"),
        "--staging-root",
        workspace.staging_root().to_str().expect("staging path"),
        "--transaction-root",
        workspace
            .transaction_root()
            .to_str()
            .expect("transaction path"),
        "--artifact-root",
        workspace
            .artifact_root()
            .path()
            .to_str()
            .expect("artifact path"),
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "stderr={}", stderr(&output));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(!stdout.contains(temp.path().to_str().expect("temp path")));
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["outcome"], "nothing_to_finalize");
    assert_eq!(json["finalized_terminal_evidence"], 0);
    assert_eq!(json["already_finalized_terminal_evidence"], 0);
    assert!(json.get("blocking_terminal_evidence_remains").is_none());
}

#[test]
fn managed_cli_authority_rejects_alternate_siblings_partial_substitution_and_weak_markers() {
    let temp = tempdir().expect("temp dir");
    let workspace = gkrm_core::resolve_trusted_update_workspace(temp.path())
        .expect("initialize managed workspace");
    let exact = [
        workspace.baseline_store().to_path_buf(),
        workspace.staging_root().to_path_buf(),
        workspace.transaction_root().to_path_buf(),
        workspace.artifact_root().path().to_path_buf(),
    ];
    drop(workspace);
    let alternate = [
        temp.path().join("baselines-2"),
        temp.path().join("staging-2"),
        temp.path().join("transactions-2"),
        temp.path().join("artifacts-2"),
    ];
    for root in &alternate {
        fs::create_dir(root).expect("alternate sibling");
    }

    for roots in [
        [&alternate[0], &alternate[1], &alternate[2], &alternate[3]],
        [&exact[0], &exact[1], &alternate[2], &exact[3]],
        [&exact[0], &exact[1], &exact[2], &alternate[3]],
    ] {
        for subcommand in ["status", "finalize"] {
            let output = run(&[
                "update",
                subcommand,
                "--baseline-store",
                roots[0].to_str().expect("baseline"),
                "--staging-root",
                roots[1].to_str().expect("staging"),
                "--transaction-root",
                roots[2].to_str().expect("transactions"),
                "--artifact-root",
                roots[3].to_str().expect("artifacts"),
                "--format",
                "json",
            ]);
            assert_eq!(output.status.code(), Some(23), "stderr={}", stderr(&output));
            assert!(output.stdout.is_empty());
            let error = stderr(&output);
            assert!(error.contains("security_rejection"));
            assert!(!error.contains(temp.path().to_str().expect("temp path")));
        }
    }

    let weak = tempdir().expect("weak marker temp");
    for name in ["baselines", "staging", "transactions", "artifacts"] {
        fs::create_dir(weak.path().join(name)).expect("weak root");
    }
    fs::write(
        weak.path().join(".gkrm-trusted-update-workspace"),
        b"gkrm-trusted-update-workspace-v1\n",
    )
    .expect("weak marker");
    for subcommand in ["status", "finalize"] {
        let weak_output = run(&[
            "update",
            subcommand,
            "--baseline-store",
            weak.path().join("baselines").to_str().expect("baseline"),
            "--staging-root",
            weak.path().join("staging").to_str().expect("staging"),
            "--transaction-root",
            weak.path()
                .join("transactions")
                .to_str()
                .expect("transactions"),
            "--artifact-root",
            weak.path().join("artifacts").to_str().expect("artifacts"),
            "--format",
            "json",
        ]);
        // Same withheld authority and same exit code as any other security rejection, but
        // named distinctly so the operator can tell a recognized pre-release layout apart
        // from damaged evidence.
        assert_eq!(weak_output.status.code(), Some(23));
        assert!(weak_output.stdout.is_empty());
        let error = stderr(&weak_output);
        assert!(error.contains("legacy_workspace_unsupported"), "{error}");
        assert!(!error.contains(weak.path().to_str().expect("weak path")));
    }
    assert_eq!(
        fs::read(weak.path().join(".gkrm-trusted-update-workspace")).unwrap(),
        b"gkrm-trusted-update-workspace-v1\n"
    );
}

#[test]
fn status_rejects_partial_managed_workspace_authority() {
    let temp = tempdir().expect("temp dir");
    let txn = temp.path().join("txn");
    let baseline = temp.path().join("baseline");
    fs::create_dir(&txn).expect("txn");
    fs::create_dir(&baseline).expect("baseline");
    let output = run(&[
        "update",
        "status",
        "--transaction-root",
        txn.to_str().expect("txn path"),
        "--baseline-store",
        baseline.to_str().expect("baseline path"),
    ]);
    assert_eq!(output.status.code(), Some(20));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("invalid_workspace_roots"));
}

#[test]
fn supported_cli_apply_finalize_and_successor_plan_use_managed_authority() {
    let fixture = cli_lifecycle_fixture();
    let artifact_t1 = fixture.artifact_root.join("plan-t1.bin");
    let artifact_t2 = fixture.artifact_root.join("plan-t2.bin");
    let artifact_t3 = fixture.artifact_root.join("plan-t3.bin");
    let decisions_t2 = fixture._temp.path().join("decisions").join("t2.bin");
    let baseline = fixture.baseline_store.to_str().expect("baseline");
    let staging = fixture.staging_root.to_str().expect("staging");
    let transactions = fixture.transaction_root.to_str().expect("transactions");
    let artifacts = fixture.artifact_root.to_str().expect("artifacts");
    let installed = fixture.installed_root.to_str().expect("installed");
    let package = fixture.package.to_str().expect("package");
    let decisions = fixture.decisions.to_str().expect("decisions");
    let t1 = artifact_t1.to_str().expect("T1 artifact");
    let t2 = artifact_t2.to_str().expect("T2 artifact");
    let t3 = artifact_t3.to_str().expect("T3 artifact");

    let plan_t1 = run(&[
        "update",
        "plan",
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--decisions",
        decisions,
        "--artifact-out",
        t1,
        "--format",
        "json",
    ]);
    assert!(plan_t1.status.success(), "stderr={}", stderr(&plan_t1));

    let apply_t1 = run(&[
        "update",
        "apply",
        "--artifact",
        t1,
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--decisions",
        decisions,
        "--format",
        "json",
    ]);
    assert!(apply_t1.status.success(), "stderr={}", stderr(&apply_t1));
    let transaction_catalog = fixture.transaction_root.join("transactions");
    let t1_transaction = fs::read_dir(&transaction_catalog)
        .expect("transaction catalog")
        .next()
        .expect("T1 transaction")
        .expect("T1 entry")
        .path();
    let t1_transaction_before = snapshot_regular_files(&t1_transaction);
    let t1_artifact_before = fs::read(&artifact_t1).expect("T1 artifact bytes");

    let blocked_t2 = run(&[
        "update",
        "plan",
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--artifact-out",
        t2,
        "--format",
        "json",
    ]);
    assert_eq!(blocked_t2.status.code(), Some(13));

    let finalize = run(&[
        "update",
        "finalize",
        "--baseline-store",
        baseline,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--artifact-root",
        artifacts,
        "--format",
        "json",
    ]);
    assert!(finalize.status.success(), "stderr={}", stderr(&finalize));
    let final_json: Value = serde_json::from_slice(&finalize.stdout).expect("finalize json");
    assert_eq!(final_json["finalized_terminal_evidence"], 1);
    assert_eq!(final_json["already_finalized_terminal_evidence"], 0);
    let output = String::from_utf8(finalize.stdout).expect("finalize output");
    assert!(!output.contains(transactions));
    assert!(!output.contains(artifacts));
    let retirement_catalog = fixture.transaction_root.join("terminal-retirements");
    let t1_retirement = fs::read_dir(&retirement_catalog)
        .expect("retirement catalog")
        .next()
        .expect("T1 retirement")
        .expect("T1 retirement entry")
        .path();
    let t1_retirement_before = snapshot_regular_files(&t1_retirement);

    let status = run(&[
        "update",
        "status",
        "--baseline-store",
        baseline,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--artifact-root",
        artifacts,
        "--format",
        "json",
    ]);
    assert!(status.status.success(), "stderr={}", stderr(&status));
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(status_json["bound_candidates"], 0);
    assert_eq!(status_json["candidate_selectors"], serde_json::json!([]));

    let successor = run(&[
        "update",
        "plan",
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--artifact-out",
        t2,
        "--format",
        "json",
    ]);
    assert_eq!(
        successor.status.code(),
        Some(10),
        "stderr={}",
        stderr(&successor)
    );

    write_current_decisions(&fixture, &decisions_t2);
    let decisions_t2_arg = decisions_t2.to_str().expect("T2 decisions");
    let ready_t2 = run(&[
        "update",
        "plan",
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--decisions",
        decisions_t2_arg,
        "--artifact-out",
        t2,
        "--format",
        "json",
    ]);
    assert!(ready_t2.status.success(), "stderr={}", stderr(&ready_t2));

    let apply_t2 = run(&[
        "update",
        "apply",
        "--artifact",
        t2,
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--decisions",
        decisions_t2_arg,
        "--format",
        "json",
    ]);
    assert!(apply_t2.status.success(), "stderr={}", stderr(&apply_t2));

    let blocked_t3 = run(&[
        "update",
        "plan",
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--artifact-out",
        t3,
        "--format",
        "json",
    ]);
    assert_eq!(blocked_t3.status.code(), Some(13));

    let finalize_t2 = run(&[
        "update",
        "finalize",
        "--baseline-store",
        baseline,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--artifact-root",
        artifacts,
        "--format",
        "json",
    ]);
    assert!(
        finalize_t2.status.success(),
        "stderr={}",
        stderr(&finalize_t2)
    );
    let final_t2_json: Value =
        serde_json::from_slice(&finalize_t2.stdout).expect("T2 finalize json");
    assert_eq!(final_t2_json["finalized_terminal_evidence"], 1);
    assert_eq!(final_t2_json["already_finalized_terminal_evidence"], 1);

    let successor_t3 = run(&[
        "update",
        "plan",
        "--package",
        package,
        "--installed",
        installed,
        "--baseline-store",
        baseline,
        "--baseline-id",
        &fixture.baseline_id,
        "--staging-root",
        staging,
        "--transaction-root",
        transactions,
        "--artifact-out",
        t3,
        "--format",
        "json",
    ]);
    assert_eq!(
        successor_t3.status.code(),
        Some(10),
        "stderr={}",
        stderr(&successor_t3)
    );
    assert_eq!(
        snapshot_regular_files(&t1_transaction),
        t1_transaction_before
    );
    assert_eq!(
        fs::read(&artifact_t1).expect("T1 artifact retained"),
        t1_artifact_before
    );
    assert_eq!(snapshot_regular_files(&t1_retirement), t1_retirement_before);
    assert_eq!(
        fs::read_dir(&retirement_catalog)
            .expect("retirement catalog retained")
            .count(),
        2
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
