//! Updating several resources from a folder of packages.

use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    apply_batch, plan_batch, resolve_trusted_update_workspace, BatchApplyResult, BatchEntryOutcome,
    TrustedUpdateWorkspace,
};
use tempfile::{tempdir, TempDir};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST_V1: &[u8] = b"fx_version 'cerulean'\nversion '1.0.0'\nescrow_ignore { 'config.lua' }\nclient_script 'client.lua'\n";
const MANIFEST_V2: &[u8] = b"fx_version 'cerulean'\nversion '2.0.0'\nescrow_ignore { 'config.lua' }\nclient_script 'client.lua'\n";

fn write_file(path: &Path, contents: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
    std::fs::write(path, contents).expect("write");
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).expect("zip");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, contents) in entries {
        writer.start_file(*name, options).expect("entry");
        writer.write_all(contents).expect("bytes");
    }
    writer.finish().expect("finish");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read")
}

struct Setup {
    _temp: TempDir,
    installed: PathBuf,
    packages: Vec<PathBuf>,
    workspace: TrustedUpdateWorkspace,
}

/// Three installed resources and a folder of packages:
///
/// * `alpha` — the developer changed a protected file; the operator's config is untouched.
/// * `beta` — the operator edited `config.lua` and so did the developer.
/// * `delta` — has no package at all.
///
/// plus a package for `gamma`, which is not installed.
fn setup() -> Setup {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("resources");
    write_file(&installed.join("alpha/fxmanifest.lua"), MANIFEST_V1);
    write_file(&installed.join("alpha/client.lua"), b"alpha v1");
    write_file(&installed.join("alpha/config.lua"), b"Config.Mine = true\n");
    write_file(&installed.join("beta/fxmanifest.lua"), MANIFEST_V1);
    write_file(&installed.join("beta/client.lua"), b"beta v1");
    write_file(&installed.join("beta/config.lua"), b"Config.Mine = true\n");
    write_file(&installed.join("delta/fxmanifest.lua"), MANIFEST_V1);
    write_file(&installed.join("delta/client.lua"), b"delta v1");
    write_file(&installed.join("delta/config.lua"), b"x\n");

    let packages_dir = temp.path().join("packages");
    std::fs::create_dir_all(&packages_dir).expect("packages");
    let alpha = packages_dir.join("alpha.zip");
    write_zip(
        &alpha,
        &[
            ("alpha/fxmanifest.lua", MANIFEST_V2),
            ("alpha/client.lua", b"alpha v2"),
            ("alpha/config.lua", b"Config.Mine = true\n"),
        ],
    );
    let beta = packages_dir.join("beta.zip");
    write_zip(
        &beta,
        &[
            ("beta/fxmanifest.lua", MANIFEST_V2),
            ("beta/client.lua", b"beta v2"),
            ("beta/config.lua", b"Config.Theirs = true\n"),
        ],
    );
    let gamma = packages_dir.join("gamma.zip");
    write_zip(
        &gamma,
        &[
            ("gamma/fxmanifest.lua", MANIFEST_V2),
            ("gamma/client.lua", b"gamma v2"),
        ],
    );

    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    Setup {
        _temp: temp,
        installed,
        packages: vec![gamma, beta, alpha],
        workspace,
    }
}

fn outcome_for<'a>(
    plan: &'a gkrm_core::BatchPlan,
    resource: &str,
) -> &'a gkrm_core::BatchPlanEntry {
    plan.entries()
        .iter()
        .find(|entry| entry.resource().map(|key| key.as_str()) == Some(resource))
        .unwrap_or_else(|| panic!("no entry for {resource}"))
}

#[test]
fn planning_sorts_each_package_into_what_it_needs_without_writing() {
    let setup = setup();
    let before = read(&setup.installed.join("beta/config.lua"));

    let plan = plan_batch(
        &setup.installed,
        &setup.packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("plan");

    assert_eq!(plan.entries().len(), 3);
    assert_eq!(
        outcome_for(&plan, "alpha").outcome(),
        &BatchEntryOutcome::Ready
    );
    assert_eq!(
        outcome_for(&plan, "beta").outcome(),
        &BatchEntryOutcome::NeedsReview {
            review: 1,
            unmergeable: 0
        }
    );
    assert_eq!(
        outcome_for(&plan, "gamma").outcome(),
        &BatchEntryOutcome::NoInstalledResource
    );
    assert_eq!(plan.ready_count(), 1);

    let alpha = outcome_for(&plan, "alpha");
    assert_eq!(alpha.installed_version(), Some("1.0.0"));
    assert_eq!(alpha.incoming_version(), Some("2.0.0"));

    // Entries come back in package order whatever order they were given in.
    let order: Vec<_> = plan
        .entries()
        .iter()
        .map(|entry| entry.package().file_name().expect("name").to_owned())
        .collect();
    assert_eq!(order, ["alpha.zip", "beta.zip", "gamma.zip"]);

    // Planning wrote nothing.
    assert_eq!(read(&setup.installed.join("alpha/client.lua")), "alpha v1");
    assert_eq!(read(&setup.installed.join("beta/config.lua")), before);
}

#[test]
fn applying_updates_only_what_needs_no_answer_and_leaves_the_rest_untouched() {
    let setup = setup();
    let plan = plan_batch(
        &setup.installed,
        &setup.packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("plan");

    let outcome = apply_batch(&plan, &setup.installed, &setup.workspace);

    assert_eq!(outcome.committed_count(), 1);
    let by_name = |name: &str| {
        outcome
            .results()
            .iter()
            .find(|(path, _)| path.file_name().is_some_and(|n| n == name))
            .map(|(_, result)| result.clone())
            .expect("result")
    };
    assert_eq!(by_name("alpha.zip"), BatchApplyResult::Committed);
    assert_eq!(by_name("beta.zip"), BatchApplyResult::Skipped);
    assert_eq!(by_name("gamma.zip"), BatchApplyResult::Skipped);

    // alpha moved to the developer's version and kept the operator's config.
    assert_eq!(read(&setup.installed.join("alpha/client.lua")), "alpha v2");
    assert_eq!(
        read(&setup.installed.join("alpha/config.lua")),
        "Config.Mine = true\n"
    );
    // beta needed an answer, so nothing of it moved — not even the protected file.
    assert_eq!(read(&setup.installed.join("beta/client.lua")), "beta v1");
    assert_eq!(
        read(&setup.installed.join("beta/config.lua")),
        "Config.Mine = true\n"
    );
    // delta had no package and was never read.
    assert_eq!(read(&setup.installed.join("delta/client.lua")), "delta v1");
}

#[test]
fn an_applied_update_blocks_the_next_one_until_it_is_closed() {
    use gkrm_core::{
        retire_trusted_terminal_update_evidence, TrustedTerminalEvidenceRetirementOptions,
    };

    let setup = setup();
    let plan = plan_batch(
        &setup.installed,
        &setup.packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("plan");
    assert_eq!(
        apply_batch(&plan, &setup.installed, &setup.workspace).committed_count(),
        1
    );

    // The finished update is still on record, and the batch says so by name rather than calling
    // the package unreadable.
    let blocked = plan_batch(
        &setup.installed,
        &setup.packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("blocked");
    assert_eq!(
        outcome_for(&blocked, "alpha").outcome(),
        &BatchEntryOutcome::BlockedByEarlierUpdate
    );
    assert_eq!(blocked.ready_count(), 0);

    // Closing it is the operator's explicit act, and keeps every backup.
    retire_trusted_terminal_update_evidence(
        &setup.workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..Default::default()
        },
    )
    .expect("close");

    let again = plan_batch(
        &setup.installed,
        &setup.packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("again");
    assert_eq!(
        outcome_for(&again, "alpha").outcome(),
        &BatchEntryOutcome::AlreadyUpToDate
    );
    assert_eq!(again.ready_count(), 0);
}

#[test]
fn two_packages_for_one_resource_are_both_refused_rather_than_one_chosen() {
    let setup = setup();
    let duplicate = setup
        .installed
        .parent()
        .expect("temp")
        .join("packages/alpha-again.zip");
    write_zip(
        &duplicate,
        &[
            ("alpha/fxmanifest.lua", MANIFEST_V2),
            ("alpha/client.lua", b"alpha v3"),
            ("alpha/config.lua", b"Config.Mine = true\n"),
        ],
    );
    let mut packages = setup.packages.clone();
    packages.push(duplicate);

    let plan = plan_batch(
        &setup.installed,
        &packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("plan");
    let alphas: Vec<_> = plan
        .entries()
        .iter()
        .filter(|entry| entry.resource().map(|key| key.as_str()) == Some("alpha"))
        .collect();
    assert_eq!(alphas.len(), 2);
    assert!(alphas
        .iter()
        .all(|entry| entry.outcome() == &BatchEntryOutcome::DuplicatePackage));

    let outcome = apply_batch(&plan, &setup.installed, &setup.workspace);
    assert_eq!(outcome.committed_count(), 0);
    assert_eq!(read(&setup.installed.join("alpha/client.lua")), "alpha v1");
}

#[test]
fn a_file_that_is_not_a_package_is_reported_not_fatal() {
    let setup = setup();
    let junk = setup
        .installed
        .parent()
        .expect("temp")
        .join("packages/notes.zip");
    std::fs::write(&junk, b"this is not a zip").expect("junk");
    let mut packages = setup.packages.clone();
    packages.push(junk);

    let plan = plan_batch(
        &setup.installed,
        &packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("plan");
    let junk_entry = plan
        .entries()
        .iter()
        .find(|entry| {
            entry
                .package()
                .file_name()
                .is_some_and(|n| n == "notes.zip")
        })
        .expect("entry");
    assert_eq!(junk_entry.outcome(), &BatchEntryOutcome::Unreadable);
    // The rest of the batch is unaffected.
    assert_eq!(
        outcome_for(&plan, "alpha").outcome(),
        &BatchEntryOutcome::Ready
    );
}

#[test]
fn a_file_changed_after_planning_fails_that_update_and_stops_the_batch() {
    let setup = setup();
    // A second ready resource, so there is something after the failure to not attempt.
    write_file(&setup.installed.join("zeta/fxmanifest.lua"), MANIFEST_V1);
    write_file(&setup.installed.join("zeta/client.lua"), b"zeta v1");
    write_file(&setup.installed.join("zeta/config.lua"), b"z\n");
    let zeta = setup
        .installed
        .parent()
        .expect("temp")
        .join("packages/zeta.zip");
    write_zip(
        &zeta,
        &[
            ("zeta/fxmanifest.lua", MANIFEST_V2),
            ("zeta/client.lua", b"zeta v2"),
            ("zeta/config.lua", b"z\n"),
        ],
    );
    let mut packages = setup.packages.clone();
    packages.push(zeta);

    let plan = plan_batch(
        &setup.installed,
        &packages,
        &setup.workspace,
        &Default::default(),
    )
    .expect("plan");
    assert_eq!(plan.ready_count(), 2);

    // Between planning and applying, alpha's installed file changes under the plan.
    write_file(
        &setup.installed.join("alpha/client.lua"),
        b"edited meanwhile",
    );

    let outcome = apply_batch(&plan, &setup.installed, &setup.workspace);
    let by_name = |name: &str| {
        outcome
            .results()
            .iter()
            .find(|(path, _)| path.file_name().is_some_and(|n| n == name))
            .map(|(_, result)| result.clone())
            .expect("result")
    };
    assert_eq!(by_name("alpha.zip"), BatchApplyResult::Failed);
    assert_eq!(by_name("zeta.zip"), BatchApplyResult::NotAttempted);
    assert_eq!(outcome.committed_count(), 0);
    // The edit made meanwhile is the operator's and is still there; nothing was written over it.
    assert_eq!(
        read(&setup.installed.join("alpha/client.lua")),
        "edited meanwhile"
    );
    assert_eq!(read(&setup.installed.join("zeta/client.lua")), "zeta v1");
}

#[test]
fn two_ready_updates_are_both_written_each_as_its_own_transaction() {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("resources");
    let packages_dir = temp.path().join("packages");
    std::fs::create_dir_all(&packages_dir).expect("packages");
    let mut packages = Vec::new();
    for name in ["alpha", "epsilon"] {
        write_file(
            &installed.join(format!("{name}/fxmanifest.lua")),
            MANIFEST_V1,
        );
        write_file(&installed.join(format!("{name}/client.lua")), b"v1");
        write_file(
            &installed.join(format!("{name}/config.lua")),
            b"Config.Mine = true\n",
        );
        let zip = packages_dir.join(format!("{name}.zip"));
        write_zip(
            &zip,
            &[
                (&format!("{name}/fxmanifest.lua"), MANIFEST_V2),
                (&format!("{name}/client.lua"), b"v2"),
                (&format!("{name}/config.lua"), b"Config.Mine = true\n"),
            ],
        );
        packages.push(zip);
    }
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");

    let plan = plan_batch(&installed, &packages, &workspace, &Default::default()).expect("plan");
    assert_eq!(plan.ready_count(), 2);

    let outcome = apply_batch(&plan, &installed, &workspace);

    assert_eq!(outcome.committed_count(), 2);
    assert_eq!(read(&installed.join("alpha/client.lua")), "v2");
    assert_eq!(read(&installed.join("epsilon/client.lua")), "v2");
    // Both are recorded so each can be put back on its own.
    assert!(outcome.applied(0).is_some() && outcome.applied(1).is_some());
}

#[test]
fn a_file_only_the_operator_changed_stops_being_a_question_once_the_batch_knows_where_it_came_from()
{
    use gkrm_core::{
        apply_two_way_update, retire_trusted_terminal_update_evidence, BaselineId,
        TrustedCliUpdateOptions, TrustedTerminalEvidenceRetirementOptions, TwoWayApplyRequest,
        TwoWayUpdateMode,
    };

    let temp = tempdir().expect("temp");
    let installed = temp.path().join("resources");
    write_file(&installed.join("alpha/fxmanifest.lua"), MANIFEST_V1);
    write_file(&installed.join("alpha/client.lua"), b"v1");
    write_file(&installed.join("alpha/config.lua"), b"Config.Mine = true\n");
    let package = temp.path().join("alpha.zip");
    write_zip(
        &package,
        &[
            ("alpha/fxmanifest.lua", MANIFEST_V2),
            ("alpha/client.lua", b"v2"),
            ("alpha/config.lua", b"Config.Theirs = true\n"),
        ],
    );
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let packages = vec![package.clone()];

    // Nothing says who changed config.lua, so it is a real question.
    let first = plan_batch(&installed, &packages, &workspace, &Default::default()).expect("plan");
    assert_eq!(
        outcome_for(&first, "alpha").outcome(),
        &BatchEntryOutcome::NeedsReview {
            review: 1,
            unmergeable: 0
        }
    );

    // The operator answers it once, keeping their own config, and the package is kept.
    let applied = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        package: &package,
        installed: &installed,
        baseline: None,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    let kept = applied.baseline_id().cloned().expect("kept");
    let _ = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..Default::default()
        },
    );
    // Merged: the operator's own line stays and the developer's arrives beside it.
    assert_eq!(
        read(&installed.join("alpha/config.lua")),
        "Config.Mine = true\nConfig.Theirs = true\n"
    );

    // Without the memory it is asked again, every time.
    let forgotten =
        plan_batch(&installed, &packages, &workspace, &Default::default()).expect("plan");
    assert_eq!(
        outcome_for(&forgotten, "alpha").outcome(),
        &BatchEntryOutcome::NeedsReview {
            review: 1,
            unmergeable: 0
        }
    );

    // With it, the developer has changed nothing since, so the file is the operator's.
    let mut remembered = std::collections::BTreeMap::new();
    remembered.insert("alpha".to_owned(), kept);
    let known = plan_batch(&installed, &packages, &workspace, &remembered).expect("plan");
    assert_eq!(
        outcome_for(&known, "alpha").outcome(),
        &BatchEntryOutcome::AlreadyUpToDate
    );

    // A remembered package that cannot be read costs a question, never a refusal.
    let mut lost = std::collections::BTreeMap::new();
    lost.insert(
        "alpha".to_owned(),
        BaselineId::parse(&"0".repeat(64)).expect("id"),
    );
    let fallback = plan_batch(&installed, &packages, &workspace, &lost).expect("plan");
    assert_eq!(
        outcome_for(&fallback, "alpha").outcome(),
        &BatchEntryOutcome::NeedsReview {
            review: 1,
            unmergeable: 0
        }
    );
}
