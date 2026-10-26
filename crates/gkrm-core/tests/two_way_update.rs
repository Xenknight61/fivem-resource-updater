//! Preview a two-way update against the committed synthetic fixtures.
//!
//! This is the case the product exists for, expressed exactly as a customer meets it: an
//! installation they have edited, a new official package, and nothing else.

use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    apply_two_way_update, preview_two_way_update, TrustedCliUpdateOptions, TwoWayApplyRequest,
    TwoWayBaselineSource, TwoWayFileAction, TwoWayFileChoice, TwoWayLineOrigin, TwoWayUpdateMode,
    TwoWayUpdateRequest,
};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures")
}

fn preview() -> gkrm_core::TwoWayUpdatePreview {
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    preview_two_way_update(TwoWayUpdateRequest {
        baseline: None,
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed: &fixtures().join("installed"),
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview")
}

fn action_for(preview: &gkrm_core::TwoWayUpdatePreview, path: &str) -> TwoWayFileAction {
    preview
        .plan()
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing {path}"))
        .action()
}

/// A pristine v1 installation, copied out of the source the v1 package was built from.
fn pristine_installation(into: &Path) -> PathBuf {
    let root = into.join("installed");
    copy_tree(&fixtures().join("sources").join("gksphone-v1"), &root);
    root
}

fn preview_with_baseline(
    installed: &Path,
    transactions: &Path,
    baseline: Option<&Path>,
) -> gkrm_core::TwoWayUpdatePreview {
    preview_two_way_update(TwoWayUpdateRequest {
        baseline: baseline.map(TwoWayBaselineSource::Package),
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed,
        resource: None,
        transaction_root: transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview")
}

/// A resource whose customisable parts are the kinds escrow cannot encrypt at all.
///
/// The manifest declares nothing escrow-ignored, because there is nothing of the four kinds to
/// declare. Every file here is plain on disk and the operator's to have edited.
fn phone_installation(temp: &Path) -> (PathBuf, PathBuf) {
    // Bytes that are not text, which is all an icon has to be here.
    const MINE_ICON: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, b'm', b'i', b'n', b'e',
    ];
    const THEIR_ICON: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, b't', b'h', b'e',
    ];
    let manifest = |version: &str| {
        format!(
            "fx_version 'cerulean'
game 'gta5'

version '{version}'
"
        )
    };
    let installed = temp.join("resources");
    let resource = installed.join("gksphone");
    std::fs::create_dir_all(resource.join("html").join("img")).expect("tree");
    std::fs::write(resource.join("fxmanifest.lua"), manifest("1.0.0")).expect("manifest");
    std::fs::write(
        resource.join("config.json"),
        b"{
  \"locale\": \"tr\",
  \"apps\": 12
}
",
    )
    .expect("json");
    // What a swapped app icon is: not text, and not something a merge can combine.
    std::fs::write(
        resource.join("html").join("img").join("bank.png"),
        MINE_ICON,
    )
    .expect("icon");

    let package = temp.join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", manifest("2.0.0").as_bytes()),
            (
                "gksphone/config.json",
                b"{
  \"locale\": \"en\",
  \"apps\": 14
}
",
            ),
            ("gksphone/html/img/bank.png", THEIR_ICON),
        ],
    );
    (installed, package)
}

#[test]
fn what_escrow_cannot_encrypt_is_not_replaced_without_asking() {
    // A phone script keeps its settings in JSON and its app icons as PNGs. Escrow encrypts
    // neither, so a customer can and does edit both — and reading "escrow did not declare this"
    // as "the operator cannot have written this" replaced an afternoon's work without a word.
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    let (installed, package) = phone_installation(temp.path());

    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");

    assert_eq!(
        action_for(&preview, "config.json"),
        TwoWayFileAction::Review
    );
    assert_eq!(
        action_for(&preview, "html/img/bank.png"),
        TwoWayFileAction::Review
    );
    // The JSON is text, so it is combined line by line like any other open file. The icon is not,
    // so it is answered whole — named rather than hidden.
    assert!(preview
        .reviewed()
        .iter()
        .any(|file| file.path().as_str() == "config.json"));
    assert_eq!(
        preview
            .unmergeable()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        vec!["html/img/bank.png"]
    );
}

#[test]
fn an_icon_the_operator_swapped_can_be_answered_either_way() {
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    std::fs::create_dir_all(&staging).expect("staging root");
    let (installed, package) = phone_installation(temp.path());
    const MINE_ICON: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, b'm', b'i', b'n', b'e',
    ];
    let icon = installed
        .join("gksphone")
        .join("html")
        .join("img")
        .join("bank.png");

    // Left alone, the whole of theirs stays.
    apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(std::fs::read(&icon).expect("icon"), MINE_ICON);
}

/// A resource whose locale file the developer reindented between releases.
fn locale_installation(temp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let manifest = |version: &str| {
        format!(
            "fx_version 'cerulean'
game 'gta5'

version '{version}'
"
        )
    };
    // Big enough that reindenting it puts the two sides past what a line diff will line up, which
    // is the whole of why keys are needed: a handful of lines is combined line by line perfectly
    // well, and a locale file is two thousand of them.
    const FILLER: usize = 2200;
    let locale = |indent: &str, newline: &str, hello: &str, bye: &str, extra: bool| -> Vec<u8> {
        let mut out = format!("{{{newline}");
        out.push_str(&format!("{indent}\"HELLO\": \"{hello}\",{newline}"));
        out.push_str(&format!("{indent}\"BYE\": \"{bye}\",{newline}"));
        for index in 0..FILLER {
            out.push_str(&format!(
                "{indent}\"FILLER_{index}\": \"text {index}\",{newline}"
            ));
        }
        if extra {
            out.push_str(&format!("{indent}\"NEW\": \"New\",{newline}"));
        }
        out.push_str(&format!("{indent}\"LAST\": \"end\"{newline}}}{newline}"));
        out.into_bytes()
    };
    // Two spaces, LF: what the operator installed.
    let baseline_locale = locale(
        "  ", "
", "Hello", "Bye", false,
    );
    // Four spaces, CRLF, and a string the operator never saw: what the update ships.
    let incoming_locale = locale(
        "    ", "
", "Hello", "Farewell", true,
    );
    // The one string they translated, in the layout they installed.
    let installed_locale = locale(
        "  ", "
", "Merhaba", "Bye", false,
    );

    let installed = temp.join("resources");
    let resource = installed.join("gksphone");
    std::fs::create_dir_all(resource.join("locales")).expect("tree");
    std::fs::write(resource.join("fxmanifest.lua"), manifest("1.0.0")).expect("manifest");
    // The operator translated one of them and left the other alone.
    std::fs::write(resource.join("locales").join("tr.json"), &installed_locale).expect("locale");

    let baseline = temp.join("baseline.zip");
    write_zip(
        &baseline,
        &[
            ("gksphone/fxmanifest.lua", manifest("1.0.0").as_bytes()),
            ("gksphone/locales/tr.json", &baseline_locale),
        ],
    );
    let package = temp.join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", manifest("2.0.0").as_bytes()),
            ("gksphone/locales/tr.json", &incoming_locale),
        ],
    );
    (installed, package, baseline)
}

/// An installation whose one Lua file the operator appended a function to, and whose earlier lines
/// the developer fixed in the meantime.
fn appended_function_installation(temp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let manifest = |version: &str| {
        format!(
            "fx_version 'cerulean'
game 'gta5'

version '{version}'
escrow_ignore {{ 'settings.lua' }}
"
        )
    };
    let base = "local function CountRows()
  local result = MySQL.Sync.fetchScalar('SELECT 1')
  return result
end
";
    // The developer modernised the query. The operator never opened that line.
    let updated = "local function CountRows()
  local result = MySQL.scalar.await('SELECT 1')
  return result
end
";
    // The operator appended a function of their own and changed nothing else.
    let mine = format!(
        "{base}
function OperatorFee(amount)
  return amount * 2
end
"
    );

    let installed = temp.join("resources");
    let resource = installed.join("gksphone");
    std::fs::create_dir_all(&resource).expect("tree");
    std::fs::write(resource.join("fxmanifest.lua"), manifest("1.0.0")).expect("manifest");
    std::fs::write(resource.join("settings.lua"), &mine).expect("settings");

    let baseline = temp.join("baseline.zip");
    write_zip(
        &baseline,
        &[
            ("gksphone/fxmanifest.lua", manifest("1.0.0").as_bytes()),
            ("gksphone/settings.lua", base.as_bytes()),
        ],
    );
    let package = temp.join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", manifest("2.0.0").as_bytes()),
            ("gksphone/settings.lua", updated.as_bytes()),
        ],
    );
    (installed, package, baseline)
}

#[test]
fn the_package_an_update_applied_is_kept_for_the_next_one() {
    // Telling an operator's own edits from the developer's needs the version they installed, and
    // asking them to have kept a ZIP for it is asking most of them for something they no longer
    // have. An update knows the package it applied, and after it runs that package is exactly what
    // the installation corresponds to.
    use gkrm_core::{
        resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let app_data = temp.path().join("appdata");
    std::fs::create_dir_all(&app_data).expect("app data");
    let (installed, package, baseline) = appended_function_installation(temp.path());

    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    let kept = outcome
        .baseline_id()
        .cloned()
        .expect("kept for the next one");

    // Closing the finished update, as the operator does, so the next one may start.
    let _ = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    );

    // And the next comparison needs nothing in hand: it reaches for what was kept.
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id: &kept,
        }),
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");

    // The installation now holds the operator's merge of the file, which is not what the package
    // ships — so it is theirs to answer, and nothing else is.
    assert_eq!(preview.plan().summary().review(), 1);
    assert_eq!(preview.plan().summary().take_from_update(), 0);
    assert_eq!(
        action_for(&preview, "settings.lua"),
        TwoWayFileAction::Review
    );
}

#[test]
fn the_package_an_update_was_told_it_came_from_is_kept_too() {
    // An update that finishes can be undone, and undoing puts the installation back to what it
    // was — including what it was installed from. The operator handed that over as a ZIP; keeping
    // it means an undo does not leave them worse off than before they ran the update, asked for a
    // ZIP the app was already holding.
    use gkrm_core::{
        resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let app_data = temp.path().join("appdata");
    std::fs::create_dir_all(&app_data).expect("app data");

    // The same installation twice: one to update, and one left as it was so the kept baseline can
    // be held against the ZIP it was taken from.
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    std::fs::create_dir_all(&first).expect("first");
    std::fs::create_dir_all(&second).expect("second");
    let (installed, package, baseline) = appended_function_installation(&first);
    let (untouched, package_again, baseline_again) = appended_function_installation(&second);
    let original_tree = undo_hash_tree(&installed.join("gksphone"));

    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");

    let was_installed_from = outcome
        .previous_baseline_id()
        .cloned()
        .expect("kept for an undo");
    // The two are different packages and must not be confused: one is what the installation is
    // now, the other what it was.
    assert_ne!(Some(&was_installed_from), outcome.baseline_id());

    // Closing the finished update, as the operator does, so the next comparison may start.
    let _ = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    );

    // What was kept has to answer the same questions the ZIP did, or putting it back would be
    // putting back something weaker than the operator gave.
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let from_the_zip = preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Package(&baseline_again)),
        package: &package_again,
        installed: &untouched,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview from the zip");
    let from_the_store = preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id: &was_installed_from,
        }),
        package: &package_again,
        installed: &untouched,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview from what was kept");

    assert_eq!(
        from_the_store.plan().summary(),
        from_the_zip.plan().summary()
    );
    assert_eq!(
        action_for(&from_the_store, "settings.lua"),
        action_for(&from_the_zip, "settings.lua")
    );
    // And it is the operator's own line that is being asked about, not everything.
    assert_eq!(from_the_store.plan().summary().review(), 1);
    // Neither a retired parent nor missing caller-owned ZIPs releases this
    // transition. Reopen its core evidence and restore metadata from that alone.
    let key = gkrm_core::SafeResourceKey::parse("gksphone").unwrap();
    let references = gkrm_core::referenced_trusted_baselines(&workspace).unwrap();
    for id in [
        was_installed_from.clone(),
        outcome.baseline_id().unwrap().clone(),
    ] {
        assert!(references.contains(&id));
        assert!(!gkrm_core::discard_unreferenced_trusted_baseline(&workspace, &key, &id).unwrap());
    }
    std::fs::remove_file(package).unwrap();
    std::fs::remove_file(baseline).unwrap();
    let selection = undo_selection(&installed);
    let source = gkrm_core::TrustedUndoSource::try_open(
        &workspace,
        &selection,
        outcome.transaction_id().unwrap(),
    )
    .unwrap();
    let previous = source.previous_baseline().unwrap().unwrap();
    assert_eq!(previous.baseline_id(), &was_installed_from);
    let plan = source.plan(&selection).unwrap();
    let result = source.execute(&selection, &plan).unwrap();
    assert!(matches!(
        result.result(),
        Some(gkrm_core::TrustedTransactionResult::Committed(_))
    ));
    assert_eq!(undo_hash_tree(&installed.join("gksphone")), original_tree);
}

#[test]
fn failed_baseline_capture_never_changes_the_installation_or_publishes_a_transaction() {
    use gkrm_core::*;
    let temp = tempdir().unwrap();
    let (installed, package, baseline) = appended_function_installation(temp.path());
    let appdata = temp.path().join("appdata");
    std::fs::create_dir(&appdata).unwrap();
    let workspace = resolve_trusted_update_workspace(&appdata).unwrap();
    // A file occupies the required inventory directory: capture cannot publish.
    std::fs::write(workspace.baseline_store().join("baselines"), b"sentinel").unwrap();
    let before = undo_hash_tree(&installed.join("gksphone"));
    assert!(apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .is_err());
    assert_eq!(undo_hash_tree(&installed.join("gksphone")), before);
    assert_eq!(
        std::fs::read_dir(workspace.artifact_root().path())
            .unwrap()
            .count(),
        0
    );
    assert!(scan_trusted_transactions(
        &TrustedTransactionRoot::try_open_in_workspace(&workspace).unwrap(),
        TrustedRecoveryScanOptions::default()
    )
    .unwrap()
    .candidates()
    .is_empty());
}

#[test]
fn external_stored_baseline_is_retained_by_identity_before_apply_and_tamper_blocks_undo() {
    use gkrm_core::*;
    let temp = tempdir().unwrap();
    let (installed, package, baseline) = appended_function_installation(temp.path());
    let standalone = resolve_standalone_baseline_store(&temp.path().join("standalone")).unwrap();
    let key = SafeResourceKey::parse("gksphone").unwrap();
    let captured = capture_official_baseline_in_standalone_store(
        &standalone,
        BaselineCaptureRequest::try_new(
            &installed,
            standalone.root(),
            &baseline,
            key.clone(),
            IncomingResourceSelector::ManifestPackagePath(
                ZipRelativePath::parse_canonical("gksphone/fxmanifest.lua").unwrap(),
            ),
            BaselineCaptureOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    let prior_id = captured.baseline_id().clone();
    let appdata = temp.path().join("appdata");
    std::fs::create_dir(&appdata).unwrap();
    let workspace = resolve_trusted_update_workspace(&appdata).unwrap();
    let applied = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Stored {
            store_root: standalone.root(),
            baseline_id: &prior_id,
        }),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(applied.previous_baseline_id(), Some(&prior_id));
    // Delete exactly the explicitly-created synthetic external store; the
    // managed store must remain sufficient after both external inputs disappear.
    assert!(discard_baseline_bundle(standalone.root(), &key, &prior_id).unwrap());
    std::fs::remove_file(baseline).unwrap();
    std::fs::remove_file(package).unwrap();
    let selection = undo_selection(&installed);
    let source =
        TrustedUndoSource::try_open(&workspace, &selection, applied.transaction_id().unwrap())
            .unwrap();
    let retained = source.previous_baseline().unwrap().unwrap();
    assert_eq!(retained.baseline_id(), &prior_id);
    for file in retained.files() {
        if let Some(blob) = file.blob_sha256() {
            retained
                .read_verified_blob(blob, &BaselineStoreLimits::default())
                .unwrap();
        }
    }
    let plan = source.plan(&selection).unwrap();
    let before = undo_hash_tree(&installed.join("gksphone"));
    std::fs::write(
        workspace
            .baseline_store()
            .join("baselines/gksphone")
            .join(prior_id.as_str())
            .join("baseline.json"),
        b"corrupted",
    )
    .unwrap();
    assert!(source.previous_baseline().is_err());
    assert!(source.execute(&selection, &plan).is_err());
    assert_eq!(undo_hash_tree(&installed.join("gksphone")), before);
}

#[test]
fn a_second_update_hands_back_the_baseline_the_first_one_left() {
    // Update, update again, then undo the second: the installation is back to what the first one
    // left, and so is what this knows it was installed from. Nothing needs capturing here — the
    // first update already kept that package — but it does need handing back.
    use gkrm_core::{
        resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let app_data = temp.path().join("appdata");
    std::fs::create_dir_all(&app_data).expect("app data");
    let (installed, package, baseline) = appended_function_installation(temp.path());

    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let first = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("first apply");
    let left_by_the_first = first.baseline_id().cloned().expect("kept for the next one");

    let _ = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    );

    // A further release, so the second update is real work rather than a no-op.
    let later = temp.path().join("later.zip");
    write_zip(
        &later,
        &[
            (
                "gksphone/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n\nversion '3.0.0'\nescrow_ignore { 'settings.lua' }\n"
                    .as_slice(),
            ),
            (
                "gksphone/settings.lua",
                b"local function CountRows()\n  local result = MySQL.scalar.await('SELECT 2')\n  return result\nend\n"
                    .as_slice(),
            ),
        ],
    );

    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let second = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        // As the desktop does after the first update: nothing in hand, reaching for what was kept.
        baseline: Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id: &left_by_the_first,
        }),
        package: &later,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::ReplaceWithIncoming,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("second apply");

    assert_eq!(second.outcome(), "committed");
    assert_eq!(second.previous_baseline_id(), Some(&left_by_the_first));
}

#[test]
fn a_staged_copy_nothing_accounts_for_is_let_go_of_and_the_rest_are_not() {
    // Every apply stages the package it is about to write, and that staged copy is what a recovery
    // replays from — so one an authority artifact still names is one somebody may yet need. Nothing
    // ever removed the others, and each is the size of the package it came from, so an operator
    // accumulated one per update they ran, indefinitely, for work that finished long ago.
    use gkrm_core::{
        discard_unaccounted_trusted_staging_bundles, resolve_trusted_update_workspace,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let app_data = temp.path().join("appdata");
    std::fs::create_dir_all(&app_data).expect("app data");
    let (installed, package, baseline) = appended_function_installation(temp.path());

    let acknowledged = || TrustedTerminalEvidenceRetirementOptions {
        acknowledged: true,
        ..TrustedTerminalEvidenceRetirementOptions::default()
    };
    let staged = || {
        let bundles = app_data.join("staging").join("bundles");
        let Ok(entries) = std::fs::read_dir(&bundles) else {
            return 0;
        };
        entries.flatten().count()
    };

    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    let transaction = outcome.transaction_id().copied().expect("on record");
    assert_eq!(staged(), 1);

    // While the update is on record, the staged copy it was applied from is kept: it is what a
    // recovery would replay, and the workspace still accounts for it.
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    assert_eq!(
        discard_unaccounted_trusted_staging_bundles(&workspace, acknowledged()).expect("release"),
        gkrm_core::TrustedStagingReleaseOutcome {
            released: 0,
            kept: 1
        }
    );
    assert_eq!(staged(), 1);

    // Retirement permits a successor update, but does not revoke Undo. Its original
    // committed staging must remain available for exact graph reconstruction.
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    gkrm_core::retire_trusted_terminal_update_evidence(&workspace, acknowledged()).expect("retire");
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let orphan = workspace
        .staging_root()
        .join("bundles/unreferenced-preview");
    std::fs::create_dir(&orphan).expect("unreferenced preview");
    std::fs::write(orphan.join("unused.txt"), b"unused").expect("unused content");
    assert_eq!(
        gkrm_core::unaccounted_trusted_staging_bundles(&workspace, acknowledged()).expect("survey"),
        vec!["unreferenced-preview"]
    );
    assert_eq!(
        discard_unaccounted_trusted_staging_bundles(&workspace, acknowledged()).expect("release"),
        gkrm_core::TrustedStagingReleaseOutcome {
            released: 1,
            kept: 1
        }
    );
    assert_eq!(staged(), 1);
    assert!(!orphan.exists());

    assert!(workspace
        .transaction_root()
        .join("transactions")
        .join(transaction.to_string())
        .join("backup")
        .is_dir());
    gkrm_core::TrustedUndoSource::try_open(&workspace, &undo_selection(&installed), &transaction)
        .expect("original source remains available");
}

#[test]
fn a_baseline_that_was_never_kept_is_simply_not_there() {
    use gkrm_core::{resolve_trusted_update_workspace, BaselineId};

    let temp = tempdir().expect("temp dir");
    let app_data = temp.path().join("appdata");
    std::fs::create_dir_all(&app_data).expect("app data");
    let (installed, package, _) = appended_function_installation(temp.path());
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let stranger = BaselineId::parse(&"a".repeat(64)).expect("id");

    // Refused rather than quietly compared against nothing: a comparison that silently lost its
    // evidence would replace the operator's work while reporting that it had checked.
    assert!(preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id: &stranger,
        }),
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .is_err());
}

#[test]
fn appending_one_function_does_not_forfeit_the_rest_of_the_file() {
    // An operator who adds a function to a file has not adopted every line above it. Preserving
    // local edits used to keep the whole file because the file was theirs, so the developer's own
    // fixes to lines they never opened were dropped on their behalf and silently.
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    std::fs::create_dir_all(&staging).expect("staging root");
    let (installed, package, baseline) = appended_function_installation(temp.path());
    let settings = installed.join("gksphone").join("settings.lua");

    apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");

    let written = std::fs::read_to_string(&settings).expect("settings");
    // Their function is theirs.
    assert!(written.contains("function OperatorFee"), "{written}");
    assert!(written.contains("return amount * 2"), "{written}");
    // And the developer's fix to a line they never touched arrived.
    assert!(written.contains("MySQL.scalar.await"), "{written}");
    assert!(!written.contains("MySQL.Sync.fetchScalar"), "{written}");
}

#[test]
fn a_line_the_operator_did_change_is_still_theirs() {
    // The other half of the same rule. Without it, "take the developer's where they did not touch
    // it" would quietly become "take the developer's".
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    std::fs::create_dir_all(&staging).expect("staging root");
    let (installed, package, baseline) = appended_function_installation(temp.path());
    let settings = installed.join("gksphone").join("settings.lua");

    // They edit the very line the developer also changed.
    let mine = std::fs::read_to_string(&settings)
        .expect("settings")
        .replace(
            "MySQL.Sync.fetchScalar('SELECT 1')",
            "MySQL.Sync.fetchScalar('SELECT 2')",
        );
    std::fs::write(&settings, mine).expect("edit");

    apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");

    let written = std::fs::read_to_string(&settings).expect("settings");
    assert!(written.contains("SELECT 2"), "{written}");
    assert!(written.contains("function OperatorFee"), "{written}");
}

#[test]
fn without_a_baseline_a_file_the_operator_edited_is_theirs_whole() {
    // Two sides cannot tell which lines are the operator's, and guessing in the other direction
    // would replace work they did.
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    std::fs::create_dir_all(&staging).expect("staging root");
    let (installed, package, _) = appended_function_installation(temp.path());
    let settings = installed.join("gksphone").join("settings.lua");

    apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");

    let written = std::fs::read_to_string(&settings).expect("settings");
    assert!(written.contains("MySQL.Sync.fetchScalar"), "{written}");
    assert!(written.contains("function OperatorFee"), "{written}");
}

#[test]
fn a_document_the_developer_relaid_out_is_combined_by_key() {
    // Reindenting a locale file changes every line in it, so a line merge has nothing to work
    // with and the operator is left choosing between their translations and the new strings.
    // Keys are the unit that still means something.
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    std::fs::create_dir_all(&staging).expect("staging root");
    let (installed, package, baseline) = locale_installation(temp.path());

    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");

    // No line view, and yet a merge: too far apart to line up, combined by key instead.
    let (path, whole) = preview
        .unmergeable()
        .find(|(path, _)| path.as_str() == "locales/tr.json")
        .expect("the locale file");
    assert_eq!(path.as_str(), "locales/tr.json");
    assert!(whole.merged().is_some());

    apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: Some(preview.plan().plan_id().digest()),
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");

    let written =
        std::fs::read_to_string(installed.join("gksphone").join("locales").join("tr.json"))
            .expect("locale");
    // Their translation is theirs.
    assert!(written.contains("\"Merhaba\""), "{written}");
    // The developer's own change to a string they never touched is taken.
    assert!(written.contains("\"Farewell\""), "{written}");
    // The new string arrives.
    assert!(written.contains("\"NEW\""), "{written}");
    // Laid out as the developer laid it out.
    assert!(
        written.starts_with(
            "{
    "
        ),
        "{written:?}"
    );
}

#[test]
fn a_kept_baseline_combines_a_relaid_out_document_exactly_as_the_package_did() {
    // The promise made when a baseline is kept is that the operator need not find the ZIP again.
    // A kept baseline that answered the same questions but combined fewer of them would be a
    // quieter way of breaking that promise: the operator would be told their locale file cannot
    // be combined, having been told they no longer need the package that would have combined it.
    use gkrm_core::{
        resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let app_data = temp.path().join("appdata");
    std::fs::create_dir_all(&app_data).expect("app data");

    // One installation to update, so the baseline it came from gets kept; a second left exactly
    // as it was, so what was kept can be held against the package it was taken from.
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    std::fs::create_dir_all(&first).expect("first");
    std::fs::create_dir_all(&second).expect("second");
    let (installed, package, baseline) = locale_installation(&first);
    let (untouched, package_again, baseline_again) = locale_installation(&second);

    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: Some(TwoWayBaselineSource::Package(&baseline)),
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    let was_installed_from = outcome
        .previous_baseline_id()
        .cloned()
        .expect("kept for an undo");

    let _ = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    );

    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let from_the_store = preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id: &was_installed_from,
        }),
        package: &package_again,
        installed: &untouched,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview from what was kept");
    let from_the_zip = preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Package(&baseline_again)),
        package: &package_again,
        installed: &untouched,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview from the zip");

    let combined = |preview: &gkrm_core::TwoWayUpdatePreview| {
        preview
            .unmergeable()
            .find(|(path, _)| path.as_str() == "locales/tr.json")
            .and_then(|(_, whole)| whole.merged().map(<[u8]>::to_vec))
    };
    let stored = combined(&from_the_store).expect("combined from what was kept");
    assert_eq!(Some(&stored), combined(&from_the_zip).as_ref());

    let text = String::from_utf8(stored).expect("utf-8");
    assert!(text.contains("\"Merhaba\""), "{text}");
    assert!(text.contains("\"Farewell\""), "{text}");
    assert!(text.contains("\"NEW\""), "{text}");
}

#[test]
fn a_file_that_changed_since_the_preview_is_refused_rather_than_answered_for() {
    // The apply re-plans from the live sources, so the file about to be written may not be the
    // file the operator answered. Matching by path and counting blocks catches only a change that
    // moves the count; the plan's identity covers both sides byte for byte.
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    std::fs::create_dir_all(&staging).expect("staging root");
    let (installed, package, _) = locale_installation(temp.path());

    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");

    // They edit the file again after looking at it and before pressing.
    let locale = installed.join("gksphone").join("locales").join("tr.json");
    let after = std::fs::read_to_string(&locale)
        .expect("locale")
        .replace("\"HELLO\": \"Merhaba\"", "\"HELLO\": \"Selam\"");
    std::fs::write(&locale, after).expect("edit");

    let error = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: Some(preview.plan().plan_id().digest()),
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect_err("the file is not the one that was answered");
    assert!(matches!(
        error,
        gkrm_core::GkrmError::TwoWayPlanChangedSincePreview
    ));
    // And their second edit is still exactly where they left it.
    assert!(std::fs::read_to_string(&locale)
        .expect("locale")
        .contains("Selam"));
}

#[test]
fn the_package_installed_from_turns_a_question_into_a_replacement() {
    // The case the baseline exists for. config.lua is escrow-ignored and the update changes it,
    // so with two sides it can only be a question. Against the package the operator installed
    // from it is plainly the developer's own change, and nobody has to answer for it.
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    let installed = pristine_installation(temp.path());
    let baseline = fixtures().join("packages").join("gksphone-official-v1.zip");

    let without = preview_with_baseline(&installed, &transactions, None);
    assert_eq!(action_for(&without, "config.lua"), TwoWayFileAction::Review);

    let with = preview_with_baseline(&installed, &transactions, Some(&baseline));
    assert_eq!(
        action_for(&with, "config.lua"),
        TwoWayFileAction::TakeFromUpdate
    );
    assert_eq!(with.plan().summary().review(), 0);
    // And the plan says what it decided that on, rather than only what it decided.
    let entry = with
        .plan()
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == "config.lua")
        .expect("config.lua");
    assert!(entry.untouched_since_install());
}

#[test]
fn a_file_the_operator_edited_is_still_theirs_to_answer_with_a_baseline() {
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    let installed = pristine_installation(temp.path());
    let config = installed.join("gksphone").join("config.lua");
    let mut edited = std::fs::read_to_string(&config).expect("read");
    edited.push_str(
        "
Config.Locale = 'tr'
",
    );
    std::fs::write(&config, edited).expect("write");

    let preview = preview_with_baseline(
        &installed,
        &transactions,
        Some(&fixtures().join("packages").join("gksphone-official-v1.zip")),
    );

    assert_eq!(action_for(&preview, "config.lua"), TwoWayFileAction::Review);
    assert_eq!(preview.plan().summary().review(), 1);
}

#[test]
fn a_baseline_for_another_resource_is_refused_rather_than_believed() {
    // A baseline that does not carry the resource being updated would answer "nobody touched
    // this" for every file in it, which is the most damaging wrong answer available here.
    let temp = tempdir().expect("temp dir");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    let installed = pristine_installation(temp.path());
    let elsewhere = temp.path().join("elsewhere.zip");
    write_zip(
        &elsewhere,
        &[(
            "othermod/fxmanifest.lua",
            b"fx_version 'cerulean'
",
        )],
    );

    let result = preview_two_way_update(TwoWayUpdateRequest {
        baseline: Some(TwoWayBaselineSource::Package(&elsewhere)),
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed: &installed,
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    });
    assert!(result.is_err());
}

#[test]
fn every_editable_file_that_differs_reaches_the_operator() {
    // Not just config.lua: every path the manifest leaves outside escrow is one the customer
    // could have edited, so every one of them that differs is review work.
    let preview = preview();
    assert_eq!(action_for(&preview, "config.lua"), TwoWayFileAction::Review);
    assert_eq!(
        action_for(&preview, "client/custom.lua"),
        TwoWayFileAction::Review
    );
    assert_eq!(preview.plan().summary().review(), 2);
    assert_eq!(preview.unmergeable_count(), 0);

    let reviewed: Vec<&str> = preview
        .reviewed()
        .iter()
        .map(|file| file.path().as_str())
        .collect();
    assert_eq!(reviewed, vec!["client/custom.lua", "config.lua"]);
}

#[test]
fn an_untouched_encrypted_file_is_left_alone() {
    assert_eq!(
        action_for(&preview(), "server/main.lua"),
        TwoWayFileAction::Unchanged
    );
}

#[test]
fn encrypted_files_are_taken_from_the_update_without_asking() {
    let preview = preview();
    for path in [
        "fxmanifest.lua",
        "client/main.lua",
        "client/new_feature.lua",
    ] {
        assert_eq!(
            action_for(&preview, path),
            TwoWayFileAction::TakeFromUpdate,
            "{path}"
        );
    }
}

#[test]
fn the_customer_owned_file_is_kept() {
    let preview = preview();
    assert_eq!(
        action_for(&preview, "data/customer_notes.txt"),
        TwoWayFileAction::KeepLocalOnly
    );
}

#[test]
fn keeping_settings_preserves_the_operator_values_and_takes_the_new_one() {
    // The whole product in one assertion: the customer's Locale and MaxContacts survive, and the
    // official EnableVoiceMail line arrives, from two inputs and no baseline.
    let preview = preview();
    let config = preview
        .reviewed()
        .iter()
        .find(|file| file.path().as_str() == "config.lua")
        .expect("config.lua review");

    let rendered: Vec<String> = config
        .merged()
        .iter()
        .map(|line| String::from_utf8(line.bytes().to_vec()).expect("utf-8"))
        .collect();
    assert_eq!(
        rendered,
        vec![
            "Config = {}",
            "",
            "Config.Locale = 'tr'",
            "Config.Currency = 'USD'",
            "Config.MaxContacts = 250",
            "Config.EnableDebug = false",
            "Config.EnableVoiceMail = true",
        ]
    );

    let origin_for = |needle: &str| {
        config
            .merged()
            .iter()
            .find(|line| String::from_utf8_lossy(line.bytes()).contains(needle))
            .unwrap_or_else(|| panic!("missing {needle}"))
            .origin()
    };
    assert_eq!(origin_for("Locale"), TwoWayLineOrigin::Installed);
    assert_eq!(origin_for("MaxContacts"), TwoWayLineOrigin::Installed);
    assert_eq!(origin_for("EnableVoiceMail"), TwoWayLineOrigin::Incoming);
    assert_eq!(origin_for("Currency"), TwoWayLineOrigin::Unchanged);
}

/// A live installation, applied against for real. The temp dir must outlive the returned paths.
struct Applied {
    _temp: tempfile::TempDir,
    installed: PathBuf,
    transactions: PathBuf,
    outcome: String,
    written_files: Vec<gkrm_core::TwoWayWrittenFile>,
}

impl Applied {
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.installed.join("gksphone").join(name)).expect(name)
    }

    fn has(&self, name: &str) -> bool {
        self.installed.join("gksphone").join(name).is_file()
    }
}

fn apply(mode: TwoWayUpdateMode) -> Applied {
    apply_with(mode, &[])
}

fn apply_with(mode: TwoWayUpdateMode, choices: &[TwoWayFileChoice<'_>]) -> Applied {
    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources");
    copy_tree(&fixtures().join("installed"), &installed);
    let staging = temp.path().join("staging");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&staging).expect("staging root");
    std::fs::create_dir_all(&transactions).expect("transaction root");

    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode,
        choices,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");

    Applied {
        _temp: temp,
        installed,
        transactions,
        outcome: outcome.outcome().to_string(),
        written_files: outcome.written_files().to_vec(),
    }
}

/// Apply the update for real against a copy of the fixtures, then read the files back.
#[test]
fn applying_with_settings_preserved_writes_the_merged_file() {
    let applied = apply(TwoWayUpdateMode::PreserveLocalEdits);
    assert_eq!(applied.outcome, "committed");
    let read = |name: &str| applied.read(name);
    // The operator's edits survive and the update's new setting arrives.
    let config = read("config.lua");
    assert!(config.contains("Config.Locale = 'tr'"), "{config}");
    assert!(config.contains("Config.MaxContacts = 250"), "{config}");
    assert!(config.contains("Config.EnableVoiceMail = true"), "{config}");
    assert!(!config.contains("'en'"), "{config}");
    assert!(!config.contains("= 100"), "{config}");

    // Their own edit to the other escrow-ignored file survives too.
    assert!(read("client/custom.lua").contains("customer hook"));

    // Encrypted files are replaced, the new one arrives, and their own file is untouched.
    assert!(read("client/main.lua").contains("client boot v2"));
    assert!(read("fxmanifest.lua").contains("version '2.0.0'"));
    assert!(applied.has("client/new_feature.lua"));
    assert!(read("data/customer_notes.txt").contains("must never delete it"));
}

#[test]
fn undo_evidence_names_exact_committed_bytes_including_merges() {
    use sha2::{Digest, Sha256};
    let applied = apply(TwoWayUpdateMode::PreserveLocalEdits);
    assert_eq!(applied.outcome, "committed");
    assert!(!applied.written_files.is_empty());
    for file in &applied.written_files {
        let bytes = std::fs::read(
            applied
                .installed
                .join("gksphone")
                .join(file.path().as_str()),
        )
        .expect("committed file");
        let actual = gkrm_core::Sha256Digest::new(Sha256::digest(&bytes).into());
        assert_eq!(file.after(), &actual, "{}", file.path().as_str());
        let before = fixtures()
            .join("installed/gksphone")
            .join(file.path().as_str());
        let expected_before = std::fs::read(before)
            .ok()
            .map(|bytes| gkrm_core::Sha256Digest::new(Sha256::digest(&bytes).into()));
        assert_eq!(file.before(), expected_before.as_ref());
    }
    let config = applied
        .written_files
        .iter()
        .find(|file| file.path().as_str() == "config.lua")
        .expect("merged config evidence");
    let incoming = fixtures().join("sources/gksphone-v2/gksphone/config.lua");
    let incoming = std::fs::read(incoming).expect("incoming config");
    assert_ne!(
        config.after(),
        &gkrm_core::Sha256Digest::new(Sha256::digest(&incoming).into())
    );
    assert!(!applied
        .written_files
        .iter()
        .any(|file| file.path().as_str() == "data/customer_notes.txt"));
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

#[test]
fn replacing_everything_takes_the_official_file_verbatim() {
    // The other button: the customer gives up their edits and takes the developer's file whole.
    let applied = apply(TwoWayUpdateMode::ReplaceWithIncoming);
    assert_eq!(applied.outcome, "committed");

    let config = applied.read("config.lua");
    assert!(config.contains("Config.Locale = 'en'"), "{config}");
    assert!(config.contains("Config.MaxContacts = 100"), "{config}");
    assert!(config.contains("Config.EnableVoiceMail = true"), "{config}");
    assert!(!config.contains("'tr'"), "{config}");
    assert!(!applied.read("client/custom.lua").contains("customer hook"));

    // A file only the customer has is still theirs to keep: replacing does not mean deleting.
    assert!(applied
        .read("data/customer_notes.txt")
        .contains("must never delete it"));
}

#[test]
fn the_apply_leaves_a_recoverable_transaction_behind() {
    // Every overwrite is backed up and journalled first, so the operator can undo the update.
    let applied = apply(TwoWayUpdateMode::PreserveLocalEdits);
    let mut journal = Vec::new();
    let mut backups = Vec::new();
    collect(&applied.transactions, &mut |path| {
        let slashed = path.to_string_lossy().replace('\\', "/");
        if let Some(name) = slashed.rsplit_once("/journal/") {
            journal.push(name.1.to_string());
        }
        if slashed.contains("/backup/files/") {
            backups.push(path.to_path_buf());
        }
    });
    journal.sort();

    // The journal records the whole crossing, so a crash at any point is recoverable.
    for step in [
        "prepared",
        "backup-complete",
        "applying",
        "applied",
        "committed",
    ] {
        assert!(
            journal.iter().any(|record| record.contains(step)),
            "no {step} record in {journal:?}"
        );
    }

    // The pre-update config.lua is recoverable byte for byte.
    let original = std::fs::read(
        fixtures()
            .join("installed")
            .join("gksphone")
            .join("config.lua"),
    )
    .expect("original config");
    assert!(
        backups
            .iter()
            .any(|path| std::fs::read(path).ok().as_deref() == Some(&original[..])),
        "the replaced config.lua was not backed up ({} backup files)",
        backups.len()
    );
}

fn collect(dir: &Path, visit: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, visit);
        } else {
            visit(&path);
        }
    }
}

#[test]
fn the_operator_can_take_one_of_their_own_changes_and_keep_the_other() {
    // The tick, end to end: in one config file, accept the developer's MaxContacts while keeping
    // their own Locale. Neither preset produces this, which is the whole reason the tick exists.
    let preview = preview();
    let config = preview
        .reviewed()
        .iter()
        .find(|file| file.path().as_str() == "config.lua")
        .expect("config.lua review");

    // Two disagreements, in file order: Locale, then MaxContacts. The third block is the update's
    // new EnableVoiceMail line, which the operator has no opinion about.
    let blocks: Vec<(Vec<String>, Vec<String>)> = config
        .blocks()
        .map(|block| {
            let render = |side: &[Vec<u8>]| {
                side.iter()
                    .map(|line| String::from_utf8(line.clone()).expect("utf-8"))
                    .collect()
            };
            (render(block.installed()), render(block.incoming()))
        })
        .collect();
    assert_eq!(
        blocks,
        vec![
            (
                vec!["Config.Locale = 'tr'".to_string()],
                vec!["Config.Locale = 'en'".to_string()]
            ),
            (
                vec!["Config.MaxContacts = 250".to_string()],
                vec!["Config.MaxContacts = 100".to_string()]
            ),
            (vec![], vec!["Config.EnableVoiceMail = true".to_string()]),
        ]
    );

    let path = config.path().clone();
    let applied = apply_with(
        TwoWayUpdateMode::PreserveLocalEdits,
        &[TwoWayFileChoice {
            path: &path,
            take_from_update: &[false, true, true],
        }],
    );
    assert_eq!(applied.outcome, "committed");

    let written = applied.read("config.lua");
    assert!(written.contains("Config.Locale = 'tr'"), "{written}");
    assert!(written.contains("Config.MaxContacts = 100"), "{written}");
    assert!(
        written.contains("Config.EnableVoiceMail = true"),
        "{written}"
    );
    assert!(!written.contains("= 250"), "{written}");

    // The other reviewed file was not decided, so it falls back to the preset.
    assert!(applied.read("client/custom.lua").contains("customer hook"));
}

#[test]
fn decisions_made_against_a_file_that_no_longer_matches_are_refused() {
    // A stale decision list would apply the operator's ticks to lines they never saw.
    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources");
    copy_tree(&fixtures().join("installed"), &installed);
    let staging = temp.path().join("staging");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&staging).expect("staging root");
    std::fs::create_dir_all(&transactions).expect("transaction root");

    let preview = preview();
    let path = preview
        .reviewed()
        .iter()
        .find(|file| file.path().as_str() == "config.lua")
        .expect("config.lua review")
        .path()
        .clone();
    let result = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[TwoWayFileChoice {
            path: &path,
            take_from_update: &[true],
        }],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    });
    assert!(result.is_err(), "a short decision list must not apply");

    // Nothing was written.
    assert!(
        std::fs::read_to_string(installed.join("gksphone").join("config.lua"))
            .expect("config")
            .contains("Config.Locale = 'tr'")
    );
}

#[test]
fn a_decision_for_a_file_this_update_does_not_review_is_refused() {
    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources");
    copy_tree(&fixtures().join("installed"), &installed);
    let staging = temp.path().join("staging");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&staging).expect("staging root");
    std::fs::create_dir_all(&transactions).expect("transaction root");

    // An encrypted file is never the operator's to decide.
    let preview = preview();
    let path = preview
        .plan()
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == "client/main.lua")
        .expect("client/main.lua")
        .path()
        .clone();
    assert!(apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[TwoWayFileChoice {
            path: &path,
            take_from_update: &[true],
        }],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .is_err());
}

#[test]
fn pointing_straight_at_the_resource_folder_works() {
    // What an operator actually does: they think of "my gksphone folder" as the thing being
    // updated, and select it. The folder is its own resource, and the seal used to lose that name
    // and report the sources as having changed.
    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources");
    copy_tree(&fixtures().join("installed"), &installed);
    let resource = installed.join("gksphone");
    let staging = temp.path().join("staging");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&staging).expect("staging root");
    std::fs::create_dir_all(&transactions).expect("transaction root");

    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: None,
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed: &resource,
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");
    assert_eq!(preview.plan().summary().review(), 2);

    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &fixtures().join("packages").join("gksphone-update.zip"),
        installed: &resource,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(outcome.outcome(), "committed");

    // The files are written where they already lived, not one level deeper.
    let config = std::fs::read_to_string(resource.join("config.lua")).expect("config");
    assert!(config.contains("Config.Locale = 'tr'"), "{config}");
    assert!(config.contains("Config.EnableVoiceMail = true"), "{config}");
    assert!(resource.join("client/new_feature.lua").is_file());
}

#[test]
fn a_second_update_is_not_blocked_by_the_first() {
    // The defect this exists for: the first update left a transaction the workspace could see but
    // not account for, so every later update on the same resource was refused forever.
    use gkrm_core::{
        resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources");
    copy_tree(&fixtures().join("installed"), &installed);
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let package = fixtures().join("packages").join("gksphone-update.zip");

    let apply_once = || {
        apply_two_way_update(TwoWayApplyRequest {
            expected_plan_id: None,
            baseline: None,
            package: &package,
            installed: &installed,
            resource: None,
            staging_root: workspace.staging_root(),
            transaction_root: workspace.transaction_root(),
            mode: TwoWayUpdateMode::PreserveLocalEdits,
            choices: &[],
            workspace: Some(&workspace),
            options: TrustedCliUpdateOptions::default(),
        })
    };

    assert_eq!(apply_once().expect("first apply").outcome(), "committed");

    // The finished update is on record, and closing it is an explicit act, never automatic.
    let retirement = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..Default::default()
        },
    )
    .expect("retire the finished update");
    assert!(
        retirement.retired_count() > 0,
        "the first update was not retirable: {retirement:?}"
    );

    // A second run now gets as far as planning rather than being refused before it starts. It
    // has nothing left to write, which is the honest answer and not a failure.
    assert_eq!(
        apply_once().expect("second apply").outcome(),
        "already_up_to_date"
    );
}

#[test]
fn an_installation_that_is_already_up_to_date_applies_without_failing() {
    // The operator ran the update, closed the record, and ran it again. Nothing differs, so
    // nothing is written — but "nothing to do" is a result, not a failure.
    use gkrm_core::{
        resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources").join("gksphone");
    copy_tree(
        &fixtures()
            .join("sources")
            .join("gksphone-v2")
            .join("gksphone"),
        &installed,
    );
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let package = fixtures().join("packages").join("gksphone-update.zip");

    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");
    assert_eq!(preview.plan().summary().review(), 0);
    assert_eq!(preview.plan().summary().take_from_update(), 0);

    let apply_once = || {
        apply_two_way_update(TwoWayApplyRequest {
            expected_plan_id: None,
            baseline: None,
            package: &package,
            installed: &installed,
            resource: None,
            staging_root: workspace.staging_root(),
            transaction_root: workspace.transaction_root(),
            mode: TwoWayUpdateMode::PreserveLocalEdits,
            choices: &[],
            workspace: Some(&workspace),
            options: TrustedCliUpdateOptions::default(),
        })
    };
    let close = || {
        retire_trusted_terminal_update_evidence(
            &workspace,
            TrustedTerminalEvidenceRetirementOptions {
                acknowledged: true,
                ..Default::default()
            },
        )
    };

    match apply_once() {
        Ok(outcome) => assert_eq!(outcome.outcome(), "already_up_to_date"),
        Err(error) => panic!("applying an up-to-date installation failed: {error}"),
    }
    // Nothing was written, so nothing is on record and there is nothing to close.
    assert_eq!(close().expect("close").retired_count(), 0);

    // And again. Repeating it is still not an error, and still leaves no evidence of an event
    // that did not happen.
    match apply_once() {
        Ok(outcome) => assert_eq!(outcome.outcome(), "already_up_to_date"),
        Err(error) => panic!("applying the same up-to-date update twice failed: {error}"),
    }
}

#[test]
fn reapplying_the_same_update_from_the_same_state_is_named_not_swallowed() {
    // A transaction is identified by the work it does and the state it does it from, so the same
    // update from the same starting point is the same transaction. Its evidence is kept and never
    // overwritten, so the second attempt is refused — the point of this test is that it is refused
    // by name, and that nothing is written when it is.
    use gkrm_core::{
        resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence, GkrmError,
        TrustedTerminalEvidenceRetirementOptions,
    };

    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources");
    let app_data = temp.path().join("app-data");
    std::fs::create_dir_all(&app_data).expect("app data");
    let workspace = resolve_trusted_update_workspace(&app_data).expect("workspace");
    let package = fixtures().join("packages").join("gksphone-update.zip");

    let reset = || {
        let _ = std::fs::remove_dir_all(&installed);
        copy_tree(&fixtures().join("installed"), &installed);
    };
    let apply_once = || {
        apply_two_way_update(TwoWayApplyRequest {
            expected_plan_id: None,
            baseline: None,
            package: &package,
            installed: &installed,
            resource: None,
            staging_root: workspace.staging_root(),
            transaction_root: workspace.transaction_root(),
            mode: TwoWayUpdateMode::PreserveLocalEdits,
            choices: &[],
            workspace: Some(&workspace),
            options: TrustedCliUpdateOptions::default(),
        })
    };

    reset();
    assert_eq!(apply_once().expect("first").outcome(), "committed");
    retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..Default::default()
        },
    )
    .expect("close");

    reset();
    assert!(matches!(
        apply_once(),
        Err(GkrmError::TrustedTransactionalApplyExecutionTransactionExists)
    ));
    // Refused before anything was written: the operator's file is still their own.
    let config =
        std::fs::read_to_string(installed.join("gksphone").join("config.lua")).expect("config");
    assert!(config.contains("Config.Locale = 'tr'"), "{config}");
    assert!(!config.contains("EnableVoiceMail"), "{config}");
}

#[test]
fn the_versions_on_both_sides_are_read_from_the_manifests() {
    // The manifest is read, never executed, and its declared version is what an operator wants to
    // see before they press anything: which version they are on, and which one this is.
    let preview = preview();
    assert_eq!(preview.installed_version(), Some("1.0.0"));
    assert_eq!(preview.incoming_version(), Some("2.0.0"));
}

#[test]
fn a_setting_only_the_operator_has_survives_alongside_one_only_the_update_has() {
    // Reported from the screen: the operator had added a setting of their own at the end of
    // config.lua, and the update had added one of its own. A line diff calls that "your last line
    // went, theirs arrived", and treating it as one decision offered a choice between two settings
    // that were never alternatives — losing one of them whichever way it was answered.
    let temp = tempdir().expect("temp dir");
    let installed = temp.path().join("resources");
    copy_tree(&fixtures().join("installed"), &installed);
    let config = installed.join("gksphone").join("config.lua");
    let mine = std::fs::read_to_string(&config).expect("config");
    std::fs::write(&config, format!("{}Config.MyOwnSetting = 'kept'\n", mine))
        .expect("add a setting of their own");

    let staging = temp.path().join("staging");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&staging).expect("staging root");
    std::fs::create_dir_all(&transactions).expect("transaction root");
    let package = fixtures().join("packages").join("gksphone-update.zip");

    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(outcome.outcome(), "committed");

    let written = std::fs::read_to_string(&config).expect("config");
    assert!(
        written.contains("Config.MyOwnSetting = 'kept'"),
        "{written}"
    );
    assert!(
        written.contains("Config.EnableVoiceMail = true"),
        "{written}"
    );
    // And the settings they had edited are still theirs.
    assert!(written.contains("Config.Locale = 'tr'"), "{written}");
    assert!(written.contains("Config.MaxContacts = 250"), "{written}");
}

/// An escrow-ignored file that differs on both sides but cannot be read as text.
///
/// Real packages ship these. The one used here is the common case in the field: a translation
/// file saved in a Turkish code page rather than UTF-8, which cannot be split into logical lines
/// and so has no line-by-line decision to offer. That does not make the update unapplicable.
fn unmergeable_installation(temp: &Path) -> (PathBuf, PathBuf) {
    let manifest = |version: &str| {
        format!(
            "fx_version 'cerulean'\ngame 'gta5'\n\nversion '{version}'\n\n\
             escrow_ignore {{\n  'config.lua',\n  'locale/tr.lua',\n}}\n\n\
             client_scripts {{\n  'config.lua',\n  'locale/tr.lua',\n}}\n"
        )
    };

    let installed = temp.join("resources");
    let resource = installed.join("gksphone");
    std::fs::create_dir_all(resource.join("locale")).expect("installed tree");
    std::fs::write(resource.join("fxmanifest.lua"), manifest("1.0.0")).expect("manifest");
    std::fs::write(
        resource.join("config.lua"),
        "Config = {}\nConfig.Locale = 'tr'\n",
    )
    .expect("config");
    // Not UTF-8: the Turkish 'ı' as the single byte a Windows code page writes it as.
    std::fs::write(
        resource.join("locale").join("tr.lua"),
        b"-- \xfdsmim\nLocale = { hello = 'merhaba' }\n",
    )
    .expect("locale");

    let package = temp.join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", manifest("2.0.0").as_bytes()),
            (
                "gksphone/config.lua",
                b"Config = {}\nConfig.Locale = 'en'\nConfig.EnableVoiceMail = true\n",
            ),
            (
                "gksphone/locale/tr.lua",
                b"-- \xfdsmim\nLocale = { hello = 'selam', bye = 'gule gule' }\n",
            ),
        ],
    );

    (installed, package)
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("start entry");
        writer.write_all(bytes).expect("write entry");
    }
    writer.finish().expect("finish zip");
}

#[test]
fn a_file_that_cannot_be_compared_line_by_line_is_named_not_hidden() {
    let temp = tempdir().expect("temp dir");
    let (installed, package) = unmergeable_installation(temp.path());
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&transactions).expect("transaction root");

    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");

    // It is review work — the operator owns the file — but there is nothing to review line by
    // line, so it reaches them as a whole-file question and never as a merged file.
    assert_eq!(
        action_for(&preview, "locale/tr.lua"),
        TwoWayFileAction::Review
    );
    let unmergeable: Vec<&str> = preview
        .unmergeable()
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(unmergeable, vec!["locale/tr.lua"]);
    let reviewed: Vec<&str> = preview
        .reviewed()
        .iter()
        .map(|file| file.path().as_str())
        .collect();
    assert_eq!(reviewed, vec!["config.lua"]);
}

fn apply_unmergeable(mode: TwoWayUpdateMode, temp: &Path) -> PathBuf {
    let (installed, package) = unmergeable_installation(temp);
    let staging = temp.join("staging");
    let transactions = temp.join("transactions");
    std::fs::create_dir_all(&staging).expect("staging root");
    std::fs::create_dir_all(&transactions).expect("transaction root");

    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode,
        choices: &[],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(outcome.outcome(), "committed");

    installed.join("gksphone")
}

#[test]
fn keeping_settings_applies_the_rest_and_leaves_the_uncomparable_file_alone() {
    // The failure this was written for: one uncomparable file among the reviewed ones refused the
    // entire update, so nothing was applied and the operator was told only that it had failed.
    let temp = tempdir().expect("temp dir");
    let resource = apply_unmergeable(TwoWayUpdateMode::PreserveLocalEdits, temp.path());

    assert_eq!(
        std::fs::read(resource.join("locale").join("tr.lua")).expect("locale"),
        b"-- \xfdsmim\nLocale = { hello = 'merhaba' }\n"
    );
    let config = std::fs::read_to_string(resource.join("config.lua")).expect("config");
    assert!(config.contains("Config.Locale = 'tr'"), "{config}");
    assert!(config.contains("Config.EnableVoiceMail = true"), "{config}");
    assert!(std::fs::read_to_string(resource.join("fxmanifest.lua"))
        .expect("manifest")
        .contains("version '2.0.0'"));
}

#[test]
fn replacing_everything_takes_the_uncomparable_file_from_the_update() {
    let temp = tempdir().expect("temp dir");
    let resource = apply_unmergeable(TwoWayUpdateMode::ReplaceWithIncoming, temp.path());

    assert_eq!(
        std::fs::read(resource.join("locale").join("tr.lua")).expect("locale"),
        b"-- \xfdsmim\nLocale = { hello = 'selam', bye = 'gule gule' }\n"
    );
    assert!(std::fs::read_to_string(resource.join("config.lua"))
        .expect("config")
        .contains("Config.Locale = 'en'"));
}

#[test]
fn a_decision_made_against_a_file_with_no_lines_to_decide_is_refused() {
    // The screen cannot offer blocks for this file, so a choice naming it was made against
    // something else. Applying it anyway would apply a decision to the wrong file.
    let temp = tempdir().expect("temp dir");
    let (installed, package) = unmergeable_installation(temp.path());
    let staging = temp.path().join("staging");
    let transactions = temp.path().join("transactions");
    std::fs::create_dir_all(&staging).expect("staging root");
    std::fs::create_dir_all(&transactions).expect("transaction root");

    let preview = preview_two_way_update(TwoWayUpdateRequest {
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        transaction_root: &transactions,
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("preview");
    let path = preview
        .unmergeable()
        .map(|(path, _)| path.clone())
        .next()
        .expect("a file with no lines to decide");
    let path = &path;

    let error = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: &staging,
        transaction_root: &transactions,
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[TwoWayFileChoice {
            path,
            take_from_update: &[true],
        }],
        workspace: None,
        options: TrustedCliUpdateOptions::default(),
    })
    .expect_err("a decision with nothing to decide is refused");
    assert!(matches!(
        error,
        gkrm_core::GkrmError::TwoWayMergeChoiceCountMismatch
    ));

    // And nothing was written on the way to refusing.
    assert_eq!(
        std::fs::read(installed.join("gksphone").join("locale").join("tr.lua")).expect("locale"),
        b"-- \xfdsmim\nLocale = { hello = 'merhaba' }\n"
    );
}

/// Real two-way evidence reconstructs after reopening the workspace without its input ZIP.
#[test]
fn two_way_recovery_reopens_committed_evidence_without_the_package() {
    use gkrm_core::*;
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    copy_tree(&fixtures().join("installed"), &installed);
    let appdata = temp.path().join("appdata");
    std::fs::create_dir(&appdata).expect("appdata");
    let package = temp.path().join("update.zip");
    std::fs::copy(fixtures().join("packages/gksphone-update.zip"), &package).expect("package");
    let workspace = resolve_trusted_update_workspace(&appdata).expect("workspace");
    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(outcome.outcome(), "committed");
    drop(outcome);
    drop(workspace);
    std::fs::remove_file(&package).expect("remove package");
    let workspace = resolve_trusted_update_workspace(&appdata).expect("reopen workspace");
    let before = temp.path().join("before-recovery");
    copy_tree(&installed, &before);
    let root =
        TrustedTransactionRoot::try_open(workspace.transaction_root()).expect("transactions");
    let scan =
        scan_trusted_transactions(&root, TrustedRecoveryScanOptions::default()).expect("scan");
    assert_eq!(scan.candidates().len(), 1);
    let candidate = *scan.candidates()[0].candidate_id();
    let selection =
        scan_trusted_installed_recovery_resources(&installed, InstalledScanLimits::default())
            .expect("selection scan")
            .select(&SafeResourceKey::parse("gksphone").expect("key"))
            .expect("selection");
    let request = TrustedPackageFreeUpdateRecoveryRequest::try_new(
        &workspace,
        &candidate,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .expect("request");
    let result = recover_trusted_published_update_v2(request).expect("package-free recovery");
    assert!(matches!(
        result,
        TrustedRecoveryResult::RecoveredCommitted(_)
    ));
    fn tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn walk(
            root: &Path,
            here: &Path,
            files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) {
            for entry in std::fs::read_dir(here).expect("entries") {
                let entry = entry.expect("entry");
                if entry.file_type().expect("kind").is_dir() {
                    walk(root, &entry.path(), files);
                } else {
                    files.insert(
                        entry
                            .path()
                            .strip_prefix(root)
                            .expect("relative")
                            .to_path_buf(),
                        std::fs::read(entry.path()).expect("bytes"),
                    );
                }
            }
        }
        let mut files = std::collections::BTreeMap::new();
        walk(root, root, &mut files);
        files
    }
    assert_eq!(tree(&installed), tree(&before));
}

fn committed_undo_fixture() -> (
    tempfile::TempDir,
    PathBuf,
    gkrm_core::TrustedUpdateWorkspace,
    gkrm_core::Sha256Digest,
) {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    copy_tree(&fixtures().join("installed"), &installed);
    let appdata = temp.path().join("appdata");
    std::fs::create_dir(&appdata).expect("appdata");
    let workspace = gkrm_core::resolve_trusted_update_workspace(&appdata).expect("workspace");
    let package = temp.path().join("update.zip");
    std::fs::copy(fixtures().join("packages/gksphone-update.zip"), &package)
        .expect("copy synthetic package");
    let result = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(result.outcome(), "committed");
    let transaction = *result.transaction_id().expect("transaction");
    (temp, installed, workspace, transaction)
}

fn undo_selection(installed: &Path) -> gkrm_core::TrustedInstalledRecoverySelection {
    gkrm_core::scan_trusted_installed_recovery_resources(
        installed,
        gkrm_core::InstalledScanLimits::default(),
    )
    .expect("scan")
    .select(&gkrm_core::SafeResourceKey::parse("gksphone").expect("key"))
    .expect("selection")
}

#[test]
fn trusted_undo_source_reproduces_real_changes_and_verified_original_bytes() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let source = TrustedUndoSource::try_open(&workspace, &undo_selection(&installed), &transaction)
        .expect("source");
    assert_eq!(source.transaction_id(), &transaction);
    assert_eq!(source.resource_key().as_str(), "gksphone");
    assert!(!source.changes().is_empty());
    for change in source.changes() {
        let expected = std::fs::read(
            fixtures()
                .join("installed/gksphone")
                .join(change.path().as_str()),
        )
        .ok();
        assert_eq!(
            source
                .original_bytes(change.path())
                .expect("verified backup"),
            expected
        );
        let actual = std::fs::read(installed.join("gksphone").join(change.path().as_str()))
            .expect("applied bytes");
        use sha2::{Digest, Sha256};
        assert_eq!(
            change.after(),
            Some(&Sha256Digest::new(Sha256::digest(actual).into()))
        );
    }
    assert!(source
        .original_bytes(&undo_relative_path("data/customer_notes.txt"))
        .is_err());
    std::fs::write(
        installed.join("gksphone/config.lua"),
        b"later customer edit",
    )
    .expect("edit");
    let source = TrustedUndoSource::try_open(&workspace, &undo_selection(&installed), &transaction)
        .expect("source after edit");
    assert!(source
        .original_bytes(&undo_relative_path("config.lua"))
        .expect("backup")
        .is_some());
    assert_eq!(
        std::fs::read(installed.join("gksphone/config.lua")).expect("current"),
        b"later customer edit"
    );
    retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    )
    .expect("retire");
    let release = discard_unaccounted_trusted_staging_bundles(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    )
    .expect("retired committed Undo source stays protected");
    assert_eq!(release.released, 0);
    assert_eq!(release.kept, 1);
    TrustedUndoSource::try_open(&workspace, &undo_selection(&installed), &transaction)
        .expect("retired committed source remains available");
}

#[test]
fn trusted_undo_source_refuses_wrong_installation_and_unknown_transaction() {
    use gkrm_core::*;
    let (temp, installed, workspace, transaction) = committed_undo_fixture();
    let other = temp.path().join("other-installation");
    copy_tree(&installed, &other);
    assert!(
        TrustedUndoSource::try_open(&workspace, &undo_selection(&other), &transaction).is_err()
    );
    assert!(TrustedUndoSource::try_open(
        &workspace,
        &undo_selection(&installed),
        &Sha256Digest::new([0; 32])
    )
    .is_err());
    assert_eq!(
        std::fs::read(installed.join("gksphone/config.lua")).expect("original"),
        std::fs::read(other.join("gksphone/config.lua")).expect("other")
    );
}

#[test]
fn trusted_undo_source_rechecks_backup_content_at_point_of_read() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let source = TrustedUndoSource::try_open(&workspace, &undo_selection(&installed), &transaction)
        .expect("source");
    let plan = source.plan(&undo_selection(&installed)).expect("plan");
    let bundles_before = std::fs::read_dir(workspace.staging_root().join("bundles"))
        .expect("bundles")
        .count();
    let path = undo_relative_path("config.lua");
    let original = source
        .original_bytes(&path)
        .expect("backup")
        .expect("original bytes");
    let files = workspace
        .transaction_root()
        .join("transactions")
        .join(transaction.to_string())
        .join("backup/files");
    let object = std::fs::read_dir(files)
        .expect("objects")
        .map(|entry| entry.expect("entry").path())
        .find(|file| std::fs::read(file).expect("read") == original)
        .expect("original object");
    let mut damaged = original;
    damaged[0] ^= 1;
    std::fs::write(&object, damaged).expect("tamper with synthetic backup");
    assert!(source.original_bytes(&path).is_err());
    assert!(source.stage(&undo_selection(&installed), &plan).is_err());
    assert_eq!(
        std::fs::read_dir(workspace.staging_root().join("bundles"))
            .expect("bundles")
            .count(),
        bundles_before
    );
    assert!(
        TrustedUndoSource::try_open(&workspace, &undo_selection(&installed), &transaction).is_err()
    );
    assert_ne!(
        std::fs::read(installed.join("gksphone/config.lua")).expect("installed"),
        std::fs::read(object).expect("damaged backup")
    );
}

fn undo_relative_path(path: &str) -> gkrm_core::ResourceRelativePath {
    gkrm_core::ResourceRelativePath::from_installation_path(
        &gkrm_core::InstalledResourceRoot::Root,
        &gkrm_core::InstallationRelativePath::from_path(Path::new(path))
            .expect("installation relative path"),
    )
    .expect("resource relative path")
}

#[test]
fn trusted_undo_plan_preserves_later_edits_deletions_and_directory_replacements() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &transaction).expect("source");
    let first = source.plan(&selection).expect("plan");
    let second = source.plan(&selection).expect("repeat plan");
    assert_eq!(first.plan_id(), second.plan_id());
    assert_eq!(first.entries(), second.entries());
    let disposition = |plan: &TrustedUndoPlan, path: &str| {
        plan.entries()
            .iter()
            .find(|entry| entry.path().as_str() == path)
            .expect("planned change")
            .disposition()
    };
    assert_eq!(
        disposition(&first, "config.lua"),
        TrustedUndoDisposition::RestoreOriginal
    );
    assert_eq!(
        disposition(&first, "client/new_feature.lua"),
        TrustedUndoDisposition::RemoveCreated
    );
    assert!(!first
        .entries()
        .iter()
        .any(|entry| entry.path().as_str() == "data/customer_notes.txt"));
    let config = installed.join("gksphone/config.lua");
    std::fs::write(&config, b"later customer edit").expect("edit");
    let edited = source
        .plan(&undo_selection(&installed))
        .expect("edited plan");
    assert_ne!(edited.plan_id(), first.plan_id());
    assert_eq!(
        disposition(&edited, "config.lua"),
        TrustedUndoDisposition::PreserveChanged
    );
    assert_eq!(
        std::fs::read(&config).expect("read"),
        b"later customer edit"
    );
    std::fs::remove_file(&config).expect("customer removed config");
    let deleted = source
        .plan(&undo_selection(&installed))
        .expect("deleted plan");
    assert_eq!(
        disposition(&deleted, "config.lua"),
        TrustedUndoDisposition::PreserveChanged
    );
    assert!(!config.exists());
    let created = installed.join("gksphone/client/new_feature.lua");
    std::fs::remove_file(&created).expect("remove created file");
    std::fs::create_dir(&created).expect("customer directory");
    let replaced = source
        .plan(&undo_selection(&installed))
        .expect("type-change plan");
    assert_eq!(
        disposition(&replaced, "client/new_feature.lua"),
        TrustedUndoDisposition::PreserveChanged
    );
    assert!(created.is_dir());
}

#[test]
fn trusted_undo_plan_recognizes_already_restored_files_and_binds_unknown_files() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let source = TrustedUndoSource::try_open(&workspace, &undo_selection(&installed), &transaction)
        .expect("source");
    let config = installed.join("gksphone/config.lua");
    let original = source
        .original_bytes(&undo_relative_path("config.lua"))
        .expect("read backup")
        .expect("original");
    std::fs::write(&config, &original).expect("already restored");
    let plan = source.plan(&undo_selection(&installed)).expect("plan");
    assert_eq!(
        plan.entries()
            .iter()
            .find(|entry| entry.path().as_str() == "config.lua")
            .expect("config")
            .disposition(),
        TrustedUndoDisposition::AlreadyOriginal
    );
    let unknown = installed.join("gksphone/customer-only-file.txt");
    std::fs::write(&unknown, b"customer-owned").expect("customer file");
    let changed = source
        .plan(&undo_selection(&installed))
        .expect("changed full tree");
    assert_ne!(plan.plan_id(), changed.plan_id());
    assert_ne!(plan.current_fingerprint(), changed.current_fingerprint());
    assert!(!changed
        .entries()
        .iter()
        .any(|entry| entry.path().as_str() == "customer-only-file.txt"));
    assert_eq!(
        std::fs::read(unknown).expect("customer file"),
        b"customer-owned"
    );
    assert_eq!(std::fs::read(config).expect("original config"), original);
}

fn undo_staged_resource(
    workspace: &gkrm_core::TrustedUpdateWorkspace,
    staged: &gkrm_core::TrustedUndoStagingBundle,
) -> PathBuf {
    workspace
        .staging_root()
        .join("bundles")
        .join(
            staged
                .bundle()
                .manifest()
                .manifest_id()
                .digest()
                .to_string(),
        )
        .join("resource")
}

#[test]
fn trusted_undo_staging_restores_old_bytes_preserves_customer_files_and_never_writes_live() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let resource = installed.join("gksphone");
    std::fs::write(resource.join("customer-only.txt"), b"customer").expect("customer file");
    std::fs::create_dir_all(resource.join("empty-customer/nested")).expect("empty dirs");
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &transaction).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let live_config = std::fs::read(resource.join("config.lua")).expect("live config");
    let staged = source.stage(&selection, &plan).expect("stage");
    let candidate = undo_staged_resource(&workspace, &staged);
    assert_eq!(
        std::fs::read(candidate.join("config.lua")).expect("candidate config"),
        std::fs::read(fixtures().join("installed/gksphone/config.lua")).expect("original")
    );
    assert!(!candidate.join("client/new_feature.lua").exists());
    assert_eq!(
        std::fs::read(candidate.join("customer-only.txt")).expect("customer"),
        b"customer"
    );
    assert!(candidate.join("empty-customer/nested").is_dir());
    assert_eq!(
        std::fs::read(resource.join("config.lua")).expect("live"),
        live_config
    );
    assert!(resource.join("client/new_feature.lua").is_file());
    let adopted = source
        .stage(&selection, &plan)
        .expect("same candidate can be adopted");
    assert_eq!(staged.bundle().bundle_id(), adopted.bundle().bundle_id());
    let apply_plan = staged
        .plan_apply(&selection)
        .expect("reverse operation plan");
    let actionable = plan
        .entries()
        .iter()
        .filter(|entry| {
            matches!(
                entry.disposition(),
                TrustedUndoDisposition::RestoreOriginal | TrustedUndoDisposition::RemoveCreated
            )
        })
        .count();
    assert_eq!(apply_plan.operations().len(), actionable);
    assert!(apply_plan
        .operations()
        .iter()
        .any(|operation| operation.kind() == TrustedApplyOperationKind::ReplaceFile));
    assert!(apply_plan
        .operations()
        .iter()
        .any(|operation| operation.kind() == TrustedApplyOperationKind::DeleteFile));
    let transaction_plan = staged
        .plan_transaction(&selection, &apply_plan)
        .expect("transaction plan");
    assert!(transaction_plan.backup().entry_count() > 0);
    assert!(!transaction_plan.rollback_steps().is_empty());
    let again = staged
        .plan_apply(&selection)
        .expect("repeat operation plan");
    assert_eq!(apply_plan.plan_id(), again.plan_id());
    assert_eq!(
        std::fs::read(resource.join("config.lua")).expect("live"),
        live_config
    );
}

#[test]
fn trusted_undo_staging_preserves_later_edits_deletions_and_type_changes() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let resource = installed.join("gksphone");
    std::fs::write(resource.join("config.lua"), b"later customer edit").expect("edit");
    std::fs::remove_file(resource.join("client/new_feature.lua")).expect("remove");
    std::fs::create_dir(resource.join("client/new_feature.lua")).expect("type change");
    std::fs::write(
        resource.join("client/new_feature.lua/customer.txt"),
        b"keep",
    )
    .expect("child");
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &transaction).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let staged = source.stage(&selection, &plan).expect("stage");
    let candidate = undo_staged_resource(&workspace, &staged);
    assert_eq!(
        std::fs::read(candidate.join("config.lua")).expect("edit"),
        b"later customer edit"
    );
    assert_eq!(
        std::fs::read(candidate.join("client/new_feature.lua/customer.txt")).expect("child"),
        b"keep"
    );
    assert_eq!(
        std::fs::read(resource.join("config.lua")).expect("live edit"),
        b"later customer edit"
    );
}

#[test]
fn trusted_undo_staging_rejects_stale_plan_before_creating_a_bundle() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &transaction).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let count = || {
        std::fs::read_dir(workspace.staging_root().join("bundles"))
            .expect("bundles")
            .count()
    };
    let before = count();
    std::fs::write(
        installed.join("gksphone/customer-only.txt"),
        b"new membership",
    )
    .expect("customer file");
    assert!(source.stage(&undo_selection(&installed), &plan).is_err());
    assert_eq!(count(), before);
    let fresh_selection = undo_selection(&installed);
    let fresh = source.plan(&fresh_selection).expect("fresh plan");
    std::fs::write(
        installed.join("gksphone/config.lua"),
        b"new customer content",
    )
    .expect("edit");
    assert!(source.stage(&undo_selection(&installed), &fresh).is_err());
    assert_eq!(count(), before);
    assert_eq!(
        std::fs::read(installed.join("gksphone/config.lua")).expect("live"),
        b"new customer content"
    );
}

#[test]
fn trusted_undo_staging_rejects_directory_tampering_without_deleting_adopted_evidence() {
    use gkrm_core::*;
    let (_temp, installed, workspace, transaction) = committed_undo_fixture();
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &transaction).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let staged = source.stage(&selection, &plan).expect("stage");
    let candidate = undo_staged_resource(&workspace, &staged);
    std::fs::create_dir(candidate.join("unreviewed-empty-directory"))
        .expect("tamper synthetic stage");
    assert!(staged.plan_apply(&selection).is_err());
    assert!(source.stage(&selection, &plan).is_err());
    assert!(candidate.join("unreviewed-empty-directory").is_dir());
    assert!(candidate.join("config.lua").is_file());
    assert!(installed.join("gksphone/client/new_feature.lua").is_file());
}

#[test]
fn trusted_undo_planning_rejects_identical_other_installation_and_empty_directory_drift() {
    use gkrm_core::*;
    let (temp, installed, workspace, transaction) = committed_undo_fixture();
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &transaction).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let staged = source.stage(&selection, &plan).expect("stage");
    let apply = staged.plan_apply(&selection).expect("apply plan");
    let other = temp.path().join("identical-other-installation");
    copy_tree(&installed, &other);
    assert!(staged.plan_apply(&undo_selection(&other)).is_err());
    assert!(staged
        .plan_transaction(&undo_selection(&other), &apply)
        .is_err());
    std::fs::create_dir(installed.join("gksphone/later-empty-directory"))
        .expect("customer directory");
    let changed = undo_selection(&installed);
    assert!(staged.plan_apply(&changed).is_err());
    assert!(staged.plan_transaction(&changed, &apply).is_err());
    assert!(installed.join("gksphone/later-empty-directory").is_dir());
}

#[test]
fn trusted_undo_staging_tracks_managed_directories_and_preserves_customer_descendants() {
    use gkrm_core::*;
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    copy_tree(&fixtures().join("installed"), &installed);
    let resource = installed.join("gksphone");
    std::fs::create_dir_all(resource.join("old-empty/child")).expect("original empty dirs");
    let package = temp.path().join("new-directories.zip");
    let manifest = std::fs::read(resource.join("fxmanifest.lua")).expect("manifest");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", &manifest),
            ("gksphone/new-module/start.lua", b"new code"),
            ("gksphone/managed-only/start.lua", b"new code"),
        ],
    );
    let appdata = temp.path().join("appdata");
    std::fs::create_dir(&appdata).expect("appdata");
    let workspace = resolve_trusted_update_workspace(&appdata).expect("workspace");
    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &package,
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .expect("apply");
    assert_eq!(outcome.outcome(), "committed");
    assert!(!resource.join("old-empty").exists());
    std::fs::create_dir_all(resource.join("new-module/customer-empty/nested"))
        .expect("customer empty dirs");
    std::fs::write(resource.join("new-module/customer.txt"), b"customer").expect("customer file");
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(
        &workspace,
        &selection,
        outcome.transaction_id().expect("id"),
    )
    .expect("source");
    let plan = source.plan(&selection).expect("plan");
    let staged = source.stage(&selection, &plan).expect("stage");
    let candidate = undo_staged_resource(&workspace, &staged);
    assert!(candidate.join("old-empty/child").is_dir());
    assert!(!candidate.join("managed-only").exists());
    assert!(!candidate.join("new-module/start.lua").exists());
    assert!(candidate.join("new-module/customer-empty/nested").is_dir());
    assert_eq!(
        std::fs::read(candidate.join("new-module/customer.txt")).expect("customer"),
        b"customer"
    );
    let apply = staged.plan_apply(&selection).expect("operations");
    let count_kind = |kind| {
        apply
            .operations()
            .iter()
            .filter(|operation| operation.kind() == kind)
            .count()
    };
    assert_eq!(count_kind(TrustedApplyOperationKind::CreateDirectory), 2);
    assert_eq!(count_kind(TrustedApplyOperationKind::RemoveDirectory), 1);
    assert_eq!(count_kind(TrustedApplyOperationKind::DeleteFile), 2);
    assert_eq!(apply.operations().len(), 5);
    staged
        .plan_transaction(&selection, &apply)
        .expect("backup and rollback plan");
    assert!(!resource.join("old-empty").exists());
    assert!(resource.join("managed-only/start.lua").is_file());
}

fn undo_hash_tree(
    root: &Path,
) -> std::collections::BTreeMap<PathBuf, Option<gkrm_core::Sha256Digest>> {
    use sha2::{Digest, Sha256};
    fn walk(
        root: &Path,
        here: &Path,
        tree: &mut std::collections::BTreeMap<PathBuf, Option<gkrm_core::Sha256Digest>>,
    ) {
        for entry in std::fs::read_dir(here).expect("tree entries") {
            let entry = entry.expect("tree entry");
            let path = entry.path();
            let relative = path.strip_prefix(root).expect("relative").to_path_buf();
            if entry.file_type().expect("kind").is_dir() {
                tree.insert(relative, None);
                walk(root, &path, tree);
            } else {
                tree.insert(
                    relative,
                    Some(gkrm_core::Sha256Digest::new(
                        Sha256::digest(std::fs::read(path).expect("bytes")).into(),
                    )),
                );
            }
        }
    }
    let mut tree = std::collections::BTreeMap::new();
    walk(root, root, &mut tree);
    tree
}

#[test]
fn trusted_undo_execution_commits_original_hash_tree_and_recovers_without_the_zip() {
    use gkrm_core::*;
    let (temp, installed, workspace, parent) = committed_undo_fixture();
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).expect("source");
    let plan = source.plan(&selection).expect("plan");
    std::fs::remove_file(temp.path().join("update.zip")).expect("remove copied ZIP before Undo");
    let outcome = source.execute(&selection, &plan).expect("execute");
    assert!(
        matches!(
            outcome.result(),
            Some(TrustedTransactionResult::Committed(_))
        ),
        "{outcome:?}"
    );
    assert_eq!(outcome.preserved_changes(), 0);
    let undo_id = *outcome.transaction_id().expect("Undo transaction");
    assert_ne!(undo_id, parent);
    assert_eq!(
        undo_hash_tree(&installed.join("gksphone")),
        undo_hash_tree(&fixtures().join("installed/gksphone"))
    );
    assert!(workspace
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .join("backup")
        .is_dir());
    let appdata = workspace.app_root().to_path_buf();
    drop(source);
    drop(workspace);
    let reopened = resolve_trusted_update_workspace(&appdata).expect("reopen");
    let selection = undo_selection(&installed);
    let inspection = inspect_trusted_published_update_v2(
        &reopened,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .expect("inspect Undo");
    let candidate = inspection.candidate_id().expect("Undo candidate");
    let request = TrustedPackageFreeUpdateRecoveryRequest::try_new(
        &reopened,
        candidate,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .expect("reconstruct Undo");
    let recovered = recover_trusted_published_update_v2(request).expect("recover committed Undo");
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveredCommitted(_)),
        "{recovered:?}"
    );
    assert_eq!(
        undo_hash_tree(&installed.join("gksphone")),
        undo_hash_tree(&fixtures().join("installed/gksphone"))
    );
    assert!(reopened
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .is_dir());
}

#[test]
fn trusted_undo_execution_preserves_later_edits_to_existing_and_created_files() {
    use gkrm_core::*;
    let (_temp, installed, workspace, parent) = committed_undo_fixture();
    let root = installed.join("gksphone");
    std::fs::write(root.join("config.lua"), b"customer config after Apply").expect("edit existing");
    std::fs::write(
        root.join("client/new_feature.lua"),
        b"customer changed new feature",
    )
    .expect("edit created");
    std::fs::create_dir_all(root.join("customer-empty/child")).expect("empty dirs");
    std::fs::write(root.join("customer.txt"), b"unknown customer file").expect("customer file");
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let outcome = source.execute(&selection, &plan).expect("execute");
    assert!(
        matches!(
            outcome.result(),
            Some(TrustedTransactionResult::Committed(_))
        ),
        "{outcome:?}"
    );
    assert_eq!(outcome.preserved_changes(), 2);
    let receipts = inspect_trusted_undo_receipts(&workspace, &undo_selection(&installed))
        .expect("partial Undo receipt");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].preserved_changes(), 2);
    assert!(!receipts[0].fully_reversed());
    assert_eq!(
        std::fs::read(root.join("config.lua")).expect("config"),
        b"customer config after Apply"
    );
    assert_eq!(
        std::fs::read(root.join("client/new_feature.lua")).expect("new feature"),
        b"customer changed new feature"
    );
    assert_eq!(
        std::fs::read(root.join("customer.txt")).expect("customer"),
        b"unknown customer file"
    );
    assert!(root.join("customer-empty/child").is_dir());
    assert!(workspace
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .is_dir());
}

/// A path the update wrote can be a directory by the time Undo runs. Reversing it would mean
/// deleting a tree the operator put there, so it is preserved — and the files whose output is
/// still exactly what the update committed must reverse anyway. A type change elsewhere in the
/// resource is not a reason to abandon the rest of the reversal.
#[test]
fn trusted_undo_execution_preserves_type_changes_and_still_reverses_unchanged_output() {
    use gkrm_core::*;
    let (_temp, installed, workspace, parent) = committed_undo_fixture();
    let root = installed.join("gksphone");
    let original = fixtures().join("installed/gksphone");

    // A file the update replaced, now a directory.
    std::fs::remove_file(root.join("client/main.lua")).expect("remove replaced file");
    std::fs::create_dir(root.join("client/main.lua")).expect("directory in its place");
    std::fs::write(root.join("client/main.lua/inside.lua"), b"operator tree").expect("child");
    // A file the update created, now a directory.
    std::fs::remove_file(root.join("client/new_feature.lua")).expect("remove created file");
    std::fs::create_dir(root.join("client/new_feature.lua")).expect("directory in its place");
    std::fs::write(
        root.join("client/new_feature.lua/inside.lua"),
        b"operator tree two",
    )
    .expect("child two");

    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let outcome = source.execute(&selection, &plan).expect("execute");
    assert!(
        matches!(
            outcome.result(),
            Some(TrustedTransactionResult::Committed(_))
        ),
        "{outcome:?}"
    );
    assert_eq!(outcome.preserved_changes(), 2);

    // Neither type change was deleted, overwritten, or recreated as a file.
    for (path, bytes) in [
        ("client/main.lua/inside.lua", &b"operator tree"[..]),
        (
            "client/new_feature.lua/inside.lua",
            &b"operator tree two"[..],
        ),
    ] {
        let child = root.join(path);
        assert!(child.is_file(), "{path} must survive untouched");
        assert_eq!(std::fs::read(&child).expect("child bytes"), bytes);
    }
    assert!(root.join("client/main.lua").is_dir());
    assert!(root.join("client/new_feature.lua").is_dir());

    // Every file whose output still matched the committed apply is back to its original bytes.
    for path in [
        "config.lua",
        "client/custom.lua",
        "fxmanifest.lua",
        "server/main.lua",
    ] {
        assert_eq!(
            std::fs::read(root.join(path)).expect("installed bytes"),
            std::fs::read(original.join(path)).expect("original bytes"),
            "{path} must reverse despite the type changes"
        );
    }
    assert!(root.join("data/customer_notes.txt").is_file());

    let receipts =
        inspect_trusted_undo_receipts(&workspace, &undo_selection(&installed)).expect("receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].preserved_changes(), 2);
    assert!(!receipts[0].fully_reversed());
    assert!(workspace
        .transaction_root()
        .join("transactions")
        .join(parent.to_string())
        .is_dir());
}

/// The other half of a type conflict: a directory the update wrote into is now a file. Writing
/// the reversal would mean removing what the operator put at that name, so every change beneath
/// it is preserved, and the files outside it still reverse.
#[test]
fn trusted_undo_execution_preserves_a_directory_replaced_by_a_file_and_reverses_the_rest() {
    use gkrm_core::*;
    let (_temp, installed, workspace, parent) = committed_undo_fixture();
    let root = installed.join("gksphone");
    let original = fixtures().join("installed/gksphone");

    std::fs::remove_dir_all(root.join("client")).expect("remove the directory");
    std::fs::write(root.join("client"), b"operator put a file here").expect("file in its place");

    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let outcome = source.execute(&selection, &plan).expect("execute");
    assert!(
        matches!(
            outcome.result(),
            Some(TrustedTransactionResult::Committed(_))
        ),
        "{outcome:?}"
    );
    // client/custom.lua, client/main.lua and client/new_feature.lua all sit under the new file.
    assert_eq!(outcome.preserved_changes(), 3);

    assert!(root.join("client").is_file());
    assert_eq!(
        std::fs::read(root.join("client")).expect("file bytes"),
        b"operator put a file here"
    );
    for path in ["config.lua", "fxmanifest.lua", "server/main.lua"] {
        assert_eq!(
            std::fs::read(root.join(path)).expect("installed bytes"),
            std::fs::read(original.join(path)).expect("original bytes"),
            "{path} must reverse although the client directory is gone"
        );
    }
    assert!(root.join("data/customer_notes.txt").is_file());

    let receipts =
        inspect_trusted_undo_receipts(&workspace, &undo_selection(&installed)).expect("receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].preserved_changes(), 3);
    assert!(!receipts[0].fully_reversed());
}

/// The desktop writes its history record after the apply commits, and that write can be lost.
/// The update still happened, and the evidence it published is enough to find it again.
#[test]
fn a_committed_update_is_discoverable_without_any_desktop_record() {
    use gkrm_core::*;
    let (_temp, installed, workspace, parent) = committed_undo_fixture();
    let selection = undo_selection(&installed);

    let updates = inspect_trusted_two_way_updates(&workspace, &selection).expect("history");
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].transaction_id(), &parent);
    assert_eq!(updates[0].resource_key().as_str(), "gksphone");
    assert!(!updates[0].undone());
    assert_eq!(updates[0].preserved_changes(), None);
    assert!(updates[0].summary().take_from_update() > 0);

    // Undoing it is reachable from that locator alone, and the same discovery then says so.
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let outcome = source.execute(&selection, &plan).expect("execute");
    let undo_id = *outcome.transaction_id().expect("Undo transaction");

    let after =
        inspect_trusted_two_way_updates(&workspace, &undo_selection(&installed)).expect("after");
    assert_eq!(after.len(), 1, "the Undo itself is not one of the updates");
    assert_eq!(after[0].transaction_id(), &parent);
    assert!(after[0].undone());
    assert_eq!(after[0].undone_by(), Some(&undo_id));
    assert_eq!(after[0].preserved_changes(), Some(0));
}

/// Discovery is bound to the installation the caller selected, not to the workspace at large.
#[test]
fn discovered_updates_belong_to_the_selected_installation_only() {
    use gkrm_core::*;
    let (temp, _installed, workspace, _parent) = committed_undo_fixture();
    let other = temp.path().join("other-installation");
    copy_tree(&fixtures().join("installed"), &other);

    let updates =
        inspect_trusted_two_way_updates(&workspace, &undo_selection(&other)).expect("history");
    assert!(
        updates.is_empty(),
        "another installation with identical content has no history here: {updates:?}"
    );
}

#[test]
fn trusted_undo_execution_refuses_stale_review_before_publishing_authority_or_writing_live() {
    use gkrm_core::*;
    let (_temp, installed, workspace, parent) = committed_undo_fixture();
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).expect("source");
    let plan = source.plan(&selection).expect("plan");
    std::fs::write(
        installed.join("gksphone/customer-after-review.txt"),
        b"new customer content",
    )
    .expect("new file");
    let before = undo_hash_tree(&installed.join("gksphone"));
    let artifacts = std::fs::read_dir(workspace.artifact_root().path())
        .expect("artifacts")
        .count();
    let transactions = std::fs::read_dir(workspace.transaction_root().join("transactions"))
        .expect("transactions")
        .count();
    assert!(source.execute(&undo_selection(&installed), &plan).is_err());
    assert_eq!(undo_hash_tree(&installed.join("gksphone")), before);
    assert_eq!(
        std::fs::read_dir(workspace.artifact_root().path())
            .expect("artifacts")
            .count(),
        artifacts
    );
    assert_eq!(
        std::fs::read_dir(workspace.transaction_root().join("transactions"))
            .expect("transactions")
            .count(),
        transactions
    );
}

#[test]
fn trusted_undo_execution_missing_parent_evidence_blocks_recovery_without_writes() {
    use gkrm_core::*;
    let (_temp, installed, workspace, parent) = committed_undo_fixture();
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).expect("source");
    let plan = source.plan(&selection).expect("plan");
    let outcome = source.execute(&selection, &plan).expect("execute");
    assert!(matches!(
        outcome.result(),
        Some(TrustedTransactionResult::Committed(_))
    ));
    let inspection = inspect_trusted_published_update_v2(
        &workspace,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .expect("inspect");
    let candidate = inspection.candidate_id().expect("candidate");
    let before = undo_hash_tree(&installed.join("gksphone"));
    drop(source);
    let parent_dir = workspace
        .transaction_root()
        .join("transactions")
        .join(parent.to_string());
    // Synthetic fault: remove one required immutable parent backup object.
    let backup_object = std::fs::read_dir(parent_dir.join("backup/files"))
        .expect("backup objects")
        .next()
        .expect("object")
        .expect("entry")
        .path();
    std::fs::remove_file(backup_object).expect("remove synthetic backup object");
    assert!(
        inspect_trusted_undo_receipts(&workspace, &selection).is_err(),
        "missing parent evidence cannot become a completed receipt"
    );
    let request = TrustedPackageFreeUpdateRecoveryRequest::try_new(
        &workspace,
        candidate,
        &selection,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )
    .expect("request");
    assert!(recover_trusted_published_update_v2(request).is_err());
    assert_eq!(undo_hash_tree(&installed.join("gksphone")), before);
    assert!(parent_dir.is_dir());
}

#[test]
fn already_restored_undo_commits_a_receipt_without_changing_the_live_tree() {
    use gkrm_core::*;
    let (temp, installed, workspace, parent) = committed_undo_fixture();
    let resource = installed.join("gksphone");
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).unwrap();
    for change in source.changes() {
        let path = resource.join(change.path().as_str());
        match source.original_bytes(change.path()).unwrap() {
            Some(bytes) => std::fs::write(path, bytes).unwrap(),
            None => std::fs::remove_file(path).unwrap(),
        }
    }
    let before = undo_hash_tree(&resource);
    assert_eq!(
        before,
        undo_hash_tree(&fixtures().join("installed/gksphone"))
    );
    let selection = undo_selection(&installed);
    let source = TrustedUndoSource::try_open(&workspace, &selection, &parent).unwrap();
    let plan = source.plan(&selection).unwrap();
    let staged = source.stage(&selection, &plan).unwrap();
    assert_eq!(
        staged.plan_apply(&selection).unwrap().status(),
        TrustedApplyStatus::NoFilesystemChanges
    );
    drop(staged);
    let outcome = source.execute(&selection, &plan).unwrap();
    assert!(matches!(
        outcome.result(),
        Some(TrustedTransactionResult::Committed(_))
    ));
    assert_eq!(undo_hash_tree(&resource), before);
    let undo_id = outcome.transaction_id().unwrap();
    let receipts = inspect_trusted_undo_receipts(&workspace, &selection).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].transaction_id(), undo_id);
    assert!(receipts[0].fully_reversed());
    assert!(TrustedUndoSource::try_open(&workspace, &selection, &parent).is_err());
    retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..TrustedTerminalEvidenceRetirementOptions::default()
        },
    )
    .unwrap();
    let applied = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: None,
        baseline: None,
        package: &temp.path().join("update.zip"),
        installed: &installed,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: TwoWayUpdateMode::PreserveLocalEdits,
        choices: &[],
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .unwrap();
    assert_eq!(applied.outcome(), "committed");
    assert_ne!(applied.transaction_id(), Some(&parent));
}

#[test]
fn completed_undo_receipts_allow_reapplication_without_deleting_original_evidence() {
    use gkrm_core::*;
    let (temp, installed, workspace, first) = committed_undo_fixture();
    let applied_tree = undo_hash_tree(&installed.join("gksphone"));
    let original_tree = undo_hash_tree(&fixtures().join("installed/gksphone"));
    let mut parent = first;
    let mut undo_ids = Vec::new();
    let mut forwards = vec![first];
    for cycle in 0..2 {
        let selection = undo_selection(&installed);
        let source = TrustedUndoSource::try_open(&workspace, &selection, &parent)
            .expect("available forward parent");
        let plan = source.plan(&selection).expect("reverse plan");
        let outcome = source.execute(&selection, &plan).expect("Undo");
        assert!(matches!(
            outcome.result(),
            Some(TrustedTransactionResult::Committed(_))
        ));
        let undo_id = *outcome.transaction_id().unwrap();
        assert!(!undo_ids.contains(&undo_id));
        undo_ids.push(undo_id);
        assert_eq!(undo_hash_tree(&installed.join("gksphone")), original_tree);
        let selection = undo_selection(&installed);
        let receipts =
            inspect_trusted_undo_receipts(&workspace, &selection).expect("durable receipts");
        assert_eq!(receipts.len(), cycle + 1);
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.parent_transaction_id() == &parent)
            .unwrap();
        assert_eq!(receipt.transaction_id(), &undo_id);
        assert!(receipt.fully_reversed());
        assert!(
            TrustedUndoSource::try_open(&workspace, &selection, &parent).is_err(),
            "completed parent cannot be undone twice"
        );
        retire_trusted_terminal_update_evidence(
            &workspace,
            TrustedTerminalEvidenceRetirementOptions {
                acknowledged: true,
                ..TrustedTerminalEvidenceRetirementOptions::default()
            },
        )
        .unwrap();
        let package = temp.path().join("update.zip");
        let preview = preview_two_way_update(TwoWayUpdateRequest {
            package: &package,
            installed: &installed,
            baseline: None,
            resource: None,
            transaction_root: workspace.transaction_root(),
            workspace: Some(&workspace),
            options: TrustedCliUpdateOptions::default(),
        })
        .expect("successor preview");
        assert_eq!(preview.plan().causal_context(), Some(&undo_id));
        let applied = apply_two_way_update(TwoWayApplyRequest {
            expected_plan_id: Some(preview.plan().plan_id().digest()),
            baseline: None,
            package: &package,
            installed: &installed,
            resource: None,
            staging_root: workspace.staging_root(),
            transaction_root: workspace.transaction_root(),
            mode: TwoWayUpdateMode::PreserveLocalEdits,
            choices: &[],
            workspace: Some(&workspace),
            options: TrustedCliUpdateOptions::default(),
        })
        .expect("same update reapplies");
        assert_eq!(applied.outcome(), "committed");
        parent = *applied.transaction_id().unwrap();
        assert!(!forwards.contains(&parent));
        forwards.push(parent);
        assert_eq!(undo_hash_tree(&installed.join("gksphone")), applied_tree);
        for original in forwards.iter().chain(undo_ids.iter()) {
            assert!(workspace
                .transaction_root()
                .join("transactions")
                .join(original.to_string())
                .join("backup")
                .is_dir());
        }
    }
}
