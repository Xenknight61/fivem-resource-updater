//! Desktop history locators and a thin adapter over core transactional Undo.
//! JSON file lists, hashes, resource paths and baseline hints never authorize writes.
//! Original bytes and destinations come only from verified committed core authority.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{DesktopFailure, DesktopResult};

/// Directory under the app data root where these records live.
const DIR_NAME: &str = "undo";
/// A record for one update, bounded so a corrupt or hostile file cannot be read without bound.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// The most files one update is recorded as having touched.
const MAX_FILES: usize = 8192;
/// One file, and the content it is expected to hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoFile {
    /// Resource-relative, forward slashes, verified before it is ever joined to a real path.
    pub path: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Exact committed output, including merges. Legacy records have no overwrite authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_sha256: Option<String>,
}

/// What one update did, expressed as what it would take to put it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoRecord {
    /// The history entry this belongs to.
    pub id: String,
    pub resource: String,
    /// The installation root the operator chose, as an absolute path.
    pub installed_root: String,
    /// Where the resource sits inside that root: empty for the root itself, a slash-separated
    /// path otherwise.
    ///
    /// A resource is not obliged to be in a directory named after it, and an operator may point
    /// at either the folder holding it or the resource itself. Guessing from the name got the
    /// second wrong, so the apply records what it actually wrote to instead. `None` is not one of
    /// the two: it is a record written before the apply said, and it keeps the old reading rather
    /// than being guessed at again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    /// Backend-only locator for the original committed core transaction.
    /// Missing legacy locators cannot authorize filesystem changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// What the installation was installed from before this update, by the identity the baseline
    /// store kept it under.
    ///
    /// Undoing puts the installation back to what it was, and what it was installed from is part
    /// of what it was. The update was told that answer, so putting it back is putting back what
    /// this already knew rather than guessing. `None` is an update that was never told — or one
    /// recorded before this was kept — and there the answer is to say nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_baseline_id: Option<String>,
    /// The version that package declared, for saying which one it is. Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_baseline_version: Option<String>,
    /// Files the update replaced, with the digest of what was there before it.
    pub restore: Vec<UndoFile>,
    /// Files the update created, with the digest of what it wrote.
    pub remove: Vec<UndoFile>,
}

/// What undoing actually did, file by file counted rather than claimed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoOutcome {
    /// Files put back from the backup store.
    pub restored: u32,
    /// Files removed because the update had created them.
    pub removed: u32,
    /// Files already holding what they held before the update.
    pub unchanged: u32,
    /// Files left alone because the operator has since changed them themselves.
    pub skipped: u32,
    /// Files whose backup is no longer in the store.
    pub missing: u32,
}

fn dir_for(app_data_root: &Path) -> PathBuf {
    app_data_root.join(DIR_NAME)
}

fn file_for(app_data_root: &Path, id: &str) -> DesktopResult<PathBuf> {
    // The id is ours, but it names a file, so it is checked like anything else that does.
    let acceptable = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if !acceptable {
        return Err(DesktopFailure::InvalidRequest);
    }
    Ok(dir_for(app_data_root).join(format!("{id}.json")))
}

/// Store the record for one update. A failure here costs the ability to undo, never the update.
pub fn write(app_data_root: &Path, record: &UndoRecord) -> DesktopResult<()> {
    if record.restore.len() + record.remove.len() > MAX_FILES {
        return Err(DesktopFailure::InvalidRequest);
    }
    let path = file_for(app_data_root, &record.id)?;
    std::fs::create_dir_all(dir_for(app_data_root)).map_err(|_| DesktopFailure::Internal)?;
    let bytes = serde_json::to_vec(record).map_err(|_| DesktopFailure::Internal)?;
    let temporary = path.with_extension("json.writing");
    {
        let mut file = std::fs::File::create(&temporary).map_err(|_| DesktopFailure::Internal)?;
        file.write_all(&bytes)
            .map_err(|_| DesktopFailure::Internal)?;
        file.sync_all().map_err(|_| DesktopFailure::Internal)?;
    }
    std::fs::rename(&temporary, &path).map_err(|_| DesktopFailure::Internal)?;
    Ok(())
}

/// Read one record back. A missing or unreadable one is simply not undoable.
pub fn read(app_data_root: &Path, id: &str) -> Option<UndoRecord> {
    let path = file_for(app_data_root, id).ok()?;
    let metadata = std::fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    let record: UndoRecord = serde_json::from_slice(&bytes).ok()?;
    (record.restore.len() + record.remove.len() <= MAX_FILES).then_some(record)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoHistoryStatus {
    Unavailable,
    Available,
    Completed { preserved: usize },
}

/// Durable core evidence determines availability and completed history. The JSON
/// record only locates the parent and selected installation.
pub fn history_status(app_data_root: &Path, id: &str) -> UndoHistoryStatus {
    let inspect = || -> Option<UndoHistoryStatus> {
        let record = read(app_data_root, id)?;
        let transaction =
            gkrm_core::Sha256Digest::from_lowercase_hex(record.transaction_id.as_deref()?).ok()?;
        let workspace = gkrm_core::open_existing_trusted_update_workspace(app_data_root).ok()??;
        let root = Path::new(&record.installed_root);
        if !root.is_absolute() {
            return None;
        }
        let key = gkrm_core::SafeResourceKey::parse(&record.resource).ok()?;
        let selection = gkrm_core::scan_trusted_installed_recovery_resources(
            root,
            gkrm_core::InstalledScanLimits::default(),
        )
        .ok()?
        .select(&key)
        .ok()?;
        let receipts = gkrm_core::inspect_trusted_undo_receipts(&workspace, &selection).ok()?;
        if let Some(receipt) = receipts
            .iter()
            .find(|receipt| receipt.parent_transaction_id() == &transaction)
        {
            return Some(UndoHistoryStatus::Completed {
                preserved: receipt.preserved_changes(),
            });
        }
        gkrm_core::TrustedUndoSource::try_open(&workspace, &selection, &transaction).ok()?;
        Some(UndoHistoryStatus::Available)
    };
    inspect().unwrap_or(UndoHistoryStatus::Unavailable)
}

/// Give back the locator for a committed update this has no record of.
///
/// The record an apply writes is best effort and the commit is not, so a crash between the two
/// leaves an update that happened and a history that cannot see it — and an operator who cannot
/// put it back. Core discovery names those updates from the evidence the apply itself published;
/// this turns each one into the locator the History screen and Undo already know how to use.
///
/// Nothing written here grants authority. The locator addresses a committed core transaction,
/// and that transaction is still what has to validate before a byte of the installation is
/// written, exactly as it is for a record that was never lost. The file lists are empty because
/// this did not watch the update run, and core does not need them to reverse it.
///
/// The id is derived from the transaction, so recovering the same update twice recovers it once.
/// Returns how many locators were written.
pub fn restore_missing_locators(
    app_data_root: &Path,
    installed_root: &Path,
    discovered: &[gkrm_core::TrustedTwoWayUpdateRecord],
) -> usize {
    let known: std::collections::BTreeSet<String> = list(app_data_root)
        .into_iter()
        .filter_map(|record| record.transaction_id)
        .collect();
    let mut written = 0;
    for update in discovered {
        let transaction = update.transaction_id().to_string();
        if known.contains(&transaction) {
            continue;
        }
        let Some(id) = recovered_locator_id(&transaction) else {
            continue;
        };
        let summary = update.summary();
        let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
        let record = UndoRecord {
            id: id.clone(),
            resource: update.resource_key().as_str().to_owned(),
            installed_root: installed_root.to_string_lossy().into_owned(),
            // The apply recorded where inside the root the resource sat. This was not there to
            // see it, and the Undo this addresses reads that from the committed transaction
            // rather than from here, so there is nothing to say.
            resource_path: None,
            transaction_id: Some(transaction),
            // What it was installed from is restored from the update's own artifact, not from a
            // hint. Saying nothing here loses nothing.
            previous_baseline_id: None,
            previous_baseline_version: None,
            restore: Vec::new(),
            remove: Vec::new(),
        };
        if write(app_data_root, &record).is_err() {
            continue;
        }
        let _ = crate::history::record_at(
            app_data_root,
            crate::history::RecordedUpdate {
                id: &id,
                resource: update.resource_key().as_str(),
                // Committed is what the journal says. Whether it has since been undone is
                // overlaid from core receipts when the list is read, as it is for any row.
                outcome: "committed",
                reviewed: count(summary.review()),
                replaced: count(summary.take_from_update()),
                total: count(summary.total()),
                from_version: None,
                to_version: None,
            },
            crate::history::TIME_NOT_RECORDED,
        );
        written += 1;
    }
    written
}

/// A locator id for a recovered update, derived from its transaction so it is stable.
fn recovered_locator_id(transaction: &str) -> Option<String> {
    let short = transaction.get(..32)?;
    short
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| format!("recovered-{short}"))
}

/// Every update that can still be put back.
///
/// Read off the directory rather than off the history index: a record is what makes an undo
/// possible, and anything deciding what may be thrown away has to see all of them, including one
/// whose history entry has since been dropped.
pub fn list(app_data_root: &Path) -> Vec<UndoRecord> {
    let Ok(entries) = std::fs::read_dir(dir_for(app_data_root)) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for entry in entries.flatten().take(MAX_FILES) {
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
            continue;
        };
        if let Some(record) = read(app_data_root, id) {
            records.push(record);
        }
    }
    records
}

/// Reopen one recorded parent against a fresh core selection. The JSON root/key
/// only locate it: original transaction authority must bind the same physical root.
pub fn undo(
    workspace: &gkrm_core::TrustedUpdateWorkspace,
    record: &UndoRecord,
) -> DesktopResult<UndoOutcome> {
    use gkrm_core::{
        InstalledScanLimits, SafeResourceKey, Sha256Digest, TrustedTransactionResult,
        TrustedUndoDisposition, TrustedUndoSource,
    };
    let transaction = record
        .transaction_id
        .as_deref()
        .and_then(|value| Sha256Digest::from_lowercase_hex(value).ok())
        .ok_or(DesktopFailure::UndoUnavailable)?;
    let root = Path::new(&record.installed_root);
    if !root.is_absolute() {
        return Err(DesktopFailure::UndoInstallationMissing);
    }
    let key =
        SafeResourceKey::parse(&record.resource).map_err(|_| DesktopFailure::UndoUnavailable)?;
    let selection =
        gkrm_core::scan_trusted_installed_recovery_resources(root, InstalledScanLimits::default())
            .map_err(|_| DesktopFailure::UndoInstallationMissing)?
            .select(&key)
            .map_err(|_| DesktopFailure::UndoUnavailable)?;
    let source = TrustedUndoSource::try_open(workspace, &selection, &transaction)
        .map_err(|_| DesktopFailure::UndoUnavailable)?;
    let plan = source
        .plan(&selection)
        .map_err(|_| DesktopFailure::UndoFailed)?;
    let previous_baseline = source
        .previous_baseline()
        .map_err(|_| DesktopFailure::UndoFailed)?;
    let result = source
        .execute(&selection, &plan)
        .map_err(|_| DesktopFailure::UndoFailed)?;
    match result.result() {
        None | Some(TrustedTransactionResult::Committed(_)) => {}
        Some(TrustedTransactionResult::RolledBack(_)) => return Err(DesktopFailure::UndoFailed),
        Some(_) => return Err(DesktopFailure::RecoveryRequired),
    }
    let mut outcome = UndoOutcome::default();
    for entry in plan.entries() {
        match entry.disposition() {
            TrustedUndoDisposition::RestoreOriginal => outcome.restored += 1,
            TrustedUndoDisposition::RemoveCreated => outcome.removed += 1,
            TrustedUndoDisposition::AlreadyOriginal => outcome.unchanged += 1,
            TrustedUndoDisposition::PreserveChanged => outcome.skipped += 1,
        }
    }
    if let Some(baseline) = previous_baseline {
        crate::installed_baseline::record(
            workspace.app_root(),
            crate::installed_baseline::InstalledBaseline {
                installed_root: record.installed_root.clone(),
                resource: baseline.resource_key().as_str().to_owned(),
                baseline_id: baseline.baseline_id().to_string(),
                version: baseline.resource_version().map(str::to_owned),
            },
        );
    } else {
        crate::installed_baseline::forget(workspace.app_root(), &record.installed_root);
    }
    // Keep the locator and all core evidence until durable Undo receipts reconcile it.
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gkrm_core::*;
    use zip::write::SimpleFileOptions;

    fn fixture() -> (tempfile::TempDir, TrustedUpdateWorkspace, UndoRecord) {
        fixture_with_baseline(false)
    }

    fn fixture_with_baseline(
        keep_prior: bool,
    ) -> (tempfile::TempDir, TrustedUpdateWorkspace, UndoRecord) {
        let temp = tempfile::tempdir().unwrap();
        let installed = temp.path().join("resources");
        let resource = installed.join("gksphone");
        std::fs::create_dir_all(&resource).unwrap();
        let manifest = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {'config.lua'}\n";
        for (path, bytes) in [
            ("fxmanifest.lua", manifest.as_slice()),
            ("config.lua", b"old config"),
            ("client.lua", b"old code"),
        ] {
            std::fs::write(resource.join(path), bytes).unwrap();
        }
        let package = temp.path().join("update.zip");
        let mut archive = zip::ZipWriter::new(std::fs::File::create(&package).unwrap());
        for (path, bytes) in [
            ("fxmanifest.lua", manifest.as_slice()),
            ("config.lua", b"new config"),
            ("client.lua", b"new code"),
            ("added.lua", b"new file"),
        ] {
            archive
                .start_file(format!("gksphone/{path}"), SimpleFileOptions::default())
                .unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap();
        let appdata = temp.path().join("appdata");
        std::fs::create_dir(&appdata).unwrap();
        let workspace = resolve_trusted_update_workspace(&appdata).unwrap();
        let baseline = temp.path().join("prior.zip");
        if keep_prior {
            let mut archive = zip::ZipWriter::new(std::fs::File::create(&baseline).unwrap());
            for (path, bytes) in [
                ("fxmanifest.lua", manifest.as_slice()),
                ("config.lua", b"old config"),
                ("client.lua", b"old code"),
            ] {
                archive
                    .start_file(format!("gksphone/{path}"), SimpleFileOptions::default())
                    .unwrap();
                archive.write_all(bytes).unwrap();
            }
            archive.finish().unwrap();
        }
        let applied = apply_two_way_update(TwoWayApplyRequest {
            expected_plan_id: None,
            baseline: keep_prior.then_some(TwoWayBaselineSource::Package(&baseline)),
            package: &package,
            installed: &installed,
            resource: None,
            staging_root: workspace.staging_root(),
            transaction_root: workspace.transaction_root(),
            mode: TwoWayUpdateMode::ReplaceWithIncoming,
            choices: &[],
            workspace: Some(&workspace),
            options: TrustedCliUpdateOptions::default(),
        })
        .unwrap();
        assert_eq!(applied.outcome(), "committed");
        let record = UndoRecord {
            id: "test-undo".into(),
            resource: "gksphone".into(),
            installed_root: installed.to_string_lossy().into_owned(),
            resource_path: Some("../untrusted-path".into()),
            transaction_id: Some(applied.transaction_id().unwrap().to_string()),
            previous_baseline_id: Some("untrusted-baseline".into()),
            previous_baseline_version: Some("untrusted-version".into()),
            restore: vec![UndoFile {
                path: "../outside.txt".into(),
                sha256: "not-a-digest".into(),
                written_sha256: None,
            }],
            remove: vec![],
        };
        write(workspace.app_root(), &record).unwrap();
        (temp, workspace, record)
    }

    /// The commit is durable and the record written after it is not. Losing that record must
    /// cost a row on a screen, not the operator's ability to put the update back.
    #[test]
    fn a_committed_update_whose_record_was_lost_is_found_and_can_still_be_put_back() {
        let (temp, workspace, record) = fixture();
        let root = PathBuf::from(&record.installed_root);
        let resource = root.join("gksphone");
        std::fs::remove_file(file_for(workspace.app_root(), &record.id).unwrap()).unwrap();
        assert!(list(workspace.app_root()).is_empty());
        assert!(crate::history::list(workspace.app_root()).is_empty());

        let selection =
            scan_trusted_installed_recovery_resources(&root, InstalledScanLimits::default())
                .unwrap()
                .select(&SafeResourceKey::parse("gksphone").unwrap())
                .unwrap();
        let discovered = inspect_trusted_two_way_updates(&workspace, &selection).unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(
            restore_missing_locators(workspace.app_root(), &root, &discovered),
            1
        );
        // The id comes from the transaction, so looking again recovers nothing a second time.
        assert_eq!(
            restore_missing_locators(workspace.app_root(), &root, &discovered),
            0
        );

        let recovered = list(workspace.app_root());
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].transaction_id, record.transaction_id);
        assert!(recovered[0].restore.is_empty());
        assert!(recovered[0].remove.is_empty());
        assert_eq!(recovered[0].resource_path, None);
        assert_eq!(
            history_status(workspace.app_root(), &recovered[0].id),
            UndoHistoryStatus::Available
        );

        let entries = crate::history::list(workspace.app_root());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].applied_at_ms,
            crate::history::TIME_NOT_RECORDED,
            "a time nobody observed must not be invented"
        );

        std::fs::remove_file(temp.path().join("update.zip")).unwrap();
        undo(&workspace, &recovered[0]).unwrap();
        assert_eq!(
            std::fs::read(resource.join("config.lua")).unwrap(),
            b"old config"
        );
        assert_eq!(
            std::fs::read(resource.join("client.lua")).unwrap(),
            b"old code"
        );
        assert!(!resource.join("added.lua").exists());
    }

    #[test]
    fn undo_restores_baseline_from_core_evidence_and_ignores_forged_json_metadata() {
        let (temp, workspace, record) = fixture_with_baseline(true);
        let root = Path::new(&record.installed_root);
        let selection =
            scan_trusted_installed_recovery_resources(root, InstalledScanLimits::default())
                .unwrap()
                .select(&SafeResourceKey::parse("gksphone").unwrap())
                .unwrap();
        let parent =
            Sha256Digest::from_lowercase_hex(record.transaction_id.as_deref().unwrap()).unwrap();
        let prior = TrustedUndoSource::try_open(&workspace, &selection, &parent)
            .unwrap()
            .previous_baseline()
            .unwrap()
            .unwrap();
        assert_ne!(
            Some(prior.baseline_id().as_str()),
            record.previous_baseline_id.as_deref()
        );
        std::fs::remove_file(temp.path().join("prior.zip")).unwrap();
        std::fs::remove_file(temp.path().join("update.zip")).unwrap();
        undo(&workspace, &record).unwrap();
        let remembered = crate::installed_baseline::lookup(workspace.app_root(), root).unwrap();
        assert_eq!(remembered.baseline_id, prior.baseline_id().as_str());
        assert_eq!(remembered.version.as_deref(), prior.resource_version());
    }

    #[test]
    fn core_authority_restores_actual_files_ignores_json_paths_and_keeps_evidence() {
        let (temp, workspace, record) = fixture();
        let outside = temp.path().join("outside.txt");
        std::fs::write(&outside, b"outside sentinel").unwrap();
        let root = Path::new(&record.installed_root).join("gksphone");
        crate::installed_baseline::record(
            workspace.app_root(),
            crate::installed_baseline::InstalledBaseline {
                installed_root: record.installed_root.clone(),
                resource: record.resource.clone(),
                baseline_id: "applied-package-hint".into(),
                version: None,
            },
        );
        std::fs::remove_file(temp.path().join("update.zip")).unwrap();
        let outcome = undo(&workspace, &record).unwrap();
        assert_eq!(outcome.restored, 2);
        assert_eq!(outcome.removed, 1);
        assert_eq!(outcome.missing, 0);
        assert_eq!(
            std::fs::read(root.join("config.lua")).unwrap(),
            b"old config"
        );
        assert_eq!(std::fs::read(root.join("client.lua")).unwrap(), b"old code");
        assert!(!root.join("added.lua").exists());
        assert_eq!(std::fs::read(outside).unwrap(), b"outside sentinel");
        assert!(read(workspace.app_root(), &record.id).is_some());
        assert_eq!(
            history_status(workspace.app_root(), &record.id),
            UndoHistoryStatus::Completed { preserved: 0 }
        );
        assert_eq!(
            undo(&workspace, &record),
            Err(DesktopFailure::UndoUnavailable)
        );
        assert!(workspace
            .transaction_root()
            .join("transactions")
            .join(record.transaction_id.unwrap())
            .join("backup")
            .is_dir());
        assert!(crate::installed_baseline::lookup(
            workspace.app_root(),
            Path::new(&record.installed_root)
        )
        .is_none());
    }

    #[test]
    fn an_identical_other_root_cannot_be_authorized_by_an_edited_json_locator() {
        let (temp, workspace, mut record) = fixture();
        let other = temp.path().join("other");
        std::fs::create_dir_all(other.join("gksphone")).unwrap();
        let original = Path::new(&record.installed_root).join("gksphone");
        for entry in std::fs::read_dir(&original).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), other.join("gksphone").join(entry.file_name())).unwrap();
        }
        record.installed_root = other.to_string_lossy().into_owned();
        assert_eq!(
            undo(&workspace, &record),
            Err(DesktopFailure::UndoUnavailable)
        );
        assert_eq!(
            std::fs::read(other.join("gksphone/config.lua")).unwrap(),
            b"new config"
        );
        assert_eq!(
            std::fs::read(original.join("config.lua")).unwrap(),
            b"new config"
        );
    }

    #[test]
    fn legacy_hash_lists_without_core_transaction_authority_are_not_undoable() {
        let (_temp, workspace, mut record) = fixture();
        record.transaction_id = None;
        write(workspace.app_root(), &record).unwrap();
        assert_eq!(
            history_status(workspace.app_root(), &record.id),
            UndoHistoryStatus::Unavailable
        );
        assert_eq!(
            undo(&workspace, &record),
            Err(DesktopFailure::UndoUnavailable)
        );
        assert_eq!(
            std::fs::read(Path::new(&record.installed_root).join("gksphone/config.lua")).unwrap(),
            b"new config"
        );
    }

    #[test]
    fn completed_history_is_derived_from_core_receipt_with_preservation_count() {
        let (_temp, workspace, record) = fixture();
        let config = Path::new(&record.installed_root).join("gksphone/config.lua");
        std::fs::write(&config, b"customer changed this after Apply").unwrap();
        let outcome = undo(&workspace, &record).unwrap();
        assert_eq!(outcome.skipped, 1);
        assert_eq!(
            history_status(workspace.app_root(), &record.id),
            UndoHistoryStatus::Completed { preserved: 1 }
        );
        assert_eq!(
            std::fs::read(config).unwrap(),
            b"customer changed this after Apply"
        );
        assert!(read(workspace.app_root(), &record.id).is_some());
    }
}
