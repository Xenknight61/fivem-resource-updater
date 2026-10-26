//! Backup creation and sealing for Task 23.

use std::io::Write;

use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{create_new_child_dir, create_new_file, open_child_dir};
use crate::baseline::store::{fsync_file, sync_dir};
use crate::trusted_transactional_apply_planning::TrustedBackupEntry;
use crate::{
    ApplyBackupRequirement, GkrmError, InstalledApplyPlanningSource, Result, Sha256Digest,
    TransactionalApplyIoOperation,
};

use super::id::encode_backup_seal;
use super::journal::{map_baseline_to_io, map_io, AppendArgs, JournalCursor};
use super::paths::{copy_file_to_backup, open_parent, split_parent_name, verify_present_file};
use super::TransactionJournalEvent;
use crate::trusted_apply_planning::ApplyFileState;

pub(crate) fn ensure_backup_layout(txn_dir: &CapDir) -> Result<(CapDir, CapDir, CapDir)> {
    let backup = create_or_open(txn_dir, "backup")?;
    let files = create_or_open(&backup, "files")?;
    let dirs = create_or_open(&backup, "directories")?;
    Ok((backup, files, dirs))
}

fn create_or_open(parent: &CapDir, name: &str) -> Result<CapDir> {
    use crate::baseline::fs_security::try_open_child_dir;
    match try_open_child_dir(parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::CreateBackupDirectory, e))?
    {
        Some(dir) => Ok(dir),
        None => create_new_child_dir(parent, name).map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateBackupDirectory, e)
        }),
    }
}

pub(crate) fn create_and_seal_backup(
    txn_dir: &CapDir,
    journal_dir: &CapDir,
    cursor: &mut JournalCursor,
    installed: &InstalledApplyPlanningSource,
    plan_id: &Sha256Digest,
    snapshot_a: &Sha256Digest,
    entries: &[TrustedBackupEntry],
    max_backup_bytes: u64,
    max_journal_bytes: u64,
    max_journal_records: usize,
) -> Result<Sha256Digest> {
    let (backup_dir, files_dir, dirs_dir) = ensure_backup_layout(txn_dir)?;
    let resource = installed
        .open_resource_dir()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    installed
        .validate_identities()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;

    let mut total_bytes = 0_u64;
    let mut entry_ids = Vec::new();
    let mut entry_content = Vec::new();

    for entry in entries {
        entry_ids.push(*entry.entry_id.digest());
        let name = entry.entry_id.digest().to_string();
        match entry.kind {
            ApplyBackupRequirement::PreserveInstalledFile => {
                let digest = entry
                    .digest
                    .as_ref()
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete)?;
                let len = entry
                    .byte_length
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete)?;
                verify_present_file(
                    &resource,
                    &entry.destination,
                    &ApplyFileState::Present {
                        digest: *digest,
                        byte_length: len,
                    },
                )?;
                let parent = open_parent(&resource, &entry.destination)?;
                let (_, file_name) = split_parent_name(&entry.destination)?;
                #[cfg(test)]
                if super::hooks::force_backup_copy_failure() {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
                }
                let (got_d, got_l) = copy_file_to_backup(&parent, file_name, &files_dir, &name)?;
                #[cfg(test)]
                if super::hooks::force_backup_sync_failure() {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
                        operation: TransactionalApplyIoOperation::SyncBackupObject,
                        kind: std::io::ErrorKind::Other,
                    });
                }
                if &got_d != digest || got_l != len {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
                }
                total_bytes = total_bytes
                    .checked_add(got_l)
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
                if total_bytes > max_backup_bytes {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
                        limit: "max_backup_bytes",
                    });
                }
                entry_content.push((*entry.entry_id.digest(), 1_u8, Some(got_d), Some(got_l)));
            }
            ApplyBackupRequirement::PreserveRemovedDirectoryMetadata => {
                let parent = open_parent(&resource, &entry.destination)?;
                let (_, dir_name) = split_parent_name(&entry.destination)?;
                let _dir = open_child_dir(&parent, dir_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e)
                })?;
                let meta_name = format!("{name}.meta");
                let mut meta = create_new_file(&dirs_dir, &meta_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::CreateBackupDirectory, e)
                })?;
                meta.write_all(&[1_u8])
                    .map_err(|e| map_io(TransactionalApplyIoOperation::WriteBackupObject, e))?;
                fsync_file(&meta, &meta_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::SyncBackupObject, e)
                })?;
                entry_content.push((*entry.entry_id.digest(), 2_u8, None, None));
            }
            ApplyBackupRequirement::None => {
                return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
            }
        }

        super::journal::append_record(
            journal_dir,
            cursor,
            AppendArgs {
                plan_id,
                snapshot_a,
                event: TransactionJournalEvent::BackupEntryCompleted,
                related_step_id: None,
                related_entry_id: Some(entry.entry_id.digest()),
                max_journal_bytes,
                max_journal_records,
            },
        )?;
    }

    let seal = encode_backup_seal(plan_id, &entry_ids, &entry_content)?;
    #[cfg(test)]
    if super::hooks::force_backup_seal_failure() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupSealMismatch);
    }

    // manifest.bin
    let mut manifest_bytes = Vec::new();
    manifest_bytes.extend_from_slice(b"gkrm-txn-backup-manifest-v1\n");
    manifest_bytes.extend_from_slice(plan_id.as_bytes());
    manifest_bytes.extend_from_slice(&(entry_ids.len() as u64).to_be_bytes());
    for id in &entry_ids {
        manifest_bytes.extend_from_slice(id.as_bytes());
    }
    let mut manifest = create_new_file(&backup_dir, "manifest.bin")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::WriteBackupManifest, e))?;
    manifest
        .write_all(&manifest_bytes)
        .map_err(|e| map_io(TransactionalApplyIoOperation::WriteBackupManifest, e))?;
    fsync_file(&manifest, "manifest.bin")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncBackupObject, e))?;

    let mut seal_file = create_new_file(&backup_dir, "seal.bin")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::WriteBackupSeal, e))?;
    seal_file
        .write_all(seal.as_bytes())
        .map_err(|e| map_io(TransactionalApplyIoOperation::WriteBackupSeal, e))?;
    fsync_file(&seal_file, "seal.bin")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncBackupObject, e))?;
    sync_dir(&backup_dir, "backup")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncBackupObject, e))?;

    #[cfg(test)]
    {
        use std::io::Write as _;
        if super::hooks::inject_backup_root_extra_file() {
            let mut f = create_new_file(&backup_dir, "evil.bin").map_err(|e| {
                map_baseline_to_io(TransactionalApplyIoOperation::WriteBackupObject, e)
            })?;
            f.write_all(b"x")
                .map_err(|e| map_io(TransactionalApplyIoOperation::WriteBackupObject, e))?;
        }
        if super::hooks::inject_backup_root_extra_dir() {
            create_new_child_dir(&backup_dir, "extra-dir").map_err(|e| {
                map_baseline_to_io(TransactionalApplyIoOperation::CreateBackupDirectory, e)
            })?;
        }
        if super::hooks::inject_backup_root_temp_file() {
            let mut f = create_new_file(&backup_dir, ".gkrm-tmp-pollute").map_err(|e| {
                map_baseline_to_io(TransactionalApplyIoOperation::WriteBackupObject, e)
            })?;
            f.write_all(b"tmp")
                .map_err(|e| map_io(TransactionalApplyIoOperation::WriteBackupObject, e))?;
        }
    }

    revalidate_complete_backup(
        &backup_dir,
        &files_dir,
        &dirs_dir,
        plan_id,
        &entry_ids,
        &entry_content,
        &seal,
        &manifest_bytes,
    )?;
    sync_dir(&backup_dir, "backup")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncBackupObject, e))?;
    sync_dir(txn_dir, "transaction")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncBackupObject, e))?;

    cursor.backup_seal = Some(seal);
    super::journal::append_record(
        journal_dir,
        cursor,
        AppendArgs {
            plan_id,
            snapshot_a,
            event: TransactionJournalEvent::BackupComplete,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes,
            max_journal_records,
        },
    )?;
    Ok(seal)
}

pub(crate) fn revalidate_complete_backup(
    backup_dir: &CapDir,
    files_dir: &CapDir,
    dirs_dir: &CapDir,
    plan_id: &Sha256Digest,
    entry_ids: &[Sha256Digest],
    entry_content: &[(Sha256Digest, u8, Option<Sha256Digest>, Option<u64>)],
    expected_seal: &Sha256Digest,
    expected_manifest: &[u8],
) -> Result<()> {
    use crate::baseline::fs_security::{open_file_nofollow, verify_regular_file};
    use std::collections::BTreeSet;
    use std::io::Read;

    #[cfg(test)]
    if super::hooks::force_backup_final_revalidate_failure() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
    }

    verify_exact_backup_root_namespace(backup_dir)?;

    let mut expected_files = BTreeSet::new();
    let mut expected_metas = BTreeSet::new();
    for (entry_id, kind, digest, len) in entry_content {
        let name = entry_id.to_string();
        match kind {
            1 => {
                expected_files.insert(name.clone());
                let file = open_file_nofollow(files_dir, &name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e)
                })?;
                verify_regular_file(&file, &name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e)
                })?;
                let (got_d, got_l) = super::paths::hash_file(&file)?;
                let Some(exp_d) = digest else {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
                };
                let Some(exp_l) = len else {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
                };
                if &got_d != exp_d || got_l != *exp_l {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
                }
            }
            2 => {
                let meta_name = format!("{name}.meta");
                expected_metas.insert(meta_name.clone());
                let mut meta = open_file_nofollow(dirs_dir, &meta_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e)
                })?;
                verify_regular_file(&meta, &meta_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e)
                })?;
                let mut bytes = Vec::new();
                meta.read_to_end(&mut bytes)
                    .map_err(|e| map_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
                if bytes.as_slice() != [1_u8] {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
                }
            }
            _ => return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete),
        }
    }

    let mut seen_files = BTreeSet::new();
    for entry in files_dir
        .entries()
        .map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?
    {
        let entry =
            entry.map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete)?;
        if !expected_files.contains(&name) {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
        if !seen_files.insert(name) {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
    }
    if seen_files != expected_files {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
    }

    let mut seen_metas = BTreeSet::new();
    for entry in dirs_dir
        .entries()
        .map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?
    {
        let entry =
            entry.map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete)?;
        if !expected_metas.contains(&name) {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
        if !seen_metas.insert(name) {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
    }
    if seen_metas != expected_metas {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
    }

    let mut manifest = open_file_nofollow(backup_dir, "manifest.bin")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
    let mut got_manifest = Vec::new();
    manifest
        .read_to_end(&mut got_manifest)
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
    if got_manifest.as_slice() != expected_manifest {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupSealMismatch);
    }

    let mut seal_file = open_file_nofollow(backup_dir, "seal.bin")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
    let mut got_seal_bytes = Vec::new();
    seal_file
        .read_to_end(&mut got_seal_bytes)
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
    if got_seal_bytes.as_slice() != expected_seal.as_bytes() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupSealMismatch);
    }
    let recomputed = encode_backup_seal(plan_id, entry_ids, entry_content)?;
    if &recomputed != expected_seal {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupSealMismatch);
    }
    Ok(())
}

fn verify_exact_backup_root_namespace(backup_dir: &CapDir) -> Result<()> {
    use crate::baseline::fs_security::{
        open_child_dir, open_file_nofollow, try_open_child_dir, verify_regular_file,
    };
    use std::collections::BTreeSet;

    const REQUIRED: &[&str] = &["files", "directories", "manifest.bin", "seal.bin"];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in backup_dir
        .entries()
        .map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?
    {
        let entry =
            entry.map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete)?;
        let canonical = name.to_ascii_lowercase();
        let expected_canonical = REQUIRED
            .iter()
            .find(|r| r.eq_ignore_ascii_case(&name))
            .copied();
        let Some(expected_name) = expected_canonical else {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        };
        if name != expected_name {
            // Case/normalization collision against the canonical child name.
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
        if !seen.insert(canonical) {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
        match expected_name {
            "files" | "directories" => {
                open_child_dir(backup_dir, expected_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e)
                })?;
            }
            "manifest.bin" | "seal.bin" => {
                let file = open_file_nofollow(backup_dir, expected_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e)
                })?;
                verify_regular_file(&file, expected_name).map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e)
                })?;
            }
            _ => return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete),
        }
    }
    for required in REQUIRED {
        if !seen.contains(&required.to_ascii_lowercase()) {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
        // Re-open to catch type swaps between enumerate and open.
        if (*required == "files" || *required == "directories")
            && try_open_child_dir(backup_dir, required)
                .map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e)
                })?
                .is_none()
        {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
        }
    }
    Ok(())
}

/// Point-of-use sealed backup revalidation for Task 24 recovery (under held locks).
pub(crate) fn revalidate_sealed_backup_for_recovery(
    txn_dir: &CapDir,
    plan_id: &Sha256Digest,
    entries: &[TrustedBackupEntry],
    expected_seal: &Sha256Digest,
) -> Result<()> {
    use crate::baseline::fs_security::{open_child_dir, open_file_nofollow};

    let backup_dir = open_child_dir(txn_dir, "backup")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
    let files_dir = open_child_dir(&backup_dir, "files")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
    let dirs_dir = open_child_dir(&backup_dir, "directories")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;

    let mut entry_ids = Vec::new();
    let mut entry_content = Vec::new();
    for entry in entries {
        entry_ids.push(*entry.entry_id.digest());
        match entry.kind {
            ApplyBackupRequirement::PreserveInstalledFile => {
                let digest = entry
                    .digest
                    .as_ref()
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete)?;
                let len = entry
                    .byte_length
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete)?;
                entry_content.push((*entry.entry_id.digest(), 1_u8, Some(*digest), Some(len)));
            }
            ApplyBackupRequirement::PreserveRemovedDirectoryMetadata => {
                entry_content.push((*entry.entry_id.digest(), 2_u8, None, None));
            }
            ApplyBackupRequirement::None => {
                return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
            }
        }
    }

    let mut manifest_bytes = Vec::new();
    manifest_bytes.extend_from_slice(b"gkrm-txn-backup-manifest-v1\n");
    manifest_bytes.extend_from_slice(plan_id.as_bytes());
    manifest_bytes.extend_from_slice(&(entry_ids.len() as u64).to_be_bytes());
    for id in &entry_ids {
        manifest_bytes.extend_from_slice(id.as_bytes());
    }

    let _ = open_file_nofollow(&backup_dir, "seal.bin")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;

    revalidate_complete_backup(
        &backup_dir,
        &files_dir,
        &dirs_dir,
        plan_id,
        &entry_ids,
        &entry_content,
        expected_seal,
        &manifest_bytes,
    )
}
