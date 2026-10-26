//! Path helpers and installed/staging mutation primitives for Task 23.

use std::io::{Read, Write};

use cap_std::fs::Dir as CapDir;
use sha2::{Digest, Sha256};

use crate::baseline::fs_security::{
    create_new_child_dir, create_new_file, open_child_dir, open_file_nofollow, try_open_child_dir,
    verify_regular_file,
};
use crate::baseline::store::{fsync_file, sync_dir};
use crate::file_identity::capture_stable_dir_identity;
use crate::trusted_apply_planning::ApplyFileState;
use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest, TransactionalApplyIoOperation};

use super::journal::{map_baseline_to_io, map_io};

/// Closed live-state probe for rollback selection. Never collapses I/O/unsafe into booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RollbackProbe {
    ProvenAbsent,
    ProvenRegularFile,
    ProvenDirectory,
    Ambiguous,
}

/// Closed match probe against an expected present file pre-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RollbackFileMatchProbe {
    ProvenMatch,
    ProvenMismatch,
    ProvenAbsent,
    Ambiguous,
}

pub(super) fn probe_destination(resource: &CapDir, path: &ResourceRelativePath) -> RollbackProbe {
    #[cfg(test)]
    if super::hooks::force_rollback_probe_ambiguous() {
        return RollbackProbe::Ambiguous;
    }
    if path.as_str().is_empty() {
        return RollbackProbe::Ambiguous;
    }
    let parent = match open_parent(resource, path) {
        Ok(parent) => parent,
        Err(_) => return RollbackProbe::Ambiguous,
    };
    let name = match split_parent_name(path) {
        Ok((_, name)) => name,
        Err(_) => return RollbackProbe::Ambiguous,
    };

    let dir_result = try_open_child_dir(&parent, name);
    let file_result = open_file_nofollow(&parent, name);

    match (dir_result, file_result) {
        (Ok(Some(dir)), Err(_)) => match dir.dir_metadata() {
            Ok(meta) if meta.file_type().is_dir() => RollbackProbe::ProvenDirectory,
            _ => RollbackProbe::Ambiguous,
        },
        (Ok(Some(_)), Ok(_)) => RollbackProbe::Ambiguous,
        (Ok(None), Ok(_)) => RollbackProbe::ProvenRegularFile,
        (Ok(None), Err(GkrmError::BaselineStoreMissing { .. })) => RollbackProbe::ProvenAbsent,
        (Ok(None), Err(GkrmError::BaselineStoreIo { cause: source, .. }))
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            RollbackProbe::ProvenAbsent
        }
        // Windows: opening a regular file as a directory fails with a non-NotFound error.
        (Err(_), Ok(_)) => RollbackProbe::ProvenRegularFile,
        (Err(_), Err(GkrmError::BaselineStoreMissing { .. })) => RollbackProbe::Ambiguous,
        (Err(_), Err(GkrmError::BaselineStoreIo { cause: source, .. }))
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            RollbackProbe::Ambiguous
        }
        (Ok(None), Err(_)) | (Err(_), Err(_)) => RollbackProbe::Ambiguous,
    }
}

pub(super) fn probe_file_pre_state(
    resource: &CapDir,
    path: &ResourceRelativePath,
    expected: &ApplyFileState,
) -> RollbackFileMatchProbe {
    #[cfg(test)]
    if super::hooks::force_rollback_probe_ambiguous() {
        return RollbackFileMatchProbe::Ambiguous;
    }
    let ApplyFileState::Present {
        digest,
        byte_length,
    } = expected
    else {
        return RollbackFileMatchProbe::Ambiguous;
    };
    match probe_destination(resource, path) {
        RollbackProbe::ProvenAbsent => RollbackFileMatchProbe::ProvenAbsent,
        RollbackProbe::ProvenDirectory | RollbackProbe::Ambiguous => {
            RollbackFileMatchProbe::Ambiguous
        }
        RollbackProbe::ProvenRegularFile => match verify_present_file(resource, path, expected) {
            Ok(()) => RollbackFileMatchProbe::ProvenMatch,
            Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch) => {
                let _ = (digest, byte_length);
                RollbackFileMatchProbe::ProvenMismatch
            }
            Err(_) => RollbackFileMatchProbe::Ambiguous,
        },
    }
}

pub(super) fn split_parent_name(path: &ResourceRelativePath) -> Result<(Vec<&str>, &str)> {
    let s = path.as_str();
    if s.is_empty() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    let mut parts: Vec<&str> = s.split('/').collect();
    let name = parts
        .pop()
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionForwardFailed)?;
    Ok((parts, name))
}

pub(super) fn open_parent(resource: &CapDir, path: &ResourceRelativePath) -> Result<CapDir> {
    let (parts, _) = split_parent_name(path)?;
    let mut cur = resource
        .try_clone()
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?;
    for part in parts {
        cur = open_child_dir(&cur, part).map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e)
        })?;
    }
    Ok(cur)
}

pub(super) fn hash_file(file: &cap_std::fs::File) -> Result<(Sha256Digest, u64)> {
    let mut file = file
        .try_clone()
        .map_err(|e| map_io(TransactionalApplyIoOperation::HashFile, e))?;
    use std::io::Seek;
    file.rewind()
        .map_err(|e| map_io(TransactionalApplyIoOperation::HashFile, e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| map_io(TransactionalApplyIoOperation::HashFile, e))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
        hasher.update(&buf[..n]);
    }
    Ok((Sha256Digest::new(hasher.finalize().into()), total))
}

pub(super) fn verify_present_file(
    resource: &CapDir,
    path: &ResourceRelativePath,
    expected: &ApplyFileState,
) -> Result<()> {
    let ApplyFileState::Present {
        digest,
        byte_length,
    } = expected
    else {
        return Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch);
    };
    let parent = open_parent(resource, path)?;
    let (_, name) = split_parent_name(path)?;
    let file = open_file_nofollow(&parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledFile, e))?;
    verify_regular_file(&file, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e))?;
    let (got_d, got_l) = hash_file(&file)?;
    if &got_d != digest || got_l != *byte_length {
        return Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch);
    }
    Ok(())
}

pub(super) fn verify_absent_file(resource: &CapDir, path: &ResourceRelativePath) -> Result<()> {
    let parent = open_parent(resource, path)?;
    let (_, name) = split_parent_name(path)?;
    if try_open_child_dir(&parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?
        .is_some()
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch);
    }
    // Only NotFound/Missing proves absence; any other open outcome fails closed.
    match open_file_nofollow(&parent, name) {
        Ok(_) => Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch),
        Err(GkrmError::BaselineStoreMissing { .. }) => Ok(()),
        Err(GkrmError::BaselineStoreIo { cause: source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        Err(_) => Err(GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject),
    }
}

pub(super) fn verify_directory_present(
    resource: &CapDir,
    path: &ResourceRelativePath,
) -> Result<()> {
    if path.as_str().is_empty() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    let parent = open_parent(resource, path)?;
    let (_, name) = split_parent_name(path)?;
    let dir = open_child_dir(&parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?;
    let meta = dir
        .dir_metadata()
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?;
    if !meta.file_type().is_dir() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject);
    }
    Ok(())
}

pub(super) fn verify_path_absent(resource: &CapDir, path: &ResourceRelativePath) -> Result<()> {
    verify_absent_file(resource, path)
}

pub(super) fn delete_file(resource: &CapDir, path: &ResourceRelativePath) -> Result<()> {
    let parent = open_parent(resource, path)?;
    let (_, name) = split_parent_name(path)?;
    parent
        .remove_file(name)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RemoveInstalledFile, e))?;
    sync_dir(&parent, "parent").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
    })?;
    Ok(())
}

pub(super) fn remove_directory(resource: &CapDir, path: &ResourceRelativePath) -> Result<()> {
    if path.as_str().is_empty() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    #[cfg(test)]
    if super::hooks::force_remove_directory_failure() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed);
    }
    let parent = open_parent(resource, path)?;
    let parent_id = capture_stable_dir_identity(&parent)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RevalidateIdentity, e))?;
    let (_, name) = split_parent_name(path)?;
    let dir = open_child_dir(&parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?;
    let meta = dir
        .dir_metadata()
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?;
    if !meta.file_type().is_dir() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject);
    }
    let mut count = 0usize;
    for entry in dir
        .entries()
        .map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?
    {
        let _ = entry.map_err(|e| map_io(TransactionalApplyIoOperation::EnumerateInstalled, e))?;
        count = count
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    }
    if count != 0 {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    drop(dir);
    parent
        .remove_dir(name)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RemoveInstalledDirectory, e))?;
    #[cfg(test)]
    if super::hooks::force_directory_remains_after_remove() {
        create_new_child_dir(&parent, name).map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateInstalledDirectory, e)
        })?;
    }
    #[cfg(test)]
    if super::hooks::force_parent_identity_replacement_on_remove() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionRootReplaced);
    }
    let parent_after = capture_stable_dir_identity(&parent)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RevalidateIdentity, e))?;
    if parent_after != parent_id {
        return Err(GkrmError::TrustedTransactionalApplyExecutionRootReplaced);
    }
    sync_dir(&parent, "parent").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
    })?;
    Ok(())
}

pub(super) fn create_directory(resource: &CapDir, path: &ResourceRelativePath) -> Result<()> {
    if path.as_str().is_empty() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    let parent = open_parent(resource, path)?;
    let parent_id = capture_stable_dir_identity(&parent)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RevalidateIdentity, e))?;
    let (_, name) = split_parent_name(path)?;
    if try_open_child_dir(&parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?
        .is_some()
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch);
    }
    match open_file_nofollow(&parent, name) {
        Ok(_) => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch);
        }
        Err(GkrmError::BaselineStoreMissing { .. }) => {}
        Err(GkrmError::BaselineStoreIo { cause: source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject);
        }
    }
    create_new_child_dir(&parent, name).map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::CreateInstalledDirectory, e)
    })?;
    let reopened = open_child_dir(&parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?;
    let meta = reopened
        .dir_metadata()
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenInstalledResource, e))?;
    if !meta.file_type().is_dir() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject);
    }
    drop(reopened);
    let parent_after = capture_stable_dir_identity(&parent)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RevalidateIdentity, e))?;
    if parent_after != parent_id {
        return Err(GkrmError::TrustedTransactionalApplyExecutionRootReplaced);
    }
    sync_dir(&parent, "parent").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
    })?;
    Ok(())
}

pub(super) fn install_or_replace_file(
    resource: &CapDir,
    path: &ResourceRelativePath,
    bytes: &[u8],
    expected_digest: &Sha256Digest,
    expected_len: u64,
    replace: bool,
) -> Result<()> {
    let parent = open_parent(resource, path)?;
    let (_, name) = split_parent_name(path)?;
    let temp = {
        let mut seed = Sha256::new();
        seed.update(name.as_bytes());
        seed.update(expected_len.to_le_bytes());
        seed.update(expected_digest.as_bytes());
        seed.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                .to_le_bytes(),
        );
        format!(
            ".gkrm-{}",
            seed.finalize()
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    };
    let mut file = create_new_file(&parent, &temp)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::CreateInstalledFile, e))?;
    file.write_all(bytes)
        .map_err(|e| map_io(TransactionalApplyIoOperation::CreateInstalledFile, e))?;
    fsync_file(&file, &temp)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledFile, e))?;
    drop(file);
    let reopened = open_file_nofollow(&parent, &temp)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledFile, e))?;
    let (got_d, got_l) = hash_file(&reopened)?;
    drop(reopened);
    if &got_d != expected_digest || got_l != expected_len {
        let _ = parent.remove_file(&temp);
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    if replace {
        super::publish::publish_replace(&parent, &temp, name, expected_digest, expected_len)
    } else {
        super::publish::publish_install(&parent, &temp, name, expected_digest, expected_len)
    }
}

pub(super) fn read_staging_file(
    resource: &CapDir,
    path: &ResourceRelativePath,
) -> Result<(Vec<u8>, Sha256Digest, u64)> {
    let parent = open_parent(resource, path)?;
    let (_, name) = split_parent_name(path)?;
    let file = open_file_nofollow(&parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenStagingResource, e))?;
    verify_regular_file(&file, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e))?;
    let (digest, len) = hash_file(&file)?;
    let mut file = file;
    use std::io::Seek;
    file.rewind()
        .map_err(|e| map_io(TransactionalApplyIoOperation::ReadStagingFile, e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| map_io(TransactionalApplyIoOperation::ReadStagingFile, e))?;
    if u64::try_from(bytes.len()).ok() != Some(len) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    Ok((bytes, digest, len))
}

pub(super) fn copy_file_to_backup(
    src_parent: &CapDir,
    src_name: &str,
    dst_parent: &CapDir,
    dst_name: &str,
) -> Result<(Sha256Digest, u64)> {
    let src = open_file_nofollow(src_parent, src_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenInstalledFile, e))?;
    verify_regular_file(&src, src_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::VerifyRegularFile, e))?;
    let mut dst = create_new_file(dst_parent, dst_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::CreateBackupFile, e))?;
    let mut src = src;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let n = src
            .read(&mut buf)
            .map_err(|e| map_io(TransactionalApplyIoOperation::HashFile, e))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
        hasher.update(&buf[..n]);
        dst.write_all(&buf[..n])
            .map_err(|e| map_io(TransactionalApplyIoOperation::WriteBackupObject, e))?;
    }
    fsync_file(&dst, dst_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncBackupObject, e))?;
    drop(dst);
    let reopened = open_file_nofollow(dst_parent, dst_name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
    let (got_d, got_l) = hash_file(&reopened)?;
    let digest = Sha256Digest::new(hasher.finalize().into());
    if got_d != digest || got_l != total {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete);
    }
    Ok((digest, total))
}
