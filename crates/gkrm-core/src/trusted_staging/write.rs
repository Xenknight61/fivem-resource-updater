//! Write, publish, and post-rename verification for trusted staging.

use std::collections::BTreeSet;
use std::io::{Read, Write};

use cap_std::fs::Dir as CapDir;
use sha2::{Digest, Sha256};

use crate::baseline::fs_security::{
    create_new_child_dir, create_new_file, open_child_dir, open_file_nofollow, try_open_child_dir,
    validate_single_component, verify_regular_file,
};
use crate::baseline::store::{allocate_temp_name, fsync_file, rename_noreplace_relative, sync_dir};
use crate::{
    GkrmError, MergedByteDisposition, Result, Sha256Digest, StagingIoOperation,
    ThreeWayMergedBytesPlan,
};

use super::manifest::encode_manifest_bytes;
use super::root::{note_staging_mutation, TrustedStagingRoot};
use super::sources::{IncomingStagingContentSource, InstalledStagingContentSource};
use super::{
    StagingContentOrigin, StagingFinalState, StagingSourceBinding, TrustedStagingManifest,
};

/// Closed input family: ordinary package bytes or a verified committed Undo backup.
#[derive(Clone, Copy)]
pub(super) enum AuxiliaryContentSource<'a> {
    Package(&'a IncomingStagingContentSource),
    Undo {
        source: &'a crate::TrustedUndoSource,
        directories: &'a BTreeSet<crate::ResourceRelativePath>,
    },
}

impl AuxiliaryContentSource<'_> {
    fn stream_verified(
        &self,
        path: &crate::ResourceRelativePath,
        digest: Sha256Digest,
        mut on_chunk: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        match self {
            Self::Package(source) => source.stream_verified(path, digest, on_chunk),
            Self::Undo { source, .. } => {
                super::note_source_read();
                let change = source
                    .changes()
                    .iter()
                    .find(|entry| entry.path() == path)
                    .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
                if change.before() != Some(&digest) {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
                let bytes = source
                    .original_bytes(path)?
                    .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
                for chunk in bytes.chunks(64 * 1024) {
                    on_chunk(chunk)?;
                }
                Ok(bytes.len() as u64)
            }
        }
    }
}

const UNTRUSTED_MARKER: &str = ".gkrm-untrusted-v1";

pub(super) struct PublishedBundleCaps {
    pub(super) published_dir: CapDir,
    pub(super) resource_dir: CapDir,
}

/// Owns a published child after atomic rename until staging fully succeeds.
///
/// Constructed inactive (with cleanup capability) before rename, then armed
/// infallibly immediately after rename. Explicit cleanup preserves compound
/// errors; `Drop` is a best-effort safety net only.
pub(super) struct PublishedBundleGuard {
    bundles_dir: CapDir,
    published_name: String,
    armed: bool,
}

impl PublishedBundleGuard {
    fn new_inactive(bundles_dir: CapDir, published_name: String) -> Self {
        Self {
            bundles_dir,
            published_name,
            armed: false,
        }
    }

    /// Infallible: call immediately after successful rename with no intervening `?`.
    fn arm(&mut self) {
        self.armed = true;
    }

    /// Disarm only immediately before returning `Ok(TrustedStagingBundle)`.
    pub(super) fn disarm(mut self) {
        self.armed = false;
    }

    /// Post-rename verification failure: wrap primary and clean up/quarantine.
    pub(super) fn fail_post_publish(mut self, primary: GkrmError) -> GkrmError {
        self.armed = false;
        fail_after_publish(primary, &self.bundles_dir, &self.published_name)
    }

    /// Later top-level failure after a verified publish: preserve primary, clean up.
    pub(super) fn fail_with_cleanup(mut self, primary: GkrmError) -> GkrmError {
        if !self.armed {
            // An adopted bundle belongs to its original publisher. A later
            // caller's validation failure must never delete retained evidence.
            return primary;
        }
        self.armed = false;
        match remove_or_quarantine_published(&self.bundles_dir, &self.published_name) {
            Ok(()) => sanitize_boundary(StagingIoOperation::RemovePublished, primary),
            Err(cleanup) => GkrmError::TrustedStagingFailedWithCleanupFailure {
                primary: Box::new(sanitize_boundary(
                    StagingIoOperation::RemovePublished,
                    primary,
                )),
                cleanup: Box::new(GkrmError::TrustedStagingCleanupFailed {
                    source: Box::new(sanitize_boundary(
                        StagingIoOperation::RemovePublished,
                        cleanup,
                    )),
                }),
            },
        }
    }
}

impl Drop for PublishedBundleGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_or_quarantine_published(&self.bundles_dir, &self.published_name);
        }
    }
}

/// Capability-relative reopen check: a directory name matching a manifest ID is never
/// sufficient trust. Rejects untrusted markers and re-runs full tree verification.
#[allow(dead_code)]
pub(crate) fn revalidate_published_child(
    bundles_dir: &CapDir,
    published_name: &str,
    manifest: &TrustedStagingManifest,
) -> Result<(CapDir, CapDir)> {
    let published_dir = open_child_dir(bundles_dir, published_name).map_err(map_fs)?;
    if open_file_nofollow(&published_dir, UNTRUSTED_MARKER).is_ok() {
        return Err(GkrmError::TrustedStagingUnsafeFilesystemObject);
    }
    let resource_dir = open_child_dir(&published_dir, "resource").map_err(map_fs)?;
    final_verify(&published_dir, &resource_dir, manifest)?;
    Ok((published_dir, resource_dir))
}

/// Read-only verification of an already-retained published bundle.
///
/// Never removes, quarantines, repairs, rewrites, or creates markers.
pub(crate) fn verify_published_bundle_readonly(
    published_dir: &CapDir,
    resource_dir: &CapDir,
    manifest: &TrustedStagingManifest,
) -> Result<()> {
    final_verify(published_dir, resource_dir, manifest)
}

pub(crate) fn read_published_manifest_bytes(
    published_dir: &CapDir,
    max_manifest_bytes: u64,
) -> Result<Vec<u8>> {
    let manifest_file = open_file_nofollow(published_dir, "manifest.bin").map_err(map_fs)?;
    verify_regular_file(&manifest_file, "manifest.bin").map_err(map_fs)?;
    let read_limit = max_manifest_bytes
        .checked_add(1)
        .ok_or(GkrmError::TrustedStagingManifestTreeMismatch)?;
    let capacity = usize::try_from(max_manifest_bytes)
        .map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?;
    let mut bytes = Vec::with_capacity(capacity.min(8192));
    manifest_file
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(io_write)?;
    if u64::try_from(bytes.len()).map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?
        > max_manifest_bytes
    {
        return Err(GkrmError::TrustedStagingLimitExceeded {
            limit: "max_manifest_bytes",
        });
    }
    Ok(bytes)
}

pub(super) fn ensure_internal_layout(root: &TrustedStagingRoot) -> Result<(CapDir, CapDir)> {
    note_staging_mutation();
    root.revalidate_identity()?;
    let tmp = match try_open_child_dir(root.dir(), ".tmp")
        .map_err(|e| map_fs_op(StagingIoOperation::CreateInternalDirectory, e))?
    {
        Some(dir) => dir,
        None => {
            note_staging_mutation();
            create_new_child_dir(root.dir(), ".tmp")
                .map_err(|e| map_fs_op(StagingIoOperation::CreateInternalDirectory, e))?
        }
    };
    let bundles = match try_open_child_dir(root.dir(), "bundles")
        .map_err(|e| map_fs_op(StagingIoOperation::CreateInternalDirectory, e))?
    {
        Some(dir) => dir,
        None => {
            note_staging_mutation();
            create_new_child_dir(root.dir(), "bundles")
                .map_err(|e| map_fs_op(StagingIoOperation::CreateInternalDirectory, e))?
        }
    };
    Ok((tmp, bundles))
}

pub(super) fn write_and_publish(
    root: &TrustedStagingRoot,
    tmp_root: &CapDir,
    bundles_dir: &CapDir,
    manifest: &TrustedStagingManifest,
    installed: &InstalledStagingContentSource,
    incoming: AuxiliaryContentSource<'_>,
    merged_bytes: Option<&ThreeWayMergedBytesPlan>,
    operator_merges: &[crate::trusted_staging::TrustedStagingOperatorMergeInput<'_>],
) -> Result<(PublishedBundleCaps, PublishedBundleGuard)> {
    let published_name = manifest.manifest_id.digest().to_string();
    // A bundle is named by the digest of its own manifest, so a name that already exists holds
    // either exactly what is about to be written or something that has been tampered with. An
    // operator applying the same update twice reaches the first case, and refusing it told them
    // their update could not be planned. Verify what is there against the manifest in hand and
    // adopt it if it matches; refuse otherwise, as before.
    if let Some(existing) = try_open_child_dir(bundles_dir, &published_name)
        .map_err(|e| map_fs_op(StagingIoOperation::OpenPublishedBundle, e))?
    {
        let adopted = (|| -> Result<PublishedBundleCaps> {
            let resource_dir = open_child_dir(&existing, "resource")
                .map_err(|e| map_fs_op(StagingIoOperation::OpenPublishedBundle, e))?;
            final_verify(&existing, &resource_dir, manifest)?;
            Ok(PublishedBundleCaps {
                published_dir: existing.try_clone().map_err(|source| {
                    staging_io(StagingIoOperation::CloneCleanupCapability, source)
                })?,
                resource_dir,
            })
        })();
        let caps = adopted.map_err(|_| GkrmError::TrustedStagingDestinationExists)?;
        // Never armed: this bundle was already there and is not ours to remove on failure.
        let cleanup_capability = bundles_dir
            .try_clone()
            .map_err(|source| staging_io(StagingIoOperation::CloneCleanupCapability, source))?;
        return Ok((
            caps,
            PublishedBundleGuard::new_inactive(cleanup_capability, published_name),
        ));
    }

    note_staging_mutation();
    let temp_name = allocate_temp_name(tmp_root)
        .map_err(|e| map_fs_op(StagingIoOperation::CreateTempDirectory, e))?;
    note_staging_mutation();
    {
        let temp_dir = create_new_child_dir(tmp_root, &temp_name)
            .map_err(|e| map_fs_op(StagingIoOperation::CreateTempDirectory, e))?;
        let write_result = (|| -> Result<()> {
            note_staging_mutation();
            let resource_dir = create_new_child_dir(&temp_dir, "resource")
                .map_err(|e| map_fs_op(StagingIoOperation::CreateResourceDirectory, e))?;
            write_present_files(
                &resource_dir,
                manifest,
                installed,
                incoming,
                merged_bytes,
                operator_merges,
            )?;
            write_manifest_bin(&temp_dir, manifest)?;
            #[cfg(test)]
            crate::trusted_staging::run_before_temp_verify_hook(&temp_dir);
            verify_resource_tree(&resource_dir, manifest)?;
            verify_temp_bundle_root(&temp_dir)?;
            sync_tree(&temp_dir, &resource_dir, manifest)?;
            root.revalidate_identity()?;
            Ok(())
        })();

        if let Err(primary) = write_result {
            drop(temp_dir);
            return Err(cleanup_temp_child(tmp_root, &temp_name, primary));
        }
        // Drop all handles into the temp child before Windows rename.
    }

    #[cfg(test)]
    crate::trusted_staging::run_before_rename_hook(tmp_root, bundles_dir, &published_name);

    // Re-check destination after any concurrent attacker insertion.
    if try_open_child_dir(bundles_dir, &published_name)
        .map_err(|e| map_fs_op(StagingIoOperation::OpenPublishedBundle, e))?
        .is_some()
    {
        return Err(cleanup_temp_child(
            tmp_root,
            &temp_name,
            GkrmError::TrustedStagingDestinationExists,
        ));
    }

    // Prepare everything the publication guard needs before rename.
    #[cfg(test)]
    if crate::trusted_staging::force_cleanup_capability_clone_failure_enabled() {
        return Err(cleanup_temp_child(
            tmp_root,
            &temp_name,
            GkrmError::TrustedStagingIo {
                operation: StagingIoOperation::CloneCleanupCapability,
                kind: std::io::ErrorKind::Other,
            },
        ));
    }
    let cleanup_capability = match bundles_dir.try_clone() {
        Ok(dir) => dir,
        Err(source) => {
            return Err(cleanup_temp_child(
                tmp_root,
                &temp_name,
                staging_io(StagingIoOperation::CloneCleanupCapability, source),
            ));
        }
    };
    let mut published_guard =
        PublishedBundleGuard::new_inactive(cleanup_capability, published_name.clone());

    note_staging_mutation();
    if let Err(source) =
        rename_noreplace_relative(tmp_root, &temp_name, bundles_dir, &published_name)
    {
        let rename_err = if source.kind() == std::io::ErrorKind::AlreadyExists {
            GkrmError::TrustedStagingDestinationExists
        } else {
            staging_io(StagingIoOperation::RenamePublish, source)
        };
        return Err(cleanup_temp_child(tmp_root, &temp_name, rename_err));
    }

    // No fallible statements between successful rename and arming.
    published_guard.arm();

    #[cfg(test)]
    crate::trusted_staging::run_after_rename_hook(bundles_dir, &published_name);

    let post_rename = (|| -> Result<PublishedBundleCaps> {
        // Make the published directory entry durable before reopen/verify.
        sync_dir(bundles_dir, "bundles")
            .map_err(|e| map_fs_op(StagingIoOperation::SyncDirectory, e))?;
        let published_dir = open_child_dir(bundles_dir, &published_name)
            .map_err(|e| map_fs_op(StagingIoOperation::OpenPublishedBundle, e))?;
        let published_resource = open_child_dir(&published_dir, "resource")
            .map_err(|e| map_fs_op(StagingIoOperation::OpenPublishedBundle, e))?;

        #[cfg(test)]
        crate::trusted_staging::run_after_publish_hook(bundles_dir, &published_name);

        final_verify(&published_dir, &published_resource, manifest)?;
        Ok(PublishedBundleCaps {
            published_dir,
            resource_dir: published_resource,
        })
    })();

    match post_rename {
        Ok(caps) => Ok((caps, published_guard)),
        Err(primary) => Err(published_guard.fail_post_publish(primary)),
    }
}

fn cleanup_temp_child(tmp_root: &CapDir, temp_name: &str, primary: GkrmError) -> GkrmError {
    let primary = sanitize_boundary(StagingIoOperation::RemoveTemp, primary);
    #[cfg(test)]
    if crate::trusted_staging::force_temp_cleanup_failure_enabled() {
        return GkrmError::TrustedStagingFailedWithCleanupFailure {
            primary: Box::new(primary),
            cleanup: Box::new(GkrmError::TrustedStagingCleanupFailed {
                source: Box::new(GkrmError::TrustedStagingIo {
                    operation: StagingIoOperation::RemoveTemp,
                    kind: std::io::ErrorKind::Other,
                }),
            }),
        };
    }
    match remove_staging_child(tmp_root, temp_name, StagingIoOperation::RemoveTemp) {
        Ok(()) => primary,
        Err(cleanup) => GkrmError::TrustedStagingFailedWithCleanupFailure {
            primary: Box::new(primary),
            cleanup: Box::new(GkrmError::TrustedStagingCleanupFailed {
                source: Box::new(sanitize_boundary(StagingIoOperation::RemoveTemp, cleanup)),
            }),
        },
    }
}

fn fail_after_publish(primary: GkrmError, bundles_dir: &CapDir, published_name: &str) -> GkrmError {
    let wrapped = GkrmError::TrustedStagingPostPublishVerificationFailed {
        source: Box::new(sanitize_boundary(
            StagingIoOperation::VerifyPublishedBundle,
            primary,
        )),
    };
    match remove_or_quarantine_published(bundles_dir, published_name) {
        Ok(()) => wrapped,
        Err(cleanup) => GkrmError::TrustedStagingFailedWithCleanupFailure {
            primary: Box::new(wrapped),
            cleanup: Box::new(GkrmError::TrustedStagingCleanupFailed {
                source: Box::new(sanitize_boundary(
                    StagingIoOperation::RemovePublished,
                    cleanup,
                )),
            }),
        },
    }
}

fn write_present_files(
    resource_dir: &CapDir,
    manifest: &TrustedStagingManifest,
    installed: &InstalledStagingContentSource,
    incoming: AuxiliaryContentSource<'_>,
    merged_bytes: Option<&ThreeWayMergedBytesPlan>,
    operator_merges: &[crate::trusted_staging::TrustedStagingOperatorMergeInput<'_>],
) -> Result<()> {
    #[cfg(test)]
    crate::trusted_staging::run_before_write_present_files_hook();
    if let AuxiliaryContentSource::Undo { directories, .. } = incoming {
        for path in directories {
            let parent = open_parent_dir(resource_dir, path)?;
            let name = file_name(path)?;
            if try_open_child_dir(&parent, name).map_err(map_fs)?.is_none() {
                note_staging_mutation();
                create_new_child_dir(&parent, name).map_err(map_fs)?;
            }
        }
    }
    for entry in &manifest.entries {
        if entry.final_state == StagingFinalState::Absent {
            continue;
        }
        let digest = entry
            .expected_digest
            .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
        let expected_len = entry
            .expected_byte_length
            .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
        ensure_parent_dirs(resource_dir, entry.path())?;
        let file_name = file_name(entry.path())?;
        let parent = open_parent_dir(resource_dir, entry.path())?;
        note_staging_mutation();
        let mut dest = create_new_file(&parent, file_name)
            .map_err(|e| map_fs_op(StagingIoOperation::CreateFile, e))?;
        let mut hasher = Sha256::new();
        let mut total = 0_u64;

        match (&entry.origin, &entry.source_binding) {
            (StagingContentOrigin::Installed, StagingSourceBinding::InstalledDigest(expected)) => {
                if *expected != digest {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
                let len = installed.stream_verified(entry.path(), digest, |chunk| {
                    accumulate(&mut total, &mut hasher, chunk)?;
                    write_chunk(&mut dest, chunk)
                })?;
                if len != expected_len || len != total {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
            }
            (StagingContentOrigin::Incoming, StagingSourceBinding::IncomingDigest(expected)) => {
                if *expected != digest {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
                let len = incoming.stream_verified(entry.path(), digest, |chunk| {
                    accumulate(&mut total, &mut hasher, chunk)?;
                    write_chunk(&mut dest, chunk)
                })?;
                if len != expected_len || len != total {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
            }
            (StagingContentOrigin::Merged, StagingSourceBinding::MergedArtifact(id)) => {
                let plan = merged_bytes.ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
                let mb_entry = plan
                    .entries()
                    .iter()
                    .find(|e| e.path() == entry.path())
                    .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
                if mb_entry.disposition() != MergedByteDisposition::ReadyForStaging {
                    return Err(GkrmError::TrustedStagingManualMergeResult);
                }
                let artifact = mb_entry
                    .artifact()
                    .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
                let artifact_id = mb_entry
                    .artifact_id()
                    .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
                if artifact_id.digest() != id.digest() {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
                let bytes = artifact.bytes_for_staging();
                if bytes.len() as u64 != expected_len || artifact.digest_for_staging() != &digest {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
                accumulate(&mut total, &mut hasher, bytes)?;
                write_chunk(&mut dest, bytes)?;
            }
            (StagingContentOrigin::Merged, StagingSourceBinding::OperatorMerge(id)) => {
                let op = operator_merges
                    .iter()
                    .find(|m| m.path == entry.path() && &m.artifact_id == id)
                    .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
                if op.bytes.len() as u64 != expected_len || op.content_digest != digest {
                    return Err(GkrmError::TrustedStagingDigestLengthMismatch);
                }
                accumulate(&mut total, &mut hasher, op.bytes)?;
                write_chunk(&mut dest, op.bytes)?;
            }
            _ => return Err(GkrmError::TrustedStagingFinalTreeRejected),
        }

        dest.flush()
            .map_err(|e| staging_io(StagingIoOperation::FlushFile, e))?;
        fsync_file(&dest, "staging-file")
            .map_err(|e| map_fs_op(StagingIoOperation::SyncFile, e))?;
        drop(dest);
        let reopened = open_file_nofollow(&parent, file_name)
            .map_err(|e| map_fs_op(StagingIoOperation::OpenFile, e))?;
        verify_regular_file(&reopened, file_name)
            .map_err(|e| map_fs_op(StagingIoOperation::OpenFile, e))?;
        let (actual_digest, actual_len) = hash_file(&reopened)?;
        if actual_digest != digest || actual_len != expected_len {
            return Err(GkrmError::TrustedStagingDigestLengthMismatch);
        }
        let written = Sha256Digest::new(hasher.finalize().into());
        if written != digest {
            return Err(GkrmError::TrustedStagingDigestLengthMismatch);
        }
    }
    if let AuxiliaryContentSource::Undo { directories, .. } = incoming {
        for path in directories.iter().rev() {
            let parent = open_parent_dir(resource_dir, path)?;
            let dir = open_child_dir(&parent, file_name(path)?).map_err(map_fs)?;
            sync_dir(&dir, "undo-staging-directory").map_err(map_fs)?;
        }
    }
    Ok(())
}

fn write_manifest_bin(temp_dir: &CapDir, manifest: &TrustedStagingManifest) -> Result<()> {
    let bytes = encode_manifest_bytes(manifest)?;
    note_staging_mutation();
    let mut file = create_new_file(temp_dir, "manifest.bin")
        .map_err(|e| map_fs_op(StagingIoOperation::CreateFile, e))?;
    file.write_all(&bytes)
        .map_err(|e| staging_io(StagingIoOperation::WriteDestination, e))?;
    file.flush()
        .map_err(|e| staging_io(StagingIoOperation::FlushFile, e))?;
    fsync_file(&file, "manifest.bin").map_err(|e| map_fs_op(StagingIoOperation::SyncFile, e))?;
    Ok(())
}

fn verify_resource_tree(resource_dir: &CapDir, manifest: &TrustedStagingManifest) -> Result<()> {
    let expected: BTreeSet<String> = manifest
        .entries
        .iter()
        .filter(|e| e.final_state != StagingFinalState::Absent)
        .map(|e| e.path().as_str().to_owned())
        .collect();
    let mut found = BTreeSet::new();
    enumerate_files(resource_dir, "", &mut found)?;
    if found != expected {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    Ok(())
}

fn final_verify(
    published_dir: &CapDir,
    resource_dir: &CapDir,
    manifest: &TrustedStagingManifest,
) -> Result<()> {
    if open_file_nofollow(published_dir, UNTRUSTED_MARKER).is_ok() {
        return Err(GkrmError::TrustedStagingUnsafeFilesystemObject);
    }
    let mut names = BTreeSet::new();
    for entry in published_dir.entries().map_err(io_enum)? {
        let entry = entry.map_err(io_enum)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?;
        names.insert(name);
    }
    if names.len() != 2 || !names.contains("resource") || !names.contains("manifest.bin") {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    verify_resource_tree(resource_dir, manifest)?;
    for entry in &manifest.entries {
        if entry.final_state == StagingFinalState::Absent {
            continue;
        }
        let digest = entry
            .expected_digest
            .ok_or(GkrmError::TrustedStagingDigestLengthMismatch)?;
        let expected_len = entry
            .expected_byte_length
            .ok_or(GkrmError::TrustedStagingDigestLengthMismatch)?;
        let file_name = file_name(entry.path())?;
        let parent = open_parent_dir(resource_dir, entry.path())?;
        let file = open_file_nofollow(&parent, file_name).map_err(map_fs)?;
        verify_regular_file(&file, file_name).map_err(map_fs)?;
        let (actual_digest, actual_len) = hash_file(&file)?;
        if actual_digest != digest || actual_len != expected_len {
            return Err(GkrmError::TrustedStagingDigestLengthMismatch);
        }
    }
    let manifest_file = open_file_nofollow(published_dir, "manifest.bin").map_err(map_fs)?;
    let expected = encode_manifest_bytes(manifest)?;
    let read_limit = u64::try_from(expected.len())
        .map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?
        .checked_add(1)
        .ok_or(GkrmError::TrustedStagingManifestTreeMismatch)?;
    let mut bytes = Vec::with_capacity(expected.len());
    manifest_file
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(io_write)?;
    if bytes != expected {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    Ok(())
}

fn sync_tree(
    temp_dir: &CapDir,
    resource_dir: &CapDir,
    manifest: &TrustedStagingManifest,
) -> Result<()> {
    let mut synced = BTreeSet::new();
    for entry in &manifest.entries {
        if entry.final_state == StagingFinalState::Absent {
            continue;
        }
        let components: Vec<_> = entry.path().as_str().split('/').collect();
        if components.len() <= 1 {
            continue;
        }
        let mut current = resource_dir
            .try_clone()
            .map_err(|e| staging_io(StagingIoOperation::SyncDirectory, e))?;
        let mut key = String::new();
        for component in &components[..components.len() - 1] {
            if key.is_empty() {
                key.push_str(component);
            } else {
                key.push('/');
                key.push_str(component);
            }
            current = open_child_dir(&current, component)
                .map_err(|e| map_fs_op(StagingIoOperation::SyncDirectory, e))?;
            if synced.insert(key.clone()) {
                sync_dir(&current, "staging-parent")
                    .map_err(|e| map_fs_op(StagingIoOperation::SyncDirectory, e))?;
            }
        }
    }
    sync_dir(resource_dir, "resource")
        .map_err(|e| map_fs_op(StagingIoOperation::SyncDirectory, e))?;
    sync_dir(temp_dir, "temp-bundle")
        .map_err(|e| map_fs_op(StagingIoOperation::SyncDirectory, e))?;
    Ok(())
}

fn verify_temp_bundle_root(temp_dir: &CapDir) -> Result<()> {
    let mut names = BTreeSet::new();
    for entry in temp_dir.entries().map_err(io_enum)? {
        let entry = entry.map_err(io_enum)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?;
        names.insert(name);
    }
    if names.len() != 2 || !names.contains("resource") || !names.contains("manifest.bin") {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    Ok(())
}

fn remove_or_quarantine_published(bundles_dir: &CapDir, published_name: &str) -> Result<()> {
    #[cfg(test)]
    if crate::trusted_staging::force_cleanup_failure_enabled() {
        quarantine_published(bundles_dir, published_name)?;
        return Err(GkrmError::TrustedStagingCleanupFailed {
            source: Box::new(GkrmError::TrustedStagingIo {
                operation: StagingIoOperation::RemovePublished,
                kind: std::io::ErrorKind::Other,
            }),
        });
    }
    match remove_staging_child(
        bundles_dir,
        published_name,
        StagingIoOperation::RemovePublished,
    ) {
        Ok(()) => Ok(()),
        Err(removal) => match quarantine_published(bundles_dir, published_name) {
            Ok(()) => Err(sanitize_boundary(
                StagingIoOperation::RemovePublished,
                removal,
            )),
            Err(quarantine) => Err(GkrmError::TrustedStagingFailedWithCleanupFailure {
                primary: Box::new(sanitize_boundary(
                    StagingIoOperation::RemovePublished,
                    removal,
                )),
                cleanup: Box::new(GkrmError::TrustedStagingCleanupFailed {
                    source: Box::new(sanitize_boundary(
                        StagingIoOperation::QuarantinePublished,
                        quarantine,
                    )),
                }),
            }),
        },
    }
}

fn quarantine_published(bundles_dir: &CapDir, published_name: &str) -> Result<()> {
    #[cfg(test)]
    if crate::trusted_staging::force_quarantine_failure_enabled() {
        return Err(GkrmError::TrustedStagingCleanupFailed {
            source: Box::new(GkrmError::TrustedStagingIo {
                operation: StagingIoOperation::QuarantinePublished,
                kind: std::io::ErrorKind::Other,
            }),
        });
    }
    let Some(published) = try_open_child_dir(bundles_dir, published_name)
        .map_err(|e| map_fs_op(StagingIoOperation::QuarantinePublished, e))?
    else {
        return Ok(());
    };
    if open_file_nofollow(&published, UNTRUSTED_MARKER).is_ok() {
        return Ok(());
    }
    note_staging_mutation();
    let mut marker = create_new_file(&published, UNTRUSTED_MARKER)
        .map_err(|e| map_fs_op(StagingIoOperation::QuarantinePublished, e))?;
    marker
        .write_all(b"untrusted")
        .map_err(|e| staging_io(StagingIoOperation::QuarantinePublished, e))?;
    marker
        .flush()
        .map_err(|e| staging_io(StagingIoOperation::QuarantinePublished, e))?;
    Ok(())
}

fn remove_staging_child(parent: &CapDir, name: &str, op: StagingIoOperation) -> Result<()> {
    validate_single_component(name).map_err(|e| map_fs_op(op, e))?;
    let Some(child) = try_open_child_dir(parent, name).map_err(|e| map_fs_op(op, e))? else {
        return Ok(());
    };
    clear_staging_tree(&child, op)?;
    drop(child);
    parent.remove_dir(name).map_err(|e| staging_io(op, e))?;
    Ok(())
}

fn clear_staging_tree(dir: &CapDir, op: StagingIoOperation) -> Result<()> {
    let entries: Vec<_> = dir
        .entries()
        .map_err(|e| staging_io(op, e))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| staging_io(op, e))?;
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?;
        validate_single_component(&name).map_err(|e| map_fs_op(op, e))?;
        let meta = entry.metadata().map_err(|e| staging_io(op, e))?;
        if meta.file_type().is_dir() {
            let nested = open_child_dir(dir, &name).map_err(|e| map_fs_op(op, e))?;
            clear_staging_tree(&nested, op)?;
            drop(nested);
            dir.remove_dir(&name).map_err(|e| staging_io(op, e))?;
        } else if meta.file_type().is_file() {
            let file = open_file_nofollow(dir, &name).map_err(|e| map_fs_op(op, e))?;
            drop(file);
            dir.remove_file(&name).map_err(|e| staging_io(op, e))?;
        } else {
            return Err(GkrmError::TrustedStagingUnsafeFilesystemObject);
        }
    }
    Ok(())
}

fn ensure_parent_dirs(resource_dir: &CapDir, path: &crate::ResourceRelativePath) -> Result<()> {
    let components: Vec<_> = path.as_str().split('/').collect();
    if components.len() <= 1 {
        return Ok(());
    }
    let mut current = resource_dir.try_clone().map_err(io_write)?;
    for component in &components[..components.len() - 1] {
        current = match try_open_child_dir(&current, component).map_err(map_fs)? {
            Some(dir) => dir,
            None => {
                note_staging_mutation();
                create_new_child_dir(&current, component).map_err(map_fs)?
            }
        };
    }
    Ok(())
}

fn open_parent_dir(resource_dir: &CapDir, path: &crate::ResourceRelativePath) -> Result<CapDir> {
    let components: Vec<_> = path.as_str().split('/').collect();
    let mut current = resource_dir.try_clone().map_err(io_write)?;
    if components.len() <= 1 {
        return Ok(current);
    }
    for component in &components[..components.len() - 1] {
        current = open_child_dir(&current, component).map_err(map_fs)?;
    }
    Ok(current)
}

fn file_name(path: &crate::ResourceRelativePath) -> Result<&str> {
    path.as_str()
        .rsplit('/')
        .next()
        .ok_or(GkrmError::TrustedStagingFinalTreeRejected)
}

fn enumerate_files(dir: &CapDir, prefix: &str, out: &mut BTreeSet<String>) -> Result<()> {
    for entry in dir.entries().map_err(io_enum)? {
        let entry = entry.map_err(io_enum)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?;
        let meta = entry.metadata().map_err(io_enum)?;
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if meta.file_type().is_dir() {
            let child = open_child_dir(dir, &name).map_err(map_fs)?;
            enumerate_files(&child, &rel, out)?;
        } else if meta.file_type().is_file() {
            out.insert(rel);
        } else {
            return Err(GkrmError::TrustedStagingUnsafeFilesystemObject);
        }
    }
    Ok(())
}

fn hash_file(file: &cap_std::fs::File) -> Result<(Sha256Digest, u64)> {
    use std::io::Seek;
    let mut file = file.try_clone().map_err(io_write)?;
    file.rewind().map_err(io_write)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(io_write)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
        hasher.update(&buffer[..read]);
    }
    Ok((Sha256Digest::new(hasher.finalize().into()), total))
}

fn accumulate(total: &mut u64, hasher: &mut Sha256, chunk: &[u8]) -> Result<()> {
    *total = total
        .checked_add(chunk.len() as u64)
        .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
    hasher.update(chunk);
    Ok(())
}

fn write_chunk(dest: &mut cap_std::fs::File, chunk: &[u8]) -> Result<()> {
    dest.write_all(chunk)
        .map_err(|e| staging_io(StagingIoOperation::WriteDestination, e))
}

fn staging_io(operation: StagingIoOperation, error: std::io::Error) -> GkrmError {
    let kind = error.kind();
    drop(error);
    GkrmError::TrustedStagingIo { operation, kind }
}

fn io_write(source: std::io::Error) -> GkrmError {
    staging_io(StagingIoOperation::WriteDestination, source)
}

fn io_enum(source: std::io::Error) -> GkrmError {
    staging_io(StagingIoOperation::OpenFile, source)
}

fn map_fs(error: GkrmError) -> GkrmError {
    map_fs_op(StagingIoOperation::WriteDestination, error)
}

fn map_fs_op(operation: StagingIoOperation, error: GkrmError) -> GkrmError {
    sanitize_boundary(operation, error)
}

fn sanitize_boundary(operation: StagingIoOperation, error: GkrmError) -> GkrmError {
    match error {
        GkrmError::BaselineStoreHardLink { .. }
        | GkrmError::BaselineStoreSymlink { .. }
        | GkrmError::BaselineStoreReparsePoint { .. }
        | GkrmError::BaselineStoreUnexpectedType { .. } => {
            GkrmError::TrustedStagingUnsafeFilesystemObject
        }
        GkrmError::BaselineStoreIo { cause: source, .. } => staging_io(operation, source),
        GkrmError::BaselineAtomicPublishFailure { cause: source } => staging_io(operation, source),
        GkrmError::BaselineStoreMissing { .. } => GkrmError::TrustedStagingIo {
            operation,
            kind: std::io::ErrorKind::NotFound,
        },
        GkrmError::TrustedStagingIo { .. }
        | GkrmError::TrustedStagingUnsafeFilesystemObject
        | GkrmError::TrustedStagingDigestLengthMismatch
        | GkrmError::TrustedStagingManifestTreeMismatch
        | GkrmError::TrustedStagingFinalTreeRejected
        | GkrmError::TrustedStagingArithmeticOverflow
        | GkrmError::TrustedStagingDestinationExists
        | GkrmError::TrustedStagingSourceUnavailable
        | GkrmError::TrustedStagingMissingMergedArtifact
        | GkrmError::TrustedStagingManualMergeResult
        | GkrmError::TrustedStagingRootReplaced
        | GkrmError::TrustedStagingRootOverlap
        | GkrmError::TrustedStagingOptionsInvalid { .. }
        | GkrmError::TrustedStagingLimitExceeded { .. }
        | GkrmError::TrustedStagingIdEncodingFailure => error,
        GkrmError::TrustedStagingWriteFailure { source } => sanitize_boundary(operation, *source),
        GkrmError::TrustedStagingCleanupFailed { source } => {
            GkrmError::TrustedStagingCleanupFailed {
                source: Box::new(sanitize_boundary(operation, *source)),
            }
        }
        GkrmError::TrustedStagingFailedWithCleanupFailure { primary, cleanup } => {
            GkrmError::TrustedStagingFailedWithCleanupFailure {
                primary: Box::new(sanitize_boundary(operation, *primary)),
                cleanup: Box::new(sanitize_boundary(operation, *cleanup)),
            }
        }
        GkrmError::TrustedStagingPostPublishVerificationFailed { source } => {
            GkrmError::TrustedStagingPostPublishVerificationFailed {
                source: Box::new(sanitize_boundary(operation, *source)),
            }
        }
        other => {
            // Drop unexpected nested path-bearing errors; keep only a closed kind.
            let _ = other;
            GkrmError::TrustedStagingIo {
                operation,
                kind: std::io::ErrorKind::Other,
            }
        }
    }
}
