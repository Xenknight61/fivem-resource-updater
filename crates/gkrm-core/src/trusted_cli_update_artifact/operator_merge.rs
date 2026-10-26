//! Trusted operator-provided merged bytes for Task 25 staging.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use cap_std::fs::Dir as CapDir;
use sha2::{Digest, Sha256};

use crate::baseline::fs_security::{
    dir_identity, open_child_dir, open_existing_directory, open_file_nofollow,
    validate_single_component,
};
use crate::installed_path::case_collision_key;
use crate::{
    GkrmError, ResourceRelativePath, Result, Sha256Digest, ThreeWayPlanId, ThreeWayPlanReviewId,
};

use super::id::{encode_operator_merge_artifact_id, encode_operator_merge_set_id};
use super::limits::TrustedCliUpdateOptions;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedOperatorMergeArtifactId(Sha256Digest);

impl TrustedOperatorMergeArtifactId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Debug for TrustedOperatorMergeArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedOperatorMergeArtifactId")
    }
}

pub struct TrustedOperatorMergeArtifact {
    artifact_id: TrustedOperatorMergeArtifactId,
    #[allow(dead_code)]
    plan_id: ThreeWayPlanId,
    #[allow(dead_code)]
    review_id: ThreeWayPlanReviewId,
    path: ResourceRelativePath,
    byte_length: u64,
    content_digest: Sha256Digest,
    bytes: Box<[u8]>,
}

impl TrustedOperatorMergeArtifact {
    pub fn artifact_id(&self) -> &TrustedOperatorMergeArtifactId {
        &self.artifact_id
    }

    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }

    pub(crate) fn bytes_for_staging(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn digest_for_staging(&self) -> &Sha256Digest {
        &self.content_digest
    }

    #[allow(dead_code)]
    pub(crate) fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[allow(dead_code)]
    pub(crate) fn plan_id(&self) -> &ThreeWayPlanId {
        &self.plan_id
    }

    #[allow(dead_code)]
    pub(crate) fn review_id(&self) -> &ThreeWayPlanReviewId {
        &self.review_id
    }
}

impl std::fmt::Debug for TrustedOperatorMergeArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedOperatorMergeArtifact")
    }
}

impl Drop for TrustedOperatorMergeArtifact {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
    }
}

pub struct TrustedOperatorMergeSet {
    artifacts: Vec<TrustedOperatorMergeArtifact>,
    set_id: Sha256Digest,
}

impl TrustedOperatorMergeSet {
    pub fn set_id(&self) -> &Sha256Digest {
        &self.set_id
    }

    pub fn artifacts(&self) -> &[TrustedOperatorMergeArtifact] {
        &self.artifacts
    }

    pub fn get(&self, path: &ResourceRelativePath) -> Option<&TrustedOperatorMergeArtifact> {
        self.artifacts.iter().find(|a| a.path() == path)
    }
}

impl std::fmt::Debug for TrustedOperatorMergeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedOperatorMergeSet")
            .field("count", &self.artifacts.len())
            .finish_non_exhaustive()
    }
}

fn load_under_opened_root(
    root_dir: &CapDir,
    relpath: &ResourceRelativePath,
    plan_id: &ThreeWayPlanId,
    review_id: &ThreeWayPlanReviewId,
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedOperatorMergeArtifact> {
    let components: Vec<&str> = relpath.as_str().split('/').collect();
    if components.is_empty() {
        return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
    }
    for c in &components {
        validate_single_component(c)
            .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    }
    let mut dir = root_dir
        .try_clone()
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    for (idx, component) in components.iter().enumerate() {
        if idx + 1 == components.len() {
            // open_file_nofollow already enforces regular / non-hardlink / non-reparse.
            let mut file = open_file_nofollow(&dir, component)
                .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
            drop(file);
            // Reopen at point of use and rehash to detect TOCTOU mutation.
            let mut reopened = open_file_nofollow(&dir, component)
                .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
            let mut again = Vec::new();
            reopened
                .read_to_end(&mut again)
                .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
            if again.as_slice() != bytes.as_slice() {
                return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
            }
            let byte_length = bytes.len() as u64;
            if byte_length == 0 || byte_length > options.max_operator_merge_bytes_per_file {
                return Err(GkrmError::TrustedCliUpdateLimitExceeded {
                    limit: "max_operator_merge_bytes_per_file",
                });
            }
            let content_digest = Sha256Digest::new(Sha256::digest(&bytes).into());
            let artifact_id = TrustedOperatorMergeArtifactId(encode_operator_merge_artifact_id(
                plan_id.digest(),
                review_id.digest(),
                relpath.as_str(),
                byte_length,
                &content_digest,
            )?);
            return Ok(TrustedOperatorMergeArtifact {
                artifact_id,
                plan_id: *plan_id,
                review_id: *review_id,
                path: relpath.clone(),
                byte_length,
                content_digest,
                bytes: bytes.into_boxed_slice(),
            });
        }
        dir = open_child_dir(&dir, component)
            .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    }
    Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid)
}

/// Load one operator-merge file under `merge_root` for an exact resource-relative path.
pub fn load_operator_merge_artifact(
    merge_root: &Path,
    relpath: &ResourceRelativePath,
    plan_id: &ThreeWayPlanId,
    review_id: &ThreeWayPlanReviewId,
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedOperatorMergeArtifact> {
    let root = open_existing_directory(merge_root, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    let before = dir_identity(&root.dir, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    let artifact = load_under_opened_root(&root.dir, relpath, plan_id, review_id, options)?;
    let after = dir_identity(&root.dir, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    if before != after {
        return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
    }
    Ok(artifact)
}

pub fn build_operator_merge_set(
    artifacts: Vec<TrustedOperatorMergeArtifact>,
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedOperatorMergeSet> {
    if artifacts.len() > options.max_operator_merge_files {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_operator_merge_files",
        });
    }
    let total: u64 = artifacts.iter().map(|a| a.byte_length).sum();
    if total > options.max_operator_merge_total_bytes {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_operator_merge_total_bytes",
        });
    }
    let mut ids: Vec<Sha256Digest> = artifacts.iter().map(|a| *a.artifact_id.digest()).collect();
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let set_id = encode_operator_merge_set_id(&ids)?;
    Ok(TrustedOperatorMergeSet { artifacts, set_id })
}

fn enumerate_operator_merge_files(
    dir: &CapDir,
    prefix: &str,
    found: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in dir
        .entries()
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
        let metadata = entry
            .metadata()
            .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
        validate_single_component(&name)
            .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if metadata.is_dir() {
            let child = open_child_dir(dir, &name)
                .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
            enumerate_operator_merge_files(&child, &rel, found)?;
        } else if metadata.is_file() {
            // Reject symlink/reparse/hard-link peers via nofollow open.
            let file = open_file_nofollow(dir, &name)
                .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
            drop(file);
            found.insert(rel);
        } else {
            return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
        }
    }
    Ok(())
}

/// Validate a dedicated operator-merge root directory against expected relative paths.
///
/// Reopens the root capability, enumerates exact membership, reloads every file nofollow,
/// recomputes digests/IDs, and rejects root replacement between open and finish.
pub fn validate_and_load_operator_merge_root(
    merge_root: &Path,
    expected_relpaths: &[ResourceRelativePath],
    plan_id: &ThreeWayPlanId,
    review_id: &ThreeWayPlanReviewId,
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedOperatorMergeSet> {
    let root = open_existing_directory(merge_root, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    let before = dir_identity(&root.dir, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;

    let mut found = BTreeSet::new();
    enumerate_operator_merge_files(&root.dir, "", &mut found)?;

    let mut case_keys = BTreeSet::new();
    for p in &found {
        if !case_keys.insert(case_collision_key(p)) {
            return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
        }
    }

    let expected_strings: BTreeSet<&str> = expected_relpaths.iter().map(|p| p.as_str()).collect();
    if expected_strings.len() != expected_relpaths.len() {
        return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
    }

    for p in &found {
        if !expected_strings.contains(p.as_str()) {
            return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
        }
    }
    for p in &expected_strings {
        if !found.contains(*p) {
            return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
        }
    }

    let mut artifacts = Vec::with_capacity(expected_relpaths.len());
    for rel in expected_relpaths {
        artifacts.push(load_under_opened_root(
            &root.dir, rel, plan_id, review_id, options,
        )?);
    }

    let after = dir_identity(&root.dir, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    if before != after {
        return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
    }

    // Reopen the root from the ambient path and require identical identity (root replacement).
    let reopened = open_existing_directory(merge_root, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    let reopened_id = dir_identity(&reopened.dir, "operator-merge-root")
        .map_err(|_| GkrmError::TrustedCliUpdateOperatorMergeInvalid)?;
    if reopened_id != before {
        return Err(GkrmError::TrustedCliUpdateOperatorMergeInvalid);
    }

    build_operator_merge_set(artifacts, options)
}
