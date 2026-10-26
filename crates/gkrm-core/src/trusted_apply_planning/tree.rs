//! Verified installed/desired tree models for apply planning.

use std::collections::{BTreeMap, BTreeSet};

use crate::three_way_fingerprint::{installed_resource_fingerprint, CanonicalFingerprintEncoder};
use crate::{GkrmError, ResourceRelativePath, Result, SafeResourceKey, Sha256Digest};

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum ApplyFileState {
    Absent,
    Present {
        digest: Sha256Digest,
        byte_length: u64,
    },
}

impl ApplyFileState {
    pub(crate) fn encode_tag(&self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::Present { .. } => 1,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn digest_opt(&self) -> Option<&Sha256Digest> {
        match self {
            Self::Absent => None,
            Self::Present { digest, .. } => Some(digest),
        }
    }

    pub(crate) fn length_opt(&self) -> Option<u64> {
        match self {
            Self::Absent => None,
            Self::Present { byte_length, .. } => Some(*byte_length),
        }
    }
}

pub(super) struct InstalledTreeModel {
    pub(super) files: BTreeMap<ResourceRelativePath, ApplyFileState>,
    pub(super) directories: BTreeSet<ResourceRelativePath>,
}

/// Complete installed tree snapshot for Task 21 race detection.
#[derive(Clone)]
pub(crate) struct InstalledApplyTreeSnapshot {
    pub(crate) files: BTreeMap<ResourceRelativePath, ApplyFileState>,
    pub(crate) directories: BTreeSet<ResourceRelativePath>,
    pub(crate) fingerprint: Sha256Digest,
}

impl InstalledApplyTreeSnapshot {
    pub(super) fn as_tree_model(&self) -> InstalledTreeModel {
        InstalledTreeModel {
            files: self.files.clone(),
            directories: self.directories.clone(),
        }
    }

    /// File-only fingerprint compatible with Task 14 installed snapshot binding.
    pub(crate) fn file_only_plan_fingerprint(
        &self,
        resource_key: &SafeResourceKey,
    ) -> Result<Sha256Digest> {
        let mut files: Vec<_> = self
            .files
            .iter()
            .filter_map(|(path, state)| match state {
                ApplyFileState::Present { digest, .. } => Some((path, digest)),
                ApplyFileState::Absent => None,
            })
            .collect();
        files.sort_by(|a, b| a.0.cmp(b.0));
        let fingerprint_files: Vec<_> = files
            .iter()
            .map(
                |(path, digest)| crate::three_way_fingerprint::InstalledFingerprintFile {
                    path,
                    sha256: digest,
                },
            )
            .collect();
        installed_resource_fingerprint(resource_key, &fingerprint_files)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)
    }
}

pub(super) struct DesiredTreeModel {
    pub(super) files: BTreeMap<ResourceRelativePath, ApplyFileState>,
    pub(super) directories: BTreeSet<ResourceRelativePath>,
}

const ENTRY_TAG_FILE: u8 = 1;
const ENTRY_TAG_DIRECTORY: u8 = 2;

/// Content-stable fingerprint over path-sorted files and directories.
///
/// Retained root/resource filesystem identities are verified independently on
/// each snapshot capture (`validate_identities`) and are intentionally omitted
/// here so plan IDs remain portable across independent installation roots.
pub(crate) fn encode_installed_apply_tree_snapshot(
    files: &BTreeMap<ResourceRelativePath, ApplyFileState>,
    directories: &BTreeSet<ResourceRelativePath>,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-installed-apply-tree-snapshot-v1")
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;

    let mut entries: Vec<(ResourceRelativePath, u8)> = Vec::new();
    for path in directories {
        entries.push((path.clone(), ENTRY_TAG_DIRECTORY));
    }
    for (path, state) in files {
        if matches!(state, ApplyFileState::Present { .. }) {
            entries.push((path.clone(), ENTRY_TAG_FILE));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    enc.usize(entries.len())
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    for (path, tag) in &entries {
        enc.path(path)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
        enc.u8(*tag);
        if *tag == ENTRY_TAG_FILE {
            let Some(ApplyFileState::Present {
                digest,
                byte_length,
            }) = files.get(path)
            else {
                return Err(GkrmError::TrustedApplyPlanningIdEncodingFailure);
            };
            enc.digest(digest);
            enc.u64(*byte_length);
        }
    }
    Ok(enc.finish())
}

pub(crate) fn parents_of(path: &ResourceRelativePath) -> Vec<ResourceRelativePath> {
    let parts: Vec<&str> = path.as_str().split('/').collect();
    let mut out = Vec::new();
    if parts.len() <= 1 {
        return out;
    }
    let mut acc = String::new();
    for part in &parts[..parts.len() - 1] {
        if acc.is_empty() {
            acc.push_str(part);
        } else {
            acc.push('/');
            acc.push_str(part);
        }
        if let Ok(p) = ResourceRelativePath::try_from_slash_str(&acc) {
            out.push(p);
        }
    }
    out
}

pub(super) fn path_depth(path: &ResourceRelativePath) -> usize {
    path.as_str().split('/').count()
}
