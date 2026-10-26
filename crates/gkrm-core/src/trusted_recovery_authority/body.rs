use std::collections::{BTreeMap, BTreeSet};

use crate::trusted_apply_planning::{
    encode_installed_apply_tree_snapshot, ApplyFileState, InstalledApplyTreeSnapshot,
};
use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest};

use super::derivation::{TASK21_APPLY_DERIVATION_V1, TASK22_TRANSACTION_DERIVATION_V1};

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RecoveryAuthorityNode {
    File {
        path: ResourceRelativePath,
        digest: Sha256Digest,
        byte_length: u64,
    },
    Directory {
        path: ResourceRelativePath,
    },
}

impl RecoveryAuthorityNode {
    pub(crate) fn path(&self) -> &ResourceRelativePath {
        match self {
            Self::File { path, .. } | Self::Directory { path } => path,
        }
    }

    pub(crate) fn tag(&self) -> u8 {
        match self {
            Self::File { .. } => 1,
            Self::Directory { .. } => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryAuthorityBodyV1 {
    pub(crate) apply_derivation_version: u8,
    pub(crate) transaction_derivation_version: u8,
    pub(crate) installed_authority_commitment: Sha256Digest,
    pub(crate) selected_resource_commitment: Sha256Digest,
    pub(crate) baseline_id: Sha256Digest,
    pub(crate) staging_manifest_id: Sha256Digest,
    pub(crate) staging_bundle_id: Sha256Digest,
    pub(crate) snapshot_a_id: Sha256Digest,
    pub(crate) apply_plan_id: Sha256Digest,
    pub(crate) transactional_plan_id: Sha256Digest,
    pub(crate) nodes: Vec<RecoveryAuthorityNode>,
}

impl std::fmt::Debug for RecoveryAuthorityBodyV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryAuthorityBodyV1")
            .field("node_count", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl RecoveryAuthorityBodyV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_snapshot(
        installed_authority_commitment: Sha256Digest,
        selected_resource_commitment: Sha256Digest,
        baseline_id: Sha256Digest,
        staging_manifest_id: Sha256Digest,
        staging_bundle_id: Sha256Digest,
        snapshot_a_id: Sha256Digest,
        apply_plan_id: Sha256Digest,
        transactional_plan_id: Sha256Digest,
        snapshot: &InstalledApplyTreeSnapshot,
    ) -> Self {
        let mut nodes = Vec::with_capacity(snapshot.files.len() + snapshot.directories.len());
        for path in &snapshot.directories {
            nodes.push(RecoveryAuthorityNode::Directory { path: path.clone() });
        }
        for (path, state) in &snapshot.files {
            if let ApplyFileState::Present {
                digest,
                byte_length,
            } = state
            {
                nodes.push(RecoveryAuthorityNode::File {
                    path: path.clone(),
                    digest: *digest,
                    byte_length: *byte_length,
                });
            }
        }
        nodes.sort_by(|left, right| {
            left.path()
                .as_str()
                .as_bytes()
                .cmp(right.path().as_str().as_bytes())
                .then(left.tag().cmp(&right.tag()))
        });
        Self {
            apply_derivation_version: TASK21_APPLY_DERIVATION_V1,
            transaction_derivation_version: TASK22_TRANSACTION_DERIVATION_V1,
            installed_authority_commitment,
            selected_resource_commitment,
            baseline_id,
            staging_manifest_id,
            staging_bundle_id,
            snapshot_a_id,
            apply_plan_id,
            transactional_plan_id,
            nodes,
        }
    }

    pub fn apply_derivation_version(&self) -> u8 {
        self.apply_derivation_version
    }

    pub fn transaction_derivation_version(&self) -> u8 {
        self.transaction_derivation_version
    }

    pub fn snapshot_a_id(&self) -> &Sha256Digest {
        &self.snapshot_a_id
    }

    pub fn transactional_plan_id(&self) -> &Sha256Digest {
        &self.transactional_plan_id
    }

    pub(crate) fn installed_authority_commitment(&self) -> &Sha256Digest {
        &self.installed_authority_commitment
    }

    pub(crate) fn selected_resource_commitment(&self) -> &Sha256Digest {
        &self.selected_resource_commitment
    }

    pub(crate) fn baseline_id(&self) -> &Sha256Digest {
        &self.baseline_id
    }

    pub(crate) fn staging_manifest_id(&self) -> &Sha256Digest {
        &self.staging_manifest_id
    }

    pub(crate) fn staging_bundle_id(&self) -> &Sha256Digest {
        &self.staging_bundle_id
    }

    pub(crate) fn apply_plan_id(&self) -> &Sha256Digest {
        &self.apply_plan_id
    }

    pub(crate) fn to_installed_snapshot(&self) -> Result<InstalledApplyTreeSnapshot> {
        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::new();
        for node in &self.nodes {
            match node {
                RecoveryAuthorityNode::File {
                    path,
                    digest,
                    byte_length,
                } => {
                    if files
                        .insert(
                            path.clone(),
                            ApplyFileState::Present {
                                digest: *digest,
                                byte_length: *byte_length,
                            },
                        )
                        .is_some()
                    {
                        return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
                    }
                }
                RecoveryAuthorityNode::Directory { path } => {
                    if !directories.insert(path.clone()) {
                        return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
                    }
                }
            }
        }
        let fingerprint = encode_installed_apply_tree_snapshot(&files, &directories)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityBindingMismatch)?;
        if fingerprint != self.snapshot_a_id {
            return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
        }
        Ok(InstalledApplyTreeSnapshot {
            files,
            directories,
            fingerprint,
        })
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}
