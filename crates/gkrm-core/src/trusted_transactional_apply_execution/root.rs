//! Read-only trusted transaction root capability.

use std::path::Path;

use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{dir_identity, open_existing_directory};
use crate::file_identity::StableFileIdentity;
use crate::TrustedUpdateWorkspace;
use crate::{GkrmError, Result};

/// Opaque retained transaction-root capability. Opening is strictly read-only.
pub struct TrustedTransactionRoot {
    path: std::path::PathBuf,
    dir: CapDir,
    identity: StableFileIdentity,
    workspace: Option<TrustedUpdateWorkspace>,
}

impl TrustedTransactionRoot {
    /// Open an existing transaction root without creating any filesystem objects.
    pub fn try_open(path: &Path) -> Result<Self> {
        let opened = open_existing_directory(path, "transaction-root")
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRootOverlap)?;
        let identity = dir_identity(&opened.dir, "transaction-root")
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRootOverlap)?;
        Ok(Self {
            path: path.to_path_buf(),
            dir: opened.dir,
            identity,
            workspace: None,
        })
    }

    /// Open the transaction root retained by a trusted managed workspace.
    /// The retained workspace authority allows recovery-first gates to validate
    /// additive retirement evidence and its exact artifact binding.
    pub fn try_open_in_workspace(workspace: &TrustedUpdateWorkspace) -> Result<Self> {
        let (dir, identity) = workspace
            .try_clone_transaction_root_capability()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRootOverlap)?;
        Ok(Self {
            path: workspace.transaction_root().to_path_buf(),
            dir,
            identity,
            workspace: Some(workspace.clone()),
        })
    }

    pub(crate) fn dir(&self) -> &CapDir {
        &self.dir
    }

    #[allow(dead_code)]
    pub(super) fn identity(&self) -> &StableFileIdentity {
        &self.identity
    }

    pub(crate) fn path_for_disjointness(&self) -> &Path {
        &self.path
    }

    pub(crate) fn workspace(&self) -> Option<&TrustedUpdateWorkspace> {
        self.workspace.as_ref()
    }

    pub(crate) fn revalidate_identity(&self) -> Result<()> {
        let current = dir_identity(&self.dir, "transaction-root")
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRootReplaced)?;
        if current != self.identity {
            return Err(GkrmError::TrustedTransactionalApplyExecutionRootReplaced);
        }
        Ok(())
    }
}

impl std::fmt::Debug for TrustedTransactionRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedTransactionRoot")
    }
}
