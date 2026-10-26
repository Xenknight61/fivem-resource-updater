//! Opaque retained installed capability for Task 21 apply planning.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use cap_std::fs::Dir as CapDir;
use sha2::{Digest, Sha256};

use crate::baseline::fs_security::{
    dir_identity, open_child_dir, open_existing_directory, open_file_nofollow, verify_regular_file,
};
use crate::file_identity::StableFileIdentity;
use crate::{
    ApplyPlanningIoOperation, GkrmError, InstalledResourceRoot, InstalledScanLimits,
    ResourceRelativePath, Result, SafeResourceKey, Sha256Digest,
};

use super::tree::{
    encode_installed_apply_tree_snapshot, ApplyFileState, InstalledApplyTreeSnapshot,
};

pub struct InstalledApplyPlanningSource {
    installed_root_path: std::path::PathBuf,
    installed_root_dir: CapDir,
    selected_resource_root: InstalledResourceRoot,
    resource_name: String,
    limits: InstalledScanLimits,
    installed_root_identity: StableFileIdentity,
    selected_resource_identity: StableFileIdentity,
}

impl InstalledApplyPlanningSource {
    pub fn try_new(
        installed_root: &Path,
        selected_resource_root: InstalledResourceRoot,
        limits: InstalledScanLimits,
    ) -> Result<Self> {
        limits
            .validate()
            .map_err(|_| GkrmError::TrustedApplyPlanningOptionsInvalid {
                limit: "installed_scan_limits",
            })?;
        let root = open_existing_directory(installed_root, "installed-root")
            .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::OpenInstalledRoot, e))?;
        let installed_root_identity = dir_identity(&root.dir, "installed-root")
            .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::OpenInstalledRoot, e))?;
        let selected_resource_dir = open_selected_resource_dir(&root.dir, &selected_resource_root)?;
        let selected_resource_identity = dir_identity(&selected_resource_dir, "installed-resource")
            .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::OpenInstalledResource, e))?;
        drop(selected_resource_dir);
        let resource_name = match &selected_resource_root {
            InstalledResourceRoot::Root => installed_root
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
                .ok_or(GkrmError::TrustedApplyPlanningInstalledStale)?,
            InstalledResourceRoot::Path(path) => path.file_name().to_owned(),
        };
        Ok(Self {
            installed_root_path: installed_root.to_path_buf(),
            installed_root_dir: root.dir,
            selected_resource_root,
            resource_name,
            limits,
            installed_root_identity,
            selected_resource_identity,
        })
    }

    pub(crate) fn installed_root_path(&self) -> &Path {
        &self.installed_root_path
    }

    pub(crate) fn installed_root_identity(&self) -> &StableFileIdentity {
        &self.installed_root_identity
    }

    pub(crate) fn selected_resource_identity(&self) -> &StableFileIdentity {
        &self.selected_resource_identity
    }

    pub(crate) fn selected_resource_root(&self) -> &InstalledResourceRoot {
        &self.selected_resource_root
    }

    /// Reopen this already-validated installed selection through its backend-owned
    /// location and require that both namespace identities still name the same
    /// filesystem objects. Callers cannot supply replacement path/selection fields.
    pub(crate) fn reopen_for_package_free_recovery(
        &self,
        limits: InstalledScanLimits,
    ) -> Result<Self> {
        self.validate_identities()?;
        let reopened = Self::try_new(
            &self.installed_root_path,
            self.selected_resource_root.clone(),
            limits,
        )?;
        if reopened.installed_root_identity != self.installed_root_identity
            || reopened.selected_resource_identity != self.selected_resource_identity
            || reopened.resource_name != self.resource_name
        {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        reopened.validate_identities()?;
        Ok(reopened)
    }

    pub(crate) fn resource_key_for_package_free_recovery(&self) -> Result<SafeResourceKey> {
        SafeResourceKey::parse(&self.resource_name)
            .map_err(|_| GkrmError::TrustedApplyPlanningInstalledStale)
    }

    pub(crate) fn open_resource_dir(&self) -> Result<CapDir> {
        open_selected_resource_dir(&self.installed_root_dir, &self.selected_resource_root)
    }

    pub(crate) fn validate_identities(&self) -> Result<()> {
        let installed_root_now = dir_identity(&self.installed_root_dir, "installed-root")
            .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::RevalidateIdentity, e))?;
        if installed_root_now != self.installed_root_identity {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        let reopened = self.open_resource_dir()?;
        let reopened_identity = dir_identity(&reopened, "installed-resource")
            .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::RevalidateIdentity, e))?;
        if reopened_identity != self.selected_resource_identity {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        Ok(())
    }

    /// Independently re-enumerate files and directories and bind a complete snapshot fingerprint.
    pub(crate) fn capture_tree_snapshot(
        &self,
        expected_key: &SafeResourceKey,
    ) -> Result<InstalledApplyTreeSnapshot> {
        self.validate_identities()?;
        note_installed_read();
        let resource_dir = self.open_resource_dir()?;

        // Keep scan limits / resource-key binding aligned with Task 14 installed snapshot.
        let resource = crate::installed_scan::scan_installed_resource_from_capability(
            &resource_dir,
            &self.resource_name,
            self.selected_resource_root.clone(),
            self.limits,
        )
        .map_err(map_installed_scan)?;
        let resource_key = SafeResourceKey::parse(&resource.name)
            .map_err(|_| GkrmError::TrustedApplyPlanningInstalledStale)?;
        if &resource_key != expected_key {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }

        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::new();
        enumerate_cap(&resource_dir, "", &mut files, &mut directories)?;
        self.validate_identities()?;

        let fingerprint = encode_installed_apply_tree_snapshot(&files, &directories)?;
        Ok(InstalledApplyTreeSnapshot {
            files,
            directories,
            fingerprint,
        })
    }
}

impl std::fmt::Debug for InstalledApplyPlanningSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstalledApplyPlanningSource")
    }
}

fn open_selected_resource_dir(
    root: &CapDir,
    selected_root: &InstalledResourceRoot,
) -> Result<CapDir> {
    match selected_root {
        InstalledResourceRoot::Root => root
            .try_clone()
            .map_err(|source| apply_io(ApplyPlanningIoOperation::OpenInstalledResource, source)),
        InstalledResourceRoot::Path(path) => {
            let mut dir = root
                .try_clone()
                .map_err(|source| apply_io(ApplyPlanningIoOperation::OpenInstalledRoot, source))?;
            for component in path.as_str().split('/') {
                dir = open_child_dir(&dir, component)
                    .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::OpenInstalledResource, e))?;
            }
            Ok(dir)
        }
    }
}

fn enumerate_cap(
    dir: &CapDir,
    prefix: &str,
    files: &mut BTreeMap<ResourceRelativePath, ApplyFileState>,
    directories: &mut BTreeSet<ResourceRelativePath>,
) -> Result<()> {
    let entries: Vec<_> = dir
        .entries()
        .map_err(|e| apply_io(ApplyPlanningIoOperation::EnumerateInstalled, e))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| apply_io(ApplyPlanningIoOperation::EnumerateInstalled, e))?;
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedApplyPlanningInstalledStale)?;
        let meta = entry
            .metadata()
            .map_err(|e| apply_io(ApplyPlanningIoOperation::EnumerateInstalled, e))?;
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let path = ResourceRelativePath::try_from_slash_str(&rel)
            .map_err(|_| GkrmError::TrustedApplyPlanningPathTypeConflict)?;
        if meta.file_type().is_dir() {
            directories.insert(path.clone());
            let child = open_child_dir(dir, &name)
                .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::EnumerateInstalled, e))?;
            enumerate_cap(&child, &rel, files, directories)?;
        } else if meta.file_type().is_file() {
            let file = open_file_nofollow(dir, &name)
                .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::EnumerateInstalled, e))?;
            verify_regular_file(&file, &name)
                .map_err(|e| sanitize_fs(ApplyPlanningIoOperation::VerifyRegularFile, e))?;
            let (digest, len) = hash_file(&file)?;
            files.insert(
                path,
                ApplyFileState::Present {
                    digest,
                    byte_length: len,
                },
            );
        } else {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
    }
    Ok(())
}

fn hash_file(file: &cap_std::fs::File) -> Result<(Sha256Digest, u64)> {
    use std::io::Seek;
    let mut file = file
        .try_clone()
        .map_err(|e| apply_io(ApplyPlanningIoOperation::HashFile, e))?;
    file.rewind()
        .map_err(|e| apply_io(ApplyPlanningIoOperation::HashFile, e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| apply_io(ApplyPlanningIoOperation::HashFile, e))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
        hasher.update(&buf[..n]);
    }
    Ok((Sha256Digest::new(hasher.finalize().into()), total))
}

fn apply_io(operation: ApplyPlanningIoOperation, error: std::io::Error) -> GkrmError {
    let kind = error.kind();
    drop(error);
    GkrmError::TrustedApplyPlanningIo { operation, kind }
}

fn sanitize_fs(operation: ApplyPlanningIoOperation, error: GkrmError) -> GkrmError {
    match error {
        GkrmError::BaselineStoreHardLink { .. }
        | GkrmError::BaselineStoreSymlink { .. }
        | GkrmError::BaselineStoreReparsePoint { .. }
        | GkrmError::BaselineStoreUnexpectedType { .. } => {
            GkrmError::TrustedApplyPlanningInstalledStale
        }
        GkrmError::BaselineStoreIo { cause: source, .. } => apply_io(operation, source),
        GkrmError::TrustedApplyPlanningIo { .. }
        | GkrmError::TrustedApplyPlanningInstalledStale
        | GkrmError::TrustedApplyPlanningPathTypeConflict => error,
        other => {
            let _ = other;
            GkrmError::TrustedApplyPlanningIo {
                operation,
                kind: std::io::ErrorKind::Other,
            }
        }
    }
}

fn map_installed_scan(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::TrustedApplyPlanningIo { .. }
        | GkrmError::TrustedApplyPlanningInstalledStale => error,
        GkrmError::BaselineStoreIo { cause: source, .. } => {
            apply_io(ApplyPlanningIoOperation::ScanInstalled, source)
        }
        other => {
            let _ = other;
            GkrmError::TrustedApplyPlanningInstalledStale
        }
    }
}

fn note_installed_read() {
    #[cfg(test)]
    super::note_installed_read();
}
