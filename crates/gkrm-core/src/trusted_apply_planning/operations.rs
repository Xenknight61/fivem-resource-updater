//! Phased operation construction for trusted apply planning.

use std::collections::{BTreeMap, BTreeSet};

use crate::trusted_staging::{StagingFinalState, StagingSourceBinding, TrustedStagingManifest};
use crate::{
    GkrmError, ResourceRelativePath, Result, TrustedStagingBundleId, TrustedStagingManifestId,
};

use super::id::{encode_operation_id, OperationIdInputs};
use super::tree::{parents_of, path_depth, ApplyFileState, DesiredTreeModel, InstalledTreeModel};
use super::{
    ApplyBackupRequirement, TrustedApplyOperation, TrustedApplyOperationKind,
    TrustedApplyOperationPhase,
};

pub(super) struct PlannedOperations {
    pub(super) operations: Vec<TrustedApplyOperation>,
    pub(super) total_write_bytes: u64,
    pub(super) total_backup_bytes: u64,
}

pub(super) fn build_desired_tree(manifest: &TrustedStagingManifest) -> Result<DesiredTreeModel> {
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    for entry in manifest.entries() {
        match entry.final_state() {
            StagingFinalState::Absent => {
                files.insert(entry.path().clone(), ApplyFileState::Absent);
            }
            StagingFinalState::Installed
            | StagingFinalState::Incoming
            | StagingFinalState::Merged => {
                let digest = *entry
                    .expected_digest()
                    .ok_or(GkrmError::TrustedApplyPlanningBundleBindingMismatch)?;
                let byte_length = entry
                    .expected_byte_length()
                    .ok_or(GkrmError::TrustedApplyPlanningBundleBindingMismatch)?;
                files.insert(
                    entry.path().clone(),
                    ApplyFileState::Present {
                        digest,
                        byte_length,
                    },
                );
                for parent in parents_of(entry.path()) {
                    directories.insert(parent);
                }
            }
        }
    }
    Ok(DesiredTreeModel { files, directories })
}

pub(super) fn build_operations(
    installed: &InstalledTreeModel,
    desired: &DesiredTreeModel,
    manifest: &TrustedStagingManifest,
    bundle_id: &TrustedStagingBundleId,
    manifest_id: &TrustedStagingManifestId,
    max_operations: usize,
) -> Result<PlannedOperations> {
    let mut binding_by_path: BTreeMap<&ResourceRelativePath, &StagingSourceBinding> =
        BTreeMap::new();
    for entry in manifest.entries() {
        binding_by_path.insert(entry.path(), entry.source_binding());
    }
    build_operations_with_bindings(
        installed,
        desired,
        &binding_by_path,
        bundle_id,
        manifest_id,
        max_operations,
    )
}

pub(super) fn build_operations_with_bindings(
    installed: &InstalledTreeModel,
    desired: &DesiredTreeModel,
    binding_by_path: &BTreeMap<&ResourceRelativePath, &StagingSourceBinding>,
    bundle_id: &TrustedStagingBundleId,
    manifest_id: &TrustedStagingManifestId,
    max_operations: usize,
) -> Result<PlannedOperations> {
    reject_dual_roles(installed, desired)?;

    let mut ops: Vec<TrustedApplyOperation> = Vec::new();
    let mut seen_dest = BTreeSet::new();

    // Phase 1: RemoveBlockingFile — installed file where desired needs a directory.
    let mut blocking_files: Vec<_> = installed
        .files
        .keys()
        .filter(|p| desired.directories.contains(p))
        .cloned()
        .collect();
    blocking_files.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then(b.cmp(a)));
    for path in blocking_files {
        let pre = installed
            .files
            .get(&path)
            .cloned()
            .unwrap_or(ApplyFileState::Absent);
        push_op(
            &mut ops,
            &mut seen_dest,
            TrustedApplyOperationKind::DeleteFile,
            TrustedApplyOperationPhase::RemoveBlockingFile,
            path,
            pre,
            ApplyFileState::Absent,
            None,
            ApplyBackupRequirement::PreserveInstalledFile,
            bundle_id,
            manifest_id,
        )?;
    }

    // Paths that are installed directories but desired files (dir→file conversion).
    let mut dir_to_file: Vec<_> = desired
        .files
        .iter()
        .filter(|(p, state)| {
            matches!(state, ApplyFileState::Present { .. }) && installed.directories.contains(p)
        })
        .map(|(p, _)| p.clone())
        .collect();
    dir_to_file.sort();

    // Phase 2: DeleteBlockingDescendant — deepest first under each dir→file path.
    let mut blocking_descendants = BTreeSet::new();
    for dir_path in &dir_to_file {
        let prefix = format!("{}/", dir_path.as_str());
        for file_path in installed.files.keys() {
            if file_path.as_str().starts_with(&prefix) {
                blocking_descendants.insert(file_path.clone());
            }
        }
    }
    let mut blocking_descendants: Vec<_> = blocking_descendants.into_iter().collect();
    blocking_descendants.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then(b.cmp(a)));
    for path in blocking_descendants {
        if seen_dest.contains(path.as_str()) {
            continue;
        }
        let pre = installed
            .files
            .get(&path)
            .cloned()
            .unwrap_or(ApplyFileState::Absent);
        push_op(
            &mut ops,
            &mut seen_dest,
            TrustedApplyOperationKind::DeleteFile,
            TrustedApplyOperationPhase::DeleteBlockingDescendant,
            path,
            pre,
            ApplyFileState::Absent,
            None,
            ApplyBackupRequirement::PreserveInstalledFile,
            bundle_id,
            manifest_id,
        )?;
    }

    // Phase 3: RemoveBlockingDirectory — deepest first dirs blocking required files.
    let mut nested_blocking_dirs = BTreeSet::new();
    for dir_path in &dir_to_file {
        nested_blocking_dirs.insert(dir_path.clone());
        let prefix = format!("{}/", dir_path.as_str());
        for d in &installed.directories {
            if d.as_str().starts_with(&prefix) {
                nested_blocking_dirs.insert(d.clone());
            }
        }
    }
    let mut blocking_dirs: Vec<_> = nested_blocking_dirs.into_iter().collect();
    blocking_dirs.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then(b.cmp(a)));
    for path in blocking_dirs {
        if seen_dest.contains(path.as_str()) {
            continue;
        }
        push_op(
            &mut ops,
            &mut seen_dest,
            TrustedApplyOperationKind::RemoveDirectory,
            TrustedApplyOperationPhase::RemoveBlockingDirectory,
            path,
            ApplyFileState::Absent,
            ApplyFileState::Absent,
            None,
            ApplyBackupRequirement::PreserveRemovedDirectoryMetadata,
            bundle_id,
            manifest_id,
        )?;
    }

    // Phase 4: CreateDirectory — shallowest first for missing desired dirs.
    let mut creates: Vec<_> = desired
        .directories
        .iter()
        .filter(|d| !installed.directories.contains(*d) || installed.files.contains_key(*d))
        .cloned()
        .collect();
    creates.sort_by(|a, b| path_depth(a).cmp(&path_depth(b)).then(a.cmp(b)));
    for path in creates {
        push_op_allow_file_dir_transition(
            &mut ops,
            &mut seen_dest,
            TrustedApplyOperationKind::CreateDirectory,
            TrustedApplyOperationPhase::CreateDirectory,
            path,
            ApplyFileState::Absent,
            ApplyFileState::Absent,
            None,
            ApplyBackupRequirement::None,
            bundle_id,
            manifest_id,
        )?;
    }

    // Phase 5: WriteFile — install/replace path-sorted.
    let mut writes: Vec<_> = desired
        .files
        .iter()
        .filter(|(_, state)| matches!(state, ApplyFileState::Present { .. }))
        .map(|(p, s)| (p.clone(), s.clone()))
        .collect();
    writes.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, desired_state) in writes {
        let current = installed
            .files
            .get(&path)
            .cloned()
            .unwrap_or(ApplyFileState::Absent);
        // If current was a directory, treat as Absent file pre-state after phase 3.
        let current = if installed.directories.contains(&path) {
            ApplyFileState::Absent
        } else {
            current
        };
        if current == desired_state {
            continue;
        }
        let (kind, backup) = match &current {
            ApplyFileState::Absent => (
                TrustedApplyOperationKind::InstallFile,
                ApplyBackupRequirement::None,
            ),
            ApplyFileState::Present { .. } => (
                TrustedApplyOperationKind::ReplaceFile,
                ApplyBackupRequirement::PreserveInstalledFile,
            ),
        };
        let binding = binding_by_path.get(&path).copied();
        push_op_allow_file_dir_transition(
            &mut ops,
            &mut seen_dest,
            kind,
            TrustedApplyOperationPhase::WriteFile,
            path,
            current,
            desired_state,
            binding,
            backup,
            bundle_id,
            manifest_id,
        )?;
    }

    // Phase 6: DeleteObsoleteFile — installed files absent from desired present set.
    let mut obsolete_files: Vec<_> = installed
        .files
        .keys()
        .filter(|p| match desired.files.get(p) {
            Some(ApplyFileState::Present { .. }) => false,
            Some(ApplyFileState::Absent) | None => true,
        })
        .filter(|p| !desired.directories.contains(p))
        .cloned()
        .collect();
    obsolete_files.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then(b.cmp(a)));
    for path in obsolete_files {
        if ops.iter().any(|o| {
            o.destination.as_str() == path.as_str()
                && matches!(
                    o.kind,
                    TrustedApplyOperationKind::DeleteFile
                        | TrustedApplyOperationKind::ReplaceFile
                        | TrustedApplyOperationKind::InstallFile
                )
        }) {
            continue;
        }
        let pre = installed
            .files
            .get(&path)
            .cloned()
            .unwrap_or(ApplyFileState::Absent);
        push_op(
            &mut ops,
            &mut seen_dest,
            TrustedApplyOperationKind::DeleteFile,
            TrustedApplyOperationPhase::DeleteObsoleteFile,
            path,
            pre,
            ApplyFileState::Absent,
            None,
            ApplyBackupRequirement::PreserveInstalledFile,
            bundle_id,
            manifest_id,
        )?;
    }

    // Phase 7: RemoveObsoleteDirectory — installed dirs not in desired, deepest first.
    let mut obsolete_dirs: Vec<_> = installed
        .directories
        .iter()
        .filter(|d| !desired.directories.contains(d))
        .filter(|d| !matches!(desired.files.get(d), Some(ApplyFileState::Present { .. })))
        .cloned()
        .collect();
    obsolete_dirs.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then(b.cmp(a)));
    for path in obsolete_dirs {
        if ops.iter().any(|o| {
            o.destination.as_str() == path.as_str()
                && o.kind == TrustedApplyOperationKind::RemoveDirectory
        }) {
            continue;
        }
        push_op(
            &mut ops,
            &mut seen_dest,
            TrustedApplyOperationKind::RemoveDirectory,
            TrustedApplyOperationPhase::RemoveObsoleteDirectory,
            path,
            ApplyFileState::Absent,
            ApplyFileState::Absent,
            None,
            ApplyBackupRequirement::PreserveRemovedDirectoryMetadata,
            bundle_id,
            manifest_id,
        )?;
    }

    reject_incompatible_destination_ops(&ops)?;

    if ops.len() > max_operations {
        return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
            limit: "max_operations",
        });
    }

    let mut total_write_bytes = 0_u64;
    let mut total_backup_bytes = 0_u64;
    for op in &ops {
        if matches!(
            op.kind,
            TrustedApplyOperationKind::InstallFile | TrustedApplyOperationKind::ReplaceFile
        ) {
            if let Some(len) = op.post_state.length_opt() {
                total_write_bytes = total_write_bytes
                    .checked_add(len)
                    .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
            }
        }
        if op.backup_requirement == ApplyBackupRequirement::PreserveInstalledFile {
            if let Some(len) = op.pre_state.length_opt() {
                total_backup_bytes = total_backup_bytes
                    .checked_add(len)
                    .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
            }
        }
    }

    Ok(PlannedOperations {
        operations: ops,
        total_write_bytes,
        total_backup_bytes,
    })
}

fn reject_dual_roles(installed: &InstalledTreeModel, desired: &DesiredTreeModel) -> Result<()> {
    reject_side_dual_roles(
        installed.files.keys(),
        &installed.directories,
        installed.files.keys().chain(installed.directories.iter()),
    )?;
    reject_side_dual_roles(
        desired
            .files
            .iter()
            .filter(|(_, state)| matches!(state, ApplyFileState::Present { .. }))
            .map(|(path, _)| path),
        &desired.directories,
        desired
            .files
            .iter()
            .filter(|(_, state)| matches!(state, ApplyFileState::Present { .. }))
            .map(|(path, _)| path)
            .chain(desired.directories.iter()),
    )?;
    Ok(())
}

fn reject_side_dual_roles<'a, F, A>(
    files: F,
    directories: &BTreeSet<ResourceRelativePath>,
    all_paths: A,
) -> Result<()>
where
    F: Iterator<Item = &'a ResourceRelativePath> + Clone,
    A: Iterator<Item = &'a ResourceRelativePath>,
{
    let file_paths: BTreeSet<_> = files.clone().collect();
    for path in &file_paths {
        if path.as_str().is_empty() {
            return Err(GkrmError::TrustedApplyPlanningPathTypeConflict);
        }
        if directories.contains(path) {
            return Err(GkrmError::TrustedApplyPlanningPathTypeConflict);
        }
    }
    for path in directories {
        if path.as_str().is_empty() {
            return Err(GkrmError::TrustedApplyPlanningPathTypeConflict);
        }
    }
    // Within one side only: a file must not be a parent of another path.
    // Cross-side file↔directory transitions are represented by phased ops.
    let all: Vec<_> = all_paths.collect();
    for file in file_paths {
        let prefix = format!("{}/", file.as_str());
        for other in &all {
            if other.as_str().starts_with(&prefix) {
                return Err(GkrmError::TrustedApplyPlanningPathTypeConflict);
            }
        }
    }
    Ok(())
}

fn reject_incompatible_destination_ops(ops: &[TrustedApplyOperation]) -> Result<()> {
    let mut by_dest: BTreeMap<&str, BTreeSet<TrustedApplyOperationKind>> = BTreeMap::new();
    for op in ops {
        by_dest
            .entry(op.destination.as_str())
            .or_default()
            .insert(op.kind);
    }
    for kinds in by_dest.values() {
        let allowed = match kinds.len() {
            1 => true,
            2 => {
                (kinds.contains(&TrustedApplyOperationKind::DeleteFile)
                    && kinds.contains(&TrustedApplyOperationKind::CreateDirectory))
                    || (kinds.contains(&TrustedApplyOperationKind::RemoveDirectory)
                        && kinds.contains(&TrustedApplyOperationKind::InstallFile))
            }
            _ => false,
        };
        if !allowed {
            return Err(GkrmError::TrustedApplyPlanningDuplicateOperation);
        }
    }
    Ok(())
}

fn push_op(
    ops: &mut Vec<TrustedApplyOperation>,
    seen_dest: &mut BTreeSet<String>,
    kind: TrustedApplyOperationKind,
    phase: TrustedApplyOperationPhase,
    destination: ResourceRelativePath,
    pre_state: ApplyFileState,
    post_state: ApplyFileState,
    staged_binding: Option<&StagingSourceBinding>,
    backup_requirement: ApplyBackupRequirement,
    bundle_id: &TrustedStagingBundleId,
    manifest_id: &TrustedStagingManifestId,
) -> Result<()> {
    let key = destination.as_str().to_owned();
    if !seen_dest.insert(key) {
        return Err(GkrmError::TrustedApplyPlanningDuplicateOperation);
    }
    push_op_inner(
        ops,
        kind,
        phase,
        destination,
        pre_state,
        post_state,
        staged_binding,
        backup_requirement,
        bundle_id,
        manifest_id,
    )
}

fn push_op_allow_file_dir_transition(
    ops: &mut Vec<TrustedApplyOperation>,
    seen_dest: &mut BTreeSet<String>,
    kind: TrustedApplyOperationKind,
    phase: TrustedApplyOperationPhase,
    destination: ResourceRelativePath,
    pre_state: ApplyFileState,
    post_state: ApplyFileState,
    staged_binding: Option<&StagingSourceBinding>,
    backup_requirement: ApplyBackupRequirement,
    bundle_id: &TrustedStagingBundleId,
    manifest_id: &TrustedStagingManifestId,
) -> Result<()> {
    // Allow DeleteFile then CreateDirectory / InstallFile at same path by keying on kind+path.
    let key = format!("{}:{}", kind_tag(kind), destination.as_str());
    if !seen_dest.insert(key) {
        return Err(GkrmError::TrustedApplyPlanningDuplicateOperation);
    }
    // Also mark bare path for obsolete-delete skip logic.
    let _ = seen_dest.insert(destination.as_str().to_owned());
    push_op_inner(
        ops,
        kind,
        phase,
        destination,
        pre_state,
        post_state,
        staged_binding,
        backup_requirement,
        bundle_id,
        manifest_id,
    )
}

fn push_op_inner(
    ops: &mut Vec<TrustedApplyOperation>,
    kind: TrustedApplyOperationKind,
    phase: TrustedApplyOperationPhase,
    destination: ResourceRelativePath,
    pre_state: ApplyFileState,
    post_state: ApplyFileState,
    staged_binding: Option<&StagingSourceBinding>,
    backup_requirement: ApplyBackupRequirement,
    bundle_id: &TrustedStagingBundleId,
    manifest_id: &TrustedStagingManifestId,
) -> Result<()> {
    let binding_tag = encode_binding_tag(staged_binding);
    let operation_id = encode_operation_id(OperationIdInputs {
        bundle_id: bundle_id.digest(),
        manifest_id: manifest_id.digest(),
        phase,
        kind,
        destination: &destination,
        pre: &pre_state,
        post: &post_state,
        binding_tag,
        backup: backup_requirement,
    })?;
    ops.push(TrustedApplyOperation {
        destination,
        kind,
        phase,
        pre_state,
        post_state,
        staged_binding_tag: binding_tag,
        backup_requirement,
        operation_id,
    });
    Ok(())
}

fn kind_tag(kind: TrustedApplyOperationKind) -> u8 {
    match kind {
        TrustedApplyOperationKind::CreateDirectory => 0,
        TrustedApplyOperationKind::InstallFile => 1,
        TrustedApplyOperationKind::ReplaceFile => 2,
        TrustedApplyOperationKind::DeleteFile => 3,
        TrustedApplyOperationKind::RemoveDirectory => 4,
    }
}

fn encode_binding_tag(binding: Option<&StagingSourceBinding>) -> u8 {
    match binding {
        None => 255,
        Some(StagingSourceBinding::Absent) => 0,
        Some(StagingSourceBinding::InstalledDigest(_)) => 1,
        Some(StagingSourceBinding::IncomingDigest(_)) => 2,
        Some(StagingSourceBinding::MergedArtifact(_)) => 3,
        Some(StagingSourceBinding::OperatorMerge(_)) => 4,
    }
}

pub(super) fn trees_equal(installed: &InstalledTreeModel, desired: &DesiredTreeModel) -> bool {
    if installed.directories != desired.directories {
        return false;
    }
    // Compare present files only against desired present; absent desired keys may
    // exist only in manifest and must not appear as installed present files.
    let mut desired_present = BTreeMap::new();
    for (p, s) in &desired.files {
        if let ApplyFileState::Present { .. } = s {
            desired_present.insert(p.clone(), s.clone());
        }
    }
    installed.files == desired_present
}

#[cfg(test)]
pub(crate) fn frozen_task21_v1_operations_fixture() -> Vec<TrustedApplyOperation> {
    frozen_task21_v1_operations_fixture_inner(false)
}

#[cfg(test)]
pub(crate) fn frozen_task21_v1_operations_with_binding_mutation_for_test(
) -> Vec<TrustedApplyOperation> {
    frozen_task21_v1_operations_fixture_inner(true)
}

#[cfg(test)]
fn frozen_task21_v1_operations_fixture_inner(
    mutate_merged_binding: bool,
) -> Vec<TrustedApplyOperation> {
    let digest = |byte| crate::Sha256Digest::new([byte; 32]);
    let path = |value: &str| ResourceRelativePath::try_from_slash_str(value).unwrap();
    let present = |byte, byte_length| ApplyFileState::Present {
        digest: digest(byte),
        byte_length,
    };
    let installed = InstalledTreeModel {
        files: BTreeMap::from([
            (path("block/deep/old.lua"), present(1, 1)),
            (path("file-to-dir"), present(2, 2)),
            (path("remove.lua"), present(3, 3)),
            (path("replace.lua"), present(4, 4)),
        ]),
        directories: BTreeSet::from([
            path("block"),
            path("block/deep"),
            path("obsolete"),
            path("obsolete/deep"),
        ]),
    };
    let desired = DesiredTreeModel {
        files: BTreeMap::from([
            (path("block"), present(5, 5)),
            (path("create.lua"), present(6, 6)),
            (path("file-to-dir/a.lua"), present(7, 7)),
            (path("file-to-dir/deep/z.lua"), present(8, 8)),
            (path("replace.lua"), present(9, 9)),
            (path("siblings/a.lua"), present(10, 10)),
            (path("siblings/b.lua"), present(11, 11)),
        ]),
        directories: BTreeSet::from([
            path("created-empty"),
            path("file-to-dir"),
            path("file-to-dir/deep"),
            path("siblings"),
        ]),
    };
    let (bindings, bundle_id, manifest_id) =
        crate::trusted_staging::frozen_task21_v1_staging_fixture_for_test(mutate_merged_binding);
    let binding_refs = bindings.iter().collect();
    build_operations_with_bindings(
        &installed,
        &desired,
        &binding_refs,
        &bundle_id,
        &manifest_id,
        10_000,
    )
    .unwrap()
    .operations
}

#[cfg(test)]
pub(crate) fn frozen_task21_v1_aggregate_ids_for_test(
    operations: &[TrustedApplyOperation],
    mutate_merged_binding: bool,
) -> (
    crate::Sha256Digest,
    crate::Sha256Digest,
    crate::Sha256Digest,
) {
    let digest = |byte| crate::Sha256Digest::new([byte; 32]);
    let path = |value: &str| ResourceRelativePath::try_from_slash_str(value).unwrap();
    let present = |byte, byte_length| ApplyFileState::Present {
        digest: digest(byte),
        byte_length,
    };
    let installed = InstalledTreeModel {
        files: BTreeMap::from([
            (path("block/deep/old.lua"), present(1, 1)),
            (path("file-to-dir"), present(2, 2)),
            (path("remove.lua"), present(3, 3)),
            (path("replace.lua"), present(4, 4)),
        ]),
        directories: BTreeSet::from([
            path("block"),
            path("block/deep"),
            path("obsolete"),
            path("obsolete/deep"),
        ]),
    };
    let snapshot =
        super::tree::encode_installed_apply_tree_snapshot(&installed.files, &installed.directories)
            .unwrap();
    let backup_set = super::id::encode_backup_set_id(operations).unwrap();
    let summary = super::summarize(operations, 56, 10).unwrap();
    let options_tag = super::TrustedApplyPlanningOptions::default()
        .options_tag()
        .unwrap();
    let (_, bundle_id, manifest_id) =
        crate::trusted_staging::frozen_task21_v1_staging_fixture_for_test(mutate_merged_binding);
    let plan_id = super::id::encode_plan_id(super::id::PlanIdInputs {
        plan_id: &digest(0x31),
        review_id: &digest(0x32),
        analysis_id: Some(&digest(0x33)),
        text_diff_id: Some(&digest(0x34)),
        synthesis_id: Some(&digest(0x35)),
        merged_bytes_id: Some(&digest(0x36)),
        bundle_id: bundle_id.digest(),
        manifest_id: manifest_id.digest(),
        resource_key: "gksphone",
        baseline_id: "3131313131313131313131313131313131313131313131313131313131313131",
        installed_fp: &digest(0x37),
        incoming_package_fp: &digest(0x38),
        incoming_resource_fp: &digest(0x39),
        options_tag: &options_tag,
        installed_tree_snapshot_fingerprint: &snapshot,
        operations,
        backup_set: &backup_set,
        summary: &summary,
        status: super::TrustedApplyStatus::ReadyForTransactionalApply,
    })
    .unwrap();
    (snapshot, *backup_set.digest(), *plan_id.digest())
}

#[cfg(test)]
mod transition_tests {
    use super::*;
    use crate::trusted_staging::StagingSourceBinding;
    use crate::{Sha256Digest, TrustedStagingBundleId, TrustedStagingManifestId};

    fn dig(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn path(s: &str) -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str(s).unwrap()
    }

    fn present(byte: u8, len: u64) -> ApplyFileState {
        ApplyFileState::Present {
            digest: dig(byte),
            byte_length: len,
        }
    }

    fn ids() -> (TrustedStagingBundleId, TrustedStagingManifestId) {
        (
            TrustedStagingBundleId::from_digest(dig(0xaa)),
            TrustedStagingManifestId::from_digest(dig(0xbb)),
        )
    }

    fn plan(
        installed: &InstalledTreeModel,
        desired: &DesiredTreeModel,
    ) -> Result<PlannedOperations> {
        let (bundle_id, manifest_id) = ids();
        let bindings = BTreeMap::new();
        build_operations_with_bindings(
            installed,
            desired,
            &bindings,
            &bundle_id,
            &manifest_id,
            10_000,
        )
    }

    fn op_tuple(
        op: &TrustedApplyOperation,
    ) -> (
        TrustedApplyOperationKind,
        TrustedApplyOperationPhase,
        &str,
        ApplyBackupRequirement,
    ) {
        (
            op.kind(),
            op.phase(),
            op.destination_for_test().as_str(),
            op.backup_requirement(),
        )
    }

    fn frozen_state_label(
        operation: &TrustedApplyOperation,
        state: &ApplyFileState,
        before: bool,
    ) -> String {
        match (operation.kind(), before) {
            (TrustedApplyOperationKind::CreateDirectory, false)
            | (TrustedApplyOperationKind::RemoveDirectory, true) => "directory".to_owned(),
            _ => match state {
                ApplyFileState::Absent => "absent".to_owned(),
                ApplyFileState::Present {
                    digest,
                    byte_length,
                } => format!("file:{digest}:{byte_length}"),
            },
        }
    }

    #[test]
    fn file_to_directory_phase_order_and_backups() {
        let mut installed_files = BTreeMap::new();
        installed_files.insert(path("config"), present(1, 4));
        let installed = InstalledTreeModel {
            files: installed_files,
            directories: BTreeSet::new(),
        };
        let mut desired_files = BTreeMap::new();
        desired_files.insert(path("config/settings.lua"), present(2, 8));
        let desired = DesiredTreeModel {
            files: desired_files,
            directories: BTreeSet::from([path("config")]),
        };
        let planned = plan(&installed, &desired).unwrap();
        let got: Vec<_> = planned.operations.iter().map(op_tuple).collect();
        assert_eq!(
            got,
            vec![
                (
                    TrustedApplyOperationKind::DeleteFile,
                    TrustedApplyOperationPhase::RemoveBlockingFile,
                    "config",
                    ApplyBackupRequirement::PreserveInstalledFile,
                ),
                (
                    TrustedApplyOperationKind::CreateDirectory,
                    TrustedApplyOperationPhase::CreateDirectory,
                    "config",
                    ApplyBackupRequirement::None,
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "config/settings.lua",
                    ApplyBackupRequirement::None,
                ),
            ]
        );
        assert!(planned.operations.iter().all(|op| {
            !(op.destination_for_test().as_str() == "config"
                && op.phase() == TrustedApplyOperationPhase::DeleteObsoleteFile)
        }));
    }

    #[test]
    fn directory_to_file_deepest_first() {
        let mut installed_files = BTreeMap::new();
        installed_files.insert(path("config/settings.lua"), present(1, 4));
        installed_files.insert(path("config/nested/value.lua"), present(2, 5));
        let installed = InstalledTreeModel {
            files: installed_files,
            directories: BTreeSet::from([path("config"), path("config/nested")]),
        };
        let mut desired_files = BTreeMap::new();
        desired_files.insert(path("config"), present(3, 6));
        let desired = DesiredTreeModel {
            files: desired_files,
            directories: BTreeSet::new(),
        };
        let planned = plan(&installed, &desired).unwrap();
        let got: Vec<_> = planned.operations.iter().map(op_tuple).collect();
        assert_eq!(
            got,
            vec![
                (
                    TrustedApplyOperationKind::DeleteFile,
                    TrustedApplyOperationPhase::DeleteBlockingDescendant,
                    "config/nested/value.lua",
                    ApplyBackupRequirement::PreserveInstalledFile,
                ),
                (
                    TrustedApplyOperationKind::DeleteFile,
                    TrustedApplyOperationPhase::DeleteBlockingDescendant,
                    "config/settings.lua",
                    ApplyBackupRequirement::PreserveInstalledFile,
                ),
                (
                    TrustedApplyOperationKind::RemoveDirectory,
                    TrustedApplyOperationPhase::RemoveBlockingDirectory,
                    "config/nested",
                    ApplyBackupRequirement::PreserveRemovedDirectoryMetadata,
                ),
                (
                    TrustedApplyOperationKind::RemoveDirectory,
                    TrustedApplyOperationPhase::RemoveBlockingDirectory,
                    "config",
                    ApplyBackupRequirement::PreserveRemovedDirectoryMetadata,
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "config",
                    ApplyBackupRequirement::None,
                ),
            ]
        );
    }

    #[test]
    fn nested_and_simultaneous_transitions() {
        let mut installed_files = BTreeMap::new();
        installed_files.insert(path("a"), present(1, 1));
        installed_files.insert(path("b/x.lua"), present(2, 2));
        installed_files.insert(path("c/inner"), present(3, 3));
        let installed = InstalledTreeModel {
            files: installed_files,
            directories: BTreeSet::from([path("b"), path("c")]),
        };
        let mut desired_files = BTreeMap::new();
        desired_files.insert(path("a/nested.lua"), present(4, 4));
        desired_files.insert(path("b"), present(5, 5));
        desired_files.insert(path("c/inner/leaf.lua"), present(6, 6));
        let desired = DesiredTreeModel {
            files: desired_files,
            directories: BTreeSet::from([path("a"), path("c"), path("c/inner")]),
        };
        let planned = plan(&installed, &desired).unwrap();
        let phases: Vec<_> = planned
            .operations
            .iter()
            .map(|o| (o.phase(), o.kind(), o.destination_for_test().as_str()))
            .collect();
        assert!(phases.iter().any(|p| {
            *p == (
                TrustedApplyOperationPhase::RemoveBlockingFile,
                TrustedApplyOperationKind::DeleteFile,
                "a",
            )
        }));
        assert!(phases.iter().any(|p| {
            *p == (
                TrustedApplyOperationPhase::RemoveBlockingFile,
                TrustedApplyOperationKind::DeleteFile,
                "c/inner",
            )
        }));
        assert!(phases.iter().any(|p| {
            *p == (
                TrustedApplyOperationPhase::DeleteBlockingDescendant,
                TrustedApplyOperationKind::DeleteFile,
                "b/x.lua",
            )
        }));
        assert!(phases.iter().any(|p| {
            *p == (
                TrustedApplyOperationPhase::WriteFile,
                TrustedApplyOperationKind::InstallFile,
                "b",
            )
        }));
    }

    #[test]
    fn staged_or_installed_file_with_descendant_rejected() {
        let mut files = BTreeMap::new();
        files.insert(path("config"), present(1, 1));
        files.insert(path("config/settings.lua"), present(2, 2));
        let bad = InstalledTreeModel {
            files: files.clone(),
            directories: BTreeSet::new(),
        };
        let desired = DesiredTreeModel {
            files: BTreeMap::new(),
            directories: BTreeSet::new(),
        };
        assert!(matches!(
            plan(&bad, &desired),
            Err(GkrmError::TrustedApplyPlanningPathTypeConflict)
        ));
        let installed = InstalledTreeModel {
            files: BTreeMap::new(),
            directories: BTreeSet::new(),
        };
        let bad_desired = DesiredTreeModel {
            files,
            directories: BTreeSet::from([path("config")]),
        };
        assert!(matches!(
            plan(&installed, &bad_desired),
            Err(GkrmError::TrustedApplyPlanningPathTypeConflict)
        ));
    }

    #[test]
    fn empty_resource_root_path_rejected() {
        // Resource-root relative path is unrepresentable; empty strings fail parsing.
        assert!(ResourceRelativePath::try_from_slash_str("").is_err());
    }

    #[test]
    fn incompatible_same_path_ops_rejected() {
        let (bundle_id, manifest_id) = ids();
        let mut ops = Vec::new();
        let mut seen = BTreeSet::new();
        push_op_allow_file_dir_transition(
            &mut ops,
            &mut seen,
            TrustedApplyOperationKind::CreateDirectory,
            TrustedApplyOperationPhase::CreateDirectory,
            path("config"),
            ApplyFileState::Absent,
            ApplyFileState::Absent,
            None,
            ApplyBackupRequirement::None,
            &bundle_id,
            &manifest_id,
        )
        .unwrap();
        push_op_allow_file_dir_transition(
            &mut ops,
            &mut seen,
            TrustedApplyOperationKind::InstallFile,
            TrustedApplyOperationPhase::WriteFile,
            path("config"),
            ApplyFileState::Absent,
            present(1, 1),
            None,
            ApplyBackupRequirement::None,
            &bundle_id,
            &manifest_id,
        )
        .unwrap();
        assert!(matches!(
            reject_incompatible_destination_ops(&ops),
            Err(GkrmError::TrustedApplyPlanningDuplicateOperation)
        ));
    }

    #[test]
    fn operation_ids_stable_under_shuffled_map_insertion() {
        let mut installed_a = InstalledTreeModel {
            files: BTreeMap::new(),
            directories: BTreeSet::from([path("b")]),
        };
        installed_a.files.insert(path("b/x"), present(1, 1));
        installed_a.files.insert(path("a"), present(2, 2));
        let mut installed_b = InstalledTreeModel {
            files: BTreeMap::new(),
            directories: BTreeSet::from([path("b")]),
        };
        installed_b.files.insert(path("a"), present(2, 2));
        installed_b.files.insert(path("b/x"), present(1, 1));

        let mut desired_files = BTreeMap::new();
        desired_files.insert(path("a/z"), present(3, 3));
        desired_files.insert(path("b"), present(4, 4));
        let desired = DesiredTreeModel {
            files: desired_files,
            directories: BTreeSet::from([path("a")]),
        };
        let pa = plan(&installed_a, &desired).unwrap();
        let pb = plan(&installed_b, &desired).unwrap();
        assert_eq!(pa.operations.len(), pb.operations.len());
        for (a, b) in pa.operations.iter().zip(pb.operations.iter()) {
            assert_eq!(a.operation_id().digest(), b.operation_id().digest());
            assert_eq!(a.kind(), b.kind());
            assert_eq!(a.phase(), b.phase());
            assert_eq!(a.destination_for_test(), b.destination_for_test());
        }
        let _ = StagingSourceBinding::Absent;
    }

    #[test]
    fn task21_v1_comprehensive_shape_has_frozen_order_and_ids() {
        let installed = InstalledTreeModel {
            files: BTreeMap::from([
                (path("block/deep/old.lua"), present(1, 1)),
                (path("file-to-dir"), present(2, 2)),
                (path("remove.lua"), present(3, 3)),
                (path("replace.lua"), present(4, 4)),
            ]),
            directories: BTreeSet::from([
                path("block"),
                path("block/deep"),
                path("obsolete"),
                path("obsolete/deep"),
            ]),
        };
        let operations = frozen_task21_v1_operations_fixture();
        let order: Vec<_> = operations.iter().map(op_tuple).collect();
        let ids: Vec<_> = operations
            .iter()
            .map(|operation| operation.operation_id().digest().to_string())
            .collect();
        assert_eq!(
            order,
            vec![
                (
                    TrustedApplyOperationKind::DeleteFile,
                    TrustedApplyOperationPhase::RemoveBlockingFile,
                    "file-to-dir",
                    ApplyBackupRequirement::PreserveInstalledFile
                ),
                (
                    TrustedApplyOperationKind::DeleteFile,
                    TrustedApplyOperationPhase::DeleteBlockingDescendant,
                    "block/deep/old.lua",
                    ApplyBackupRequirement::PreserveInstalledFile
                ),
                (
                    TrustedApplyOperationKind::RemoveDirectory,
                    TrustedApplyOperationPhase::RemoveBlockingDirectory,
                    "block/deep",
                    ApplyBackupRequirement::PreserveRemovedDirectoryMetadata
                ),
                (
                    TrustedApplyOperationKind::RemoveDirectory,
                    TrustedApplyOperationPhase::RemoveBlockingDirectory,
                    "block",
                    ApplyBackupRequirement::PreserveRemovedDirectoryMetadata
                ),
                (
                    TrustedApplyOperationKind::CreateDirectory,
                    TrustedApplyOperationPhase::CreateDirectory,
                    "created-empty",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::CreateDirectory,
                    TrustedApplyOperationPhase::CreateDirectory,
                    "file-to-dir",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::CreateDirectory,
                    TrustedApplyOperationPhase::CreateDirectory,
                    "siblings",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::CreateDirectory,
                    TrustedApplyOperationPhase::CreateDirectory,
                    "file-to-dir/deep",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "block",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "create.lua",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "file-to-dir/a.lua",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "file-to-dir/deep/z.lua",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::ReplaceFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "replace.lua",
                    ApplyBackupRequirement::PreserveInstalledFile
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "siblings/a.lua",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::InstallFile,
                    TrustedApplyOperationPhase::WriteFile,
                    "siblings/b.lua",
                    ApplyBackupRequirement::None
                ),
                (
                    TrustedApplyOperationKind::DeleteFile,
                    TrustedApplyOperationPhase::DeleteObsoleteFile,
                    "remove.lua",
                    ApplyBackupRequirement::PreserveInstalledFile
                ),
                (
                    TrustedApplyOperationKind::RemoveDirectory,
                    TrustedApplyOperationPhase::RemoveObsoleteDirectory,
                    "obsolete/deep",
                    ApplyBackupRequirement::PreserveRemovedDirectoryMetadata
                ),
                (
                    TrustedApplyOperationKind::RemoveDirectory,
                    TrustedApplyOperationPhase::RemoveObsoleteDirectory,
                    "obsolete",
                    ApplyBackupRequirement::PreserveRemovedDirectoryMetadata
                ),
            ]
        );
        // Literal IDs below were regenerated and checked with an independent
        // Python struct.pack(<Q)/SHA-256 canonical encoder, not this Rust encoder.
        assert_eq!(
            ids,
            [
                "7ebb803fc4dce74483b26c6432129fafb6fa5540624457688b8fddf0f8de4317",
                "3da586d8454150cf6d46ce9b86daeb569121df23dc630b314c07a2b05823424c",
                "af0890c36761188378ed1cbd4f661d1480779a6fefe4d58362c6a957bedbafef",
                "9dbc44bd24092eb7624f2c78d986fa3ce7194dee1f0f50f4552487dc14bf82d0",
                "053eded2c5e72441b7031f2f6e69ca3c238b9c8a97c1a9bf31a5e8ee3ccd4fec",
                "8912ca28a368991b8d45a8d9e00d10470044cef216879e119cc2735d7b975a55",
                "9661b5d3748bf1c523f70a5ed77105f021d60b53891d2db75501450d796cca79",
                "981c5f473df94e2247c0aa2b52e7907b2f19add138b0893d643468b910d36a93",
                "d98f2ae4877bec645837db665b4b4ff92b779134ad2e663bd712766643bb51eb",
                "7a75efee50a78b3e5a49778c6b065bc5fce372286166c8bd27ba2badd5595642",
                "addc9e87548617802e46fc332f91d32995f17e05a2765f4b21695b622838a66c",
                "989a4268b33569c02925157ce57d8abf8743b33904e0be227fbf61956d0acad8",
                "bed0e69f92ff3447d289333495a1c912b98b67baae0a1069514cd38086cc1bb4",
                "871a9c62447e7d1d298131586e8d09d95599a07cd1732581ed05bf4f9db11a0a",
                "36579b23111e576b3f44ac0d41b9a1851f6a5a46941e00672ec8472bbd7ab8d2",
                "5f83313d93fd3a8d955e375e799ec20e87db7445ef3a3e6a2635821f3c887b56",
                "c813dc99b58cb63eeac8410992f8c12ab7e51a41dff7d336e6e02ddbf735b222",
                "f92cbe61eb93055722aeac51ebb590de4e489996bbcf09e05e13b620125127f2",
            ]
        );

        let (bindings, fixture_bundle_id, fixture_manifest_id) =
            crate::trusted_staging::frozen_task21_v1_staging_fixture_for_test(false);
        let binding_details: Vec<_> = bindings
            .into_iter()
            .map(|(path, binding)| {
                let binding = match binding {
                    StagingSourceBinding::InstalledDigest(digest) => {
                        format!("installed:{digest}")
                    }
                    StagingSourceBinding::IncomingDigest(digest) => {
                        format!("incoming:{digest}")
                    }
                    StagingSourceBinding::MergedArtifact(id) => {
                        format!("merged-artifact:{}", id.digest())
                    }
                    StagingSourceBinding::OperatorMerge(id) => {
                        format!("operator-merge:{id}")
                    }
                    StagingSourceBinding::Absent => "absent".to_owned(),
                };
                format!(
                    "{}|{}|bundle:{}|manifest:{}",
                    path.as_str(),
                    binding,
                    fixture_bundle_id.digest(),
                    fixture_manifest_id.digest()
                )
            })
            .collect();
        assert_eq!(
            binding_details,
            [
                "block|incoming:0505050505050505050505050505050505050505050505050505050505050505|bundle:196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1|manifest:96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7",
                "create.lua|incoming:0606060606060606060606060606060606060606060606060606060606060606|bundle:196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1|manifest:96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7",
                "file-to-dir/a.lua|merged-artifact:a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7|bundle:196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1|manifest:96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7",
                "file-to-dir/deep/z.lua|operator-merge:a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8|bundle:196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1|manifest:96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7",
                "replace.lua|incoming:0909090909090909090909090909090909090909090909090909090909090909|bundle:196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1|manifest:96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7",
                "siblings/a.lua|merged-artifact:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|bundle:196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1|manifest:96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7",
                "siblings/b.lua|operator-merge:abababababababababababababababababababababababababababababababab|bundle:196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1|manifest:96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7",
            ]
        );

        let complete: Vec<_> = operations
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                format!(
                    "{index}|{:?}|{:?}|{}|{:?}|{}|{}|{}|{}",
                    operation.phase(),
                    operation.kind(),
                    operation.destination_for_test().as_str(),
                    operation.backup_requirement(),
                    frozen_state_label(operation, operation.pre_state(), true),
                    frozen_state_label(operation, operation.post_state(), false),
                    operation.staged_binding_tag(),
                    operation.operation_id().digest(),
                )
            })
            .collect();
        // The complete rows also pin 255 (no staging binding) on every non-write
        // operation, including both sides of the file-to-directory transition.
        assert_eq!(
            complete,
            [
                "0|RemoveBlockingFile|DeleteFile|file-to-dir|PreserveInstalledFile|file:0202020202020202020202020202020202020202020202020202020202020202:2|absent|255|7ebb803fc4dce74483b26c6432129fafb6fa5540624457688b8fddf0f8de4317",
                "1|DeleteBlockingDescendant|DeleteFile|block/deep/old.lua|PreserveInstalledFile|file:0101010101010101010101010101010101010101010101010101010101010101:1|absent|255|3da586d8454150cf6d46ce9b86daeb569121df23dc630b314c07a2b05823424c",
                "2|RemoveBlockingDirectory|RemoveDirectory|block/deep|PreserveRemovedDirectoryMetadata|directory|absent|255|af0890c36761188378ed1cbd4f661d1480779a6fefe4d58362c6a957bedbafef",
                "3|RemoveBlockingDirectory|RemoveDirectory|block|PreserveRemovedDirectoryMetadata|directory|absent|255|9dbc44bd24092eb7624f2c78d986fa3ce7194dee1f0f50f4552487dc14bf82d0",
                "4|CreateDirectory|CreateDirectory|created-empty|None|absent|directory|255|053eded2c5e72441b7031f2f6e69ca3c238b9c8a97c1a9bf31a5e8ee3ccd4fec",
                "5|CreateDirectory|CreateDirectory|file-to-dir|None|absent|directory|255|8912ca28a368991b8d45a8d9e00d10470044cef216879e119cc2735d7b975a55",
                "6|CreateDirectory|CreateDirectory|siblings|None|absent|directory|255|9661b5d3748bf1c523f70a5ed77105f021d60b53891d2db75501450d796cca79",
                "7|CreateDirectory|CreateDirectory|file-to-dir/deep|None|absent|directory|255|981c5f473df94e2247c0aa2b52e7907b2f19add138b0893d643468b910d36a93",
                "8|WriteFile|InstallFile|block|None|absent|file:0505050505050505050505050505050505050505050505050505050505050505:5|2|d98f2ae4877bec645837db665b4b4ff92b779134ad2e663bd712766643bb51eb",
                "9|WriteFile|InstallFile|create.lua|None|absent|file:0606060606060606060606060606060606060606060606060606060606060606:6|2|7a75efee50a78b3e5a49778c6b065bc5fce372286166c8bd27ba2badd5595642",
                "10|WriteFile|InstallFile|file-to-dir/a.lua|None|absent|file:0707070707070707070707070707070707070707070707070707070707070707:7|3|addc9e87548617802e46fc332f91d32995f17e05a2765f4b21695b622838a66c",
                "11|WriteFile|InstallFile|file-to-dir/deep/z.lua|None|absent|file:0808080808080808080808080808080808080808080808080808080808080808:8|4|989a4268b33569c02925157ce57d8abf8743b33904e0be227fbf61956d0acad8",
                "12|WriteFile|ReplaceFile|replace.lua|PreserveInstalledFile|file:0404040404040404040404040404040404040404040404040404040404040404:4|file:0909090909090909090909090909090909090909090909090909090909090909:9|2|bed0e69f92ff3447d289333495a1c912b98b67baae0a1069514cd38086cc1bb4",
                "13|WriteFile|InstallFile|siblings/a.lua|None|absent|file:0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a:10|3|871a9c62447e7d1d298131586e8d09d95599a07cd1732581ed05bf4f9db11a0a",
                "14|WriteFile|InstallFile|siblings/b.lua|None|absent|file:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b:11|4|36579b23111e576b3f44ac0d41b9a1851f6a5a46941e00672ec8472bbd7ab8d2",
                "15|DeleteObsoleteFile|DeleteFile|remove.lua|PreserveInstalledFile|file:0303030303030303030303030303030303030303030303030303030303030303:3|absent|255|5f83313d93fd3a8d955e375e799ec20e87db7445ef3a3e6a2635821f3c887b56",
                "16|RemoveObsoleteDirectory|RemoveDirectory|obsolete/deep|PreserveRemovedDirectoryMetadata|directory|absent|255|c813dc99b58cb63eeac8410992f8c12ab7e51a41dff7d336e6e02ddbf735b222",
                "17|RemoveObsoleteDirectory|RemoveDirectory|obsolete|PreserveRemovedDirectoryMetadata|directory|absent|255|f92cbe61eb93055722aeac51ebb590de4e489996bbcf09e05e13b620125127f2",
            ]
        );

        let snapshot_a = super::super::tree::encode_installed_apply_tree_snapshot(
            &installed.files,
            &installed.directories,
        )
        .unwrap();
        let backup_set = super::super::id::encode_backup_set_id(&operations).unwrap();
        let summary = super::super::summarize(&operations, 56, 10).unwrap();
        let options_tag = super::super::TrustedApplyPlanningOptions::default()
            .options_tag()
            .unwrap();
        let plan_id = super::super::id::encode_plan_id(super::super::id::PlanIdInputs {
            plan_id: &crate::Sha256Digest::new([0x31; 32]),
            review_id: &crate::Sha256Digest::new([0x32; 32]),
            analysis_id: Some(&crate::Sha256Digest::new([0x33; 32])),
            text_diff_id: Some(&crate::Sha256Digest::new([0x34; 32])),
            synthesis_id: Some(&crate::Sha256Digest::new([0x35; 32])),
            merged_bytes_id: Some(&crate::Sha256Digest::new([0x36; 32])),
            bundle_id: fixture_bundle_id.digest(),
            manifest_id: fixture_manifest_id.digest(),
            resource_key: "gksphone",
            baseline_id: "3131313131313131313131313131313131313131313131313131313131313131",
            installed_fp: &crate::Sha256Digest::new([0x37; 32]),
            incoming_package_fp: &crate::Sha256Digest::new([0x38; 32]),
            incoming_resource_fp: &crate::Sha256Digest::new([0x39; 32]),
            options_tag: &options_tag,
            installed_tree_snapshot_fingerprint: &snapshot_a,
            operations: &operations,
            backup_set: &backup_set,
            summary: &summary,
            status: super::super::TrustedApplyStatus::ReadyForTransactionalApply,
        })
        .unwrap();
        assert_eq!(
            snapshot_a.to_string(),
            "6dd3bce88d3f0dd6c0e514088c7d70731f64427f8d81341be4063933acafac3d"
        );
        assert_eq!(
            backup_set.digest().to_string(),
            "87bec313adf0b4fb7e5a80f6347d5348e1cb87be0ffa8bd493cd8d8caa20be73"
        );
        assert_eq!(
            plan_id.digest().to_string(),
            "2c4f6dabe072570da4ddc7560a2de3137d2d5ea5723fc10ea144b72be701dd5d"
        );
    }
}
