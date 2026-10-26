//! Complete reverse candidates built only from a verified Undo source and fresh installation.

use super::*;
use crate::baseline::fs_security::{dir_identity, open_child_dir, validate_single_component};
use crate::trusted_apply_planning::{
    parents_of, ApplyFileState, InstalledApplyPlanningSource, InstalledApplyTreeSnapshot,
};
use crate::{TrustedUndoDisposition, TrustedUndoPlan, TrustedUndoSource, TrustedUpdateWorkspace};
use cap_fs_ext::DirEntryExt;
use cap_std::fs::Dir as CapDir;
use std::collections::BTreeMap;

pub(crate) const UNDO_BASELINE_MARKER: &str = "undo:no-official-baseline";

/// Opaque staged reverse tree. This is not permission to change the live installation.
pub struct TrustedUndoStagingBundle {
    parent_transaction_id: Sha256Digest,
    previous_attempt: Option<Sha256Digest>,
    bundle: TrustedStagingBundle,
    resource_key: crate::SafeResourceKey,
    original_artifact_id: Sha256Digest,
    original_authority_id: Sha256Digest,
    installed_fingerprint: Sha256Digest,
    current_tree_fingerprint: Sha256Digest,
    installed: InstalledApplyPlanningSource,
    directories: BTreeSet<ResourceRelativePath>,
}

impl std::fmt::Debug for TrustedUndoStagingBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedUndoStagingBundle")
    }
}

impl TrustedUndoStagingBundle {
    pub(crate) fn previous_attempt(&self) -> Option<&Sha256Digest> {
        self.previous_attempt.as_ref()
    }

    pub(crate) fn into_bundle(self) -> TrustedStagingBundle {
        self.bundle
    }
    pub fn execution_descriptor(&self) -> Result<super::TrustedUndoExecutionDescriptor> {
        super::TrustedUndoExecutionDescriptor::from_staged(self)
    }

    pub fn parent_transaction_id(&self) -> &Sha256Digest {
        &self.parent_transaction_id
    }

    pub(crate) fn selected_root(&self) -> &crate::InstalledResourceRoot {
        self.installed.selected_resource_root()
    }

    /// Derive ordinary core operations without changing the installation.
    pub fn plan_apply(
        &self,
        selection: &crate::TrustedInstalledRecoverySelection,
    ) -> Result<crate::TrustedApplyPlan> {
        let installed = self.reopen_selected(selection)?;
        crate::plan_trusted_apply(crate::TrustedApplyPlanningRequest::try_new_undo(
            self,
            &installed,
            crate::TrustedApplyPlanningOptions::default(),
        )?)
    }

    /// Prepare backup, journal and rollback steps; this does not execute them.
    pub fn plan_transaction(
        &self,
        selection: &crate::TrustedInstalledRecoverySelection,
        apply_plan: &crate::TrustedApplyPlan,
    ) -> Result<crate::TrustedTransactionalApplyPlan> {
        let installed = self.reopen_selected(selection)?;
        crate::plan_trusted_transactional_apply(
            crate::TrustedTransactionalApplyPlanningRequest::try_new_undo(
                apply_plan,
                self,
                &installed,
                crate::TrustedTransactionalApplyPlanningOptions::default(),
            )?,
        )
    }

    fn reopen_selected(
        &self,
        selection: &crate::TrustedInstalledRecoverySelection,
    ) -> Result<InstalledApplyPlanningSource> {
        let installed = selection
            .source()
            .reopen_for_package_free_recovery(crate::InstalledScanLimits::default())?;
        self.validate_installed_binding(&installed)?;
        if installed
            .capture_tree_snapshot(&self.resource_key)?
            .fingerprint
            != self.current_tree_fingerprint
        {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        Ok(installed)
    }

    pub(crate) fn validate_installed_binding(
        &self,
        installed: &InstalledApplyPlanningSource,
    ) -> Result<()> {
        self.installed.validate_identities()?;
        installed.validate_identities()?;
        if installed.installed_root_identity() != self.installed.installed_root_identity()
            || installed.selected_resource_identity() != self.installed.selected_resource_identity()
            || installed.selected_resource_root() != self.installed.selected_resource_root()
        {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        Ok(())
    }

    pub(crate) fn current_tree_fingerprint(&self) -> &Sha256Digest {
        &self.current_tree_fingerprint
    }

    pub(crate) fn verify_directories(&self) -> Result<()> {
        verify_directories(
            &self.bundle.resource_dir,
            &self.directories,
            TrustedStagingOptions::default(),
        )
    }

    pub fn bundle(&self) -> &TrustedStagingBundle {
        &self.bundle
    }
    pub fn resource_key(&self) -> &crate::SafeResourceKey {
        &self.resource_key
    }
    pub fn original_artifact_id(&self) -> &Sha256Digest {
        &self.original_artifact_id
    }
    pub fn original_authority_id(&self) -> &Sha256Digest {
        &self.original_authority_id
    }
    pub fn installed_fingerprint(&self) -> &Sha256Digest {
        &self.installed_fingerprint
    }
    pub fn directories(&self) -> &BTreeSet<ResourceRelativePath> {
        &self.directories
    }
}

pub(crate) fn stage_undo_candidate(
    source: &TrustedUndoSource,
    plan: &TrustedUndoPlan,
    current: &InstalledApplyTreeSnapshot,
    installed_authority: &InstalledApplyPlanningSource,
    installed_content: &InstalledStagingContentSource,
    root: &TrustedStagingRoot,
    workspace: &TrustedUpdateWorkspace,
) -> Result<TrustedUndoStagingBundle> {
    let PreparedUndoCandidate {
        manifest,
        summary,
        directories,
        installed_fingerprint,
    } = prepare_undo_candidate(source, plan, current)?;
    let options = TrustedStagingOptions::default();
    let manifest_bytes = encode_manifest_bytes(&manifest)?;
    let bytes = summary
        .total_bytes()
        .checked_add(manifest_bytes.len() as u64)
        .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
    let entry_count = directories
        .len()
        .checked_add(summary.present_entries())
        .and_then(|count| count.checked_add(5))
        .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
    let _publication_lock = crate::acquire_trusted_update_workspace_publication_lock(workspace)?;
    crate::enforce_trusted_update_workspace_capacity_for_reservation(
        workspace,
        crate::TrustedUpdateWorkspaceOptions::default(),
        crate::TrustedUpdateWorkspaceReservation::new(bytes, entry_count, 0, 0)?,
    )?;
    root.revalidate_identity()?;
    installed_authority.validate_identities()?;
    let (tmp, bundles) = ensure_internal_layout(root)?;
    let (published, guard) = write_and_publish(
        root,
        &tmp,
        &bundles,
        &manifest,
        installed_content,
        write::AuxiliaryContentSource::Undo {
            source,
            directories: &directories,
        },
        None,
        &[],
    )?;
    let finished = (|| {
        verify_directories(&published.resource_dir, &directories, options)?;
        installed_authority.validate_identities()?;
        if installed_authority
            .capture_tree_snapshot(source.resource_key())?
            .fingerprint
            != current.fingerprint
        {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        root.revalidate_identity()?;
        let status = TrustedStagingStatus::ReadyForApplyPlanning;
        let bundle_id = encode_bundle_id(&manifest, &summary, status)?;
        Ok(TrustedUndoStagingBundle {
            parent_transaction_id: *source.transaction_id(),
            previous_attempt: plan.previous_attempt().copied(),
            bundle: TrustedStagingBundle {
                staging_root: TrustedStagingRoot::try_open(root.path_for_disjointness())?,
                published_dir: published.published_dir,
                resource_dir: published.resource_dir,
                manifest,
                summary,
                status,
                bundle_id,
            },
            resource_key: source.resource_key().clone(),
            original_artifact_id: *source.artifact_id(),
            original_authority_id: *source.authority_id(),
            installed_fingerprint,
            current_tree_fingerprint: current.fingerprint,
            installed: installed_authority
                .reopen_for_package_free_recovery(crate::InstalledScanLimits::default())?,
            directories,
        })
    })();
    match finished {
        Ok(bundle) => {
            guard.disarm();
            Ok(bundle)
        }
        Err(error) => Err(guard.fail_with_cleanup(error)),
    }
}

struct PreparedUndoCandidate {
    manifest: TrustedStagingManifest,
    summary: TrustedStagingSummary,
    directories: BTreeSet<ResourceRelativePath>,
    installed_fingerprint: Sha256Digest,
}

pub(crate) fn reopen_undo_candidate(
    workspace: &TrustedUpdateWorkspace,
    source: &TrustedUndoSource,
    current: &InstalledApplyTreeSnapshot,
    installed: &InstalledApplyPlanningSource,
    body: &crate::TrustedCliUpdateArtifactBody,
    descriptor: &super::TrustedUndoExecutionDescriptor,
) -> Result<TrustedUndoStagingBundle> {
    let plan = source.plan_from_snapshot(current, descriptor.previous_attempt()?)?;
    if source.transaction_id() != &descriptor.parent_transaction_id()?
        || source.artifact_id() != &descriptor.parent_artifact_id()?
        || source.authority_id() != &descriptor.parent_authority_id()?
        || source.resource_key() != &descriptor.resource_key()?
        || installed.selected_resource_root() != &descriptor.selected_root()?
        || plan.plan_id() != &descriptor.plan_id()?
        || current.fingerprint != descriptor.current_tree_fingerprint()?
    {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let prepared = prepare_undo_candidate(source, &plan, current)?;
    if prepared.directories != descriptor.directories()?
        || prepared.installed_fingerprint != descriptor.current_files_fingerprint()?
        || prepared.manifest.manifest_id().digest() != &body.staging_manifest_id
    {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let root = TrustedStagingRoot::try_open(workspace.staging_root())?;
    let bundle = super::reopen_staging_artifact_with_marker(
        &root,
        body,
        source.resource_key(),
        UNDO_BASELINE_MARKER,
        &prepared.installed_fingerprint,
        source.artifact_id(),
        source.authority_id(),
        TrustedStagingOptions::default(),
    )?;
    if encode_manifest_bytes(bundle.manifest())? != encode_manifest_bytes(&prepared.manifest)? {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let staged = TrustedUndoStagingBundle {
        parent_transaction_id: *source.transaction_id(),
        previous_attempt: plan.previous_attempt().copied(),
        bundle,
        resource_key: source.resource_key().clone(),
        original_artifact_id: *source.artifact_id(),
        original_authority_id: *source.authority_id(),
        installed_fingerprint: prepared.installed_fingerprint,
        current_tree_fingerprint: current.fingerprint,
        installed: installed
            .reopen_for_package_free_recovery(crate::InstalledScanLimits::default())?,
        directories: prepared.directories,
    };
    staged.verify_directories()?;
    if staged.execution_descriptor()?.encode()? != descriptor.encode()? {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    Ok(staged)
}

pub(crate) fn undo_record_marker(name: &str) -> Result<Sha256Digest> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-undo-record-marker-v1")?;
    encoder.string(name)?;
    Ok(encoder.finish())
}

fn prepare_undo_candidate(
    source: &TrustedUndoSource,
    plan: &TrustedUndoPlan,
    current: &InstalledApplyTreeSnapshot,
) -> Result<PreparedUndoCandidate> {
    if &current.fingerprint != plan.current_fingerprint()
        || plan.transaction_id() != source.transaction_id()
    {
        return Err(GkrmError::TrustedApplyPlanningInstalledStale);
    }
    let options = TrustedStagingOptions::default();
    let mut entries = BTreeMap::new();
    for (path, state) in &current.files {
        if let ApplyFileState::Present {
            digest,
            byte_length,
        } = state
        {
            entries.insert(
                path.clone(),
                manifest::present(
                    path.clone(),
                    StagingFinalState::Installed,
                    StagingContentOrigin::Installed,
                    *digest,
                    StagingSourceBinding::InstalledDigest(*digest),
                    Some(*byte_length),
                ),
            );
        }
    }
    for entry in plan.entries() {
        match entry.disposition() {
            TrustedUndoDisposition::RestoreOriginal => {
                let original = source
                    .changes()
                    .iter()
                    .find(|change| change.path() == entry.path())
                    .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
                if original.before() != entry.original() {
                    return Err(GkrmError::TrustedStagingFinalTreeRejected);
                }
                let digest = *original
                    .before()
                    .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
                let length = original
                    .before_length()
                    .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
                entries.insert(
                    entry.path().clone(),
                    manifest::present(
                        entry.path().clone(),
                        StagingFinalState::Incoming,
                        StagingContentOrigin::Incoming,
                        digest,
                        StagingSourceBinding::IncomingDigest(digest),
                        Some(length),
                    ),
                );
            }
            TrustedUndoDisposition::RemoveCreated => {
                entries.insert(entry.path().clone(), manifest::absent(entry.path().clone()));
            }
            TrustedUndoDisposition::AlreadyOriginal | TrustedUndoDisposition::PreserveChanged => {}
        }
    }
    let present: BTreeSet<_> = entries
        .values()
        .filter(|entry| entry.final_state() != StagingFinalState::Absent)
        .map(|entry| entry.path().clone())
        .collect();
    let mut directories: BTreeSet<_> = current
        .directories
        .difference(source.created_directories())
        .cloned()
        .collect();
    for directory in source.removed_directories() {
        if !present.contains(directory)
            && !parents_of(directory)
                .iter()
                .any(|parent| present.contains(parent))
        {
            directories.insert(directory.clone());
        }
    }
    for path in &present {
        directories.extend(parents_of(path));
    }
    let retained: Vec<_> = directories.iter().cloned().collect();
    for path in retained {
        directories.extend(parents_of(&path));
    }
    if directories.len() > options.max_directories()
        || directories.iter().any(|directory| {
            present.contains(directory)
                || parents_of(directory)
                    .iter()
                    .any(|parent| present.contains(parent))
        })
    {
        return Err(GkrmError::TrustedStagingFinalTreeRejected);
    }
    let mut entries: Vec<_> = entries.into_values().collect();
    enforce_structural_limits(&entries, options)?;
    assign_entry_ids(&mut entries, plan.plan_id())?;
    let mut review = CanonicalFingerprintEncoder::new("gkrm-undo-staging-review-v1")
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    review.digest(plan.plan_id());
    review
        .usize(directories.len())
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    for directory in &directories {
        review
            .path(directory)
            .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    }
    let review_id = review.finish();
    let installed_fingerprint = current.file_only_plan_fingerprint(source.resource_key())?;
    let manifest_id = encode_manifest_id(
        plan.plan_id(),
        &review_id,
        None,
        None,
        None,
        None,
        source.resource_key().as_str(),
        UNDO_BASELINE_MARKER,
        &installed_fingerprint,
        source.artifact_id(),
        source.authority_id(),
        &options.options_tag()?,
        &entries,
    )?;
    let summary = summarize(&entries)?;
    enforce_byte_limits(&entries, &summary, options)?;
    let manifest = TrustedStagingManifest {
        entries,
        manifest_id,
        plan_id: *plan.plan_id(),
        review_id,
        analysis_id: None,
        text_diff_id: None,
        synthesis_id: None,
        merged_bytes_id: None,
    };
    Ok(PreparedUndoCandidate {
        manifest,
        summary,
        directories,
        installed_fingerprint,
    })
}

fn verify_directories(
    root: &CapDir,
    expected: &BTreeSet<ResourceRelativePath>,
    options: TrustedStagingOptions,
) -> Result<()> {
    fn walk(
        dir: &CapDir,
        prefix: &str,
        found: &mut BTreeSet<ResourceRelativePath>,
        options: TrustedStagingOptions,
        count: &mut usize,
    ) -> Result<()> {
        let identity = dir_identity(dir, "undo-staging-directory")?;
        for entry in dir
            .entries()
            .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?
        {
            let entry = entry.map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?;
            *count = count
                .checked_add(1)
                .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
            if *count > options.max_entries() + options.max_directories() {
                return Err(GkrmError::TrustedStagingFinalTreeRejected);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?;
            validate_single_component(&name)?;
            let metadata = entry
                .full_metadata()
                .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?;
            if metadata.file_type().is_symlink()
                || crate::file_identity::is_windows_reparse_point_cap(&metadata)
            {
                return Err(GkrmError::TrustedStagingUnsafeFilesystemObject);
            }
            if metadata.file_type().is_dir() {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let relative = ResourceRelativePath::try_from_slash_str(&path)?;
                if relative.as_str().split('/').count() > options.max_path_depth() {
                    return Err(GkrmError::TrustedStagingFinalTreeRejected);
                }
                found.insert(relative);
                let child = open_child_dir(dir, &name)?;
                walk(&child, &path, found, options, count)?;
            } else if !metadata.file_type().is_file() {
                return Err(GkrmError::TrustedStagingUnsafeFilesystemObject);
            }
        }
        if dir_identity(dir, "undo-staging-directory")? != identity {
            return Err(GkrmError::TrustedStagingUnsafeFilesystemObject);
        }
        Ok(())
    }
    let mut found = BTreeSet::new();
    walk(root, "", &mut found, options, &mut 0)?;
    if &found != expected {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    Ok(())
}
