//! Artifact-bound official baseline metadata and conservative retention.
use super::*;
use crate::two_way_plan::execution_descriptor::TwoWayExecutionDescriptor;
use crate::{BaselineId, BaselineStoreLimits, StoredBaseline};

pub(crate) fn resolve_baseline(
    workspace: &TrustedUpdateWorkspace,
    key: &SafeResourceKey,
    id: &BaselineId,
) -> Result<StoredBaseline> {
    let (dir, _) = workspace.try_clone_baseline_store_capability()?;
    crate::baseline::store::load_baseline_from_open_store(
        &crate::baseline::fs_security::OpenStoreRoot {
            path: workspace.baseline_store().to_path_buf(),
            dir,
        },
        key,
        id,
        BaselineStoreLimits::default(),
    )
}

pub(crate) fn validate_two_way_baseline_transition(
    workspace: &TrustedUpdateWorkspace,
    descriptor: &TwoWayExecutionDescriptor,
) -> Result<()> {
    let Some(transition) = descriptor.baseline_transition() else {
        return Ok(());
    };
    let plan = descriptor.reconstruct()?;
    let after = resolve_baseline(workspace, plan.resource_key(), &transition.after()?)?;
    if after.source_package_fingerprint() != Some(plan.incoming_package_fingerprint()) {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    if let Some(before) = transition.before()? {
        resolve_baseline(workspace, plan.resource_key(), &before)?;
    }
    Ok(())
}

/// Retention only: every bounded, canonical artifact can keep referenced content.
/// No unverified metadata grants mutation or declares an installation's baseline.
/// A malformed catalog refuses cleanup rather than hiding a reference.
pub fn referenced_trusted_baselines(
    workspace: &TrustedUpdateWorkspace,
) -> Result<BTreeSet<BaselineId>> {
    let options = TrustedPackageFreeUpdateRecoveryOptions::default();
    let (root, identity) = workspace.try_clone_artifact_root_capability()?;
    let mut result = BTreeSet::new();
    let mut entries = 0usize;
    let mut artifacts = 0usize;
    let mut total = 0u64;
    let parse_options = TrustedCliUpdateOptions::default();
    for entry in root
        .entries()
        .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        entries += 1;
        if entries > options.max_artifact_directory_entries {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        validate_single_component(&name)?;
        let meta = entry
            .full_metadata()
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        if is_windows_reparse_point_cap(&meta) || meta.file_type().is_symlink() {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        if !meta.is_file() || !name.starts_with("plan-") || !name.ends_with(".bin") {
            continue;
        }
        artifacts += 1;
        total = total
            .checked_add(meta.len())
            .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
        if artifacts > options.max_artifacts
            || meta.len() > options.max_artifact_bytes
            || total > options.max_total_artifact_bytes
        {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let mut file = open_file_nofollow(&root, &name)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(options.max_artifact_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        let artifact = parse_cli_artifact(&bytes, &parse_options)?;
        // Includes the three-way baseline; absent-record marker identities retain
        // no real bundle and are harmless conservative entries.
        result.insert(BaselineId::from_digest(artifact.body().baseline_id_digest));
        if let Some(transition) = artifact
            .two_way_descriptor()
            .and_then(|d| d.baseline_transition())
        {
            result.insert(transition.after()?);
            result.extend(transition.before()?);
        }
    }
    if dir_identity(&root, "artifacts")? != identity {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    Ok(result)
}

/// Recheck recovery state and durable baseline references under the publication
/// lock. Retirement alone never releases a baseline needed by retained history.
pub fn discard_unreferenced_trusted_baseline(
    workspace: &TrustedUpdateWorkspace,
    key: &SafeResourceKey,
    id: &BaselineId,
) -> Result<bool> {
    let _lock = crate::acquire_trusted_update_workspace_publication_lock(workspace)?;
    check_staging_release_allowed(
        workspace,
        TrustedPackageFreeUpdateRecoveryOptions::default(),
    )?;
    if referenced_trusted_baselines(workspace)?.contains(id) {
        return Ok(false);
    }
    let (store, _) = workspace.try_clone_baseline_store_capability()?;
    crate::baseline::store::discard_baseline_bundle_from_dir(&store, key, id)
}
