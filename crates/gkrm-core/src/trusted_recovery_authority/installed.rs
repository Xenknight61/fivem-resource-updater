use crate::file_identity::StableFileIdentity;
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::trusted_apply_planning::InstalledApplyPlanningSource;
use crate::{GkrmError, InstalledResourceRoot, Result, SafeResourceKey, Sha256Digest};

pub(crate) fn installed_authority_commitment(
    source: &InstalledApplyPlanningSource,
    resource_key: &SafeResourceKey,
) -> Result<Sha256Digest> {
    source.validate_identities()?;
    encode_installed_authority_commitment(
        source.installed_root_identity(),
        source.selected_resource_identity(),
        source.selected_resource_root(),
        resource_key,
    )
}

pub(crate) fn verify_installed_authority_commitment(
    source: &InstalledApplyPlanningSource,
    resource_key: &SafeResourceKey,
    stored: &Sha256Digest,
) -> Result<()> {
    if &installed_authority_commitment(source, resource_key)? != stored {
        return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
    }
    Ok(())
}

pub(crate) fn encode_installed_authority_commitment(
    root_identity: &StableFileIdentity,
    resource_identity: &StableFileIdentity,
    selected_root: &InstalledResourceRoot,
    resource_key: &SafeResourceKey,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-installed-recovery-authority-v1")
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    enc.u8(1);
    encode_identity_pair(&mut enc, root_identity, resource_identity)?;
    match selected_root {
        InstalledResourceRoot::Root => enc.u8(0),
        InstalledResourceRoot::Path(path) => {
            enc.u8(1);
            enc.string(path.as_str())
                .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
        }
    }
    enc.string(resource_key.as_str())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    Ok(enc.finish())
}

fn encode_identity_pair(
    enc: &mut CanonicalFingerprintEncoder,
    root: &StableFileIdentity,
    resource: &StableFileIdentity,
) -> Result<()> {
    match (root, resource) {
        #[cfg(unix)]
        (
            StableFileIdentity::Unix {
                device: root_device,
                inode: root_inode,
            },
            StableFileIdentity::Unix {
                device: resource_device,
                inode: resource_inode,
            },
        ) => {
            enc.u8(1);
            enc.u64(*root_device);
            enc.u64(*root_inode);
            enc.u64(*resource_device);
            enc.u64(*resource_inode);
        }
        #[cfg(windows)]
        (
            StableFileIdentity::Windows {
                volume_serial: root_volume,
                file_index: root_index,
            },
            StableFileIdentity::Windows {
                volume_serial: resource_volume,
                file_index: resource_index,
            },
        ) => {
            enc.u8(2);
            enc.u64(*root_volume);
            enc.u64(*root_index);
            enc.u64(*resource_volume);
            enc.u64(*resource_index);
        }
    }
    Ok(())
}
