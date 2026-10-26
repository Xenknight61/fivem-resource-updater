//! Canonical CLI update artifact (single immutable binary object).

use crate::trusted_staging::TrustedUndoExecutionDescriptor;
use crate::two_way_plan::execution_descriptor::TwoWayExecutionDescriptor;
use sha2::{Digest, Sha256};

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, Result, Sha256Digest};
use serde::{Deserialize, Serialize};

use super::id::{encode_cli_artifact_id, encode_cli_artifact_v2_id};
use super::limits::TrustedCliUpdateOptions;

pub const ARTIFACT_MAGIC: &[u8] = b"gkrm-cli-update-artifact-v1\n";
pub const ARTIFACT_FORMAT_VERSION: u8 = 1;
pub const ARTIFACT_V2_MAGIC: &[u8] = b"gkrm-cli-update-artifact-v2\n";
pub const ARTIFACT_V2_FORMAT_VERSION: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedCliUpdateArtifactId(Sha256Digest);

impl TrustedCliUpdateArtifactId {
    pub fn to_hex(&self) -> String {
        self.0.to_string()
    }

    pub(crate) fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl std::fmt::Debug for TrustedCliUpdateArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedCliUpdateArtifactId")
    }
}

/// Opaque commitments bound into the CLI artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedCliUpdateArtifactBody {
    pub package_fingerprint: Sha256Digest,
    pub selected_resource_commitment: Sha256Digest,
    pub baseline_id_digest: Sha256Digest,
    pub plan_id: Sha256Digest,
    pub review_id: Sha256Digest,
    pub analysis_id: Option<Sha256Digest>,
    pub text_diff_id: Option<Sha256Digest>,
    pub synthesis_id: Option<Sha256Digest>,
    pub merged_bytes_id: Option<Sha256Digest>,
    pub operator_merge_set_id: Sha256Digest,
    pub staging_manifest_id: Sha256Digest,
    pub staging_bundle_id: Sha256Digest,
    pub apply_plan_id: Sha256Digest,
    pub snapshot_a: Sha256Digest,
    pub transactional_plan_id: Sha256Digest,
    pub recovery_authority_id: Option<Sha256Digest>,
    pub decision_document_id: Sha256Digest,
}

impl std::fmt::Debug for TrustedCliUpdateArtifactBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedCliUpdateArtifactBody")
    }
}

pub struct TrustedCliUpdateArtifact {
    version: u8,
    artifact_id: TrustedCliUpdateArtifactId,
    body: TrustedCliUpdateArtifactBody,
    apply_descriptor: Option<TrustedCliApplyDescriptor>,
    two_way_descriptor: Option<TwoWayExecutionDescriptor>,
    undo_descriptor: Option<TrustedUndoExecutionDescriptor>,
    bytes: Vec<u8>,
}

impl TrustedCliUpdateArtifact {
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn artifact_id(&self) -> &TrustedCliUpdateArtifactId {
        &self.artifact_id
    }

    pub fn body(&self) -> &TrustedCliUpdateArtifactBody {
        &self.body
    }

    pub fn apply_descriptor(&self) -> Option<&TrustedCliApplyDescriptor> {
        self.apply_descriptor.as_ref()
    }

    pub fn two_way_descriptor(&self) -> Option<&TwoWayExecutionDescriptor> {
        self.two_way_descriptor.as_ref()
    }

    pub fn undo_descriptor(&self) -> Option<&TrustedUndoExecutionDescriptor> {
        self.undo_descriptor.as_ref()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedCliApplyDescriptor {
    version: u8,
    resource_key: String,
    baseline_id: String,
    selected_installed_root: String,
    installed_snapshot_fingerprint: String,
    incoming_package_fingerprint: String,
    incoming_resource_fingerprint: String,
    entries: Vec<TrustedCliApplyDescriptorEntry>,
}

impl TrustedCliApplyDescriptor {
    pub const VERSION: u8 = 1;

    pub fn try_new(
        resource_key: &crate::SafeResourceKey,
        baseline_id: &crate::BaselineId,
        selected_installed_root: &crate::InstalledResourceRoot,
        installed_snapshot_fingerprint: &Sha256Digest,
        incoming_package_fingerprint: &Sha256Digest,
        incoming_resource_fingerprint: &Sha256Digest,
        plan: &crate::ThreeWayUpdatePlan,
        review: &crate::ThreeWayPlanReview,
    ) -> Result<Self> {
        if plan.entries().len() != review.entries().len() {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let selected_installed_root = match selected_installed_root {
            crate::InstalledResourceRoot::Root => ".".to_owned(),
            crate::InstalledResourceRoot::Path(path) => path.as_str().to_owned(),
        };
        let descriptor = Self {
            version: Self::VERSION,
            resource_key: resource_key.as_str().to_owned(),
            baseline_id: baseline_id.as_str().to_owned(),
            selected_installed_root,
            installed_snapshot_fingerprint: installed_snapshot_fingerprint.to_string(),
            incoming_package_fingerprint: incoming_package_fingerprint.to_string(),
            incoming_resource_fingerprint: incoming_resource_fingerprint.to_string(),
            entries: plan
                .entries()
                .iter()
                .zip(review.entries())
                .map(|(plan, review)| {
                    TrustedCliApplyDescriptorEntry::from_plan_review(plan, review)
                })
                .collect::<Result<Vec<_>>>()?,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn resource_key(&self) -> Result<crate::SafeResourceKey> {
        crate::SafeResourceKey::parse(&self.resource_key)
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)
    }

    pub fn baseline_id(&self) -> Result<crate::BaselineId> {
        crate::BaselineId::parse(&self.baseline_id)
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)
    }

    pub fn selected_installed_root(&self) -> Result<crate::InstalledResourceRoot> {
        if self.selected_installed_root == "." {
            return Ok(crate::InstalledResourceRoot::Root);
        }
        let path = crate::InstallationRelativePath::from_path(std::path::Path::new(
            &self.selected_installed_root,
        ))
        .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        Ok(crate::InstalledResourceRoot::Path(path))
    }

    pub fn installed_snapshot_fingerprint(&self) -> Result<Sha256Digest> {
        parse_descriptor_digest(&self.installed_snapshot_fingerprint)
    }

    pub fn incoming_package_fingerprint(&self) -> Result<Sha256Digest> {
        parse_descriptor_digest(&self.incoming_package_fingerprint)
    }

    pub fn incoming_resource_fingerprint(&self) -> Result<Sha256Digest> {
        parse_descriptor_digest(&self.incoming_resource_fingerprint)
    }

    fn validate(&self) -> Result<()> {
        if self.version != Self::VERSION {
            return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
        }
        let _ = self.resource_key()?;
        let _ = self.baseline_id()?;
        let _ = self.selected_installed_root()?;
        let _ = self.installed_snapshot_fingerprint()?;
        let _ = self.incoming_package_fingerprint()?;
        let _ = self.incoming_resource_fingerprint()?;
        if self.entries.is_empty() {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let mut previous_path: Option<&str> = None;
        for entry in &self.entries {
            entry.validate()?;
            if previous_path.is_some_and(|previous| previous >= entry.path.as_str()) {
                return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
            }
            previous_path = Some(entry.path.as_str());
        }
        Ok(())
    }

    pub(crate) fn plan_entries(&self) -> Result<Vec<crate::ThreeWayPlanEntry>> {
        self.entries
            .iter()
            .map(TrustedCliApplyDescriptorEntry::plan_entry)
            .collect()
    }

    pub(crate) fn review_entries(&self) -> Result<Vec<crate::ThreeWayPlanReviewEntry>> {
        self.entries
            .iter()
            .map(TrustedCliApplyDescriptorEntry::review_entry)
            .collect()
    }
}

impl std::fmt::Debug for TrustedCliApplyDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedCliApplyDescriptor")
    }
}

fn parse_descriptor_digest(value: &str) -> Result<Sha256Digest> {
    Sha256Digest::from_lowercase_hex(value).map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)
}

const APPLY_DESCRIPTOR_MAGIC: &[u8] = b"gkrm-cli-apply-descriptor-bin-v1\n";

fn encode_apply_descriptor_bytes(descriptor: &TrustedCliApplyDescriptor) -> Result<Vec<u8>> {
    descriptor.validate()?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(APPLY_DESCRIPTOR_MAGIC);
    bytes.push(descriptor.version);
    write_canonical_string(&mut bytes, &descriptor.resource_key)?;
    write_canonical_string(&mut bytes, &descriptor.baseline_id)?;
    write_canonical_string(&mut bytes, &descriptor.selected_installed_root)?;
    bytes.extend_from_slice(descriptor.installed_snapshot_fingerprint()?.as_bytes());
    bytes.extend_from_slice(descriptor.incoming_package_fingerprint()?.as_bytes());
    bytes.extend_from_slice(descriptor.incoming_resource_fingerprint()?.as_bytes());
    write_canonical_len(&mut bytes, descriptor.entries.len())?;
    for entry in &descriptor.entries {
        write_canonical_string(&mut bytes, &entry.path)?;
        write_file_state(&mut bytes, &entry.baseline_state)?;
        write_file_state(&mut bytes, &entry.installed_state)?;
        write_file_state(&mut bytes, &entry.incoming_state)?;
        bytes.push(encode_delta_tag(decode_delta(&entry.local_delta)?)?);
        bytes.push(encode_delta_tag(decode_delta(&entry.incoming_delta)?)?);
        bytes.push(encode_disposition_tag(decode_disposition(
            &entry.disposition,
        )?)?);
        bytes.push(encode_reviewed_action_tag(decode_reviewed_action(
            &entry.reviewed_action,
        )?)?);
    }
    Ok(bytes)
}

fn parse_apply_descriptor_bytes(
    bytes: &[u8],
    max_entries: usize,
) -> Result<TrustedCliApplyDescriptor> {
    if bytes.len() < APPLY_DESCRIPTOR_MAGIC.len() + 1 {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    if !bytes.starts_with(APPLY_DESCRIPTOR_MAGIC) {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let mut offset = APPLY_DESCRIPTOR_MAGIC.len();
    let version = read_canonical_u8(bytes, &mut offset)?;
    if version != TrustedCliApplyDescriptor::VERSION {
        return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
    }
    let resource_key = read_canonical_string(bytes, &mut offset)?;
    let baseline_id = read_canonical_string(bytes, &mut offset)?;
    let selected_installed_root = read_canonical_string(bytes, &mut offset)?;
    let installed_snapshot_fingerprint = read_canonical_digest(bytes, &mut offset)?.to_string();
    let incoming_package_fingerprint = read_canonical_digest(bytes, &mut offset)?.to_string();
    let incoming_resource_fingerprint = read_canonical_digest(bytes, &mut offset)?.to_string();
    let entry_count = read_canonical_len(bytes, &mut offset)?;
    if entry_count == 0 || entry_count > max_entries {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_decision_entries",
        });
    }
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        entries.push(TrustedCliApplyDescriptorEntry {
            path: read_canonical_string(bytes, &mut offset)?,
            baseline_state: read_file_state(bytes, &mut offset)?,
            installed_state: read_file_state(bytes, &mut offset)?,
            incoming_state: read_file_state(bytes, &mut offset)?,
            local_delta: encode_delta(decode_delta_tag(read_canonical_u8(bytes, &mut offset)?)?)
                .to_owned(),
            incoming_delta: encode_delta(decode_delta_tag(read_canonical_u8(bytes, &mut offset)?)?)
                .to_owned(),
            disposition: encode_disposition(decode_disposition_tag(read_canonical_u8(
                bytes,
                &mut offset,
            )?)?)
            .to_owned(),
            reviewed_action: encode_reviewed_action(decode_reviewed_action_tag(
                read_canonical_u8(bytes, &mut offset)?,
            )?)
            .to_owned(),
        });
    }
    if offset != bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let descriptor = TrustedCliApplyDescriptor {
        version,
        resource_key,
        baseline_id,
        selected_installed_root,
        installed_snapshot_fingerprint,
        incoming_package_fingerprint,
        incoming_resource_fingerprint,
        entries,
    };
    descriptor.validate()?;
    if encode_apply_descriptor_bytes(&descriptor)? != bytes {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    Ok(descriptor)
}

fn write_file_state(bytes: &mut Vec<u8>, state: &TrustedCliApplyDescriptorFileState) -> Result<()> {
    match state.to_state()? {
        crate::ThreeWayFileState::Absent => bytes.push(0),
        crate::ThreeWayFileState::Present {
            sha256,
            escrow_class,
            trusted_baseline_blob_available,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(sha256.as_bytes());
            bytes.push(match escrow_class {
                None => 0,
                Some(crate::BaselineEscrowClass::Protected) => 1,
                Some(crate::BaselineEscrowClass::Ignored) => 2,
                Some(crate::BaselineEscrowClass::NotSupported) => 3,
            });
            bytes.push(u8::from(trusted_baseline_blob_available));
        }
    }
    Ok(())
}

fn read_file_state(bytes: &[u8], offset: &mut usize) -> Result<TrustedCliApplyDescriptorFileState> {
    match read_canonical_u8(bytes, offset)? {
        0 => Ok(TrustedCliApplyDescriptorFileState {
            presence: "absent".to_owned(),
            sha256: None,
            escrow_class: None,
            trusted_baseline_blob_available: false,
        }),
        1 => {
            let sha256 = read_canonical_digest(bytes, offset)?;
            let escrow_class = match read_canonical_u8(bytes, offset)? {
                0 => None,
                1 => Some("protected".to_owned()),
                2 => Some("ignored".to_owned()),
                3 => Some("not_supported".to_owned()),
                _ => return Err(GkrmError::TrustedCliUpdateArtifactInvalid),
            };
            let trusted_baseline_blob_available = match read_canonical_u8(bytes, offset)? {
                0 => false,
                1 => true,
                _ => return Err(GkrmError::TrustedCliUpdateArtifactInvalid),
            };
            Ok(TrustedCliApplyDescriptorFileState {
                presence: "present".to_owned(),
                sha256: Some(sha256.to_string()),
                escrow_class,
                trusted_baseline_blob_available,
            })
        }
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

fn write_canonical_len(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u64::try_from(value).map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_canonical_string(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    write_canonical_len(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_canonical_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
    if *offset >= bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let value = bytes[*offset];
    *offset += 1;
    Ok(value)
}

fn read_canonical_len(bytes: &[u8], offset: &mut usize) -> Result<usize> {
    let end = checked_artifact_end(*offset, 8)?;
    if end > bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let value = u64::from_le_bytes(bytes[*offset..end].try_into().unwrap());
    *offset = end;
    let remaining = bytes.len().saturating_sub(*offset);
    if value > u64::try_from(remaining).map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)? {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    usize::try_from(value).map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)
}

fn read_canonical_string(bytes: &[u8], offset: &mut usize) -> Result<String> {
    let len = read_canonical_len(bytes, offset)?;
    let end = checked_artifact_end(*offset, len)?;
    if len == 0 || end > bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let value = std::str::from_utf8(&bytes[*offset..end])
        .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
    *offset = end;
    Ok(value.to_owned())
}

fn read_canonical_digest(bytes: &[u8], offset: &mut usize) -> Result<Sha256Digest> {
    let end = checked_artifact_end(*offset, 32)?;
    if end > bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    Ok(Sha256Digest::new(digest))
}

fn checked_artifact_end(offset: usize, len: usize) -> Result<usize> {
    offset
        .checked_add(len)
        .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedCliApplyDescriptorEntry {
    path: String,
    baseline_state: TrustedCliApplyDescriptorFileState,
    installed_state: TrustedCliApplyDescriptorFileState,
    incoming_state: TrustedCliApplyDescriptorFileState,
    local_delta: String,
    incoming_delta: String,
    disposition: String,
    reviewed_action: String,
}

impl TrustedCliApplyDescriptorEntry {
    fn from_plan_review(
        plan: &crate::ThreeWayPlanEntry,
        review: &crate::ThreeWayPlanReviewEntry,
    ) -> Result<Self> {
        if plan.path() != review.path() {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        Ok(Self {
            path: plan.path().as_str().to_owned(),
            baseline_state: TrustedCliApplyDescriptorFileState::from_state(plan.baseline_state()),
            installed_state: TrustedCliApplyDescriptorFileState::from_state(plan.installed_state()),
            incoming_state: TrustedCliApplyDescriptorFileState::from_state(plan.incoming_state()),
            local_delta: encode_delta(plan.local_delta()).to_owned(),
            incoming_delta: encode_delta(plan.incoming_delta()).to_owned(),
            disposition: encode_disposition(plan.disposition()).to_owned(),
            reviewed_action: encode_reviewed_action(review.action()).to_owned(),
        })
    }

    fn validate(&self) -> Result<()> {
        let _ = crate::ResourceRelativePath::try_from_slash_str(&self.path)
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        let _ = self.baseline_state.to_state()?;
        let _ = self.installed_state.to_state()?;
        let _ = self.incoming_state.to_state()?;
        let _ = decode_delta(&self.local_delta)?;
        let _ = decode_delta(&self.incoming_delta)?;
        let _ = decode_disposition(&self.disposition)?;
        let _ = decode_reviewed_action(&self.reviewed_action)?;
        Ok(())
    }

    fn plan_entry(&self) -> Result<crate::ThreeWayPlanEntry> {
        Ok(
            crate::ThreeWayPlanEntry::from_desktop_apply_descriptor_exact(
                crate::ResourceRelativePath::try_from_slash_str(&self.path)
                    .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?,
                self.baseline_state.to_state()?,
                self.installed_state.to_state()?,
                self.incoming_state.to_state()?,
                decode_delta(&self.local_delta)?,
                decode_delta(&self.incoming_delta)?,
                decode_disposition(&self.disposition)?,
            ),
        )
    }

    fn review_entry(&self) -> Result<crate::ThreeWayPlanReviewEntry> {
        Ok(
            crate::ThreeWayPlanReviewEntry::from_desktop_apply_descriptor(
                crate::ResourceRelativePath::try_from_slash_str(&self.path)
                    .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?,
                decode_reviewed_action(&self.reviewed_action)?,
            ),
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedCliApplyDescriptorFileState {
    presence: String,
    sha256: Option<String>,
    escrow_class: Option<String>,
    trusted_baseline_blob_available: bool,
}

impl TrustedCliApplyDescriptorFileState {
    fn from_state(state: &crate::ThreeWayFileState) -> Self {
        match state {
            crate::ThreeWayFileState::Absent => Self {
                presence: "absent".to_owned(),
                sha256: None,
                escrow_class: None,
                trusted_baseline_blob_available: false,
            },
            crate::ThreeWayFileState::Present {
                sha256,
                escrow_class,
                trusted_baseline_blob_available,
            } => Self {
                presence: "present".to_owned(),
                sha256: Some(sha256.to_string()),
                escrow_class: escrow_class.map(|class| class.as_str().to_owned()),
                trusted_baseline_blob_available: *trusted_baseline_blob_available,
            },
        }
    }

    fn to_state(&self) -> Result<crate::ThreeWayFileState> {
        match self.presence.as_str() {
            "absent" => {
                if self.sha256.is_some()
                    || self.escrow_class.is_some()
                    || self.trusted_baseline_blob_available
                {
                    return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
                }
                Ok(crate::ThreeWayFileState::Absent)
            }
            "present" => {
                let sha256 = self
                    .sha256
                    .as_deref()
                    .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)
                    .and_then(parse_descriptor_digest)?;
                Ok(crate::ThreeWayFileState::Present {
                    sha256,
                    escrow_class: match self.escrow_class.as_deref() {
                        None => None,
                        Some("protected") => Some(crate::BaselineEscrowClass::Protected),
                        Some("ignored") => Some(crate::BaselineEscrowClass::Ignored),
                        Some("not_supported") => Some(crate::BaselineEscrowClass::NotSupported),
                        Some(_) => return Err(GkrmError::TrustedCliUpdateArtifactInvalid),
                    },
                    trusted_baseline_blob_available: self.trusted_baseline_blob_available,
                })
            }
            _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
        }
    }
}

fn encode_delta(value: crate::ThreeWayDelta) -> &'static str {
    match value {
        crate::ThreeWayDelta::Unchanged => "unchanged",
        crate::ThreeWayDelta::Added => "added",
        crate::ThreeWayDelta::Modified => "modified",
        crate::ThreeWayDelta::Deleted => "deleted",
    }
}

fn encode_delta_tag(value: crate::ThreeWayDelta) -> Result<u8> {
    Ok(match value {
        crate::ThreeWayDelta::Unchanged => 0,
        crate::ThreeWayDelta::Added => 1,
        crate::ThreeWayDelta::Modified => 2,
        crate::ThreeWayDelta::Deleted => 3,
    })
}

fn decode_delta_tag(value: u8) -> Result<crate::ThreeWayDelta> {
    match value {
        0 => Ok(crate::ThreeWayDelta::Unchanged),
        1 => Ok(crate::ThreeWayDelta::Added),
        2 => Ok(crate::ThreeWayDelta::Modified),
        3 => Ok(crate::ThreeWayDelta::Deleted),
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

fn decode_delta(value: &str) -> Result<crate::ThreeWayDelta> {
    match value {
        "unchanged" => Ok(crate::ThreeWayDelta::Unchanged),
        "added" => Ok(crate::ThreeWayDelta::Added),
        "modified" => Ok(crate::ThreeWayDelta::Modified),
        "deleted" => Ok(crate::ThreeWayDelta::Deleted),
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

fn encode_disposition(value: crate::ThreeWayPlanDisposition) -> &'static str {
    match value {
        crate::ThreeWayPlanDisposition::NoChange => "no_change",
        crate::ThreeWayPlanDisposition::UseIncoming => "use_incoming",
        crate::ThreeWayPlanDisposition::RemoveForIncoming => "remove_for_incoming",
        crate::ThreeWayPlanDisposition::PreserveInstalled => "preserve_installed",
        crate::ThreeWayPlanDisposition::PreserveInstalledDeletion => "preserve_installed_deletion",
        crate::ThreeWayPlanDisposition::AddIncoming => "add_incoming",
        crate::ThreeWayPlanDisposition::PreserveInstalledAddition => "preserve_installed_addition",
        crate::ThreeWayPlanDisposition::Converged => "converged",
        crate::ThreeWayPlanDisposition::ConvergedAddition => "converged_addition",
        crate::ThreeWayPlanDisposition::ConvergedDeletion => "converged_deletion",
        crate::ThreeWayPlanDisposition::MergeCandidate => "merge_candidate",
        crate::ThreeWayPlanDisposition::ConflictReview => "conflict_review",
        crate::ThreeWayPlanDisposition::DeleteVsModifyConflict => "delete_vs_modify_conflict",
        crate::ThreeWayPlanDisposition::ModifyVsDeleteConflict => "modify_vs_delete_conflict",
        crate::ThreeWayPlanDisposition::AddVsAddConflict => "add_vs_add_conflict",
        crate::ThreeWayPlanDisposition::PolicyReview => "policy_review",
        crate::ThreeWayPlanDisposition::PolicyConflictReview => "policy_conflict_review",
    }
}

fn encode_disposition_tag(value: crate::ThreeWayPlanDisposition) -> Result<u8> {
    Ok(match value {
        crate::ThreeWayPlanDisposition::NoChange => 0,
        crate::ThreeWayPlanDisposition::UseIncoming => 1,
        crate::ThreeWayPlanDisposition::RemoveForIncoming => 2,
        crate::ThreeWayPlanDisposition::PreserveInstalled => 3,
        crate::ThreeWayPlanDisposition::PreserveInstalledDeletion => 4,
        crate::ThreeWayPlanDisposition::AddIncoming => 5,
        crate::ThreeWayPlanDisposition::PreserveInstalledAddition => 6,
        crate::ThreeWayPlanDisposition::Converged => 7,
        crate::ThreeWayPlanDisposition::ConvergedAddition => 8,
        crate::ThreeWayPlanDisposition::ConvergedDeletion => 9,
        crate::ThreeWayPlanDisposition::MergeCandidate => 10,
        crate::ThreeWayPlanDisposition::ConflictReview => 11,
        crate::ThreeWayPlanDisposition::DeleteVsModifyConflict => 12,
        crate::ThreeWayPlanDisposition::ModifyVsDeleteConflict => 13,
        crate::ThreeWayPlanDisposition::AddVsAddConflict => 14,
        crate::ThreeWayPlanDisposition::PolicyReview => 15,
        crate::ThreeWayPlanDisposition::PolicyConflictReview => 16,
    })
}

fn decode_disposition_tag(value: u8) -> Result<crate::ThreeWayPlanDisposition> {
    match value {
        0 => Ok(crate::ThreeWayPlanDisposition::NoChange),
        1 => Ok(crate::ThreeWayPlanDisposition::UseIncoming),
        2 => Ok(crate::ThreeWayPlanDisposition::RemoveForIncoming),
        3 => Ok(crate::ThreeWayPlanDisposition::PreserveInstalled),
        4 => Ok(crate::ThreeWayPlanDisposition::PreserveInstalledDeletion),
        5 => Ok(crate::ThreeWayPlanDisposition::AddIncoming),
        6 => Ok(crate::ThreeWayPlanDisposition::PreserveInstalledAddition),
        7 => Ok(crate::ThreeWayPlanDisposition::Converged),
        8 => Ok(crate::ThreeWayPlanDisposition::ConvergedAddition),
        9 => Ok(crate::ThreeWayPlanDisposition::ConvergedDeletion),
        10 => Ok(crate::ThreeWayPlanDisposition::MergeCandidate),
        11 => Ok(crate::ThreeWayPlanDisposition::ConflictReview),
        12 => Ok(crate::ThreeWayPlanDisposition::DeleteVsModifyConflict),
        13 => Ok(crate::ThreeWayPlanDisposition::ModifyVsDeleteConflict),
        14 => Ok(crate::ThreeWayPlanDisposition::AddVsAddConflict),
        15 => Ok(crate::ThreeWayPlanDisposition::PolicyReview),
        16 => Ok(crate::ThreeWayPlanDisposition::PolicyConflictReview),
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

fn decode_disposition(value: &str) -> Result<crate::ThreeWayPlanDisposition> {
    match value {
        "no_change" => Ok(crate::ThreeWayPlanDisposition::NoChange),
        "use_incoming" => Ok(crate::ThreeWayPlanDisposition::UseIncoming),
        "remove_for_incoming" => Ok(crate::ThreeWayPlanDisposition::RemoveForIncoming),
        "preserve_installed" => Ok(crate::ThreeWayPlanDisposition::PreserveInstalled),
        "preserve_installed_deletion" => {
            Ok(crate::ThreeWayPlanDisposition::PreserveInstalledDeletion)
        }
        "add_incoming" => Ok(crate::ThreeWayPlanDisposition::AddIncoming),
        "preserve_installed_addition" => {
            Ok(crate::ThreeWayPlanDisposition::PreserveInstalledAddition)
        }
        "converged" => Ok(crate::ThreeWayPlanDisposition::Converged),
        "converged_addition" => Ok(crate::ThreeWayPlanDisposition::ConvergedAddition),
        "converged_deletion" => Ok(crate::ThreeWayPlanDisposition::ConvergedDeletion),
        "merge_candidate" => Ok(crate::ThreeWayPlanDisposition::MergeCandidate),
        "conflict_review" => Ok(crate::ThreeWayPlanDisposition::ConflictReview),
        "delete_vs_modify_conflict" => Ok(crate::ThreeWayPlanDisposition::DeleteVsModifyConflict),
        "modify_vs_delete_conflict" => Ok(crate::ThreeWayPlanDisposition::ModifyVsDeleteConflict),
        "add_vs_add_conflict" => Ok(crate::ThreeWayPlanDisposition::AddVsAddConflict),
        "policy_review" => Ok(crate::ThreeWayPlanDisposition::PolicyReview),
        "policy_conflict_review" => Ok(crate::ThreeWayPlanDisposition::PolicyConflictReview),
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

fn encode_reviewed_action(value: crate::ThreeWayReviewedAction) -> &'static str {
    match value {
        crate::ThreeWayReviewedAction::NotRequired => "not_required",
        crate::ThreeWayReviewedAction::Pending => "pending",
        crate::ThreeWayReviewedAction::UseIncomingState => "use_incoming_state",
        crate::ThreeWayReviewedAction::PreserveInstalledState => "preserve_installed_state",
        crate::ThreeWayReviewedAction::QueueMergeAnalysis => "queue_merge_analysis",
        crate::ThreeWayReviewedAction::ManualReview => "manual_review",
    }
}

fn encode_reviewed_action_tag(value: crate::ThreeWayReviewedAction) -> Result<u8> {
    Ok(match value {
        crate::ThreeWayReviewedAction::NotRequired => 0,
        crate::ThreeWayReviewedAction::Pending => 1,
        crate::ThreeWayReviewedAction::UseIncomingState => 2,
        crate::ThreeWayReviewedAction::PreserveInstalledState => 3,
        crate::ThreeWayReviewedAction::QueueMergeAnalysis => 4,
        crate::ThreeWayReviewedAction::ManualReview => 5,
    })
}

fn decode_reviewed_action_tag(value: u8) -> Result<crate::ThreeWayReviewedAction> {
    match value {
        0 => Ok(crate::ThreeWayReviewedAction::NotRequired),
        1 => Ok(crate::ThreeWayReviewedAction::Pending),
        2 => Ok(crate::ThreeWayReviewedAction::UseIncomingState),
        3 => Ok(crate::ThreeWayReviewedAction::PreserveInstalledState),
        4 => Ok(crate::ThreeWayReviewedAction::QueueMergeAnalysis),
        5 => Ok(crate::ThreeWayReviewedAction::ManualReview),
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

fn decode_reviewed_action(value: &str) -> Result<crate::ThreeWayReviewedAction> {
    match value {
        "not_required" => Ok(crate::ThreeWayReviewedAction::NotRequired),
        "pending" => Ok(crate::ThreeWayReviewedAction::Pending),
        "use_incoming_state" => Ok(crate::ThreeWayReviewedAction::UseIncomingState),
        "preserve_installed_state" => Ok(crate::ThreeWayReviewedAction::PreserveInstalledState),
        "queue_merge_analysis" => Ok(crate::ThreeWayReviewedAction::QueueMergeAnalysis),
        "manual_review" => Ok(crate::ThreeWayReviewedAction::ManualReview),
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

impl std::fmt::Debug for TrustedCliUpdateArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedCliUpdateArtifact")
    }
}

fn write_opt(out: &mut Vec<u8>, value: Option<&Sha256Digest>) {
    match value {
        Some(d) => {
            out.push(1);
            out.extend_from_slice(d.as_bytes());
        }
        None => out.push(0),
    }
}

fn read_opt(bytes: &[u8], offset: &mut usize) -> Result<Option<Sha256Digest>> {
    if *offset >= bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let flag = bytes[*offset];
    *offset += 1;
    match flag {
        0 => Ok(None),
        1 => {
            let end = checked_artifact_end(*offset, 32)?;
            if end > bytes.len() {
                return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
            }
            let mut d = [0u8; 32];
            d.copy_from_slice(&bytes[*offset..end]);
            *offset = end;
            Ok(Some(Sha256Digest::new(d)))
        }
        _ => Err(GkrmError::TrustedCliUpdateArtifactInvalid),
    }
}

pub(crate) fn encode_body(body: &TrustedCliUpdateArtifactBody) -> Result<Vec<u8>> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-update-artifact-body-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.u8(ARTIFACT_FORMAT_VERSION);
    enc.digest(&body.package_fingerprint);
    enc.digest(&body.selected_resource_commitment);
    enc.digest(&body.baseline_id_digest);
    enc.digest(&body.plan_id);
    enc.digest(&body.review_id);
    match &body.analysis_id {
        Some(d) => {
            enc.u8(1);
            enc.digest(d);
        }
        None => enc.u8(0),
    }
    match &body.text_diff_id {
        Some(d) => {
            enc.u8(1);
            enc.digest(d);
        }
        None => enc.u8(0),
    }
    match &body.synthesis_id {
        Some(d) => {
            enc.u8(1);
            enc.digest(d);
        }
        None => enc.u8(0),
    }
    match &body.merged_bytes_id {
        Some(d) => {
            enc.u8(1);
            enc.digest(d);
        }
        None => enc.u8(0),
    }
    enc.digest(&body.operator_merge_set_id);
    enc.digest(&body.staging_manifest_id);
    enc.digest(&body.staging_bundle_id);
    enc.digest(&body.apply_plan_id);
    enc.digest(&body.snapshot_a);
    enc.digest(&body.transactional_plan_id);
    enc.digest(&body.decision_document_id);
    Ok(enc.finish().as_bytes().to_vec())
}

pub fn encode_cli_artifact(
    body: &TrustedCliUpdateArtifactBody,
) -> Result<TrustedCliUpdateArtifact> {
    encode_cli_artifact_inner(body, None)
}

pub fn encode_cli_artifact_with_apply_descriptor(
    body: &TrustedCliUpdateArtifactBody,
    apply_descriptor: &TrustedCliApplyDescriptor,
) -> Result<TrustedCliUpdateArtifact> {
    apply_descriptor.validate()?;
    encode_cli_artifact_inner(body, Some(apply_descriptor))
}

fn encode_cli_artifact_inner(
    body: &TrustedCliUpdateArtifactBody,
    apply_descriptor: Option<&TrustedCliApplyDescriptor>,
) -> Result<TrustedCliUpdateArtifact> {
    if body.recovery_authority_id.is_some() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let body_digest_bytes = encode_body(body)?;
    let body_digest = Sha256Digest::new(
        body_digest_bytes
            .as_slice()
            .try_into()
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?,
    );

    let mut wire = Vec::new();
    wire.extend_from_slice(ARTIFACT_MAGIC);
    wire.push(ARTIFACT_FORMAT_VERSION);
    // Length-prefixed raw field encoding for reopen (not the fingerprint alone).
    let mut fields = Vec::new();
    fields.extend_from_slice(body.package_fingerprint.as_bytes());
    fields.extend_from_slice(body.selected_resource_commitment.as_bytes());
    fields.extend_from_slice(body.baseline_id_digest.as_bytes());
    fields.extend_from_slice(body.plan_id.as_bytes());
    fields.extend_from_slice(body.review_id.as_bytes());
    write_opt(&mut fields, body.analysis_id.as_ref());
    write_opt(&mut fields, body.text_diff_id.as_ref());
    write_opt(&mut fields, body.synthesis_id.as_ref());
    write_opt(&mut fields, body.merged_bytes_id.as_ref());
    fields.extend_from_slice(body.operator_merge_set_id.as_bytes());
    fields.extend_from_slice(body.staging_manifest_id.as_bytes());
    fields.extend_from_slice(body.staging_bundle_id.as_bytes());
    fields.extend_from_slice(body.apply_plan_id.as_bytes());
    fields.extend_from_slice(body.snapshot_a.as_bytes());
    fields.extend_from_slice(body.transactional_plan_id.as_bytes());
    fields.extend_from_slice(body.decision_document_id.as_bytes());
    wire.extend_from_slice(&(fields.len() as u64).to_le_bytes());
    wire.extend_from_slice(&fields);
    if let Some(descriptor) = apply_descriptor {
        let descriptor_bytes = encode_apply_descriptor_bytes(descriptor)?;
        wire.extend_from_slice(&(descriptor_bytes.len() as u64).to_le_bytes());
        wire.extend_from_slice(&descriptor_bytes);
    }
    let artifact_id = TrustedCliUpdateArtifactId(encode_cli_artifact_id(&body_digest)?);
    wire.extend_from_slice(artifact_id.digest().as_bytes());

    // Seal over entire wire prefix excluding self-id, then verify id matches.
    let prefix_hash = Sha256Digest::new(Sha256::digest(&wire[..wire.len() - 32]).into());
    let expected_id = encode_cli_artifact_id(&prefix_hash)?;
    // Replace trailing id with seal over prefix (canonical self-ID).
    wire.truncate(wire.len() - 32);
    let artifact_id = TrustedCliUpdateArtifactId(expected_id);
    wire.extend_from_slice(artifact_id.digest().as_bytes());

    Ok(TrustedCliUpdateArtifact {
        version: ARTIFACT_FORMAT_VERSION,
        artifact_id,
        body: body.clone(),
        apply_descriptor: apply_descriptor.cloned(),
        two_way_descriptor: None,
        undo_descriptor: None,
        bytes: wire,
    })
}

pub fn parse_cli_artifact(
    bytes: &[u8],
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedCliUpdateArtifact> {
    if bytes.starts_with(ARTIFACT_MAGIC) {
        return parse_cli_artifact_v1(bytes, options);
    }
    if bytes.starts_with(ARTIFACT_V2_MAGIC) {
        return parse_cli_artifact_v2(bytes, options);
    }
    Err(GkrmError::TrustedCliUpdateArtifactInvalid)
}

fn parse_cli_artifact_v1(
    bytes: &[u8],
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedCliUpdateArtifact> {
    if bytes.len() > options.max_artifact_bytes {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes",
        });
    }
    if bytes.len() < ARTIFACT_MAGIC.len() + 1 + 8 + 32 {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    if &bytes[..ARTIFACT_MAGIC.len()] != ARTIFACT_MAGIC {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let mut offset = ARTIFACT_MAGIC.len();
    if bytes[offset] != ARTIFACT_FORMAT_VERSION {
        return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
    }
    offset += 1;
    let len_end = checked_artifact_end(offset, 8)?;
    let field_len_u64 = u64::from_le_bytes(bytes[offset..len_end].try_into().unwrap());
    offset = len_end;
    let max_field_len = bytes
        .len()
        .checked_sub(offset)
        .and_then(|value| value.checked_sub(32))
        .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
    if field_len_u64
        > u64::try_from(max_field_len).map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?
    {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let field_len =
        usize::try_from(field_len_u64).map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
    let fields_end = checked_artifact_end(offset, field_len)?;
    if fields_end
        .checked_add(32)
        .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?
        > bytes.len()
    {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let fields = &bytes[offset..fields_end];
    let mut fo = 0usize;
    let take32 = |fo: &mut usize| -> Result<Sha256Digest> {
        let end = checked_artifact_end(*fo, 32)?;
        if end > fields.len() {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&fields[*fo..end]);
        *fo = end;
        Ok(Sha256Digest::new(d))
    };
    let package_fingerprint = take32(&mut fo)?;
    let selected_resource_commitment = take32(&mut fo)?;
    let baseline_id_digest = take32(&mut fo)?;
    let plan_id = take32(&mut fo)?;
    let review_id = take32(&mut fo)?;
    let analysis_id = read_opt(fields, &mut fo)?;
    let text_diff_id = read_opt(fields, &mut fo)?;
    let synthesis_id = read_opt(fields, &mut fo)?;
    let merged_bytes_id = read_opt(fields, &mut fo)?;
    let operator_merge_set_id = take32(&mut fo)?;
    let staging_manifest_id = take32(&mut fo)?;
    let staging_bundle_id = take32(&mut fo)?;
    let apply_plan_id = take32(&mut fo)?;
    let snapshot_a = take32(&mut fo)?;
    let transactional_plan_id = take32(&mut fo)?;
    let decision_document_id = take32(&mut fo)?;
    let body = TrustedCliUpdateArtifactBody {
        package_fingerprint,
        selected_resource_commitment,
        baseline_id_digest,
        plan_id,
        review_id,
        analysis_id,
        text_diff_id,
        synthesis_id,
        merged_bytes_id,
        operator_merge_set_id,
        staging_manifest_id,
        staging_bundle_id,
        apply_plan_id,
        snapshot_a,
        transactional_plan_id,
        recovery_authority_id: None,
        decision_document_id,
    };
    if fo != fields.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    offset = fields_end;
    let artifact_id_end = checked_artifact_end(offset, 32)?;
    let apply_descriptor = if artifact_id_end == bytes.len() {
        None
    } else {
        let len_end = checked_artifact_end(offset, 8)?;
        if len_end
            .checked_add(32)
            .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?
            > bytes.len()
        {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let descriptor_len_u64 = u64::from_le_bytes(bytes[offset..len_end].try_into().unwrap());
        offset = len_end;
        let max_descriptor_len = bytes
            .len()
            .checked_sub(offset)
            .and_then(|value| value.checked_sub(32))
            .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
        if descriptor_len_u64 == 0
            || descriptor_len_u64
                > u64::try_from(max_descriptor_len)
                    .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?
        {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let descriptor_len = usize::try_from(descriptor_len_u64)
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        let descriptor_end = checked_artifact_end(offset, descriptor_len)?;
        if descriptor_end
            .checked_add(32)
            .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?
            != bytes.len()
        {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let descriptor = parse_apply_descriptor_bytes(
            &bytes[offset..descriptor_end],
            options.max_decision_entries,
        )?;
        offset = descriptor_end;
        Some(descriptor)
    };
    let mut got_id = [0u8; 32];
    let id_end = checked_artifact_end(offset, 32)?;
    if id_end != bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    got_id.copy_from_slice(&bytes[offset..id_end]);
    let prefix_hash = Sha256Digest::new(Sha256::digest(&bytes[..offset]).into());
    let expected = encode_cli_artifact_id(&prefix_hash)?;
    if expected.as_bytes() != &got_id {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    Ok(TrustedCliUpdateArtifact {
        version: ARTIFACT_FORMAT_VERSION,
        artifact_id: TrustedCliUpdateArtifactId(expected),
        body,
        apply_descriptor,
        two_way_descriptor: None,
        undo_descriptor: None,
        bytes: bytes.to_vec(),
    })
}

/// Legacy descriptor-less v2 fixtures. Production two-way publication uses its own
/// descriptor family; retain this encoder only to verify old wire compatibility.
#[cfg(test)]
pub(crate) fn encode_cli_artifact_v2_without_apply_descriptor(
    body: &TrustedCliUpdateArtifactBody,
) -> Result<TrustedCliUpdateArtifact> {
    encode_cli_artifact_v2_inner(body, None, None, None)
}

pub(crate) fn encode_cli_artifact_v2_with_apply_descriptor(
    body: &TrustedCliUpdateArtifactBody,
    apply_descriptor: &TrustedCliApplyDescriptor,
) -> Result<TrustedCliUpdateArtifact> {
    apply_descriptor.validate()?;
    encode_cli_artifact_v2_inner(body, Some(apply_descriptor), None, None)
}

pub(crate) fn encode_cli_artifact_v2_with_two_way_descriptor(
    body: &TrustedCliUpdateArtifactBody,
    descriptor: &TwoWayExecutionDescriptor,
) -> Result<TrustedCliUpdateArtifact> {
    let plan = descriptor.reconstruct()?;
    crate::trusted_recovery_authority::verify_selected_resource_commitment(
        plan.resource_key(),
        &body.selected_resource_commitment,
    )?;
    if plan.plan_id().digest() != &body.plan_id
        || plan.incoming_package_fingerprint() != &body.package_fingerprint
    {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    encode_cli_artifact_v2_inner(body, None, Some(descriptor), None)
}

pub fn encode_cli_artifact_v2_with_undo_descriptor(
    body: &TrustedCliUpdateArtifactBody,
    descriptor: &TrustedUndoExecutionDescriptor,
) -> Result<TrustedCliUpdateArtifact> {
    validate_undo_body(body, descriptor)?;
    encode_cli_artifact_v2_inner(body, None, None, Some(descriptor))
}

fn validate_undo_body(
    body: &TrustedCliUpdateArtifactBody,
    descriptor: &TrustedUndoExecutionDescriptor,
) -> Result<()> {
    descriptor.encode()?;
    crate::trusted_recovery_authority::verify_selected_resource_commitment(
        &descriptor.resource_key()?,
        &body.selected_resource_commitment,
    )?;
    if descriptor.plan_id()? != body.plan_id
        || descriptor.parent_artifact_id()? != body.package_fingerprint
        || descriptor.current_tree_fingerprint()? != body.snapshot_a
        || descriptor.review_id()? != body.review_id
        || descriptor.parent_transaction_id()? == body.transactional_plan_id
        || descriptor.previous_attempt()? == Some(body.transactional_plan_id)
        || body.baseline_id_digest != crate::trusted_staging::undo_record_marker("baseline")?
        || body.operator_merge_set_id
            != crate::trusted_staging::undo_record_marker("operator-merges")?
        || body.decision_document_id
            != crate::trusted_staging::undo_record_marker("decision-document")?
        || body.analysis_id.is_some()
        || body.text_diff_id.is_some()
        || body.synthesis_id.is_some()
        || body.merged_bytes_id.is_some()
    {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    Ok(())
}

fn encode_cli_artifact_v2_inner(
    body: &TrustedCliUpdateArtifactBody,
    apply_descriptor: Option<&TrustedCliApplyDescriptor>,
    two_way_descriptor: Option<&TwoWayExecutionDescriptor>,
    undo_descriptor: Option<&TrustedUndoExecutionDescriptor>,
) -> Result<TrustedCliUpdateArtifact> {
    let authority_id = body
        .recovery_authority_id
        .as_ref()
        .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
    let mut fields = Vec::new();
    fields.extend_from_slice(body.package_fingerprint.as_bytes());
    fields.extend_from_slice(body.selected_resource_commitment.as_bytes());
    fields.extend_from_slice(body.baseline_id_digest.as_bytes());
    fields.extend_from_slice(body.plan_id.as_bytes());
    fields.extend_from_slice(body.review_id.as_bytes());
    write_opt(&mut fields, body.analysis_id.as_ref());
    write_opt(&mut fields, body.text_diff_id.as_ref());
    write_opt(&mut fields, body.synthesis_id.as_ref());
    write_opt(&mut fields, body.merged_bytes_id.as_ref());
    fields.extend_from_slice(body.operator_merge_set_id.as_bytes());
    fields.extend_from_slice(body.staging_manifest_id.as_bytes());
    fields.extend_from_slice(body.staging_bundle_id.as_bytes());
    fields.extend_from_slice(body.apply_plan_id.as_bytes());
    fields.extend_from_slice(body.snapshot_a.as_bytes());
    fields.extend_from_slice(body.transactional_plan_id.as_bytes());
    fields.extend_from_slice(authority_id.as_bytes());
    fields.extend_from_slice(body.decision_document_id.as_bytes());

    let mut wire = Vec::new();
    wire.extend_from_slice(ARTIFACT_V2_MAGIC);
    wire.push(ARTIFACT_V2_FORMAT_VERSION);
    wire.extend_from_slice(
        &u64::try_from(fields.len())
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?
            .to_le_bytes(),
    );
    wire.extend_from_slice(&fields);
    if usize::from(apply_descriptor.is_some())
        + usize::from(two_way_descriptor.is_some())
        + usize::from(undo_descriptor.is_some())
        > 1
    {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    match apply_descriptor {
        Some(descriptor) => {
            let descriptor_bytes = encode_apply_descriptor_bytes(descriptor)?;
            wire.push(1);
            wire.extend_from_slice(
                &u64::try_from(descriptor_bytes.len())
                    .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?
                    .to_le_bytes(),
            );
            wire.extend_from_slice(&descriptor_bytes);
        }
        None => match two_way_descriptor {
            Some(descriptor) => {
                let encoded = descriptor.encode()?;
                wire.push(2);
                wire.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
                wire.extend_from_slice(&encoded);
            }
            None => match undo_descriptor {
                Some(descriptor) => {
                    let encoded = descriptor.encode()?;
                    wire.push(3);
                    wire.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
                    wire.extend_from_slice(&encoded);
                }
                None => wire.push(0),
            },
        },
    }
    let artifact_id = TrustedCliUpdateArtifactId(encode_cli_artifact_v2_id(&wire)?);
    wire.extend_from_slice(artifact_id.digest().as_bytes());
    Ok(TrustedCliUpdateArtifact {
        version: ARTIFACT_V2_FORMAT_VERSION,
        artifact_id,
        body: body.clone(),
        apply_descriptor: apply_descriptor.cloned(),
        two_way_descriptor: two_way_descriptor.cloned(),
        undo_descriptor: undo_descriptor.cloned(),
        bytes: wire,
    })
}

fn parse_cli_artifact_v2(
    bytes: &[u8],
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedCliUpdateArtifact> {
    if bytes.len() > options.max_artifact_bytes {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes",
        });
    }
    // Magic, version, field length, the fields themselves, the descriptor presence byte, and the
    // trailing id. The descriptor's own length prefix is not counted: an artifact that carries no
    // descriptor does not have one, and every later read is bounds-checked in any case.
    let minimum = ARTIFACT_V2_MAGIC.len() + 1 + 8 + 13 * 32 + 4 + 1 + 32;
    if bytes.len() < minimum || !bytes.starts_with(ARTIFACT_V2_MAGIC) {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let mut offset = ARTIFACT_V2_MAGIC.len();
    if bytes[offset] != ARTIFACT_V2_FORMAT_VERSION {
        return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
    }
    offset += 1;
    let fields_len = read_u64_len(bytes, &mut offset)?;
    let fields_end = checked_artifact_end(offset, fields_len)?;
    if fields_end > bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let fields = &bytes[offset..fields_end];
    let mut fo = 0usize;
    let package_fingerprint = take_digest(fields, &mut fo)?;
    let selected_resource_commitment = take_digest(fields, &mut fo)?;
    let baseline_id_digest = take_digest(fields, &mut fo)?;
    let plan_id = take_digest(fields, &mut fo)?;
    let review_id = take_digest(fields, &mut fo)?;
    let analysis_id = read_opt(fields, &mut fo)?;
    let text_diff_id = read_opt(fields, &mut fo)?;
    let synthesis_id = read_opt(fields, &mut fo)?;
    let merged_bytes_id = read_opt(fields, &mut fo)?;
    let operator_merge_set_id = take_digest(fields, &mut fo)?;
    let staging_manifest_id = take_digest(fields, &mut fo)?;
    let staging_bundle_id = take_digest(fields, &mut fo)?;
    let apply_plan_id = take_digest(fields, &mut fo)?;
    let snapshot_a = take_digest(fields, &mut fo)?;
    let transactional_plan_id = take_digest(fields, &mut fo)?;
    let recovery_authority_id = Some(take_digest(fields, &mut fo)?);
    let decision_document_id = take_digest(fields, &mut fo)?;
    if fo != fields.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    offset = fields_end;
    // Descriptor family: absent (legacy), three-way, or two-way. Never reinterpret families.
    let family = *bytes
        .get(offset)
        .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
    if family > 3 {
        return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
    }
    offset += 1;
    let mut descriptor = None;
    let mut two_way_descriptor = None;
    let mut undo_descriptor = None;
    if family != 0 {
        let length = read_u64_len(bytes, &mut offset)?;
        if length == 0 {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let end = checked_artifact_end(offset, length)?;
        let encoded = bytes
            .get(offset..end)
            .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
        if family == 1 {
            descriptor = Some(parse_apply_descriptor_bytes(
                encoded,
                options.max_decision_entries,
            )?);
        } else if family == 3 {
            undo_descriptor = Some(TrustedUndoExecutionDescriptor::decode(encoded)?);
        } else {
            let parsed = TwoWayExecutionDescriptor::decode(encoded)?;
            let plan = parsed.reconstruct()?;
            crate::trusted_recovery_authority::verify_selected_resource_commitment(
                plan.resource_key(),
                &selected_resource_commitment,
            )?;
            if plan.entries().len() > options.max_decision_entries
                || plan.plan_id().digest() != &plan_id
                || plan.incoming_package_fingerprint() != &package_fingerprint
            {
                return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
            }
            two_way_descriptor = Some(parsed);
        }
        offset = end;
    }
    let descriptor_end = offset;
    let id_end = descriptor_end
        .checked_add(32)
        .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
    if id_end != bytes.len() {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let stored_id = take_digest(bytes, &mut offset)?;
    let expected = encode_cli_artifact_v2_id(&bytes[..descriptor_end])?;
    if stored_id != expected {
        return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
    }
    let artifact = TrustedCliUpdateArtifact {
        version: ARTIFACT_V2_FORMAT_VERSION,
        artifact_id: TrustedCliUpdateArtifactId(expected),
        body: TrustedCliUpdateArtifactBody {
            package_fingerprint,
            selected_resource_commitment,
            baseline_id_digest,
            plan_id,
            review_id,
            analysis_id,
            text_diff_id,
            synthesis_id,
            merged_bytes_id,
            operator_merge_set_id,
            staging_manifest_id,
            staging_bundle_id,
            apply_plan_id,
            snapshot_a,
            transactional_plan_id,
            recovery_authority_id,
            decision_document_id,
        },
        apply_descriptor: descriptor,
        two_way_descriptor,
        undo_descriptor,
        bytes: bytes.to_vec(),
    };
    if let Some(descriptor) = artifact.undo_descriptor() {
        if descriptor.directories()?.len() > options.max_decision_entries {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        validate_undo_body(artifact.body(), descriptor)?;
    }
    Ok(artifact)
}

fn read_u64_len(bytes: &[u8], offset: &mut usize) -> Result<usize> {
    let end = checked_artifact_end(*offset, 8)?;
    let raw = bytes
        .get(*offset..end)
        .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?;
    *offset = end;
    usize::try_from(u64::from_le_bytes(
        raw.try_into()
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?,
    ))
    .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)
}

fn take_digest(bytes: &[u8], offset: &mut usize) -> Result<Sha256Digest> {
    let end = checked_artifact_end(*offset, 32)?;
    let digest = Sha256Digest::new(
        bytes
            .get(*offset..end)
            .ok_or(GkrmError::TrustedCliUpdateArtifactInvalid)?
            .try_into()
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?,
    );
    *offset = end;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use std::panic;

    use super::*;

    fn fixed_body() -> TrustedCliUpdateArtifactBody {
        TrustedCliUpdateArtifactBody {
            package_fingerprint: Sha256Digest::new([1; 32]),
            selected_resource_commitment: Sha256Digest::new([2; 32]),
            baseline_id_digest: Sha256Digest::new([3; 32]),
            plan_id: Sha256Digest::new([4; 32]),
            review_id: Sha256Digest::new([5; 32]),
            analysis_id: None,
            text_diff_id: None,
            synthesis_id: None,
            merged_bytes_id: None,
            operator_merge_set_id: Sha256Digest::new([6; 32]),
            staging_manifest_id: Sha256Digest::new([7; 32]),
            staging_bundle_id: Sha256Digest::new([8; 32]),
            apply_plan_id: Sha256Digest::new([9; 32]),
            snapshot_a: Sha256Digest::new([10; 32]),
            transactional_plan_id: Sha256Digest::new([11; 32]),
            recovery_authority_id: None,
            decision_document_id: Sha256Digest::new([12; 32]),
        }
    }

    fn assert_artifact_parse_err_no_panic(bytes: Vec<u8>) {
        let parsed =
            panic::catch_unwind(|| parse_cli_artifact(&bytes, &TrustedCliUpdateOptions::default()));
        assert!(matches!(parsed, Ok(Err(_))));
    }

    fn artifact_with_field_len(field_len: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ARTIFACT_MAGIC);
        bytes.push(ARTIFACT_FORMAT_VERSION);
        bytes.extend_from_slice(&field_len.to_le_bytes());
        bytes.extend_from_slice(&[0; 32]);
        bytes
    }

    fn descriptor_with_resource_key_len(len: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(APPLY_DESCRIPTOR_MAGIC);
        bytes.push(TrustedCliApplyDescriptor::VERSION);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn assert_descriptor_parse_err_no_panic(bytes: Vec<u8>) {
        let parsed = panic::catch_unwind(|| parse_apply_descriptor_bytes(&bytes, 8));
        assert!(matches!(parsed, Ok(Err(_))));
    }

    #[test]
    fn malformed_artifact_lengths_return_errors_without_panic() {
        assert_artifact_parse_err_no_panic(vec![0, 1, 2, 3]);
        assert_artifact_parse_err_no_panic(artifact_with_field_len(u64::MAX));
        assert_artifact_parse_err_no_panic(artifact_with_field_len(
            u64::try_from(usize::MAX).unwrap(),
        ));
        assert_artifact_parse_err_no_panic(artifact_with_field_len(1024));
        assert_artifact_parse_err_no_panic(artifact_with_field_len(0));

        let mut trailing = encode_cli_artifact(&fixed_body())
            .unwrap()
            .canonical_bytes()
            .to_vec();
        trailing.push(0);
        assert_artifact_parse_err_no_panic(trailing);

        let mut descriptor_truncated = encode_cli_artifact(&fixed_body())
            .unwrap()
            .canonical_bytes()
            .to_vec();
        descriptor_truncated.truncate(descriptor_truncated.len() - 20);
        assert_artifact_parse_err_no_panic(descriptor_truncated);
    }

    #[test]
    fn two_way_descriptor_family_roundtrips_and_is_bound_to_artifact() {
        let key = crate::SafeResourceKey::parse("gksphone").unwrap();
        let path = crate::ResourceRelativePath::try_from_slash_str("config.lua").unwrap();
        let installed = crate::InstalledResourceSnapshot::from_parts_for_test(
            key.clone(),
            vec![(path.clone(), Sha256Digest::new([1; 32]))],
        );
        let incoming = crate::IncomingOfficialResourceSnapshot::from_parts_for_test(
            key.clone(),
            Sha256Digest::new([2; 32]),
            vec![(
                path,
                Sha256Digest::new([3; 32]),
                crate::BaselineEscrowClass::Ignored,
            )],
        );
        let plan = crate::create_two_way_update_plan(&installed, &incoming, None).unwrap();
        let descriptor =
            TwoWayExecutionDescriptor::from_plan(&plan, &crate::InstalledResourceRoot::Root)
                .unwrap();
        let mut body = fixed_body();
        body.plan_id = *plan.plan_id().digest();
        body.package_fingerprint = *plan.incoming_package_fingerprint();
        body.selected_resource_commitment =
            crate::trusted_recovery_authority::selected_resource_commitment(&key).unwrap();
        body.recovery_authority_id = Some(Sha256Digest::new([13; 32]));
        let artifact = encode_cli_artifact_v2_with_two_way_descriptor(&body, &descriptor).unwrap();
        let parsed = parse_cli_artifact(
            artifact.canonical_bytes(),
            &TrustedCliUpdateOptions::default(),
        )
        .unwrap();
        assert!(parsed.apply_descriptor().is_none());
        assert_eq!(
            parsed.two_way_descriptor().unwrap().encode().unwrap(),
            descriptor.encode().unwrap()
        );
        assert_eq!(
            parsed.two_way_descriptor().unwrap().reconstruct().unwrap(),
            plan
        );
        assert_eq!(parsed.artifact_id(), artifact.artifact_id());
        let original = artifact.canonical_bytes();
        for index in [original.len() - 1, original.len() - 40] {
            let mut damaged = original.to_vec();
            damaged[index] ^= 1;
            assert!(parse_cli_artifact(&damaged, &TrustedCliUpdateOptions::default()).is_err());
        }
        body.plan_id = Sha256Digest::new([0; 32]);
        assert!(encode_cli_artifact_v2_with_two_way_descriptor(&body, &descriptor).is_err());
    }

    #[test]
    fn undo_descriptor_family_is_distinct_and_bound_to_parent_plan_snapshot_and_review() {
        let mut body = fixed_body();
        body.baseline_id_digest = crate::trusted_staging::undo_record_marker("baseline").unwrap();
        body.operator_merge_set_id =
            crate::trusted_staging::undo_record_marker("operator-merges").unwrap();
        body.decision_document_id =
            crate::trusted_staging::undo_record_marker("decision-document").unwrap();
        body.recovery_authority_id = Some(Sha256Digest::new([13; 32]));
        let descriptor: TrustedUndoExecutionDescriptor =
            serde_json::from_value(serde_json::json!({
                "version": 1, "parent": "14".repeat(32),
                "parent_artifact": body.package_fingerprint.to_string(),
                "parent_authority": "15".repeat(32), "resource": "gksphone",
                "selected_root": ".", "plan": body.plan_id.to_string(),
                "current_tree": body.snapshot_a.to_string(), "current_files": "16".repeat(32),
                "directories": ["empty", "empty/nested"]
            }))
            .unwrap();
        body.selected_resource_commitment =
            crate::trusted_recovery_authority::selected_resource_commitment(
                &descriptor.resource_key().unwrap(),
            )
            .unwrap();
        body.review_id = descriptor.review_id().unwrap();
        let artifact = encode_cli_artifact_v2_with_undo_descriptor(&body, &descriptor).unwrap();
        let parsed = parse_cli_artifact(
            artifact.canonical_bytes(),
            &TrustedCliUpdateOptions::default(),
        )
        .unwrap();
        assert!(parsed.apply_descriptor().is_none());
        assert!(parsed.two_way_descriptor().is_none());
        assert_eq!(parsed.undo_descriptor().unwrap(), &descriptor);
        assert_eq!(parsed.artifact_id(), artifact.artifact_id());
        for case in 0..6 {
            let mut changed = body.clone();
            match case {
                0 => changed.plan_id = Sha256Digest::new([0; 32]),
                1 => changed.package_fingerprint = Sha256Digest::new([0; 32]),
                2 => changed.snapshot_a = Sha256Digest::new([0; 32]),
                3 => changed.review_id = Sha256Digest::new([0; 32]),
                4 => changed.transactional_plan_id = descriptor.parent_transaction_id().unwrap(),
                _ => changed.analysis_id = Some(Sha256Digest::new([0; 32])),
            }
            assert!(encode_cli_artifact_v2_with_undo_descriptor(&changed, &descriptor).is_err());
        }
        let mut changed = artifact.canonical_bytes().to_vec();
        let last = changed.len() - 40;
        changed[last] ^= 1;
        assert!(parse_cli_artifact(&changed, &TrustedCliUpdateOptions::default()).is_err());
    }

    #[test]
    fn a_version_two_artifact_can_carry_no_apply_descriptor() {
        // A two-way update has no per-file plan and review to describe. The presence byte the
        // format already carried makes that expressible without changing a byte of any artifact
        // that does describe itself per file.
        let body = TrustedCliUpdateArtifactBody {
            recovery_authority_id: Some(Sha256Digest::new([13; 32])),
            ..fixed_body()
        };
        let artifact = encode_cli_artifact_v2_without_apply_descriptor(&body).unwrap();
        let parsed = parse_cli_artifact(
            artifact.canonical_bytes(),
            &TrustedCliUpdateOptions::default(),
        )
        .unwrap();
        assert_eq!(parsed.version(), ARTIFACT_V2_FORMAT_VERSION);
        assert_eq!(parsed.body(), &body);
        assert_eq!(parsed.apply_descriptor(), None);
        assert_eq!(parsed.artifact_id(), artifact.artifact_id());

        // The two shapes are distinct identities, not two spellings of one.
        let bytes = artifact.canonical_bytes().to_vec();
        let presence = bytes.len() - 32 - 1;
        assert_eq!(bytes[presence], 0);
        let mut claims_a_descriptor = bytes;
        claims_a_descriptor[presence] = 1;
        assert_artifact_parse_err_no_panic(claims_a_descriptor);
    }

    #[test]
    fn malformed_apply_descriptor_lengths_return_errors_without_panic() {
        assert_descriptor_parse_err_no_panic(APPLY_DESCRIPTOR_MAGIC[..4].to_vec());
        let mut truncated_prefix = APPLY_DESCRIPTOR_MAGIC.to_vec();
        truncated_prefix.push(TrustedCliApplyDescriptor::VERSION);
        truncated_prefix.extend_from_slice(&[0xaa; 4]);
        assert_descriptor_parse_err_no_panic(truncated_prefix);
        assert_descriptor_parse_err_no_panic(descriptor_with_resource_key_len(0, b""));
        assert_descriptor_parse_err_no_panic(descriptor_with_resource_key_len(u64::MAX, b""));
        assert_descriptor_parse_err_no_panic(descriptor_with_resource_key_len(
            u64::try_from(usize::MAX).unwrap(),
            b"",
        ));
        assert_descriptor_parse_err_no_panic(descriptor_with_resource_key_len(1024, b"tiny"));
        assert_descriptor_parse_err_no_panic(descriptor_with_resource_key_len(4, b"gksxextra"));

        #[cfg(target_pointer_width = "32")]
        assert_descriptor_parse_err_no_panic(descriptor_with_resource_key_len(
            u64::from(usize::MAX) + 1,
            b"",
        ));
    }

    #[test]
    fn artifact_v2_descriptor_present_round_trip_and_fixed_id() {
        let mut body = fixed_body();
        body.recovery_authority_id = Some(Sha256Digest::new([0x0d; 32]));
        let descriptor = TrustedCliApplyDescriptor {
            version: TrustedCliApplyDescriptor::VERSION,
            resource_key: "gksphone".to_owned(),
            baseline_id: "11".repeat(32),
            selected_installed_root: ".".to_owned(),
            installed_snapshot_fingerprint: "22".repeat(32),
            incoming_package_fingerprint: "33".repeat(32),
            incoming_resource_fingerprint: "44".repeat(32),
            entries: vec![TrustedCliApplyDescriptorEntry {
                path: "fxmanifest.lua".to_owned(),
                baseline_state: TrustedCliApplyDescriptorFileState {
                    presence: "absent".to_owned(),
                    sha256: None,
                    escrow_class: None,
                    trusted_baseline_blob_available: false,
                },
                installed_state: TrustedCliApplyDescriptorFileState {
                    presence: "absent".to_owned(),
                    sha256: None,
                    escrow_class: None,
                    trusted_baseline_blob_available: false,
                },
                incoming_state: TrustedCliApplyDescriptorFileState {
                    presence: "absent".to_owned(),
                    sha256: None,
                    escrow_class: None,
                    trusted_baseline_blob_available: false,
                },
                local_delta: "unchanged".to_owned(),
                incoming_delta: "unchanged".to_owned(),
                disposition: "no_change".to_owned(),
                reviewed_action: "not_required".to_owned(),
            }],
        };
        descriptor.validate().unwrap();
        let artifact = encode_cli_artifact_v2_with_apply_descriptor(&body, &descriptor).unwrap();
        let parsed = parse_cli_artifact(
            artifact.canonical_bytes(),
            &TrustedCliUpdateOptions::default(),
        )
        .unwrap();
        assert_eq!(parsed.version(), ARTIFACT_V2_FORMAT_VERSION);
        assert_eq!(parsed.body(), &body);
        assert_eq!(parsed.apply_descriptor(), Some(&descriptor));
        // Independently derived with a small Python struct/sha256 reference encoder that does
        // not import or execute this crate. All expected wire/hash values are literal.
        const PREFIX_HEX: &str = "676b726d2d636c692d7570646174652d61727469666163742d76320a02a401000000000000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050000000006060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808080808080808080809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c010801000000000000676b726d2d636c692d6170706c792d64657363726970746f722d62696e2d76310a010800000000000000676b7370686f6e6540000000000000003131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313101000000000000002e22222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444401000000000000000e0000000000000066786d616e69666573742e6c756100000000000000";
        fn decode_literal_hex(value: &str) -> Vec<u8> {
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let nibble = |byte: u8| match byte {
                        b'0'..=b'9' => byte - b'0',
                        b'a'..=b'f' => byte - b'a' + 10,
                        _ => panic!("invalid literal hex"),
                    };
                    (nibble(pair[0]) << 4) | nibble(pair[1])
                })
                .collect()
        }
        let prefix = &artifact.canonical_bytes()[..artifact.canonical_bytes().len() - 32];
        assert_eq!(prefix, decode_literal_hex(PREFIX_HEX));
        assert_eq!(
            Sha256Digest::new(Sha256::digest(prefix).into()).to_string(),
            "fbfb9a110cdcb73449965229a133c08d3205d8700d5cc844f392c2c30a223ea6"
        );
        assert_eq!(
            artifact.artifact_id().to_hex(),
            "67bdfcee68372247e0db3dae738a3a7996ffc8831f132b1b36164be7b2a52ae2"
        );
    }
}
