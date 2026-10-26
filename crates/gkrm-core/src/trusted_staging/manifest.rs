//! Final-tree mapping and canonical manifest.bin encoding.

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::three_way_merge_synthesis::{MergeSynthesisDisposition, ThreeWayMergeSynthesisPlan};
use crate::{
    GkrmError, MergedByteDisposition, ResourceRelativePath, Result, Sha256Digest,
    ThreeWayFileState, ThreeWayMergedBytesPlan, ThreeWayPlanDisposition, ThreeWayPlanEntry,
    ThreeWayPlanReviewEntry, ThreeWayReviewedAction,
};

use super::id::{encode_final_state, encode_origin};
use super::{
    StagingContentOrigin, StagingFinalState, StagingSourceBinding, TrustedStagingEntry,
    TrustedStagingEntryId, TrustedStagingManifest, TrustedStagingManifestId,
};

pub(super) fn map_final_tree(
    plan_entries: &[ThreeWayPlanEntry],
    review_entries: &[ThreeWayPlanReviewEntry],
    synthesis: Option<&ThreeWayMergeSynthesisPlan>,
    merged_bytes: Option<&ThreeWayMergedBytesPlan>,
    operator_merges: &[crate::trusted_staging::TrustedStagingOperatorMergeInput<'_>],
) -> Result<Vec<TrustedStagingEntry>> {
    if plan_entries.len() != review_entries.len() {
        return Err(GkrmError::TrustedStagingFinalTreeRejected);
    }
    let mut out = Vec::with_capacity(plan_entries.len());
    for (plan_entry, review_entry) in plan_entries.iter().zip(review_entries) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::TrustedStagingFinalTreeRejected);
        }
        let mapped = map_one(
            plan_entry,
            review_entry,
            synthesis,
            merged_bytes,
            operator_merges,
        )?;
        out.push(mapped);
    }
    out.sort_by(|a, b| a.path().cmp(b.path()));
    for window in out.windows(2) {
        if window[0].path() == window[1].path() {
            return Err(GkrmError::TrustedStagingFinalTreeRejected);
        }
    }
    Ok(out)
}

fn map_one(
    plan_entry: &ThreeWayPlanEntry,
    review_entry: &ThreeWayPlanReviewEntry,
    synthesis: Option<&ThreeWayMergeSynthesisPlan>,
    merged_bytes: Option<&ThreeWayMergedBytesPlan>,
    operator_merges: &[crate::trusted_staging::TrustedStagingOperatorMergeInput<'_>],
) -> Result<TrustedStagingEntry> {
    match review_entry.action() {
        ThreeWayReviewedAction::Pending => Err(GkrmError::TrustedStagingReviewUnresolved),
        ThreeWayReviewedAction::ManualReview => {
            if plan_entry.disposition() != ThreeWayPlanDisposition::MergeCandidate {
                return Err(GkrmError::TrustedStagingReviewUnresolved);
            }
            let op = operator_merges
                .iter()
                .find(|m| m.path == plan_entry.path())
                .ok_or(GkrmError::TrustedStagingReviewUnresolved)?;
            if op.bytes.len() as u64 == 0 {
                return Err(GkrmError::TrustedStagingManualMergeResult);
            }
            Ok(present(
                plan_entry.path().clone(),
                StagingFinalState::Merged,
                StagingContentOrigin::Merged,
                op.content_digest,
                StagingSourceBinding::OperatorMerge(op.artifact_id),
                Some(op.bytes.len() as u64),
            ))
        }
        ThreeWayReviewedAction::UseIncomingState => match plan_entry.incoming_state() {
            ThreeWayFileState::Present { sha256, .. } => Ok(present(
                plan_entry.path().clone(),
                StagingFinalState::Incoming,
                StagingContentOrigin::Incoming,
                *sha256,
                StagingSourceBinding::IncomingDigest(*sha256),
                None,
            )),
            ThreeWayFileState::Absent => Ok(absent(plan_entry.path().clone())),
        },
        ThreeWayReviewedAction::PreserveInstalledState => match plan_entry.installed_state() {
            ThreeWayFileState::Present { sha256, .. } => Ok(present(
                plan_entry.path().clone(),
                StagingFinalState::Installed,
                StagingContentOrigin::Installed,
                *sha256,
                StagingSourceBinding::InstalledDigest(*sha256),
                None,
            )),
            ThreeWayFileState::Absent => Ok(absent(plan_entry.path().clone())),
        },
        ThreeWayReviewedAction::QueueMergeAnalysis => {
            if plan_entry.disposition() != ThreeWayPlanDisposition::MergeCandidate {
                return Err(GkrmError::TrustedStagingFinalTreeRejected);
            }
            if let Some(synthesis) = synthesis {
                if let Some(entry) = synthesis
                    .entries()
                    .iter()
                    .find(|e| e.path() == plan_entry.path())
                {
                    if entry.disposition() == MergeSynthesisDisposition::ManualReviewOperationLimit
                    {
                        let op = operator_merges
                            .iter()
                            .find(|m| m.path == plan_entry.path())
                            .ok_or(GkrmError::TrustedStagingManualMergeResult)?;
                        return Ok(present(
                            plan_entry.path().clone(),
                            StagingFinalState::Merged,
                            StagingContentOrigin::Merged,
                            op.content_digest,
                            StagingSourceBinding::OperatorMerge(op.artifact_id),
                            Some(op.bytes.len() as u64),
                        ));
                    }
                }
            }
            let merged = merged_bytes.ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
            let entry = merged
                .entries()
                .iter()
                .find(|e| e.path() == plan_entry.path())
                .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
            if entry.disposition() == MergedByteDisposition::ManualReviewOutputLimit {
                let op = operator_merges
                    .iter()
                    .find(|m| m.path == plan_entry.path())
                    .ok_or(GkrmError::TrustedStagingManualMergeResult)?;
                return Ok(present(
                    plan_entry.path().clone(),
                    StagingFinalState::Merged,
                    StagingContentOrigin::Merged,
                    op.content_digest,
                    StagingSourceBinding::OperatorMerge(op.artifact_id),
                    Some(op.bytes.len() as u64),
                ));
            }
            let artifact = entry
                .artifact()
                .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
            let artifact_id = entry
                .artifact_id()
                .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
            let digest = *artifact.digest_for_staging();
            Ok(present(
                plan_entry.path().clone(),
                StagingFinalState::Merged,
                StagingContentOrigin::Merged,
                digest,
                StagingSourceBinding::MergedArtifact(*artifact_id),
                Some(artifact.byte_length()),
            ))
        }
        ThreeWayReviewedAction::NotRequired => match plan_entry.disposition() {
            ThreeWayPlanDisposition::ConvergedDeletion => Ok(absent(plan_entry.path().clone())),
            ThreeWayPlanDisposition::NoChange
            | ThreeWayPlanDisposition::Converged
            | ThreeWayPlanDisposition::ConvergedAddition => match plan_entry.installed_state() {
                ThreeWayFileState::Present { sha256, .. } => {
                    if let ThreeWayFileState::Present {
                        sha256: incoming, ..
                    } = plan_entry.incoming_state()
                    {
                        if sha256 != incoming {
                            return Err(GkrmError::TrustedStagingFinalTreeRejected);
                        }
                    }
                    Ok(present(
                        plan_entry.path().clone(),
                        StagingFinalState::Installed,
                        StagingContentOrigin::Installed,
                        *sha256,
                        StagingSourceBinding::InstalledDigest(*sha256),
                        None,
                    ))
                }
                ThreeWayFileState::Absent => Ok(absent(plan_entry.path().clone())),
            },
            _ => Err(GkrmError::TrustedStagingFinalTreeRejected),
        },
    }
}

pub(super) fn present(
    path: ResourceRelativePath,
    final_state: StagingFinalState,
    origin: StagingContentOrigin,
    digest: Sha256Digest,
    binding: StagingSourceBinding,
    known_length: Option<u64>,
) -> TrustedStagingEntry {
    TrustedStagingEntry {
        path,
        final_state,
        origin,
        expected_digest: Some(digest),
        expected_byte_length: known_length,
        source_binding: binding,
        entry_id: TrustedStagingEntryId(Sha256Digest::new([0; 32])), // filled later
    }
}

pub(super) fn absent(path: ResourceRelativePath) -> TrustedStagingEntry {
    TrustedStagingEntry {
        path,
        final_state: StagingFinalState::Absent,
        origin: StagingContentOrigin::Absent,
        expected_digest: None,
        expected_byte_length: None,
        source_binding: StagingSourceBinding::Absent,
        entry_id: TrustedStagingEntryId(Sha256Digest::new([0; 32])),
    }
}

pub(super) fn assign_entry_ids(
    entries: &mut [TrustedStagingEntry],
    plan_id: &Sha256Digest,
) -> Result<()> {
    for entry in entries.iter_mut() {
        entry.entry_id = encode_entry_id(plan_id, entry)?;
    }
    Ok(())
}

pub(super) fn encode_entry_id(
    plan_id: &Sha256Digest,
    entry: &TrustedStagingEntry,
) -> Result<TrustedStagingEntryId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-staging-entry-v1")
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.digest(plan_id);
    encoder
        .path(entry.path())
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.u8(encode_final_state(entry.final_state));
    encoder.u8(encode_origin(entry.origin));
    match (
        entry.expected_digest,
        entry.expected_byte_length,
        &entry.source_binding,
    ) {
        (None, None, StagingSourceBinding::Absent) => {
            encoder.u8(0);
        }
        (Some(digest), Some(len), binding) => {
            encoder.u8(1);
            encoder.digest(&digest);
            encoder.u64(len);
            encode_binding(&mut encoder, binding)?;
        }
        _ => return Err(GkrmError::TrustedStagingFinalTreeRejected),
    }
    Ok(TrustedStagingEntryId(encoder.finish()))
}

fn encode_binding(
    encoder: &mut CanonicalFingerprintEncoder,
    binding: &StagingSourceBinding,
) -> Result<()> {
    match binding {
        StagingSourceBinding::InstalledDigest(d) => {
            encoder.u8(0);
            encoder.digest(d);
        }
        StagingSourceBinding::IncomingDigest(d) => {
            encoder.u8(1);
            encoder.digest(d);
        }
        StagingSourceBinding::MergedArtifact(id) => {
            encoder.u8(2);
            encoder.digest(id.digest());
        }
        StagingSourceBinding::OperatorMerge(id) => {
            encoder.u8(4);
            encoder.digest(id);
        }
        StagingSourceBinding::Absent => encoder.u8(3),
    }
    Ok(())
}

pub(super) fn encode_manifest_id(
    plan_id: &Sha256Digest,
    review_id: &Sha256Digest,
    analysis_id: Option<&Sha256Digest>,
    text_diff_id: Option<&Sha256Digest>,
    synthesis_id: Option<&Sha256Digest>,
    merged_bytes_id: Option<&Sha256Digest>,
    resource_key: &str,
    baseline_id: &str,
    installed_fp: &Sha256Digest,
    incoming_pkg_fp: &Sha256Digest,
    incoming_res_fp: &Sha256Digest,
    options_tag: &[u8],
    entries: &[TrustedStagingEntry],
) -> Result<TrustedStagingManifestId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-staging-manifest-v1")
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.digest(plan_id);
    encoder.digest(review_id);
    match analysis_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    match text_diff_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    match synthesis_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    match merged_bytes_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    encoder
        .string(resource_key)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder
        .string(baseline_id)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.digest(installed_fp);
    encoder.digest(incoming_pkg_fp);
    encoder.digest(incoming_res_fp);
    encoder
        .octet_string(options_tag)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder
        .usize(entries.len())
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    for entry in entries {
        encoder.digest(entry.entry_id.digest());
        encoder
            .path(entry.path())
            .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
        encoder.u8(encode_final_state(entry.final_state));
        encoder.u8(encode_origin(entry.origin));
        match (entry.expected_digest, entry.expected_byte_length) {
            (Some(d), Some(len)) => {
                encoder.u8(1);
                encoder.digest(&d);
                encoder.u64(len);
            }
            (None, None) => encoder.u8(0),
            _ => return Err(GkrmError::TrustedStagingFinalTreeRejected),
        }
        encode_binding(&mut encoder, &entry.source_binding)?;
    }
    Ok(TrustedStagingManifestId(encoder.finish()))
}

pub(crate) fn encode_manifest_bytes(manifest: &TrustedStagingManifest) -> Result<Vec<u8>> {
    // Deterministic binary sidecar (not JSON): reuse fingerprint encoder domain as framing.
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-staging-manifest-bin-v1")
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.digest(manifest.manifest_id.digest());
    encoder
        .usize(manifest.entries.len())
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    for entry in &manifest.entries {
        encoder.digest(entry.entry_id.digest());
        encoder
            .path(entry.path())
            .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
        encoder.u8(encode_final_state(entry.final_state));
        encoder.u8(encode_origin(entry.origin));
        match (entry.expected_digest, entry.expected_byte_length) {
            (Some(d), Some(len)) => {
                encoder.u8(1);
                encoder.digest(&d);
                encoder.u64(len);
            }
            (None, None) => encoder.u8(0),
            _ => return Err(GkrmError::TrustedStagingFinalTreeRejected),
        }
        encode_binding(&mut encoder, &entry.source_binding)?;
    }
    // Expose raw canonical bytes by finishing into digest is wrong — we need the byte buffer.
    // CanonicalFingerprintEncoder doesn't expose bytes. Encode manually:
    manual_manifest_bytes(manifest)
}

pub(super) fn parse_manifest_bytes(
    bytes: &[u8],
    plan_id: Sha256Digest,
    review_id: Sha256Digest,
    analysis_id: Option<Sha256Digest>,
    text_diff_id: Option<Sha256Digest>,
    synthesis_id: Option<Sha256Digest>,
    merged_bytes_id: Option<Sha256Digest>,
    max_entries: usize,
) -> Result<TrustedStagingManifest> {
    let mut offset = 0usize;
    let domain = read_str(bytes, &mut offset)?;
    if domain != "gkrm-staging-manifest-bin-v1" {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let manifest_id = TrustedStagingManifestId::from_digest(read_digest(bytes, &mut offset)?);
    let entry_count = read_usize(bytes, &mut offset)?;
    if entry_count > max_entries {
        return Err(GkrmError::TrustedStagingLimitExceeded {
            limit: "max_entries",
        });
    }
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let entry_id = TrustedStagingEntryId(read_digest(bytes, &mut offset)?);
        let path = ResourceRelativePath::try_from_slash_str(read_str(bytes, &mut offset)?)
            .map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?;
        let final_state = decode_final_state(read_u8(bytes, &mut offset)?)?;
        let origin = decode_origin(read_u8(bytes, &mut offset)?)?;
        let state_flag = read_u8(bytes, &mut offset)?;
        let (expected_digest, expected_byte_length) = match state_flag {
            0 => (None, None),
            1 => (
                Some(read_digest(bytes, &mut offset)?),
                Some(read_u64(bytes, &mut offset)?),
            ),
            _ => return Err(GkrmError::TrustedStagingManifestTreeMismatch),
        };
        let source_binding = decode_binding(bytes, &mut offset)?;
        entries.push(TrustedStagingEntry {
            path,
            final_state,
            origin,
            expected_digest,
            expected_byte_length,
            source_binding,
            entry_id,
        });
    }
    if offset != bytes.len() {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let manifest = TrustedStagingManifest {
        entries,
        manifest_id,
        plan_id,
        review_id,
        analysis_id,
        text_diff_id,
        synthesis_id,
        merged_bytes_id,
    };
    let expected = encode_manifest_bytes(&manifest)?;
    if expected != bytes {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    Ok(manifest)
}

fn decode_final_state(value: u8) -> Result<StagingFinalState> {
    match value {
        0 => Ok(StagingFinalState::Installed),
        1 => Ok(StagingFinalState::Incoming),
        2 => Ok(StagingFinalState::Merged),
        3 => Ok(StagingFinalState::Absent),
        _ => Err(GkrmError::TrustedStagingManifestTreeMismatch),
    }
}

fn decode_origin(value: u8) -> Result<StagingContentOrigin> {
    match value {
        0 => Ok(StagingContentOrigin::Installed),
        1 => Ok(StagingContentOrigin::Incoming),
        2 => Ok(StagingContentOrigin::Merged),
        3 => Ok(StagingContentOrigin::Absent),
        _ => Err(GkrmError::TrustedStagingManifestTreeMismatch),
    }
}

fn decode_binding(bytes: &[u8], offset: &mut usize) -> Result<StagingSourceBinding> {
    match read_u8(bytes, offset)? {
        0 => Ok(StagingSourceBinding::InstalledDigest(read_digest(
            bytes, offset,
        )?)),
        1 => Ok(StagingSourceBinding::IncomingDigest(read_digest(
            bytes, offset,
        )?)),
        2 => Ok(StagingSourceBinding::MergedArtifact(
            crate::MergedByteArtifactId::from_digest(read_digest(bytes, offset)?),
        )),
        3 => Ok(StagingSourceBinding::Absent),
        4 => Ok(StagingSourceBinding::OperatorMerge(read_digest(
            bytes, offset,
        )?)),
        _ => Err(GkrmError::TrustedStagingManifestTreeMismatch),
    }
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
    if *offset >= bytes.len() {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let value = bytes[*offset];
    *offset += 1;
    Ok(value)
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let end = checked_manifest_end(*offset, 8)?;
    if end > bytes.len() {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let value = u64::from_le_bytes(bytes[*offset..end].try_into().unwrap());
    *offset = end;
    Ok(value)
}

fn read_usize(bytes: &[u8], offset: &mut usize) -> Result<usize> {
    let value = read_u64(bytes, offset)?;
    let remaining = bytes.len().saturating_sub(*offset);
    if value > u64::try_from(remaining).map_err(|_| GkrmError::TrustedStagingArithmeticOverflow)? {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    usize::try_from(value).map_err(|_| GkrmError::TrustedStagingArithmeticOverflow)
}

fn read_digest(bytes: &[u8], offset: &mut usize) -> Result<Sha256Digest> {
    let end = checked_manifest_end(*offset, 32)?;
    if end > bytes.len() {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[*offset..end]);
    *offset = end;
    Ok(Sha256Digest::new(digest))
}

fn read_str<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a str> {
    let len = read_usize(bytes, offset)?;
    let end = checked_manifest_end(*offset, len)?;
    if end > bytes.len() {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let value = std::str::from_utf8(&bytes[*offset..end])
        .map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?;
    *offset = end;
    Ok(value)
}

fn checked_manifest_end(offset: usize, len: usize) -> Result<usize> {
    offset
        .checked_add(len)
        .ok_or(GkrmError::TrustedStagingManifestTreeMismatch)
}

fn manual_manifest_bytes(manifest: &TrustedStagingManifest) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    push_str(&mut bytes, "gkrm-staging-manifest-bin-v1")?;
    bytes.extend_from_slice(manifest.manifest_id.digest().as_bytes());
    push_usize(&mut bytes, manifest.entries.len())?;
    for entry in &manifest.entries {
        bytes.extend_from_slice(entry.entry_id.digest().as_bytes());
        push_str(&mut bytes, entry.path().as_str())?;
        bytes.push(encode_final_state(entry.final_state));
        bytes.push(encode_origin(entry.origin));
        match (entry.expected_digest, entry.expected_byte_length) {
            (Some(d), Some(len)) => {
                bytes.push(1);
                bytes.extend_from_slice(d.as_bytes());
                bytes.extend_from_slice(&len.to_le_bytes());
            }
            (None, None) => bytes.push(0),
            _ => return Err(GkrmError::TrustedStagingFinalTreeRejected),
        }
        match &entry.source_binding {
            StagingSourceBinding::InstalledDigest(d) => {
                bytes.push(0);
                bytes.extend_from_slice(d.as_bytes());
            }
            StagingSourceBinding::IncomingDigest(d) => {
                bytes.push(1);
                bytes.extend_from_slice(d.as_bytes());
            }
            StagingSourceBinding::MergedArtifact(id) => {
                bytes.push(2);
                bytes.extend_from_slice(id.digest().as_bytes());
            }
            StagingSourceBinding::OperatorMerge(id) => {
                bytes.push(4);
                bytes.extend_from_slice(id.as_bytes());
            }
            StagingSourceBinding::Absent => bytes.push(3),
        }
    }
    Ok(bytes)
}

fn push_str(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    push_usize(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u64::try_from(value).map_err(|_| GkrmError::TrustedStagingArithmeticOverflow)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::panic;

    use super::*;

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::new([value; 32])
    }

    fn empty_manifest_bytes() -> Vec<u8> {
        let manifest = TrustedStagingManifest {
            entries: Vec::new(),
            manifest_id: TrustedStagingManifestId::from_digest(digest(1)),
            plan_id: digest(2),
            review_id: digest(3),
            analysis_id: None,
            text_diff_id: None,
            synthesis_id: None,
            merged_bytes_id: None,
        };
        encode_manifest_bytes(&manifest).unwrap()
    }

    fn assert_manifest_parse_err_no_panic(bytes: Vec<u8>) {
        let parsed = panic::catch_unwind(|| {
            parse_manifest_bytes(&bytes, digest(2), digest(3), None, None, None, None, 8)
        });
        assert!(matches!(parsed, Ok(Err(_))));
    }

    fn manifest_with_domain_len(len: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn malformed_manifest_lengths_return_errors_without_panic() {
        assert_manifest_parse_err_no_panic(vec![0xaa; 4]);
        assert_manifest_parse_err_no_panic(manifest_with_domain_len(0, b""));
        assert_manifest_parse_err_no_panic(manifest_with_domain_len(u64::MAX, b""));
        assert_manifest_parse_err_no_panic(manifest_with_domain_len(
            u64::try_from(usize::MAX).unwrap(),
            b"",
        ));
        assert_manifest_parse_err_no_panic(manifest_with_domain_len(1024, b"tiny"));

        let mut trailing = empty_manifest_bytes();
        trailing.push(0);
        assert_manifest_parse_err_no_panic(trailing);

        let mut truncated_digest = empty_manifest_bytes();
        truncated_digest.truncate(truncated_digest.len() - 12);
        assert_manifest_parse_err_no_panic(truncated_digest);

        #[cfg(target_pointer_width = "32")]
        assert_manifest_parse_err_no_panic(manifest_with_domain_len(
            u64::from(usize::MAX) + 1,
            b"",
        ));
    }
}
