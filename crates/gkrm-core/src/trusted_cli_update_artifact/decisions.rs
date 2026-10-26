//! Canonical operator decision document (Task 14 plan → decisions → Task 15).

use std::collections::BTreeSet;
use std::io::Write;

use sha2::{Digest, Sha256};

use crate::installed_path::case_collision_key;
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{
    GkrmError, PolicyTransitionAcknowledgement, ResourceRelativePath, Result, Sha256Digest,
    ThreeWayPlanDecision, ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet,
    ThreeWayPlanDisposition, ThreeWayPlanId, ThreeWayUpdatePlan,
};

use super::id::{encode_decision_document_id, encode_disposition_domain};
use super::limits::TrustedCliUpdateOptions;

pub const DECISION_MAGIC: &[u8] = b"gkrm-cli-decisions-v1\n";
pub const DECISION_FORMAT_VERSION: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedCliDecisionDocumentId(Sha256Digest);

impl TrustedCliDecisionDocumentId {
    pub fn to_hex(&self) -> String {
        self.0.to_string()
    }

    pub(crate) fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl std::fmt::Debug for TrustedCliDecisionDocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedCliDecisionDocumentId")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedCliDecisionEntry {
    pub path: ResourceRelativePath,
    pub choice: ThreeWayPlanDecisionChoice,
    pub policy_acknowledgement: PolicyTransitionAcknowledgement,
    /// Resource-relative path under the operator-merge root, when needed later.
    pub operator_merge_relpath: Option<ResourceRelativePath>,
}

pub struct TrustedCliDecisionDocument {
    plan_id: ThreeWayPlanId,
    document_id: TrustedCliDecisionDocumentId,
    entries: Vec<TrustedCliDecisionEntry>,
    #[allow(dead_code)]
    disposition_domain: Sha256Digest,
    bytes: Vec<u8>,
}

impl TrustedCliDecisionDocument {
    pub fn document_id(&self) -> &TrustedCliDecisionDocumentId {
        &self.document_id
    }

    pub fn plan_id(&self) -> &ThreeWayPlanId {
        &self.plan_id
    }

    pub fn entries(&self) -> &[TrustedCliDecisionEntry] {
        &self.entries
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_decision_set(&self) -> Result<ThreeWayPlanDecisionSet> {
        let decisions = self
            .entries
            .iter()
            .map(|e| {
                ThreeWayPlanDecision::try_new(e.path.clone(), e.choice, e.policy_acknowledgement)
            })
            .collect::<Result<Vec<_>>>()?;
        ThreeWayPlanDecisionSet::try_new(*self.plan_id(), decisions)
    }
}

impl std::fmt::Debug for TrustedCliDecisionDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedCliDecisionDocument")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

fn disposition_tag(d: ThreeWayPlanDisposition) -> u8 {
    match d {
        ThreeWayPlanDisposition::NoChange => 0,
        ThreeWayPlanDisposition::UseIncoming => 1,
        ThreeWayPlanDisposition::RemoveForIncoming => 2,
        ThreeWayPlanDisposition::PreserveInstalled => 3,
        ThreeWayPlanDisposition::PreserveInstalledDeletion => 4,
        ThreeWayPlanDisposition::AddIncoming => 5,
        ThreeWayPlanDisposition::PreserveInstalledAddition => 6,
        ThreeWayPlanDisposition::Converged => 7,
        ThreeWayPlanDisposition::ConvergedAddition => 8,
        ThreeWayPlanDisposition::ConvergedDeletion => 9,
        ThreeWayPlanDisposition::MergeCandidate => 10,
        ThreeWayPlanDisposition::ConflictReview => 11,
        ThreeWayPlanDisposition::DeleteVsModifyConflict => 12,
        ThreeWayPlanDisposition::ModifyVsDeleteConflict => 13,
        ThreeWayPlanDisposition::AddVsAddConflict => 14,
        ThreeWayPlanDisposition::PolicyReview => 15,
        ThreeWayPlanDisposition::PolicyConflictReview => 16,
    }
}

fn choice_tag(c: ThreeWayPlanDecisionChoice) -> u8 {
    match c {
        ThreeWayPlanDecisionChoice::AcceptRecommended => 0,
        ThreeWayPlanDecisionChoice::UseIncomingState => 1,
        ThreeWayPlanDecisionChoice::PreserveInstalledState => 2,
        ThreeWayPlanDecisionChoice::QueueMergeAnalysis => 3,
        ThreeWayPlanDecisionChoice::ManualReview => 4,
    }
}

fn policy_tag(p: PolicyTransitionAcknowledgement) -> u8 {
    match p {
        PolicyTransitionAcknowledgement::NotProvided => 0,
        PolicyTransitionAcknowledgement::Acknowledged => 1,
    }
}

fn parse_choice(tag: u8) -> Result<ThreeWayPlanDecisionChoice> {
    Ok(match tag {
        0 => ThreeWayPlanDecisionChoice::AcceptRecommended,
        1 => ThreeWayPlanDecisionChoice::UseIncomingState,
        2 => ThreeWayPlanDecisionChoice::PreserveInstalledState,
        3 => ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
        4 => ThreeWayPlanDecisionChoice::ManualReview,
        _ => return Err(GkrmError::TrustedCliUpdateDecisionsInvalid),
    })
}

fn parse_policy(tag: u8) -> Result<PolicyTransitionAcknowledgement> {
    Ok(match tag {
        0 => PolicyTransitionAcknowledgement::NotProvided,
        1 => PolicyTransitionAcknowledgement::Acknowledged,
        _ => return Err(GkrmError::TrustedCliUpdateDecisionsInvalid),
    })
}

/// Build and encode a decision document from validated entries against a Task 14 plan.
pub fn build_decision_document(
    plan: &ThreeWayUpdatePlan,
    mut entries: Vec<TrustedCliDecisionEntry>,
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedCliDecisionDocument> {
    if entries.len() > options.max_decision_entries {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_decision_entries",
        });
    }
    entries.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    validate_entries_against_plan(plan, &entries)?;

    let domain_pairs: Vec<(String, u8)> = plan
        .entries()
        .iter()
        .map(|e| {
            (
                e.path().as_str().to_owned(),
                disposition_tag(e.disposition()),
            )
        })
        .collect();
    let disposition_domain = encode_disposition_domain(plan.plan_id().digest(), &domain_pairs)?;

    let bytes = encode_decision_bytes(plan.plan_id().digest(), &disposition_domain, &entries)?;
    if bytes.len() > options.max_decision_document_bytes {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_decision_document_bytes",
        });
    }
    let body = Sha256Digest::new(Sha256::digest(&bytes).into());
    let document_id = TrustedCliDecisionDocumentId(encode_decision_document_id(&body)?);
    Ok(TrustedCliDecisionDocument {
        plan_id: *plan.plan_id(),
        document_id,
        entries,
        disposition_domain,
        bytes,
    })
}

pub fn parse_decision_document(
    plan: &ThreeWayUpdatePlan,
    bytes: &[u8],
    options: &TrustedCliUpdateOptions,
) -> Result<TrustedCliDecisionDocument> {
    if bytes.len() > options.max_decision_document_bytes {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_decision_document_bytes",
        });
    }
    let (plan_id, disposition_domain, entries, consumed) = decode_decision_bytes(bytes)?;
    if consumed != bytes.len() {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    if &plan_id != plan.plan_id().digest() {
        return Err(GkrmError::TrustedCliUpdateDecisionsPlanMismatch);
    }
    let domain_pairs: Vec<(String, u8)> = plan
        .entries()
        .iter()
        .map(|e| {
            (
                e.path().as_str().to_owned(),
                disposition_tag(e.disposition()),
            )
        })
        .collect();
    let expected_domain = encode_disposition_domain(plan.plan_id().digest(), &domain_pairs)?;
    if disposition_domain != expected_domain {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    validate_entries_against_plan(plan, &entries)?;
    let body = Sha256Digest::new(Sha256::digest(bytes).into());
    let document_id = TrustedCliDecisionDocumentId(encode_decision_document_id(&body)?);
    Ok(TrustedCliDecisionDocument {
        plan_id: *plan.plan_id(),
        document_id,
        entries,
        disposition_domain,
        bytes: bytes.to_vec(),
    })
}

fn validate_entries_against_plan(
    plan: &ThreeWayUpdatePlan,
    entries: &[TrustedCliDecisionEntry],
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut case_keys = BTreeSet::new();
    for entry in entries {
        let path = entry.path.as_str();
        if path.is_empty() || path.contains('\\') || path.starts_with('/') {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        }
        for part in path.split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
            }
        }
        if !seen.insert(path.to_owned()) {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        }
        if !case_keys.insert(case_collision_key(path)) {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        }
        let plan_entry = plan
            .entries()
            .iter()
            .find(|e| e.path().as_str() == path)
            .ok_or(GkrmError::TrustedCliUpdateDecisionsInvalid)?;
        match plan_entry.disposition() {
            ThreeWayPlanDisposition::NoChange
            | ThreeWayPlanDisposition::Converged
            | ThreeWayPlanDisposition::ConvergedAddition
            | ThreeWayPlanDisposition::ConvergedDeletion => {
                return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
            }
            ThreeWayPlanDisposition::MergeCandidate
                if !matches!(
                    entry.choice,
                    ThreeWayPlanDecisionChoice::QueueMergeAnalysis
                        | ThreeWayPlanDecisionChoice::ManualReview
                        | ThreeWayPlanDecisionChoice::AcceptRecommended
                        | ThreeWayPlanDecisionChoice::UseIncomingState
                        | ThreeWayPlanDecisionChoice::PreserveInstalledState
                ) =>
            {
                return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
            }
            _ => {}
        }
        match &entry.operator_merge_relpath {
            Some(rel) => {
                if entry.choice != ThreeWayPlanDecisionChoice::ManualReview {
                    return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
                }
                if rel.as_str() != path {
                    return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
                }
                if rel.as_str().starts_with('/')
                    || rel.as_str().contains('\\')
                    || rel.as_str().contains(':')
                {
                    return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
                }
            }
            None if entry.choice == ThreeWayPlanDecisionChoice::ManualReview => {
                // ManualReview without operator-merge path is allowed at document
                // parse time; plan/apply later require the merge root + file.
            }
            None => {}
        }
    }
    // Canonical order required.
    for window in entries.windows(2) {
        if window[0].path.as_str() > window[1].path.as_str() {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        }
    }
    Ok(())
}

fn encode_decision_bytes(
    plan_id: &Sha256Digest,
    disposition_domain: &Sha256Digest,
    entries: &[TrustedCliDecisionEntry],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(DECISION_MAGIC);
    out.push(DECISION_FORMAT_VERSION);
    out.extend_from_slice(plan_id.as_bytes());
    out.extend_from_slice(disposition_domain.as_bytes());
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        let path = entry.path.as_str().as_bytes();
        out.extend_from_slice(&(path.len() as u64).to_le_bytes());
        out.extend_from_slice(path);
        out.push(choice_tag(entry.choice));
        out.push(policy_tag(entry.policy_acknowledgement));
        match &entry.operator_merge_relpath {
            Some(p) => {
                out.push(1);
                let pb = p.as_str().as_bytes();
                out.extend_from_slice(&(pb.len() as u64).to_le_bytes());
                out.extend_from_slice(pb);
            }
            None => out.push(0),
        }
    }
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-decision-body-seal-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.octet_string(&out)
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    let seal = enc.finish();
    out.extend_from_slice(seal.as_bytes());
    let _ = Write::flush(&mut out);
    Ok(out)
}

fn decode_decision_bytes(
    bytes: &[u8],
) -> Result<(
    Sha256Digest,
    Sha256Digest,
    Vec<TrustedCliDecisionEntry>,
    usize,
)> {
    if bytes.len() < DECISION_MAGIC.len() + 1 + 32 + 32 + 8 + 32 {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    if &bytes[..DECISION_MAGIC.len()] != DECISION_MAGIC {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    let mut offset = DECISION_MAGIC.len();
    if bytes[offset] != DECISION_FORMAT_VERSION {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    offset += 1;
    let mut plan_bytes = [0u8; 32];
    let end = checked_decision_end(offset, 32)?;
    plan_bytes.copy_from_slice(&bytes[offset..end]);
    offset = end;
    let mut domain_bytes = [0u8; 32];
    let end = checked_decision_end(offset, 32)?;
    domain_bytes.copy_from_slice(&bytes[offset..end]);
    offset = end;
    let end = checked_decision_end(offset, 8)?;
    let count_u64 = u64::from_le_bytes(bytes[offset..end].try_into().unwrap());
    offset = end;
    let remaining_without_seal = bytes
        .len()
        .checked_sub(offset)
        .and_then(|value| value.checked_sub(32))
        .ok_or(GkrmError::TrustedCliUpdateDecisionsInvalid)?;
    const MIN_DECISION_ENTRY_BYTES: usize = 8 + 2 + 1;
    if count_u64
        > u64::try_from(remaining_without_seal / MIN_DECISION_ENTRY_BYTES)
            .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?
    {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    let count =
        usize::try_from(count_u64).map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let len_end = checked_decision_end(offset, 8)?;
        if len_end > bytes.len() {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        }
        let path_len_u64 = u64::from_le_bytes(bytes[offset..len_end].try_into().unwrap());
        offset = len_end;
        let remaining_for_path = bytes
            .len()
            .checked_sub(offset)
            .and_then(|value| value.checked_sub(3 + 32))
            .ok_or(GkrmError::TrustedCliUpdateDecisionsInvalid)?;
        if path_len_u64
            > u64::try_from(remaining_for_path)
                .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?
        {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        }
        let path_len = usize::try_from(path_len_u64)
            .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?;
        let path_end = checked_decision_end(offset, path_len)?;
        if path_end
            .checked_add(3 + 32)
            .ok_or(GkrmError::TrustedCliUpdateDecisionsInvalid)?
            > bytes.len()
        {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        }
        let path_str = std::str::from_utf8(&bytes[offset..path_end])
            .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?;
        offset = path_end;
        let choice = parse_choice(bytes[offset])?;
        offset += 1;
        let policy = parse_policy(bytes[offset])?;
        offset += 1;
        let merge_flag = bytes[offset];
        offset += 1;
        let operator_merge_relpath = if merge_flag == 1 {
            let len_end = checked_decision_end(offset, 8)?;
            if len_end > bytes.len() {
                return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
            }
            let mlen_u64 = u64::from_le_bytes(bytes[offset..len_end].try_into().unwrap());
            offset = len_end;
            let remaining_for_merge = bytes
                .len()
                .checked_sub(offset)
                .and_then(|value| value.checked_sub(32))
                .ok_or(GkrmError::TrustedCliUpdateDecisionsInvalid)?;
            if mlen_u64
                > u64::try_from(remaining_for_merge)
                    .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?
            {
                return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
            }
            let mlen = usize::try_from(mlen_u64)
                .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?;
            let merge_end = checked_decision_end(offset, mlen)?;
            if merge_end
                .checked_add(32)
                .ok_or(GkrmError::TrustedCliUpdateDecisionsInvalid)?
                > bytes.len()
            {
                return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
            }
            let mpath = std::str::from_utf8(&bytes[offset..merge_end])
                .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?;
            offset = merge_end;
            Some(
                ResourceRelativePath::try_from_slash_str(mpath)
                    .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?,
            )
        } else if merge_flag == 0 {
            None
        } else {
            return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
        };
        entries.push(TrustedCliDecisionEntry {
            path: ResourceRelativePath::try_from_slash_str(path_str)
                .map_err(|_| GkrmError::TrustedCliUpdateDecisionsInvalid)?,
            choice,
            policy_acknowledgement: policy,
            operator_merge_relpath,
        });
    }
    let seal_end = checked_decision_end(offset, 32)?;
    if seal_end > bytes.len() {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    let body_without_seal = &bytes[..offset];
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-decision-body-seal-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.octet_string(body_without_seal)
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    let expected_seal = enc.finish();
    let mut got_seal = [0u8; 32];
    got_seal.copy_from_slice(&bytes[offset..seal_end]);
    offset = seal_end;
    if expected_seal.as_bytes() != &got_seal {
        return Err(GkrmError::TrustedCliUpdateDecisionsInvalid);
    }
    Ok((
        Sha256Digest::new(plan_bytes),
        Sha256Digest::new(domain_bytes),
        entries,
        offset,
    ))
}

fn checked_decision_end(offset: usize, len: usize) -> Result<usize> {
    offset
        .checked_add(len)
        .ok_or(GkrmError::TrustedCliUpdateDecisionsInvalid)
}

#[cfg(test)]
mod tests {
    use std::panic;

    use super::*;

    fn malformed_decision_with_count(count: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DECISION_MAGIC);
        bytes.push(DECISION_FORMAT_VERSION);
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&[0; 32]);
        bytes
    }

    fn malformed_decision_with_path_len(len: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DECISION_MAGIC);
        bytes.push(DECISION_FORMAT_VERSION);
        bytes.extend_from_slice(&[1; 32]);
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&[0; 32]);
        bytes
    }

    fn assert_decision_parse_err_no_panic(bytes: Vec<u8>) {
        let parsed = panic::catch_unwind(|| decode_decision_bytes(&bytes));
        assert!(matches!(parsed, Ok(Err(_))));
    }

    #[test]
    fn malformed_decision_lengths_return_errors_without_panic() {
        assert_decision_parse_err_no_panic(vec![0xaa; 4]);
        assert_decision_parse_err_no_panic(malformed_decision_with_count(u64::MAX));
        assert_decision_parse_err_no_panic(malformed_decision_with_path_len(u64::MAX, b""));
        assert_decision_parse_err_no_panic(malformed_decision_with_path_len(
            u64::try_from(usize::MAX).unwrap(),
            b"",
        ));
        assert_decision_parse_err_no_panic(malformed_decision_with_path_len(1024, b"tiny"));
        assert_decision_parse_err_no_panic(malformed_decision_with_path_len(0, b""));

        #[cfg(target_pointer_width = "32")]
        assert_decision_parse_err_no_panic(malformed_decision_with_path_len(
            u64::from(usize::MAX) + 1,
            b"",
        ));
    }
}
