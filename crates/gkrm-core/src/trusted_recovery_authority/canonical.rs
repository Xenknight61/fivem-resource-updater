use std::io::{Read, Write};

use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest};
use sha2::{Digest, Sha256};
use unicode_casefold::{Locale, UnicodeCaseFold, Variant};
use unicode_normalization::UnicodeNormalization;

use super::body::{RecoveryAuthorityBodyV1, RecoveryAuthorityNode};
use super::id::RecoveryAuthorityId;
use super::limits::RecoveryAuthorityLimits;

pub(crate) const BODY_MAGIC: &[u8] = b"gkrm-recovery-authority-body-v1\n";
const BODY_VERSION: u8 = 1;

pub fn encode_recovery_authority_body(
    body: &RecoveryAuthorityBodyV1,
    limits: RecoveryAuthorityLimits,
) -> Result<Vec<u8>> {
    let limits = limits.validate()?;
    validate_body(body, limits)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(estimated_body_bytes(body)?)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_body_bytes",
        })?;
    encode_into(body, &mut bytes, limits)?;
    Ok(bytes)
}

pub(crate) fn estimated_body_bytes(body: &RecoveryAuthorityBodyV1) -> Result<usize> {
    let mut total = BODY_MAGIC
        .len()
        .checked_add(3)
        .and_then(|v| v.checked_add(8 * 32))
        .and_then(|v| v.checked_add(8))
        .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
    for node in &body.nodes {
        total = total
            .checked_add(8)
            .and_then(|v| v.checked_add(node.path().as_str().len()))
            .and_then(|v| v.checked_add(1))
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        if matches!(node, RecoveryAuthorityNode::File { .. }) {
            total = total
                .checked_add(40)
                .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        }
    }
    Ok(total)
}

struct LimitedWriter<W> {
    inner: W,
    written: usize,
    limit: usize,
}

impl<W: Write> LimitedWriter<W> {
    fn write_all_checked(&mut self, bytes: &[u8]) -> Result<()> {
        self.written = self
            .written
            .checked_add(bytes.len())
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        if self.written > self.limit {
            return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
                limit: "max_body_bytes",
            });
        }
        self.inner
            .write_all(bytes)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)
    }
}

pub(crate) fn encode_into<W: Write>(
    body: &RecoveryAuthorityBodyV1,
    writer: W,
    limits: RecoveryAuthorityLimits,
) -> Result<()> {
    let mut out = LimitedWriter {
        inner: writer,
        written: 0,
        limit: limits.max_body_bytes,
    };
    out.write_all_checked(BODY_MAGIC)?;
    out.write_all_checked(&[
        BODY_VERSION,
        body.apply_derivation_version,
        body.transaction_derivation_version,
    ])?;
    for digest in [
        &body.installed_authority_commitment,
        &body.selected_resource_commitment,
        &body.baseline_id,
        &body.staging_manifest_id,
        &body.staging_bundle_id,
        &body.snapshot_a_id,
        &body.apply_plan_id,
        &body.transactional_plan_id,
    ] {
        out.write_all_checked(digest.as_bytes())?;
    }
    let count = u64::try_from(body.nodes.len())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
    out.write_all_checked(&count.to_le_bytes())?;
    for node in &body.nodes {
        let path = node.path().as_str().as_bytes();
        let len = u64::try_from(path.len())
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        out.write_all_checked(&len.to_le_bytes())?;
        out.write_all_checked(path)?;
        out.write_all_checked(&[node.tag()])?;
        if let RecoveryAuthorityNode::File {
            digest,
            byte_length,
            ..
        } = node
        {
            out.write_all_checked(digest.as_bytes())?;
            out.write_all_checked(&byte_length.to_le_bytes())?;
        }
    }
    Ok(())
}

pub fn parse_recovery_authority_body(
    bytes: &[u8],
    limits: RecoveryAuthorityLimits,
) -> Result<RecoveryAuthorityBodyV1> {
    let body_len = u64::try_from(bytes.len())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
    let (body, _) =
        parse_recovery_authority_body_reader(&mut std::io::Cursor::new(bytes), body_len, limits)?;
    Ok(body)
}

pub(crate) fn parse_recovery_authority_body_reader<R: Read>(
    reader: &mut R,
    body_len: u64,
    limits: RecoveryAuthorityLimits,
) -> Result<(RecoveryAuthorityBodyV1, RecoveryAuthorityId)> {
    let limits = limits.validate()?;
    let body_len_usize = usize::try_from(body_len)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
    if body_len_usize > limits.max_body_bytes {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_body_bytes",
        });
    }
    let mut input = StreamingBodyReader::new(reader, body_len)?;
    if input.bytes(BODY_MAGIC.len())? != BODY_MAGIC {
        return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
    }
    if input.u8()? != BODY_VERSION {
        return Err(GkrmError::TrustedRecoveryAuthorityVersionUnsupported);
    }
    let apply_derivation_version = input.u8()?;
    let transaction_derivation_version = input.u8()?;
    let installed_authority_commitment = input.digest()?;
    let selected_resource_commitment = input.digest()?;
    let baseline_id = input.digest()?;
    let staging_manifest_id = input.digest()?;
    let staging_bundle_id = input.digest()?;
    let snapshot_a_id = input.digest()?;
    let apply_plan_id = input.digest()?;
    let transactional_plan_id = input.digest()?;
    let node_count = usize::try_from(input.u64()?)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
    if node_count > limits.max_nodes {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit: "max_nodes" });
    }
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(node_count)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit: "max_nodes" })?;
    for _ in 0..node_count {
        let path_len = usize::try_from(input.u64()?)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        if path_len > limits.max_path_bytes {
            return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
                limit: "max_path_bytes",
            });
        }
        let raw_path = input.bytes(path_len)?;
        let path_text =
            String::from_utf8(raw_path).map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
        validate_path_limits(&path_text, limits)?;
        let path = ResourceRelativePath::try_from_slash_string(path_text)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
        match input.u8()? {
            1 => nodes.push(RecoveryAuthorityNode::File {
                path,
                digest: input.digest()?,
                byte_length: input.u64()?,
            }),
            2 => nodes.push(RecoveryAuthorityNode::Directory { path }),
            _ => return Err(GkrmError::TrustedRecoveryAuthorityInvalid),
        }
    }
    if input.remaining != 0 {
        return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
    }
    let authority_id = input.finish();
    let body = RecoveryAuthorityBodyV1 {
        apply_derivation_version,
        transaction_derivation_version,
        installed_authority_commitment,
        selected_resource_commitment,
        baseline_id,
        staging_manifest_id,
        staging_bundle_id,
        snapshot_a_id,
        apply_plan_id,
        transactional_plan_id,
        nodes,
    };
    validate_body(&body, limits)?;
    if estimated_body_bytes(&body)? != body_len_usize {
        return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
    }
    Ok((body, authority_id))
}

struct StreamingBodyReader<'a, R> {
    reader: &'a mut R,
    remaining: u64,
    hasher: Sha256,
}

impl<'a, R: Read> StreamingBodyReader<'a, R> {
    fn new(reader: &'a mut R, body_len: u64) -> Result<Self> {
        let domain = b"gkrm-recovery-authority-id-v1";
        let mut hasher = Sha256::new();
        hasher.update(
            u64::try_from(domain.len())
                .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
                .to_le_bytes(),
        );
        hasher.update(domain);
        hasher.update(body_len.to_le_bytes());
        Ok(Self {
            reader,
            remaining: body_len,
            hasher,
        })
    }

    fn bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let len_u64 = u64::try_from(len)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        if len_u64 > self.remaining {
            return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| {
            GkrmError::TrustedRecoveryAuthorityLimitExceeded {
                limit: "max_path_bytes",
            }
        })?;
        bytes.resize(len, 0);
        self.reader
            .read_exact(&mut bytes)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
        self.hasher.update(&bytes);
        self.remaining -= len_u64;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.bytes(8)?
                .try_into()
                .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?,
        ))
    }

    fn digest(&mut self) -> Result<Sha256Digest> {
        Ok(Sha256Digest::new(
            self.bytes(32)?
                .try_into()
                .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?,
        ))
    }

    fn finish(self) -> RecoveryAuthorityId {
        RecoveryAuthorityId(Sha256Digest::new(self.hasher.finalize().into()))
    }
}

fn validate_body(body: &RecoveryAuthorityBodyV1, limits: RecoveryAuthorityLimits) -> Result<()> {
    if body.nodes.len() > limits.max_nodes {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit: "max_nodes" });
    }
    let mut collision_keys = Vec::new();
    collision_keys
        .try_reserve_exact(body.nodes.len())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit: "max_nodes" })?;
    let mut file_count = 0usize;
    let mut directory_count = 0usize;
    let mut previous: Option<&[u8]> = None;
    for node in &body.nodes {
        let path = node.path().as_str();
        validate_path_limits(path, limits)?;
        if let Some(prev) = previous {
            if prev >= path.as_bytes() {
                return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
            }
        }
        previous = Some(path.as_bytes());
        let collision_key = bounded_case_collision_key(path, limits.max_path_bytes)?;
        let collision_digest = Sha256Digest::new(Sha256::digest(collision_key.as_bytes()).into());
        collision_keys.push(collision_digest);
        if let Some((parent, _)) = path.rsplit_once('/') {
            if !has_directory_node(&body.nodes, parent) {
                return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
            }
        }
        match node {
            RecoveryAuthorityNode::File { .. } => {
                file_count = file_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
            }
            RecoveryAuthorityNode::Directory { .. } => {
                directory_count = directory_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
            }
        }
    }
    collision_keys.sort_unstable();
    if collision_keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
    }
    if file_count > limits.max_files {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit: "max_files" });
    }
    if directory_count > limits.max_directories {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_directories",
        });
    }
    let snapshot = encode_snapshot_from_nodes(&body.nodes)?;
    if snapshot != body.snapshot_a_id {
        return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
    }
    if estimated_body_bytes(body)? > limits.max_body_bytes {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_body_bytes",
        });
    }
    Ok(())
}

fn bounded_case_collision_key(path: &str, max_bytes: usize) -> Result<String> {
    let mut key = String::new();
    key.try_reserve_exact(max_bytes).map_err(|_| {
        GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_path_bytes",
        }
    })?;
    for character in path
        .nfkc()
        .case_fold_with(Variant::Full, Locale::NonTurkic)
        .nfc()
    {
        let next = key
            .len()
            .checked_add(character.len_utf8())
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        if next > max_bytes {
            return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
                limit: "max_path_bytes",
            });
        }
        key.push(character);
    }
    Ok(key)
}

fn has_directory_node(nodes: &[RecoveryAuthorityNode], wanted: &str) -> bool {
    nodes
        .binary_search_by(|node| node.path().as_str().as_bytes().cmp(wanted.as_bytes()))
        .ok()
        .is_some_and(|index| matches!(nodes[index], RecoveryAuthorityNode::Directory { .. }))
}

fn encode_snapshot_from_nodes(nodes: &[RecoveryAuthorityNode]) -> Result<Sha256Digest> {
    // Stream the Task 21 fingerprint grammar directly. Retaining a second path-sized
    // CanonicalFingerprintEncoder buffer here would violate the authority parser's
    // single-copy memory model.
    let domain = b"gkrm-installed-apply-tree-snapshot-v1";
    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        u64::try_from(nodes.len())
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
            .to_le_bytes(),
    );
    for node in nodes {
        let path = node.path().as_str().as_bytes();
        hasher.update(
            u64::try_from(path.len())
                .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
                .to_le_bytes(),
        );
        hasher.update(path);
        hasher.update([node.tag()]);
        if let RecoveryAuthorityNode::File {
            digest,
            byte_length,
            ..
        } = node
        {
            hasher.update(digest.as_bytes());
            hasher.update(byte_length.to_le_bytes());
        }
    }
    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn validate_path_limits(path: &str, limits: RecoveryAuthorityLimits) -> Result<()> {
    if path.len() > limits.max_path_bytes {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_path_bytes",
        });
    }
    let mut depth = 0usize;
    for component in path.split('/') {
        depth = depth
            .checked_add(1)
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        if component.len() > limits.max_component_bytes {
            return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
                limit: "max_component_bytes",
            });
        }
    }
    if depth > limits.max_depth {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit: "max_depth" });
    }
    Ok(())
}
