//! Closed canonical Undo provenance. A descriptor is data, never write authority.

use crate::{
    GkrmError, InstalledResourceRoot, ResourceRelativePath, Result, SafeResourceKey, Sha256Digest,
};
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIRECTORIES: usize = 20_000;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedUndoExecutionDescriptor {
    version: u8,
    parent: String,
    parent_artifact: String,
    parent_authority: String,
    resource: String,
    selected_root: String,
    plan: String,
    current_tree: String,
    current_files: String,
    directories: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_attempt: Option<String>,
}

impl std::fmt::Debug for TrustedUndoExecutionDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedUndoExecutionDescriptor")
    }
}

impl TrustedUndoExecutionDescriptor {
    pub(super) fn from_staged(staged: &super::TrustedUndoStagingBundle) -> Result<Self> {
        let value = Self {
            version: 1,
            previous_attempt: staged.previous_attempt().map(ToString::to_string),
            parent: staged.parent_transaction_id().to_string(),
            parent_artifact: staged.original_artifact_id().to_string(),
            parent_authority: staged.original_authority_id().to_string(),
            resource: staged.resource_key().as_str().to_owned(),
            selected_root: match staged.selected_root() {
                InstalledResourceRoot::Root => ".".into(),
                InstalledResourceRoot::Path(path) => path.as_str().to_owned(),
            },
            plan: staged.bundle().manifest().plan_id_digest().to_string(),
            current_tree: staged.current_tree_fingerprint().to_string(),
            current_files: staged.installed_fingerprint().to_string(),
            directories: staged
                .directories()
                .iter()
                .map(|path| path.as_str().to_owned())
                .collect(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn previous_attempt(&self) -> Result<Option<Sha256Digest>> {
        self.previous_attempt.as_deref().map(digest).transpose()
    }
    pub fn parent_transaction_id(&self) -> Result<Sha256Digest> {
        digest(&self.parent)
    }
    pub fn parent_artifact_id(&self) -> Result<Sha256Digest> {
        digest(&self.parent_artifact)
    }
    pub fn parent_authority_id(&self) -> Result<Sha256Digest> {
        digest(&self.parent_authority)
    }
    pub fn plan_id(&self) -> Result<Sha256Digest> {
        digest(&self.plan)
    }
    pub fn current_tree_fingerprint(&self) -> Result<Sha256Digest> {
        digest(&self.current_tree)
    }
    pub fn current_files_fingerprint(&self) -> Result<Sha256Digest> {
        digest(&self.current_files)
    }
    pub fn resource_key(&self) -> Result<SafeResourceKey> {
        SafeResourceKey::parse(&self.resource).map_err(|_| invalid())
    }
    pub fn selected_root(&self) -> Result<InstalledResourceRoot> {
        if self.selected_root == "." {
            return Ok(InstalledResourceRoot::Root);
        }
        let path = bounded_path(&self.selected_root)?;
        Ok(InstalledResourceRoot::Path(
            crate::InstallationRelativePath::from_path(std::path::Path::new(path.as_str()))
                .map_err(|_| invalid())?,
        ))
    }
    pub fn directories(&self) -> Result<std::collections::BTreeSet<ResourceRelativePath>> {
        if self.directories.len() > MAX_DIRECTORIES {
            return Err(invalid());
        }
        let mut directories = std::collections::BTreeSet::new();
        let mut previous: Option<&str> = None;
        for path in &self.directories {
            if previous.is_some_and(|before| before >= path.as_str()) {
                return Err(invalid());
            }
            let relative = bounded_path(path)?;
            for parent in crate::trusted_apply_planning::parents_of(&relative) {
                if !directories.contains(&parent) {
                    return Err(invalid());
                }
            }
            directories.insert(relative);
            previous = Some(path);
        }
        Ok(directories)
    }
    pub fn review_id(&self) -> Result<Sha256Digest> {
        let mut encoder = crate::three_way_fingerprint::CanonicalFingerprintEncoder::new(
            "gkrm-undo-staging-review-v1",
        )?;
        encoder.digest(&self.plan_id()?);
        let directories = self.directories()?;
        encoder.usize(directories.len())?;
        for path in directories {
            encoder.path(&path)?;
        }
        Ok(encoder.finish())
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
        }
        if self
            .previous_attempt()?
            .is_some_and(|previous| self.parent_transaction_id().ok() == Some(previous))
        {
            return Err(invalid());
        }
        self.parent_transaction_id()?;
        self.parent_artifact_id()?;
        self.parent_authority_id()?;
        self.plan_id()?;
        self.current_tree_fingerprint()?;
        self.current_files_fingerprint()?;
        self.resource_key()?;
        self.selected_root()?;
        self.directories()?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if value.encode()? != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
}

fn digest(value: &str) -> Result<Sha256Digest> {
    Sha256Digest::from_lowercase_hex(value).map_err(|_| invalid())
}
fn bounded_path(value: &str) -> Result<ResourceRelativePath> {
    let path = ResourceRelativePath::try_from_slash_str(value).map_err(|_| invalid())?;
    if path.as_str().split('/').count() > 64
        || path
            .as_str()
            .split('/')
            .any(|component| component.len() > 255)
    {
        return Err(invalid());
    }
    Ok(path)
}
fn invalid() -> GkrmError {
    GkrmError::TrustedCliUpdateArtifactInvalid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> TrustedUndoExecutionDescriptor {
        TrustedUndoExecutionDescriptor {
            version: 1,
            previous_attempt: None,
            parent: "01".repeat(32),
            parent_artifact: "02".repeat(32),
            parent_authority: "03".repeat(32),
            resource: "gksphone".into(),
            selected_root: ".".into(),
            plan: "04".repeat(32),
            current_tree: "05".repeat(32),
            current_files: "06".repeat(32),
            directories: vec!["empty".into(), "empty/nested".into()],
        }
    }

    #[test]
    fn undo_descriptor_canonical_roundtrip_preserves_provenance_and_directories() {
        let original = fixture();
        let bytes = original.encode().unwrap();
        let decoded = TrustedUndoExecutionDescriptor::decode(&bytes).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(
            decoded.selected_root().unwrap(),
            InstalledResourceRoot::Root
        );
        let mut changed = original.clone();
        changed.directories.push("other-empty".into());
        assert_ne!(changed.review_id().unwrap(), original.review_id().unwrap());
    }

    #[test]
    fn retry_context_is_optional_canonical_and_cannot_name_the_forward_parent() {
        let mut value = fixture();
        let original = value.encode().unwrap();
        assert!(!std::str::from_utf8(&original)
            .unwrap()
            .contains("previous_attempt"));
        assert_eq!(
            TrustedUndoExecutionDescriptor::decode(&original)
                .unwrap()
                .previous_attempt()
                .unwrap(),
            None
        );
        value.previous_attempt = Some("ab".repeat(32));
        let bytes = value.encode().unwrap();
        assert_eq!(
            TrustedUndoExecutionDescriptor::decode(&bytes).unwrap(),
            value
        );
        value.previous_attempt = Some(value.parent.clone());
        assert!(value.encode().is_err());
        value.previous_attempt = Some("not-a-digest".into());
        assert!(value.encode().is_err());
    }

    #[test]
    fn undo_descriptor_rejects_bad_versions_digests_paths_order_and_missing_parents() {
        for case in 0..9 {
            let mut value = fixture();
            match case {
                0 => value.version = 2,
                1 => value.parent = "AA".repeat(32),
                2 => value.selected_root = "C:/outside".into(),
                3 => value.directories.push("../outside".into()),
                4 => value.directories.reverse(),
                5 => value.directories.push("empty/nested".into()),
                6 => value.directories = vec!["missing/child".into()],
                7 => value.resource = "../outside".into(),
                _ => {
                    value.directories = (0..=MAX_DIRECTORIES)
                        .map(|i| format!("dir{i:06}"))
                        .collect()
                }
            }
            assert!(value.encode().is_err(), "case {case}");
        }
    }

    #[test]
    fn undo_descriptor_refuses_noncanonical_truncated_unknown_duplicate_and_oversized_bytes() {
        let bytes = fixture().encode().unwrap();
        let mut trailing = bytes.clone();
        trailing.push(b' ');
        assert!(TrustedUndoExecutionDescriptor::decode(&trailing).is_err());
        for length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(TrustedUndoExecutionDescriptor::decode(&bytes[..length]).is_err());
        }
        let text = std::str::from_utf8(&bytes).unwrap();
        for prefix in ["{\"unknown\":0,", "{\"version\":1,"] {
            let injected = format!("{prefix}{}", &text[1..]);
            assert!(TrustedUndoExecutionDescriptor::decode(injected.as_bytes()).is_err());
        }
        assert!(TrustedUndoExecutionDescriptor::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
}
