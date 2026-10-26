//! Canonical, bounded two-way execution description. Decoding reproduces the exact plan
//! commitment; it does not grant filesystem mutation authority.

use super::*;
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwoWayExecutionDescriptor {
    version: u8,
    resource: String,
    selected_root: String,
    installed: String,
    package: String,
    incoming: String,
    plan_id: String,
    entries: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    causal_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    baseline_transition: Option<ManagedBaselineTransition>,
}

/// Backend-only metadata bound by the published artifact identity. Absence on an
/// older artifact means unknown, never permission to infer a previous baseline.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedBaselineTransition {
    before: Option<String>,
    after: String,
}

impl ManagedBaselineTransition {
    pub(crate) fn new(before: Option<&crate::BaselineId>, after: &crate::BaselineId) -> Self {
        Self {
            before: before.map(ToString::to_string),
            after: after.to_string(),
        }
    }
    pub(crate) fn before(&self) -> Result<Option<crate::BaselineId>> {
        self.before
            .as_deref()
            .map(crate::BaselineId::parse)
            .transpose()
    }
    pub(crate) fn after(&self) -> Result<crate::BaselineId> {
        crate::BaselineId::parse(&self.after)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    action: u8,
    editable: bool,
    installed: Option<String>,
    incoming: Option<String>,
    baseline: Option<String>,
}

impl TwoWayExecutionDescriptor {
    pub fn from_plan(plan: &TwoWayUpdatePlan, root: &crate::InstalledResourceRoot) -> Result<Self> {
        let value = Self {
            version: 1,
            resource: plan.resource_key().as_str().to_owned(),
            selected_root: match root {
                crate::InstalledResourceRoot::Root => ".".into(),
                crate::InstalledResourceRoot::Path(path) => path.as_str().to_owned(),
            },
            installed: plan.installed_fingerprint().to_string(),
            package: plan.incoming_package_fingerprint().to_string(),
            incoming: plan.incoming_resource_fingerprint().to_string(),
            plan_id: plan.plan_id().digest().to_string(),
            causal_context: plan.causal_context().map(ToString::to_string),
            baseline_transition: None,
            entries: plan
                .entries()
                .iter()
                .map(|entry| Entry {
                    path: entry.path().as_str().to_owned(),
                    action: action_code(entry.action()) as u8,
                    editable: entry.editable(),
                    installed: entry.installed_digest().map(ToString::to_string),
                    incoming: entry.incoming_digest().map(ToString::to_string),
                    baseline: entry.baseline_digest().map(ToString::to_string),
                })
                .collect(),
        };
        value.reconstruct()?;
        Ok(value)
    }

    pub fn selected_root(&self) -> Result<crate::InstalledResourceRoot> {
        if self.selected_root == "." {
            return Ok(crate::InstalledResourceRoot::Root);
        }
        let relative =
            ResourceRelativePath::try_from_slash_str(&self.selected_root).map_err(|_| invalid())?;
        let path =
            crate::InstallationRelativePath::from_path(std::path::Path::new(relative.as_str()))
                .map_err(|_| invalid())?;
        Ok(crate::InstalledResourceRoot::Path(path))
    }

    pub(crate) fn with_baseline_transition(
        mut self,
        transition: ManagedBaselineTransition,
    ) -> Self {
        self.baseline_transition = Some(transition);
        self
    }

    pub(crate) fn baseline_transition(&self) -> Option<&ManagedBaselineTransition> {
        self.baseline_transition.as_ref()
    }

    pub fn reconstruct(&self) -> Result<TwoWayUpdatePlan> {
        if self.version != 1 {
            return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
        }
        self.selected_root()?;
        if let Some(transition) = &self.baseline_transition {
            transition.before()?;
            transition.after()?;
        }
        if self.entries.is_empty() || self.entries.len() > MAX_ENTRIES {
            return Err(invalid());
        }
        let key = SafeResourceKey::parse(&self.resource).map_err(|_| invalid())?;
        let mut entries = Vec::with_capacity(self.entries.len());
        let mut summary = TwoWayPlanSummary {
            unchanged: 0,
            take_from_update: 0,
            review: 0,
            keep_local_only: 0,
        };
        for item in &self.entries {
            let path =
                ResourceRelativePath::try_from_slash_str(&item.path).map_err(|_| invalid())?;
            if entries
                .last()
                .is_some_and(|previous: &TwoWayPlanEntry| previous.path() >= &path)
            {
                return Err(invalid());
            }
            let installed = optional_digest(&item.installed)?;
            let incoming = optional_digest(&item.incoming)?;
            let action = match item.action {
                1 if installed.is_some() && installed == incoming => {
                    summary.unchanged += 1;
                    TwoWayFileAction::Unchanged
                }
                2 if incoming.is_some() && installed != incoming => {
                    summary.take_from_update += 1;
                    TwoWayFileAction::TakeFromUpdate
                }
                3 if item.editable
                    && installed.is_some()
                    && incoming.is_some()
                    && installed != incoming =>
                {
                    summary.review += 1;
                    TwoWayFileAction::Review
                }
                4 if installed.is_some() && incoming.is_none() => {
                    summary.keep_local_only += 1;
                    TwoWayFileAction::KeepLocalOnly
                }
                _ => return Err(invalid()),
            };
            entries.push(TwoWayPlanEntry {
                path,
                action,
                editable: item.editable,
                installed_digest: installed,
                incoming_digest: incoming,
                baseline_digest: optional_digest(&item.baseline)?,
            });
        }
        let installed = digest(&self.installed)?;
        let package = digest(&self.package)?;
        let incoming = digest(&self.incoming)?;
        let plan_id = encode_two_way_plan_id(&key, &installed, &package, &incoming, &entries)?;
        let plan = TwoWayUpdatePlan {
            resource_key: key,
            installed_fingerprint: installed,
            incoming_package_fingerprint: package,
            incoming_resource_fingerprint: incoming,
            entries,
            summary,
            plan_id,
            causal_context: None,
        }
        .with_causal_context(optional_digest(&self.causal_context)?)?;
        if plan.plan_id().digest() != &digest(&self.plan_id)? {
            return Err(invalid());
        }
        Ok(plan)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.reconstruct()?;
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if value.encode()? != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
}

fn invalid() -> GkrmError {
    GkrmError::TrustedCliUpdateArtifactInvalid
}
fn digest(value: &str) -> Result<Sha256Digest> {
    Sha256Digest::from_lowercase_hex(value).map_err(|_| invalid())
}
fn optional_digest(value: &Option<String>) -> Result<Option<Sha256Digest>> {
    value.as_deref().map(digest).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> TwoWayExecutionDescriptor {
        TwoWayExecutionDescriptor::from_plan(
            &super::super::tests::fixture_plan(),
            &crate::InstalledResourceRoot::Root,
        )
        .expect("descriptor")
    }
    #[test]
    fn baseline_transition_is_optional_canonical_and_requires_exact_identifiers() {
        let legacy = fixture();
        assert!(!String::from_utf8(legacy.encode().unwrap())
            .unwrap()
            .contains("baseline_transition"));
        let before = crate::BaselineId::parse(&"ab".repeat(32)).unwrap();
        let after = crate::BaselineId::parse(&"cd".repeat(32)).unwrap();
        let mut value = legacy
            .clone()
            .with_baseline_transition(ManagedBaselineTransition::new(Some(&before), &after));
        let bytes = value.encode().unwrap();
        let decoded = TwoWayExecutionDescriptor::decode(&bytes).unwrap();
        assert_eq!(
            decoded.reconstruct().unwrap(),
            legacy.reconstruct().unwrap()
        );
        assert_eq!(
            decoded.baseline_transition().unwrap().before().unwrap(),
            Some(before)
        );
        assert_eq!(
            decoded.baseline_transition().unwrap().after().unwrap(),
            after
        );
        value.baseline_transition.as_mut().unwrap().before = Some("../other".into());
        assert!(value.encode().is_err());
        value.baseline_transition.as_mut().unwrap().before = None;
        value.baseline_transition.as_mut().unwrap().after = "AB".repeat(32);
        assert!(value.encode().is_err());
    }
    #[test]
    fn canonical_roundtrip_reconstructs_exact_plan_and_selection() {
        let value = fixture();
        let bytes = value.encode().expect("encode");
        let decoded = TwoWayExecutionDescriptor::decode(&bytes).expect("decode");
        assert_eq!(
            decoded.reconstruct().expect("plan"),
            super::super::tests::fixture_plan()
        );
        assert_eq!(
            decoded.selected_root().expect("root"),
            crate::InstalledResourceRoot::Root
        );
        assert_eq!(decoded.encode().expect("canonical"), bytes);
    }

    #[test]
    fn causal_context_changes_identity_and_roundtrips_without_changing_legacy_none_encoding() {
        let original = super::super::tests::fixture_plan();
        let legacy =
            TwoWayExecutionDescriptor::from_plan(&original, &crate::InstalledResourceRoot::Root)
                .unwrap();
        assert!(!std::str::from_utf8(&legacy.encode().unwrap())
            .unwrap()
            .contains("causal_context"));
        let rebound = original.clone().with_causal_context(None).unwrap();
        assert_eq!(rebound, original);
        let causal = original
            .clone()
            .with_causal_context(Some(Sha256Digest::new([37; 32])))
            .unwrap();
        assert_ne!(causal.plan_id(), original.plan_id());
        assert_eq!(causal.entries(), original.entries());
        let mut descriptor =
            TwoWayExecutionDescriptor::from_plan(&causal, &crate::InstalledResourceRoot::Root)
                .unwrap();
        assert_eq!(
            TwoWayExecutionDescriptor::decode(&descriptor.encode().unwrap())
                .unwrap()
                .reconstruct()
                .unwrap(),
            causal
        );
        descriptor.causal_context = Some("ab".repeat(32));
        assert!(descriptor.reconstruct().is_err());
    }
    #[test]
    fn inconsistent_plan_fields_order_and_versions_are_refused() {
        for case in 0..7 {
            let mut value = fixture();
            match case {
                0 => value.version = 2,
                1 => value.entries[0].action = 255,
                2 => value.entries[0].path = "../outside".into(),
                3 => value.entries.swap(0, 1),
                4 => value.plan_id = "00".repeat(32),
                5 => value.selected_root = "C:/outside".into(),
                _ => value.entries.push(value.entries[0].clone()),
            }
            assert!(value.encode().is_err(), "case {case}");
        }
    }
    #[test]
    fn rejects_noncanonical_unknown_duplicate_truncated_and_oversized_input() {
        let bytes = fixture().encode().expect("encode");
        let mut trailing = bytes.clone();
        trailing.push(b' ');
        assert!(TwoWayExecutionDescriptor::decode(&trailing).is_err());
        for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(TwoWayExecutionDescriptor::decode(&bytes[..end]).is_err());
        }
        let text = String::from_utf8(bytes).expect("utf8");
        for prefix in ["{\"unknown\":0,", "{\"version\":1,"] {
            let injected = format!("{prefix}{}", &text[1..]);
            assert!(TwoWayExecutionDescriptor::decode(injected.as_bytes()).is_err());
        }
        assert!(TwoWayExecutionDescriptor::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
}
