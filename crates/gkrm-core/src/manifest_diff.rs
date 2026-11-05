//! What changed between two manifests, as things an operator should know before updating.
//!
//! Both manifests are only ever parsed, never executed. This module compares what the parse
//! produced; it reads no file and writes nothing.

use std::collections::BTreeSet;

use crate::manifest::{parse_resource_manifest_source, FxManifest, ManifestLimits, ManifestString};
use crate::three_way_merged_bytes::ThreeWayMergedBytesOptions;
use crate::{
    BaselineFreeUpdatePlan, FullInspectionReport, InstalledMergeContentSource,
    InstalledResourceRoot, InstalledScanLimits, ResourceRelativePath, Sha256Digest,
    ZipResourceRoot,
};

/// A manifest list that gained or lost entries between the installed and the incoming resource.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListChange {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl ListChange {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// A scalar manifest declaration whose value differs. `None` means "not declared".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueChange {
    pub installed: Option<String>,
    pub incoming: Option<String>,
}

/// Everything about a manifest that an update would change and an operator should be told about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestChanges {
    pub fx_version: Option<ValueChange>,
    pub version: Option<ValueChange>,
    pub dependencies: ListChange,
    pub client_scripts: ListChange,
    pub server_scripts: ListChange,
    pub shared_scripts: ListChange,
    pub files: ListChange,
    pub ui_pages: ListChange,
    pub escrow_ignore: ListChange,
}

impl ManifestChanges {
    pub fn is_empty(&self) -> bool {
        self.fx_version.is_none()
            && self.version.is_none()
            && self.dependencies.is_empty()
            && self.client_scripts.is_empty()
            && self.server_scripts.is_empty()
            && self.shared_scripts.is_empty()
            && self.files.is_empty()
            && self.ui_pages.is_empty()
            && self.escrow_ignore.is_empty()
    }
}

/// Compare an installed manifest with the incoming one.
///
/// Lists are compared as sets: a reordering is not a change an operator needs to act on, and
/// the result is sorted so it is deterministic.
pub fn compare_manifests(installed: &FxManifest, incoming: &FxManifest) -> ManifestChanges {
    ManifestChanges {
        fx_version: scalar_change(&installed.fx_versions, &incoming.fx_versions),
        version: scalar_change(&installed.versions, &incoming.versions),
        dependencies: list_change(&installed.dependencies, &incoming.dependencies),
        client_scripts: list_change(&installed.client_scripts, &incoming.client_scripts),
        server_scripts: list_change(&installed.server_scripts, &incoming.server_scripts),
        shared_scripts: list_change(&installed.shared_scripts, &incoming.shared_scripts),
        files: list_change(&installed.files, &incoming.files),
        ui_pages: list_change(&installed.ui_pages, &incoming.ui_pages),
        escrow_ignore: list_change(&installed.escrow_ignore, &incoming.escrow_ignore),
    }
}

/// The installed manifest at `path`, read through the verified, no-follow installed reader and
/// parsed — never executed. `None` when it cannot be read or does not parse: a comparison built
/// from half the evidence would read as a clean one.
pub(crate) fn read_parsed_installed_manifest(
    installed: &InstalledMergeContentSource,
    path: &ResourceRelativePath,
    digest: Sha256Digest,
) -> Option<FxManifest> {
    let max_retain = ThreeWayMergedBytesOptions::default().max_source_bytes_per_file();
    let bytes = installed
        .read_verified_merge_text(path, digest, max_retain, |_| Ok(()))
        .ok()?
        .into_parts()
        .1?;
    let source = String::from_utf8(bytes).ok()?;
    parse_resource_manifest_source("fxmanifest.lua", source, ManifestLimits::default())
        .ok()
        .map(|(manifest, _)| manifest)
}

/// What one planned resource's manifest would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceManifestChanges {
    pub installed_resource: InstalledResourceRoot,
    pub incoming_resource: ZipResourceRoot,
    /// `None` when either manifest could not be read; see [`read_parsed_installed_manifest`].
    pub changes: Option<ManifestChanges>,
}

/// The manifest changes for every resource a baseline-free plan covers.
///
/// Read-only: the installed manifest is read through the same verified reader the update itself
/// uses, and checked against the digest the plan was made from, so what is compared is what was
/// planned. Nothing is written.
pub fn plan_manifest_changes(
    report: &FullInspectionReport,
    plan: &BaselineFreeUpdatePlan,
) -> Vec<ResourceManifestChanges> {
    plan.resources()
        .iter()
        .map(|resource| {
            let matched = resource.resource_match();
            ResourceManifestChanges {
                installed_resource: matched.installed_resource.clone(),
                incoming_resource: matched.incoming_resource.clone(),
                changes: manifest_changes_for(report, resource, matched),
            }
        })
        .collect()
}

fn manifest_changes_for(
    report: &FullInspectionReport,
    resource: &crate::ResourceUpdatePlan,
    matched: &crate::ResourceMatch,
) -> Option<ManifestChanges> {
    let file = resource
        .files()
        .iter()
        .find(|file| file.relative_path().as_str() == "fxmanifest.lua")?;
    let digest = *file.expected_installed()?.sha256();
    let incoming = report
        .manifests()
        .resources
        .iter()
        .find(|parsed| parsed.resource_root == matched.incoming_resource)?;
    let source = InstalledMergeContentSource::try_new(
        &report.installed().root,
        matched.installed_resource.clone(),
        InstalledScanLimits::default(),
    )
    .ok()?;
    let installed = read_parsed_installed_manifest(&source, file.relative_path(), digest)?;
    Some(compare_manifests(&installed, &incoming.manifest))
}

fn values(items: &[ManifestString]) -> BTreeSet<&str> {
    items.iter().map(|item| item.value.as_str()).collect()
}

fn list_change(installed: &[ManifestString], incoming: &[ManifestString]) -> ListChange {
    let (before, after) = (values(installed), values(incoming));
    ListChange {
        added: after.difference(&before).map(|v| (*v).to_owned()).collect(),
        removed: before.difference(&after).map(|v| (*v).to_owned()).collect(),
    }
}

/// A scalar is compared only when each side declares it at most once; several declarations
/// cannot be summarised honestly, so they report nothing, as `declared_manifest_version` does.
fn scalar_change(installed: &[ManifestString], incoming: &[ManifestString]) -> Option<ValueChange> {
    let one = |items: &[ManifestString]| match items {
        [] => Some(None),
        [only] => Some(Some(only.value.clone())),
        _ => None,
    };
    let (before, after) = (one(installed)?, one(incoming)?);
    (before != after).then_some(ValueChange {
        installed: before,
        incoming: after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{parse_resource_manifest_source, ManifestLimits};

    fn parse(source: &str) -> FxManifest {
        parse_resource_manifest_source(
            "fxmanifest.lua",
            source.to_owned(),
            ManifestLimits::default(),
        )
        .expect("manifest parses")
        .0
    }

    #[test]
    fn identical_manifests_report_nothing() {
        let m = parse("fx_version 'cerulean'\nserver_script 'server.lua'\n");
        assert!(compare_manifests(&m, &m).is_empty());
    }

    #[test]
    fn reports_added_and_removed_entries_sorted() {
        let old = parse("server_scripts { 'a.lua', 'b.lua' }\ndependency 'oxmysql'\n");
        let new = parse(
            "server_scripts { 'b.lua', 'd.lua', 'c.lua' }\ndependencies { 'oxmysql', 'ox_lib' }\n",
        );
        let changes = compare_manifests(&old, &new);
        assert_eq!(changes.server_scripts.added, ["c.lua", "d.lua"]);
        assert_eq!(changes.server_scripts.removed, ["a.lua"]);
        assert_eq!(changes.dependencies.added, ["ox_lib"]);
        assert!(changes.dependencies.removed.is_empty());
    }

    #[test]
    fn reordering_is_not_a_change() {
        let old = parse("client_scripts { 'a.lua', 'b.lua' }\n");
        let new = parse("client_scripts { 'b.lua', 'a.lua' }\n");
        assert!(compare_manifests(&old, &new).is_empty());
    }

    #[test]
    fn reports_scalar_changes_including_newly_declared() {
        let old = parse("fx_version 'adamant'\n");
        let new = parse("fx_version 'cerulean'\nversion '2.0.0'\n");
        let changes = compare_manifests(&old, &new);
        assert_eq!(
            changes.fx_version,
            Some(ValueChange {
                installed: Some("adamant".into()),
                incoming: Some("cerulean".into())
            })
        );
        assert_eq!(
            changes.version,
            Some(ValueChange {
                installed: None,
                incoming: Some("2.0.0".into())
            })
        );
    }

    #[test]
    fn repeated_scalar_declarations_report_nothing() {
        let old = parse("version '1'\n");
        let new = parse("version '2'\nversion '3'\n");
        assert!(compare_manifests(&old, &new).version.is_none());
    }
}
