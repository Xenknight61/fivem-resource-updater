use std::collections::BTreeMap;

use crate::{GkrmError, Result, ZipEntryInfo, ZipEntryKind, ZipInspection, ZipRelativePath};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipResourceDiscovery {
    pub resources: Vec<DiscoveredZipResource>,
    pub unassigned_entries: Vec<ZipEntryInfo>,
    pub warnings: Vec<ZipResourceWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredZipResource {
    pub name: ZipResourceName,
    pub root: ZipResourceRoot,
    pub manifest_path: ZipRelativePath,
    pub entries: Vec<ZipEntryInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZipResourceRoot {
    Root,
    Path(ZipRelativePath),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipResourceName {
    Directory(String),
    ZipRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipResourceWarning {
    NoFiveMResourcesFound,
    UnassignedPackageEntries { count: usize },
}

struct ResourceBuilder {
    name: ZipResourceName,
    root: ZipResourceRoot,
    manifest_path: ZipRelativePath,
    entries: Vec<ZipEntryInfo>,
}

pub fn discover_zip_resources(inspection: &ZipInspection) -> Result<ZipResourceDiscovery> {
    let resource_roots = collect_resource_roots(inspection)?;
    let mut resource_builders = resource_roots
        .values()
        .map(|resource| ResourceBuilder {
            name: resource_name(&resource.root),
            root: resource.root.clone(),
            manifest_path: resource.manifest_path.clone(),
            entries: Vec::new(),
        })
        .collect::<Vec<_>>();

    resource_builders.sort_by(|left, right| left.root.sort_key().cmp(right.root.sort_key()));

    let mut unassigned_entries = Vec::new();

    for entry in &inspection.entries {
        if let Some(resource_index) = deepest_matching_resource(&resource_builders, entry) {
            resource_builders[resource_index]
                .entries
                .push(entry.clone());
        } else if !is_wrapper_only_directory(entry, &resource_builders) {
            unassigned_entries.push(entry.clone());
        }
    }

    for resource in &mut resource_builders {
        resource
            .entries
            .sort_by(|left, right| left.path.cmp(&right.path));
    }

    unassigned_entries.sort_by(|left, right| left.path.cmp(&right.path));

    let resources = resource_builders
        .into_iter()
        .map(|resource| DiscoveredZipResource {
            name: resource.name,
            root: resource.root,
            manifest_path: resource.manifest_path,
            entries: resource.entries,
        })
        .collect::<Vec<_>>();

    let mut warnings = Vec::new();
    if resources.is_empty() {
        warnings.push(ZipResourceWarning::NoFiveMResourcesFound);
    }
    if !unassigned_entries.is_empty() {
        warnings.push(ZipResourceWarning::UnassignedPackageEntries {
            count: unassigned_entries.len(),
        });
    }

    Ok(ZipResourceDiscovery {
        resources,
        unassigned_entries,
        warnings,
    })
}

fn collect_resource_roots(
    inspection: &ZipInspection,
) -> Result<BTreeMap<String, ResourceManifestLocation>> {
    let mut resource_roots = BTreeMap::<String, ResourceManifestLocation>::new();

    for entry in &inspection.entries {
        if !is_manifest_entry(entry) {
            continue;
        }

        let root = manifest_resource_root(&entry.path)?;
        let root_key = root.sort_key().to_owned();
        let manifest_path = entry.path.clone();

        if let Some(existing) = resource_roots.insert(
            root_key.clone(),
            ResourceManifestLocation {
                root,
                manifest_path: manifest_path.clone(),
            },
        ) {
            return Err(GkrmError::ZipResourceDuplicateManifest {
                root: root_key,
                first: existing.manifest_path.to_string(),
                second: manifest_path.to_string(),
            });
        }
    }

    Ok(resource_roots)
}

#[derive(Debug, Clone)]
struct ResourceManifestLocation {
    root: ZipResourceRoot,
    manifest_path: ZipRelativePath,
}

fn is_manifest_entry(entry: &ZipEntryInfo) -> bool {
    entry.kind == ZipEntryKind::File && final_component(&entry.path) == "fxmanifest.lua"
}

fn manifest_resource_root(path: &ZipRelativePath) -> Result<ZipResourceRoot> {
    match parent_path(path) {
        Some(parent) => Ok(ZipResourceRoot::Path(parent?)),
        None => Ok(ZipResourceRoot::Root),
    }
}

fn parent_path(path: &ZipRelativePath) -> Option<Result<ZipRelativePath>> {
    let parent = path.as_str().rsplit_once('/').map(|(parent, _)| parent)?;
    Some(ZipRelativePath::new(0, parent.as_bytes()))
}

fn final_component(path: &ZipRelativePath) -> &str {
    path.as_str()
        .rsplit_once('/')
        .map_or(path.as_str(), |(_, name)| name)
}

fn resource_name(root: &ZipResourceRoot) -> ZipResourceName {
    match root {
        ZipResourceRoot::Root => ZipResourceName::ZipRoot,
        ZipResourceRoot::Path(path) => ZipResourceName::Directory(final_component(path).to_owned()),
    }
}

fn deepest_matching_resource(resources: &[ResourceBuilder], entry: &ZipEntryInfo) -> Option<usize> {
    resources
        .iter()
        .enumerate()
        .filter(|(_, resource)| resource.root.contains(&entry.path))
        .max_by_key(|(_, resource)| resource.root.depth())
        .map(|(index, _)| index)
}

fn is_wrapper_only_directory(entry: &ZipEntryInfo, resources: &[ResourceBuilder]) -> bool {
    entry.kind == ZipEntryKind::Directory
        && resources.iter().any(|resource| match &resource.root {
            ZipResourceRoot::Root => false,
            ZipResourceRoot::Path(root) => is_ancestor_path(&entry.path, root),
        })
}

fn is_ancestor_path(ancestor: &ZipRelativePath, descendant: &ZipRelativePath) -> bool {
    let ancestor = ancestor.as_str();
    let descendant = descendant.as_str();

    descendant.len() > ancestor.len()
        && descendant.starts_with(ancestor)
        && descendant.as_bytes().get(ancestor.len()) == Some(&b'/')
}

impl ZipResourceRoot {
    fn sort_key(&self) -> &str {
        match self {
            ZipResourceRoot::Root => "/",
            ZipResourceRoot::Path(path) => path.as_str(),
        }
    }

    fn depth(&self) -> usize {
        match self {
            ZipResourceRoot::Root => 0,
            ZipResourceRoot::Path(path) => path.as_str().split('/').count(),
        }
    }

    fn contains(&self, path: &ZipRelativePath) -> bool {
        match self {
            ZipResourceRoot::Root => true,
            ZipResourceRoot::Path(root) => {
                path == root
                    || path
                        .as_str()
                        .strip_prefix(root.as_str())
                        .is_some_and(|suffix| suffix.as_bytes().first() == Some(&b'/'))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use zip::CompressionMethod;

    fn file(path: &str) -> ZipEntryInfo {
        entry(path, ZipEntryKind::File)
    }

    fn dir(path: &str) -> ZipEntryInfo {
        entry(path, ZipEntryKind::Directory)
    }

    fn entry(path: &str, kind: ZipEntryKind) -> ZipEntryInfo {
        ZipEntryInfo {
            archive_index: 0,
            path: ZipRelativePath::new(0, path.as_bytes()).expect("test path should be valid"),
            compressed_size: 0,
            uncompressed_size: 0,
            crc32: 0,
            compression_method: CompressionMethod::Stored,
            encrypted: false,
            unix_mode: None,
            kind,
        }
    }

    fn inspection(entries: Vec<ZipEntryInfo>) -> ZipInspection {
        ZipInspection {
            path: PathBuf::from("package.zip"),
            entries,
        }
    }

    fn paths(entries: &[ZipEntryInfo]) -> Vec<&str> {
        entries.iter().map(|entry| entry.path.as_str()).collect()
    }

    fn root(path: &str) -> ZipResourceRoot {
        ZipResourceRoot::Path(
            ZipRelativePath::new(0, path.as_bytes()).expect("root should be valid"),
        )
    }

    fn resource_by_root<'a>(
        discovery: &'a ZipResourceDiscovery,
        root: &ZipResourceRoot,
    ) -> &'a DiscoveredZipResource {
        discovery
            .resources
            .iter()
            .find(|resource| &resource.root == root)
            .expect("resource root should exist")
    }

    fn assert_entries_assigned_at_most_once(discovery: &ZipResourceDiscovery) {
        let mut assigned = Vec::new();
        for resource in &discovery.resources {
            for entry in &resource.entries {
                assert!(
                    !assigned.contains(&entry.path.as_str()),
                    "{} should be assigned at most once",
                    entry.path
                );
                assigned.push(entry.path.as_str());
            }
        }
    }

    #[test]
    fn discovers_root_resource() {
        let discovery = discover_zip_resources(&inspection(vec![
            file("client/main.lua"),
            file("fxmanifest.lua"),
        ]))
        .expect("resource discovery should succeed");

        assert_eq!(discovery.resources.len(), 1);
        assert_eq!(discovery.resources[0].name, ZipResourceName::ZipRoot);
        assert_eq!(discovery.resources[0].root, ZipResourceRoot::Root);
        assert_eq!(
            paths(&discovery.resources[0].entries),
            vec!["client/main.lua", "fxmanifest.lua"]
        );
        assert!(discovery.unassigned_entries.is_empty());
        assert!(discovery.warnings.is_empty());
    }

    #[test]
    fn discovers_wrapper_resource() {
        let discovery = discover_zip_resources(&inspection(vec![
            dir("bundle"),
            dir("bundle/gksphone"),
            file("bundle/gksphone/client/main.lua"),
            file("bundle/gksphone/fxmanifest.lua"),
        ]))
        .expect("resource discovery should succeed");

        assert_eq!(discovery.resources.len(), 1);
        assert_eq!(
            discovery.resources[0].name,
            ZipResourceName::Directory("gksphone".to_owned())
        );
        assert_eq!(
            discovery.resources[0].root,
            ZipResourceRoot::Path(
                ZipRelativePath::new(0, b"bundle/gksphone").expect("root should be valid")
            )
        );
        assert_eq!(
            paths(&discovery.resources[0].entries),
            vec![
                "bundle/gksphone",
                "bundle/gksphone/client/main.lua",
                "bundle/gksphone/fxmanifest.lua"
            ]
        );
        assert!(discovery.unassigned_entries.is_empty());
        assert!(discovery.warnings.is_empty());
    }

    #[test]
    fn sorts_multiple_sibling_resources() {
        let discovery = discover_zip_resources(&inspection(vec![
            file("b/fxmanifest.lua"),
            file("a/fxmanifest.lua"),
        ]))
        .expect("resource discovery should succeed");

        assert_eq!(
            discovery
                .resources
                .iter()
                .map(|resource| resource.root.sort_key())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn assigns_nested_entries_to_deepest_resource() {
        let discovery = discover_zip_resources(&inspection(vec![
            file("bundle/phone/fxmanifest.lua"),
            file("bundle/phone/plugins/example/fxmanifest.lua"),
            file("bundle/phone/plugins/example/client.lua"),
        ]))
        .expect("resource discovery should succeed");

        assert_eq!(discovery.resources.len(), 2);
        let parent = resource_by_root(&discovery, &root("bundle/phone"));
        let nested = resource_by_root(&discovery, &root("bundle/phone/plugins/example"));

        assert_eq!(
            paths(parent.entries.as_slice()),
            vec!["bundle/phone/fxmanifest.lua"]
        );
        assert_eq!(
            paths(nested.entries.as_slice()),
            vec![
                "bundle/phone/plugins/example/client.lua",
                "bundle/phone/plugins/example/fxmanifest.lua"
            ]
        );
        assert!(
            !paths(parent.entries.as_slice()).contains(&"bundle/phone/plugins/example/client.lua")
        );
        assert_entries_assigned_at_most_once(&discovery);
    }

    #[test]
    fn sibling_prefix_collision_does_not_assign_outside_file_to_resource() {
        let discovery = discover_zip_resources(&inspection(vec![
            file("bundle/phone/fxmanifest.lua"),
            file("bundle/phone/client.lua"),
            file("bundle/phone-extra/file.lua"),
        ]))
        .expect("resource discovery should succeed");

        let phone = resource_by_root(&discovery, &root("bundle/phone"));
        assert_eq!(
            paths(phone.entries.as_slice()),
            vec!["bundle/phone/client.lua", "bundle/phone/fxmanifest.lua"]
        );
        assert!(!paths(phone.entries.as_slice()).contains(&"bundle/phone-extra/file.lua"));
        assert_eq!(
            paths(&discovery.unassigned_entries),
            vec!["bundle/phone-extra/file.lua"]
        );
    }

    #[test]
    fn directory_named_fxmanifest_lua_is_not_manifest_but_remains_unassigned() {
        let discovery = discover_zip_resources(&inspection(vec![dir("fxmanifest.lua")]))
            .expect("resource discovery should succeed");

        assert!(discovery.resources.is_empty());
        assert_eq!(paths(&discovery.unassigned_entries), vec!["fxmanifest.lua"]);
        assert_eq!(
            discovery.warnings,
            vec![
                ZipResourceWarning::NoFiveMResourcesFound,
                ZipResourceWarning::UnassignedPackageEntries { count: 1 }
            ]
        );
    }

    #[test]
    fn wrapper_only_directories_do_not_warn_as_unassigned() {
        let discovery = discover_zip_resources(&inspection(vec![
            dir("bundle"),
            dir("bundle/gksphone"),
            file("bundle/gksphone/fxmanifest.lua"),
            file("bundle/gksphone/client/main.lua"),
        ]))
        .expect("resource discovery should succeed");

        assert!(discovery.unassigned_entries.is_empty());
        assert!(discovery.warnings.is_empty());
    }

    #[test]
    fn files_outside_roots_are_unassigned_and_warn() {
        let discovery = discover_zip_resources(&inspection(vec![
            file("README.md"),
            file("bundle/gksphone/fxmanifest.lua"),
        ]))
        .expect("resource discovery should succeed");

        assert_eq!(paths(&discovery.unassigned_entries), vec!["README.md"]);
        assert_eq!(
            discovery.warnings,
            vec![ZipResourceWarning::UnassignedPackageEntries { count: 1 }]
        );
    }

    #[test]
    fn no_resources_warns_and_returns_unassigned_files() {
        let discovery = discover_zip_resources(&inspection(vec![file("README.md")]))
            .expect("resource discovery should succeed");

        assert!(discovery.resources.is_empty());
        assert_eq!(paths(&discovery.unassigned_entries), vec!["README.md"]);
        assert_eq!(
            discovery.warnings,
            vec![
                ZipResourceWarning::NoFiveMResourcesFound,
                ZipResourceWarning::UnassignedPackageEntries { count: 1 }
            ]
        );
    }

    #[test]
    fn duplicate_manifest_for_same_root_is_hard_error() {
        let err = discover_zip_resources(&inspection(vec![
            file("resource/fxmanifest.lua"),
            file("resource/fxmanifest.lua"),
        ]))
        .expect_err("duplicate manifest should fail");

        assert!(matches!(
            err,
            GkrmError::ZipResourceDuplicateManifest { .. }
        ));
    }
}
