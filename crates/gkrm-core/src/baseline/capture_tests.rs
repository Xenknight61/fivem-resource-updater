//! Unit tests for official baseline capture selection helpers.

use crate::baseline::capture::{
    select_resource_for_tests, BaselineCaptureWarning, IncomingResourceSelector,
};
use crate::baseline::SafeResourceKey;
use crate::resource_discovery::{
    DiscoveredZipResource, ZipResourceDiscovery, ZipResourceName, ZipResourceRoot,
};
use crate::zip_package::{ZipEntryInfo, ZipEntryKind};
use crate::zip_path::ZipRelativePath;
use crate::GkrmError;
use zip::CompressionMethod;

fn entry(path: &str, index: usize) -> ZipEntryInfo {
    ZipEntryInfo {
        archive_index: index,
        path: ZipRelativePath::parse_canonical(path).expect("path"),
        compressed_size: 1,
        uncompressed_size: 1,
        crc32: 0,
        compression_method: CompressionMethod::Stored,
        encrypted: false,
        unix_mode: None,
        kind: ZipEntryKind::File,
    }
}

fn discovery(resources: Vec<DiscoveredZipResource>) -> ZipResourceDiscovery {
    ZipResourceDiscovery {
        resources,
        unassigned_entries: Vec::new(),
        warnings: Vec::new(),
    }
}

#[test]
fn auto_single_selects_one_resource() {
    let resource = DiscoveredZipResource {
        name: ZipResourceName::Directory("gksphone".into()),
        root: ZipResourceRoot::Path(ZipRelativePath::parse_canonical("gksphone").unwrap()),
        manifest_path: ZipRelativePath::parse_canonical("gksphone/fxmanifest.lua").unwrap(),
        entries: vec![entry("gksphone/fxmanifest.lua", 0)],
    };
    let discovery = discovery(vec![resource]);
    let key = SafeResourceKey::parse("gksphone").unwrap();
    let (selected, warnings) =
        select_resource_for_tests(&discovery, &IncomingResourceSelector::AutoSingle, &key)
            .expect("select");
    assert_eq!(selected.manifest_path.as_str(), "gksphone/fxmanifest.lua");
    assert!(warnings.is_empty());
}

#[test]
fn auto_single_ambiguous_lists_labels() {
    let discovery = discovery(vec![
        DiscoveredZipResource {
            name: ZipResourceName::Directory("a".into()),
            root: ZipResourceRoot::Path(ZipRelativePath::parse_canonical("a").unwrap()),
            manifest_path: ZipRelativePath::parse_canonical("a/fxmanifest.lua").unwrap(),
            entries: vec![entry("a/fxmanifest.lua", 0)],
        },
        DiscoveredZipResource {
            name: ZipResourceName::Directory("b".into()),
            root: ZipResourceRoot::Path(ZipRelativePath::parse_canonical("b").unwrap()),
            manifest_path: ZipRelativePath::parse_canonical("b/fxmanifest.lua").unwrap(),
            entries: vec![entry("b/fxmanifest.lua", 1)],
        },
    ]);
    let key = SafeResourceKey::parse("x").unwrap();
    let err = select_resource_for_tests(&discovery, &IncomingResourceSelector::AutoSingle, &key)
        .expect_err("ambiguous");
    match err {
        GkrmError::BaselineCaptureAmbiguousResources => {}
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn explicit_root_manifest_selection_warns() {
    let resource = DiscoveredZipResource {
        name: ZipResourceName::ZipRoot,
        root: ZipResourceRoot::Root,
        manifest_path: ZipRelativePath::parse_canonical("fxmanifest.lua").unwrap(),
        entries: vec![entry("fxmanifest.lua", 0)],
    };
    let discovery = discovery(vec![resource]);
    let key = SafeResourceKey::parse("rootres").unwrap();
    let selector = IncomingResourceSelector::ManifestPackagePath(
        ZipRelativePath::parse_canonical("fxmanifest.lua").unwrap(),
    );
    let (selected, warnings) =
        select_resource_for_tests(&discovery, &selector, &key).expect("select");
    assert_eq!(selected.manifest_path.as_str(), "fxmanifest.lua");
    assert_eq!(warnings, vec![BaselineCaptureWarning::RootResourceSelected]);
}
