use std::collections::BTreeMap;

use globset::{GlobBuilder, GlobMatcher};

use crate::{
    GkrmError, ManifestString, Result, ZipEntryInfo, ZipEntryKind, ZipInspection,
    ZipManifestParseReport, ZipRelativePath, ZipResourceDiscovery, ZipResourceRoot,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowFileClassification {
    Protected,
    Ignored {
        matching_patterns: Vec<String>,
    },
    NotSupported {
        matching_ignore_patterns: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedResourceFile {
    pub package_path: ZipRelativePath,
    pub resource_relative_path: String,
    pub classification: EscrowFileClassification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedZipResource {
    pub resource_root: ZipResourceRoot,
    pub files: Vec<ClassifiedResourceFile>,
    pub warnings: Vec<EscrowClassificationWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowClassificationReport {
    pub resources: Vec<ClassifiedZipResource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowClassificationWarning {
    IgnorePatternMatchedNoFiles { pattern: String },
    IgnorePatternMatchedOnlyUnsupportedFiles { pattern: String },
}

struct IgnorePattern {
    original: String,
    matcher: GlobMatcher,
    matched_supported_files: usize,
    matched_unsupported_files: usize,
}

pub fn classify_zip_resource_escrow(
    inspection: &ZipInspection,
    discovery: &ZipResourceDiscovery,
    manifests: &ZipManifestParseReport,
) -> Result<EscrowClassificationReport> {
    let manifest_by_root = manifests_by_root(discovery, manifests)?;
    let inspection_by_path = inspection
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    let mut resources = Vec::with_capacity(discovery.resources.len());
    for resource in &discovery.resources {
        let root_key = root_key(&resource.root);
        let parsed_manifest =
            manifest_by_root
                .get(root_key)
                .ok_or_else(|| GkrmError::EscrowManifestMissing {
                    root: root_key.to_owned(),
                })?;
        resources.push(classify_one_resource(
            resource,
            parsed_manifest,
            &inspection_by_path,
        )?);
    }

    Ok(EscrowClassificationReport { resources })
}

/// Classify only the selected discovered resource using its parsed manifest.
pub(crate) fn classify_selected_zip_resource_escrow(
    inspection: &ZipInspection,
    resource: &crate::DiscoveredZipResource,
    parsed_manifest: &crate::ParsedZipResourceManifest,
) -> Result<ClassifiedZipResource> {
    if parsed_manifest.resource_root != resource.root
        || parsed_manifest.manifest_path != resource.manifest_path
    {
        return Err(GkrmError::EscrowManifestPathMismatch {
            root: root_key(&resource.root).to_owned(),
            expected: resource.manifest_path.to_string(),
            actual: parsed_manifest.manifest_path.to_string(),
        });
    }
    let inspection_by_path = inspection
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    classify_one_resource(resource, parsed_manifest, &inspection_by_path)
}

fn classify_one_resource(
    resource: &crate::DiscoveredZipResource,
    parsed_manifest: &crate::ParsedZipResourceManifest,
    inspection_by_path: &BTreeMap<&str, &ZipEntryInfo>,
) -> Result<ClassifiedZipResource> {
    let root_key = root_key(&resource.root);
    let mut patterns = compile_ignore_patterns(&parsed_manifest.manifest.escrow_ignore)?;
    let mut files = Vec::new();

    for discovered_entry in &resource.entries {
        let entry = verified_inspection_entry(inspection_by_path, root_key, discovered_entry)?;

        if entry.kind != ZipEntryKind::File {
            continue;
        }

        let resource_relative_path = resource_relative_path(&resource.root, entry)?;
        let mut matching_patterns = Vec::new();
        let supported = is_asset_escrow_supported(&resource_relative_path);

        for pattern in &mut patterns {
            if pattern.matcher.is_match(resource_relative_path.as_str()) {
                matching_patterns.push(pattern.original.clone());
                if supported {
                    pattern.matched_supported_files += 1;
                } else {
                    pattern.matched_unsupported_files += 1;
                }
            }
        }

        let classification = if !supported {
            EscrowFileClassification::NotSupported {
                matching_ignore_patterns: matching_patterns,
            }
        } else if matching_patterns.is_empty() {
            EscrowFileClassification::Protected
        } else {
            EscrowFileClassification::Ignored { matching_patterns }
        };

        files.push(ClassifiedResourceFile {
            package_path: entry.path.clone(),
            resource_relative_path,
            classification,
        });
    }

    let warnings = pattern_warnings(&patterns);
    Ok(ClassifiedZipResource {
        resource_root: resource.root.clone(),
        files,
        warnings,
    })
}

fn manifests_by_root<'a>(
    discovery: &ZipResourceDiscovery,
    manifests: &'a ZipManifestParseReport,
) -> Result<BTreeMap<String, &'a crate::ParsedZipResourceManifest>> {
    let discovered_by_root = discovery
        .resources
        .iter()
        .map(|resource| (root_key(&resource.root), resource))
        .collect::<BTreeMap<_, _>>();
    let mut manifest_by_root = BTreeMap::new();

    for manifest in &manifests.resources {
        let root = root_key(&manifest.resource_root);
        let Some(discovered_resource) = discovered_by_root.get(root) else {
            return Err(GkrmError::EscrowManifestRootMismatch {
                root: root.to_owned(),
            });
        };

        if manifest.manifest_path != discovered_resource.manifest_path {
            return Err(GkrmError::EscrowManifestPathMismatch {
                root: root.to_owned(),
                expected: discovered_resource.manifest_path.to_string(),
                actual: manifest.manifest_path.to_string(),
            });
        }

        if manifest_by_root.insert(root.to_owned(), manifest).is_some() {
            return Err(GkrmError::EscrowManifestDuplicate {
                root: root.to_owned(),
            });
        }
    }

    Ok(manifest_by_root)
}

fn verified_inspection_entry<'a>(
    inspection_by_path: &BTreeMap<&str, &'a ZipEntryInfo>,
    root: &str,
    discovered: &ZipEntryInfo,
) -> Result<&'a ZipEntryInfo> {
    let Some(inspected) = inspection_by_path.get(discovered.path.as_str()).copied() else {
        return Err(GkrmError::EscrowDiscoveryEntryMismatch {
            entry: discovered.path.to_string(),
            reason: format!("entry is not present in inspection for resource root {root:?}"),
        });
    };

    if inspected.path != discovered.path
        || inspected.kind != discovered.kind
        || inspected.archive_index != discovered.archive_index
        || inspected.compressed_size != discovered.compressed_size
        || inspected.uncompressed_size != discovered.uncompressed_size
        || inspected.crc32 != discovered.crc32
        || inspected.compression_method != discovered.compression_method
        || inspected.encrypted != discovered.encrypted
        || inspected.unix_mode != discovered.unix_mode
    {
        return Err(GkrmError::EscrowDiscoveryEntryMismatch {
            entry: discovered.path.to_string(),
            reason: "path, kind, archive index, size, CRC32, compression, encryption, or Unix mode metadata does not match inspection".to_owned(),
        });
    }

    Ok(inspected)
}

fn compile_ignore_patterns(patterns: &[ManifestString]) -> Result<Vec<IgnorePattern>> {
    patterns
        .iter()
        .map(|pattern| {
            let normalized = normalize_and_validate_pattern(&pattern.value)?;
            let matcher = GlobBuilder::new(&normalized)
                .literal_separator(true)
                .case_insensitive(false)
                .backslash_escape(false)
                .build()
                .map_err(|source| GkrmError::EscrowGlobMalformed {
                    pattern: pattern.value.clone(),
                    cause: source,
                })?
                .compile_matcher();

            Ok(IgnorePattern {
                original: pattern.value.clone(),
                matcher,
                matched_supported_files: 0,
                matched_unsupported_files: 0,
            })
        })
        .collect()
}

fn normalize_and_validate_pattern(pattern: &str) -> Result<String> {
    if pattern.is_empty() {
        return unsafe_pattern(pattern, "pattern is empty");
    }

    if pattern
        .chars()
        .any(|character| character == '\0' || matches!(character, '\u{1}'..='\u{1f}' | '\u{7f}'))
    {
        return unsafe_pattern(pattern, "pattern contains NUL or ASCII control characters");
    }

    if starts_with_windows_drive(pattern) {
        return unsafe_pattern(pattern, "pattern has a Windows drive prefix");
    }

    if pattern.starts_with("\\\\") || pattern.starts_with("//") {
        return unsafe_pattern(pattern, "pattern is a UNC path");
    }

    if pattern.starts_with('\\') {
        return unsafe_pattern(pattern, "pattern begins with a Windows root separator");
    }

    if pattern.starts_with('/') {
        return unsafe_pattern(pattern, "pattern is Unix absolute");
    }

    let normalized = pattern.replace('\\', "/");

    if normalized.ends_with('/') {
        return Err(GkrmError::EscrowGlobTrailingSlash {
            pattern: pattern.to_owned(),
        });
    }

    for component in normalized.split('/') {
        match component {
            "" => return unsafe_pattern(pattern, "pattern contains an empty component"),
            "." => {
                return unsafe_pattern(pattern, "pattern contains a current-directory component")
            }
            ".." => return unsafe_pattern(pattern, "pattern contains parent traversal"),
            _ => {}
        }
    }

    Ok(normalized)
}

fn pattern_warnings(patterns: &[IgnorePattern]) -> Vec<EscrowClassificationWarning> {
    patterns
        .iter()
        .filter_map(|pattern| {
            let supported = pattern.matched_supported_files;
            let unsupported = pattern.matched_unsupported_files;
            if supported == 0 && unsupported == 0 {
                Some(EscrowClassificationWarning::IgnorePatternMatchedNoFiles {
                    pattern: pattern.original.clone(),
                })
            } else if supported == 0 {
                Some(
                    EscrowClassificationWarning::IgnorePatternMatchedOnlyUnsupportedFiles {
                        pattern: pattern.original.clone(),
                    },
                )
            } else {
                None
            }
        })
        .collect()
}

fn resource_relative_path(root: &ZipResourceRoot, entry: &ZipEntryInfo) -> Result<String> {
    match root {
        ZipResourceRoot::Root => Ok(entry.path.as_str().to_owned()),
        ZipResourceRoot::Path(root_path) => entry
            .path
            .as_str()
            .strip_prefix(root_path.as_str())
            .and_then(|suffix| suffix.strip_prefix('/'))
            .filter(|suffix| !suffix.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| GkrmError::EscrowResourceRelativePath {
                root: root_key(root).to_owned(),
                entry: entry.path.to_string(),
            }),
    }
}

fn is_asset_escrow_supported(path: &str) -> bool {
    let Some(file_name) = path.rsplit('/').next() else {
        return false;
    };
    let Some((_, extension)) = file_name.rsplit_once('.') else {
        return false;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "lua" | "yft" | "ydd" | "ydr"
    )
}

fn root_key(root: &ZipResourceRoot) -> &str {
    match root {
        ZipResourceRoot::Root => "/",
        ZipResourceRoot::Path(path) => path.as_str(),
    }
}

fn starts_with_windows_drive(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn unsafe_pattern<T>(pattern: &str, reason: &str) -> Result<T> {
    Err(GkrmError::EscrowGlobUnsafe {
        pattern: pattern.to_owned(),
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use zip::CompressionMethod;

    use super::*;
    use crate::{
        DiscoveredZipResource, FxManifest, ManifestDeclarationKind, ParsedZipResourceManifest,
        ZipResourceDiscovery, ZipResourceName,
    };

    fn path(path: &str) -> ZipRelativePath {
        ZipRelativePath::new(0, path.as_bytes()).expect("path should be valid")
    }

    fn root(path: &str) -> ZipResourceRoot {
        ZipResourceRoot::Path(self::path(path))
    }

    fn entry(path: &str, kind: ZipEntryKind) -> ZipEntryInfo {
        ZipEntryInfo {
            archive_index: 0,
            path: self::path(path),
            compressed_size: 0,
            uncompressed_size: 0,
            crc32: 0,
            compression_method: CompressionMethod::Stored,
            encrypted: false,
            unix_mode: None,
            kind,
        }
    }

    fn file(path: &str) -> ZipEntryInfo {
        entry(path, ZipEntryKind::File)
    }

    fn dir(path: &str) -> ZipEntryInfo {
        entry(path, ZipEntryKind::Directory)
    }

    fn inspection(entries: Vec<ZipEntryInfo>) -> ZipInspection {
        ZipInspection {
            path: PathBuf::from("package.zip"),
            entries,
        }
    }

    fn resource(root: ZipResourceRoot, entries: Vec<ZipEntryInfo>) -> DiscoveredZipResource {
        let manifest_path = match &root {
            ZipResourceRoot::Root => path("fxmanifest.lua"),
            ZipResourceRoot::Path(root_path) => {
                path(&format!("{}/fxmanifest.lua", root_path.as_str()))
            }
        };

        DiscoveredZipResource {
            name: ZipResourceName::Directory("resource".to_owned()),
            root,
            manifest_path,
            entries,
        }
    }

    fn discovery(resources: Vec<DiscoveredZipResource>) -> ZipResourceDiscovery {
        ZipResourceDiscovery {
            resources,
            unassigned_entries: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn manifest(root: ZipResourceRoot, patterns: &[&str]) -> ParsedZipResourceManifest {
        let manifest_path = match &root {
            ZipResourceRoot::Root => path("fxmanifest.lua"),
            ZipResourceRoot::Path(root_path) => {
                path(&format!("{}/fxmanifest.lua", root_path.as_str()))
            }
        };

        manifest_with_path(root, manifest_path, patterns)
    }

    fn manifest_with_path(
        root: ZipResourceRoot,
        manifest_path: ZipRelativePath,
        patterns: &[&str],
    ) -> ParsedZipResourceManifest {
        ParsedZipResourceManifest {
            resource_root: root,
            manifest_path,
            manifest: FxManifest {
                escrow_ignore: patterns
                    .iter()
                    .enumerate()
                    .map(|(order, value)| ManifestString {
                        value: (*value).to_owned(),
                        declaration: ManifestDeclarationKind::EscrowIgnore,
                        order,
                    })
                    .collect(),
                ..FxManifest::default()
            },
            warnings: Vec::new(),
        }
    }

    fn report(resources: Vec<ParsedZipResourceManifest>) -> ZipManifestParseReport {
        ZipManifestParseReport { resources }
    }

    fn classify(
        resource_root: ZipResourceRoot,
        entries: Vec<ZipEntryInfo>,
        patterns: &[&str],
    ) -> Result<ClassifiedZipResource> {
        let inspection = inspection(entries.clone());
        let discovery = discovery(vec![resource(resource_root.clone(), entries)]);
        let manifests = report(vec![manifest(resource_root, patterns)]);

        classify_zip_resource_escrow(&inspection, &discovery, &manifests).map(|report| {
            report
                .resources
                .into_iter()
                .next()
                .expect("resource should exist")
        })
    }

    fn classifications(resource: &ClassifiedZipResource) -> Vec<(&str, &EscrowFileClassification)> {
        resource
            .files
            .iter()
            .map(|file| (file.resource_relative_path.as_str(), &file.classification))
            .collect()
    }

    #[test]
    fn classifies_supported_extensions_as_protected() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![
                file("client.lua"),
                file("stream/car.yft"),
                file("stream/car.ydd"),
                file("stream/car.ydr"),
            ],
            &[],
        )
        .expect("classification should succeed");

        assert!(classifications(&resource)
            .iter()
            .all(|(_, classification)| {
                matches!(classification, EscrowFileClassification::Protected)
            }));
    }

    #[test]
    fn classifies_uppercase_supported_extensions_as_protected() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("CLIENT.LUA"), file("stream/CAR.YFT")],
            &[],
        )
        .expect("classification should succeed");

        assert!(classifications(&resource)
            .iter()
            .all(|(_, classification)| {
                matches!(classification, EscrowFileClassification::Protected)
            }));
    }

    #[test]
    fn exact_ignore_match_classifies_supported_file_as_ignored() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("config.lua"), file("client/main.lua")],
            &["config.lua"],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource.files[0].classification,
            EscrowFileClassification::Ignored {
                matching_patterns: vec!["config.lua".to_owned()]
            }
        );
        assert_eq!(
            resource.files[1].classification,
            EscrowFileClassification::Protected
        );
    }

    #[test]
    fn supports_star_double_star_and_question_globs() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![
                file("client/file1.lua"),
                file("config/a.lua"),
                file("config/nested/b.lua"),
            ],
            &["config/*.lua", "config/**/*.lua", "client/file?.lua"],
        )
        .expect("classification should succeed");

        assert_eq!(
            classifications(&resource),
            vec![
                (
                    "client/file1.lua",
                    &EscrowFileClassification::Ignored {
                        matching_patterns: vec!["client/file?.lua".to_owned()]
                    }
                ),
                (
                    "config/a.lua",
                    &EscrowFileClassification::Ignored {
                        matching_patterns: vec![
                            "config/*.lua".to_owned(),
                            "config/**/*.lua".to_owned()
                        ]
                    }
                ),
                (
                    "config/nested/b.lua",
                    &EscrowFileClassification::Ignored {
                        matching_patterns: vec!["config/**/*.lua".to_owned()]
                    }
                )
            ]
        );
    }

    #[test]
    fn glob_matching_is_case_sensitive() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("Config.lua")],
            &["config.lua"],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource.files[0].classification,
            EscrowFileClassification::Protected
        );
        assert_eq!(
            resource.warnings,
            vec![EscrowClassificationWarning::IgnorePatternMatchedNoFiles {
                pattern: "config.lua".to_owned()
            }]
        );
    }

    #[test]
    fn question_glob_does_not_cross_path_separator() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("client/file/x.lua")],
            &["client/file?.lua"],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource.files[0].classification,
            EscrowFileClassification::Protected
        );
        assert_eq!(
            resource.warnings,
            vec![EscrowClassificationWarning::IgnorePatternMatchedNoFiles {
                pattern: "client/file?.lua".to_owned()
            }]
        );
    }

    #[test]
    fn normalizes_backslashes_in_ignore_patterns() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("config/file.lua")],
            &["config\\*.lua"],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource.files[0].classification,
            EscrowFileClassification::Ignored {
                matching_patterns: vec!["config\\*.lua".to_owned()]
            }
        );
    }

    #[test]
    fn multiple_matching_patterns_preserve_manifest_order() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("client/main.lua")],
            &["client/*.lua", "client/main.lua"],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource.files[0].classification,
            EscrowFileClassification::Ignored {
                matching_patterns: vec!["client/*.lua".to_owned(), "client/main.lua".to_owned()]
            }
        );
    }

    #[test]
    fn unsupported_files_remain_not_supported_even_when_matched() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("html/index.html")],
            &["html/*"],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource.files[0].classification,
            EscrowFileClassification::NotSupported {
                matching_ignore_patterns: vec!["html/*".to_owned()]
            }
        );
        assert_eq!(
            resource.warnings,
            vec![
                EscrowClassificationWarning::IgnorePatternMatchedOnlyUnsupportedFiles {
                    pattern: "html/*".to_owned()
                }
            ]
        );
    }

    #[test]
    fn unused_patterns_warn_deterministically() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![file("client/main.lua")],
            &["missing/*.lua", "html/*"],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource.warnings,
            vec![
                EscrowClassificationWarning::IgnorePatternMatchedNoFiles {
                    pattern: "missing/*.lua".to_owned()
                },
                EscrowClassificationWarning::IgnorePatternMatchedNoFiles {
                    pattern: "html/*".to_owned()
                }
            ]
        );
    }

    #[test]
    fn directory_entries_are_excluded() {
        let resource = classify(
            ZipResourceRoot::Root,
            vec![dir("config"), file("config/main.lua")],
            &["config"],
        )
        .expect("classification should succeed");

        assert_eq!(resource.files.len(), 1);
        assert_eq!(resource.files[0].resource_relative_path, "config/main.lua");
    }

    #[test]
    fn nested_resources_use_only_their_own_patterns() {
        let parent_entries = vec![
            file("bundle/phone/fxmanifest.lua"),
            file("bundle/phone/config.lua"),
        ];
        let nested_entries = vec![
            file("bundle/phone/plugins/example/fxmanifest.lua"),
            file("bundle/phone/plugins/example/config.lua"),
        ];
        let all_entries = parent_entries
            .iter()
            .chain(nested_entries.iter())
            .cloned()
            .collect::<Vec<_>>();
        let discovery = discovery(vec![
            resource(root("bundle/phone"), parent_entries),
            resource(root("bundle/phone/plugins/example"), nested_entries),
        ]);
        let manifests = report(vec![
            manifest(
                root("bundle/phone"),
                &["plugins/example/*.lua", "config.lua"],
            ),
            manifest(root("bundle/phone/plugins/example"), &[]),
        ]);

        let report = classify_zip_resource_escrow(&inspection(all_entries), &discovery, &manifests)
            .expect("classification should succeed");

        assert_eq!(
            report.resources[0].files[1].classification,
            EscrowFileClassification::Ignored {
                matching_patterns: vec!["config.lua".to_owned()]
            }
        );
        assert_eq!(
            report.resources[1].files[1].classification,
            EscrowFileClassification::Protected
        );
    }

    #[test]
    fn sibling_prefix_paths_are_not_classified_into_resource() {
        let phone_entries = vec![
            file("bundle/phone/client.lua"),
            file("bundle/phone/fxmanifest.lua"),
        ];
        let inspection_entries = vec![
            file("bundle/phone/client.lua"),
            file("bundle/phone/fxmanifest.lua"),
            file("bundle/phone-extra/file.lua"),
        ];
        let discovery = discovery(vec![resource(root("bundle/phone"), phone_entries)]);
        let manifests = report(vec![manifest(root("bundle/phone"), &[])]);

        let report =
            classify_zip_resource_escrow(&inspection(inspection_entries), &discovery, &manifests)
                .expect("classification should succeed");

        assert_eq!(
            report.resources[0]
                .files
                .iter()
                .map(|file| file.package_path.as_str())
                .collect::<Vec<_>>(),
            vec!["bundle/phone/client.lua", "bundle/phone/fxmanifest.lua"]
        );
    }

    #[test]
    fn sibling_prefix_entry_inside_resource_is_rejected() {
        let entries = vec![
            file("bundle/phone/fxmanifest.lua"),
            file("bundle/phone-extra/client.lua"),
        ];
        let discovery = discovery(vec![resource(root("bundle/phone"), entries.clone())]);
        let manifests = report(vec![manifest(root("bundle/phone"), &[])]);

        let err = classify_zip_resource_escrow(&inspection(entries), &discovery, &manifests)
            .expect_err("sibling prefix entry should be rejected");

        assert!(matches!(err, GkrmError::EscrowResourceRelativePath { .. }));
    }

    #[test]
    fn wrapper_directories_are_skipped() {
        let resource = classify(
            root("bundle/phone"),
            vec![
                dir("bundle/phone"),
                file("bundle/phone/fxmanifest.lua"),
                file("bundle/phone/client.lua"),
            ],
            &[],
        )
        .expect("classification should succeed");

        assert_eq!(
            resource
                .files
                .iter()
                .map(|file| file.resource_relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["fxmanifest.lua", "client.lua"]
        );
    }

    #[test]
    fn unsafe_globs_are_hard_errors() {
        for pattern in [
            "",
            "/config.lua",
            "C:/config.lua",
            "\\\\server\\share\\config.lua",
            "\\config.lua",
            "../config.lua",
            "config/../file.lua",
            "config//file.lua",
            "config\n/file.lua",
        ] {
            let err = classify(ZipResourceRoot::Root, vec![file("config.lua")], &[pattern])
                .expect_err("unsafe glob should fail");

            assert!(
                matches!(err, GkrmError::EscrowGlobUnsafe { .. }),
                "{pattern:?} returned {err:?}"
            );
        }
    }

    #[test]
    fn trailing_slash_glob_is_hard_error() {
        let err = classify(
            ZipResourceRoot::Root,
            vec![file("config.lua")],
            &["config/"],
        )
        .expect_err("trailing slash glob should fail");

        assert!(matches!(err, GkrmError::EscrowGlobTrailingSlash { .. }));
    }

    #[test]
    fn malformed_glob_is_hard_error() {
        let err = classify(ZipResourceRoot::Root, vec![file("config.lua")], &["["])
            .expect_err("malformed glob should fail");

        assert!(matches!(err, GkrmError::EscrowGlobMalformed { .. }));
    }

    #[test]
    fn missing_parsed_manifest_is_hard_error() {
        let entries = vec![file("fxmanifest.lua")];
        let inspection = inspection(entries.clone());
        let discovery = discovery(vec![resource(ZipResourceRoot::Root, entries)]);
        let manifests = report(Vec::new());

        let err = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
            .expect_err("missing manifest should fail");

        assert!(matches!(err, GkrmError::EscrowManifestMissing { .. }));
    }

    #[test]
    fn duplicate_parsed_manifest_is_hard_error() {
        let entries = vec![file("fxmanifest.lua")];
        let inspection = inspection(entries.clone());
        let discovery = discovery(vec![resource(ZipResourceRoot::Root, entries)]);
        let manifests = report(vec![
            manifest(ZipResourceRoot::Root, &[]),
            manifest(ZipResourceRoot::Root, &[]),
        ]);

        let err = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
            .expect_err("duplicate manifest should fail");

        assert!(matches!(err, GkrmError::EscrowManifestDuplicate { .. }));
    }

    #[test]
    fn parsed_manifest_for_unknown_root_is_hard_error() {
        let entries = vec![file("fxmanifest.lua")];
        let inspection = inspection(entries.clone());
        let discovery = discovery(vec![resource(ZipResourceRoot::Root, entries)]);
        let manifests = report(vec![manifest(root("other"), &[])]);

        let err = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
            .expect_err("unknown manifest root should fail");

        assert!(matches!(err, GkrmError::EscrowManifestRootMismatch { .. }));
    }

    #[test]
    fn parsed_manifest_path_mismatch_is_hard_error() {
        let entries = vec![file("bundle/phone/fxmanifest.lua")];
        let inspection = inspection(entries.clone());
        let discovery = discovery(vec![resource(root("bundle/phone"), entries)]);
        let manifests = report(vec![manifest_with_path(
            root("bundle/phone"),
            path("bundle/phone/other.lua"),
            &[],
        )]);

        let err = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
            .expect_err("manifest path mismatch should fail");

        assert!(matches!(err, GkrmError::EscrowManifestPathMismatch { .. }));
    }

    #[test]
    fn discovery_entry_metadata_mismatch_is_hard_error() {
        let inspection_entries = vec![file("fxmanifest.lua"), file("client.lua")];
        let mut discovered_client = file("client.lua");
        discovered_client.archive_index = 1;
        let discovery_entries = vec![file("fxmanifest.lua"), discovered_client];
        let inspection = inspection(inspection_entries);
        let discovery = discovery(vec![resource(ZipResourceRoot::Root, discovery_entries)]);
        let manifests = report(vec![manifest(ZipResourceRoot::Root, &[])]);

        let err = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
            .expect_err("metadata mismatch should fail");

        assert!(matches!(
            err,
            GkrmError::EscrowDiscoveryEntryMismatch { .. }
        ));
    }

    #[test]
    fn resources_and_files_keep_deterministic_input_order() {
        let first_entries = vec![file("a/fxmanifest.lua"), file("a/client.lua")];
        let second_entries = vec![file("b/fxmanifest.lua"), file("b/client.lua")];
        let all_entries = first_entries
            .iter()
            .chain(second_entries.iter())
            .cloned()
            .collect::<Vec<_>>();
        let discovery = discovery(vec![
            resource(root("a"), first_entries),
            resource(root("b"), second_entries),
        ]);
        let manifests = report(vec![manifest(root("a"), &[]), manifest(root("b"), &[])]);

        let report = classify_zip_resource_escrow(&inspection(all_entries), &discovery, &manifests)
            .expect("classification should succeed");

        assert_eq!(
            report
                .resources
                .iter()
                .map(|resource| root_key(&resource.resource_root))
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(
            report.resources[0]
                .files
                .iter()
                .map(|file| file.resource_relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["fxmanifest.lua", "client.lua"]
        );
    }
}
