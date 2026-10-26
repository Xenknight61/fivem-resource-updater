use std::fs;
use std::path::{Path, PathBuf};

use gkrm_core::{
    scan_installed_resources, GkrmError, InstallationRelativePath, InstalledResourceRoot,
    InstalledScanLimits,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn limits() -> InstalledScanLimits {
    InstalledScanLimits {
        max_resources: 20,
        max_files_per_resource: 50,
        max_total_files: 200,
        max_total_entries: 250,
        max_directories: 100,
        max_file_size: 1024 * 1024,
        max_total_size: 4 * 1024 * 1024,
        max_directory_depth: 16,
    }
}

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("test path should have parent"))
        .expect("parent directory should be created");
    fs::write(path, contents).expect("file should be written");
}

fn rel(path: &str) -> InstallationRelativePath {
    InstallationRelativePath::from_path(Path::new(path)).expect("test path should be valid")
}

fn file_paths(resource: &gkrm_core::InstalledResourceScan) -> Vec<&str> {
    resource
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect()
}

fn resource_sort_keys(scan: &gkrm_core::InstalledInstallationScan) -> Vec<String> {
    scan.resources
        .iter()
        .map(|resource| match &resource.root {
            InstalledResourceRoot::Root => ".".to_owned(),
            InstalledResourceRoot::Path(path) => path.to_string(),
        })
        .collect()
}

#[test]
fn scans_direct_root_resource() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("gksphone");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("client/main.lua"), b"client");

    let scan = scan_installed_resources(&root, limits()).expect("resource should scan");

    assert_eq!(scan.resources.len(), 1);
    assert_eq!(scan.resources[0].root, InstalledResourceRoot::Root);
    assert_eq!(
        scan.resources[0].manifest_relative_path.as_str(),
        "fxmanifest.lua"
    );
    assert_eq!(
        file_paths(&scan.resources[0]),
        vec!["client/main.lua", "fxmanifest.lua"]
    );
    assert!(scan.warnings.is_empty());
}

#[test]
fn scans_multiple_sibling_resources() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("[gks]");
    write_file(&root.join("gksphone/fxmanifest.lua"), b"phone");
    write_file(&root.join("gksphone/client.lua"), b"phone client");
    write_file(&root.join("gks-tablet/fxmanifest.lua"), b"tablet");

    let scan = scan_installed_resources(&root, limits()).expect("resources should scan");

    assert_eq!(
        resource_sort_keys(&scan),
        vec!["gks-tablet".to_owned(), "gksphone".to_owned()]
    );
    assert_eq!(scan.resources[0].name, "gks-tablet");
    assert_eq!(scan.resources[1].name, "gksphone");
}

#[test]
fn scans_wrapper_directory_resource() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("package");
    write_file(&root.join("bundle/gksphone/fxmanifest.lua"), b"manifest");
    write_file(&root.join("bundle/gksphone/server/main.lua"), b"server");

    let scan = scan_installed_resources(&root, limits()).expect("wrapper should scan");

    assert_eq!(
        scan.resources[0].root,
        InstalledResourceRoot::Path(rel("bundle/gksphone"))
    );
    assert_eq!(
        scan.resources[0].manifest_relative_path.as_str(),
        "bundle/gksphone/fxmanifest.lua"
    );
    assert_eq!(
        file_paths(&scan.resources[0]),
        vec!["fxmanifest.lua", "server/main.lua"]
    );
}

#[test]
fn root_resource_and_nested_resource_are_separate() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("gksphone");
    write_file(&root.join("fxmanifest.lua"), b"root manifest");
    write_file(&root.join("client.lua"), b"root client");
    write_file(
        &root.join("plugins/example/fxmanifest.lua"),
        b"nested manifest",
    );
    write_file(&root.join("plugins/example/client.lua"), b"nested client");

    let scan = scan_installed_resources(&root, limits()).expect("resources should scan");

    assert_eq!(
        resource_sort_keys(&scan),
        vec![".".to_owned(), "plugins/example".to_owned()]
    );
    assert_eq!(
        file_paths(&scan.resources[0]),
        vec!["client.lua", "fxmanifest.lua"]
    );
    assert_eq!(
        file_paths(&scan.resources[1]),
        vec!["client.lua", "fxmanifest.lua"]
    );
}

#[test]
fn deepest_nested_resource_owns_nested_files() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resources");
    write_file(&root.join("phone/fxmanifest.lua"), b"phone");
    write_file(&root.join("phone/client.lua"), b"phone client");
    write_file(
        &root.join("phone/plugins/example/fxmanifest.lua"),
        b"example",
    );
    write_file(
        &root.join("phone/plugins/example/client.lua"),
        b"example client",
    );
    write_file(
        &root.join("phone/plugins/example/addon/fxmanifest.lua"),
        b"addon",
    );
    write_file(
        &root.join("phone/plugins/example/addon/client.lua"),
        b"addon client",
    );

    let scan = scan_installed_resources(&root, limits()).expect("resources should scan");

    assert_eq!(
        resource_sort_keys(&scan),
        vec![
            "phone".to_owned(),
            "phone/plugins/example".to_owned(),
            "phone/plugins/example/addon".to_owned()
        ]
    );
    assert_eq!(
        file_paths(&scan.resources[0]),
        vec!["client.lua", "fxmanifest.lua"]
    );
    assert_eq!(
        file_paths(&scan.resources[1]),
        vec!["client.lua", "fxmanifest.lua"]
    );
    assert_eq!(
        file_paths(&scan.resources[2]),
        vec!["client.lua", "fxmanifest.lua"]
    );
}

#[test]
fn sibling_prefix_resources_do_not_overlap() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resources");
    write_file(&root.join("phone/fxmanifest.lua"), b"phone");
    write_file(&root.join("phone/client.lua"), b"phone client");
    write_file(&root.join("phone-extra/fxmanifest.lua"), b"extra");
    write_file(&root.join("phone-extra/client.lua"), b"extra client");

    let scan = scan_installed_resources(&root, limits()).expect("resources should scan");

    assert_eq!(
        resource_sort_keys(&scan),
        vec!["phone".to_owned(), "phone-extra".to_owned()]
    );
    assert_eq!(
        file_paths(&scan.resources[0]),
        vec!["client.lua", "fxmanifest.lua"]
    );
    assert_eq!(
        file_paths(&scan.resources[1]),
        vec!["client.lua", "fxmanifest.lua"]
    );
}

#[test]
fn deterministic_ordering_is_lexical() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resources");
    write_file(&root.join("b/fxmanifest.lua"), b"b");
    write_file(&root.join("b/z.lua"), b"z");
    write_file(&root.join("b/a.lua"), b"a");
    write_file(&root.join("a/fxmanifest.lua"), b"a");

    let scan = scan_installed_resources(&root, limits()).expect("resources should scan");

    assert_eq!(
        resource_sort_keys(&scan),
        vec!["a".to_owned(), "b".to_owned()]
    );
    assert_eq!(
        file_paths(&scan.resources[1]),
        vec!["a.lua", "fxmanifest.lua", "z.lua"]
    );
}

#[test]
fn hashes_known_sha256_digest() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"abc");

    let scan = scan_installed_resources(&root, limits()).expect("resource should scan");

    assert_eq!(
        scan.resources[0].files[0].sha256.to_string(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn hashes_empty_file_digest() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"");

    let scan = scan_installed_resources(&root, limits()).expect("resource should scan");

    assert_eq!(
        scan.resources[0].files[0].sha256.to_string(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hashes_file_larger_than_internal_buffer_by_streaming() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    let large = vec![b'x'; 150_000];
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("large.bin"), &large);
    let expected = Sha256::digest(&large);

    let scan = scan_installed_resources(&root, limits()).expect("resource should scan");
    let large_file = scan.resources[0]
        .files
        .iter()
        .find(|file| file.relative_path.as_str() == "large.bin")
        .expect("large file should be present");

    assert_eq!(large_file.size, 150_000);
    assert_eq!(large_file.sha256.as_bytes().as_slice(), expected.as_slice());
}

#[test]
fn enforces_resource_count_limit() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resources");
    write_file(&root.join("a/fxmanifest.lua"), b"a");
    write_file(&root.join("b/fxmanifest.lua"), b"b");
    let small_limits = InstalledScanLimits {
        max_resources: 1,
        ..limits()
    };

    let err = scan_installed_resources(&root, small_limits).expect_err("limit should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledResourceCountLimitExceeded { .. }
    ));
}

#[test]
fn enforces_file_count_limits() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("client.lua"), b"client");
    let per_resource_limit = InstalledScanLimits {
        max_files_per_resource: 1,
        ..limits()
    };

    let err = scan_installed_resources(&root, per_resource_limit).expect_err("limit should fail");
    assert!(matches!(
        err,
        GkrmError::InstalledFilesPerResourceLimitExceeded { .. }
    ));

    let total_file_limit = InstalledScanLimits {
        max_total_files: 1,
        ..limits()
    };
    let err = scan_installed_resources(&root, total_file_limit).expect_err("limit should fail");
    assert!(matches!(
        err,
        GkrmError::InstalledTotalFilesLimitExceeded { .. }
    ));
}

#[test]
fn enforces_total_entry_limit_while_reading() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("client.lua"), b"client");
    let entry_limit = InstalledScanLimits {
        max_total_entries: 1,
        ..limits()
    };

    let err = scan_installed_resources(&root, entry_limit).expect_err("entry limit should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledTotalEntriesLimitExceeded { .. }
    ));
}

#[test]
fn enforces_directory_count_limit() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    fs::create_dir_all(root.join("client")).expect("client dir should be created");
    let directory_limit = InstalledScanLimits {
        max_directories: 1,
        ..limits()
    };

    let err =
        scan_installed_resources(&root, directory_limit).expect_err("directory limit should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledDirectoryCountLimitExceeded { .. }
    ));
}

#[test]
fn enforces_size_limits() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("client.lua"), b"client");
    let file_size_limit = InstalledScanLimits {
        max_file_size: 5,
        ..limits()
    };

    let err = scan_installed_resources(&root, file_size_limit).expect_err("limit should fail");
    assert!(matches!(
        err,
        GkrmError::InstalledFileSizeLimitExceeded { .. }
    ));

    let total_size_limit = InstalledScanLimits {
        max_total_size: 10,
        ..limits()
    };
    let err = scan_installed_resources(&root, total_size_limit).expect_err("limit should fail");
    assert!(matches!(
        err,
        GkrmError::InstalledTotalSizeLimitExceeded { .. }
    ));
}

#[test]
fn rejects_total_size_before_hashing_unreadable_file_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("big.bin"), &[b'x'; 64]);
    let total_size_limit = InstalledScanLimits {
        max_total_size: 8,
        ..limits()
    };

    let err = scan_installed_resources(&root, total_size_limit)
        .expect_err("total size should fail before hashing");

    assert!(matches!(
        err,
        GkrmError::InstalledTotalSizeLimitExceeded { .. }
    ));
}

#[test]
fn immediate_resource_limit_wins_before_later_entry_errors() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resources");
    write_file(&root.join("a/fxmanifest.lua"), b"a");
    write_file(&root.join("b/fxmanifest.lua"), b"b");
    let resource_limit = InstalledScanLimits {
        max_resources: 1,
        max_total_entries: 100,
        ..limits()
    };

    let err =
        scan_installed_resources(&root, resource_limit).expect_err("resource limit should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledResourceCountLimitExceeded { actual: 2, .. }
    ));
}

#[test]
fn large_directory_is_bounded_by_total_entry_limit() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    for index in 0..10 {
        write_file(&root.join(format!("file-{index}.lua")), b"file");
    }
    let entry_limit = InstalledScanLimits {
        max_total_entries: 5,
        ..limits()
    };

    let err = scan_installed_resources(&root, entry_limit).expect_err("large dir should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledTotalEntriesLimitExceeded { .. }
    ));
}

#[test]
fn enforces_directory_depth_limit() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("client/deep/main.lua"), b"client");
    let shallow = InstalledScanLimits {
        max_directory_depth: 1,
        ..limits()
    };

    let err = scan_installed_resources(&root, shallow).expect_err("depth should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledDirectoryDepthLimitExceeded { .. }
    ));
}

#[test]
fn rejects_zero_limits() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    fs::create_dir_all(&root).expect("root should be created");
    let zero = InstalledScanLimits {
        max_resources: 0,
        ..limits()
    };

    let err = scan_installed_resources(&root, zero).expect_err("zero limit should fail");

    assert!(matches!(err, GkrmError::InstalledScanZeroLimit { .. }));
}

#[test]
fn rejects_files_outside_discovered_resources() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resources");
    write_file(&root.join("bundle/readme.txt"), b"readme");
    write_file(&root.join("bundle/gksphone/fxmanifest.lua"), b"manifest");

    let err = scan_installed_resources(&root, limits()).expect_err("unassigned file should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledFileOutsideResource { .. }
    ));
}

#[test]
fn rejects_control_character_names_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    let bad_path = root.join("bad\nname.lua");
    if fs::write(&bad_path, b"bad").is_err() {
        return;
    }

    let err = scan_installed_resources(&root, limits()).expect_err("control name should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledPathControlCharacter { .. }
    ));
}

#[test]
fn rejects_c1_control_character_names_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    let bad_path = root.join("bad\u{85}name.lua");
    if fs::write(&bad_path, b"bad").is_err() {
        return;
    }

    let err = scan_installed_resources(&root, limits()).expect_err("C1 control name should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledPathControlCharacter {
            codepoint: 0x85,
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn rejects_non_utf8_names_on_unix() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    let mut bad = PathBuf::from(&root);
    bad.push(OsString::from_vec(b"bad\xff.lua".to_vec()));
    fs::write(&bad, b"bad").expect("non-UTF-8 file should be written");

    let err = scan_installed_resources(&root, limits()).expect_err("non-UTF-8 name should fail");

    assert!(matches!(err, GkrmError::InstalledPathNonUtf8 { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_case_insensitive_collisions_on_case_sensitive_filesystems() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("Config.lua"), b"a");
    write_file(&root.join("config.lua"), b"b");

    let err = scan_installed_resources(&root, limits()).expect_err("case collision should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledPathCaseInsensitiveCollision { .. }
    ));
}

#[cfg(unix)]
#[test]
fn rejects_non_ascii_case_collisions_on_case_sensitive_filesystems() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("İmage.lua"), b"a");
    write_file(&root.join("i\u{307}mage.lua"), b"b");

    let err = scan_installed_resources(&root, limits()).expect_err("case collision should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledPathCaseInsensitiveCollision { .. }
    ));
}

#[test]
fn rejects_file_symlinks_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("target.lua"), b"target");
    if !try_symlink_file(&root.join("target.lua"), &root.join("link.lua")) {
        return;
    }

    let err = scan_installed_resources(&root, limits()).expect_err("symlink should fail");

    assert!(matches!(err, GkrmError::InstalledEntrySymlink { .. }));
}

#[test]
fn rejects_directory_symlinks_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    fs::create_dir_all(root.join("target-dir")).expect("target dir should be created");
    if !try_symlink_dir(&root.join("target-dir"), &root.join("link-dir")) {
        return;
    }

    let err = scan_installed_resources(&root, limits()).expect_err("symlink should fail");

    assert!(matches!(err, GkrmError::InstalledEntrySymlink { .. }));
}

#[test]
fn no_follow_directory_opening_rejects_symlinks_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    let outside = temp.path().join("outside");
    write_file(&outside.join("nested.lua"), b"outside");
    if !try_symlink_dir(&outside, &root.join("client")) {
        return;
    }

    let err = scan_installed_resources(&root, limits()).expect_err("symlink dir should fail");

    assert!(matches!(err, GkrmError::InstalledEntrySymlink { .. }));
}

#[test]
fn no_follow_file_opening_rejects_symlinks_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    let outside = temp.path().join("outside.lua");
    fs::write(&outside, b"outside").expect("outside file should be written");
    if !try_symlink_file(&outside, &root.join("client.lua")) {
        return;
    }

    let err = scan_installed_resources(&root, limits()).expect_err("symlink file should fail");

    assert!(matches!(err, GkrmError::InstalledEntrySymlink { .. }));
}

#[cfg(windows)]
#[test]
fn rejects_windows_junction_reparse_points_where_supported() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    let target = temp.path().join("target");
    fs::create_dir_all(&target).expect("target dir should be created");
    let junction = root.join("junction");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .status();
    if !matches!(status, Ok(status) if status.success()) {
        return;
    }

    let err = scan_installed_resources(&root, limits()).expect_err("junction should fail");

    assert!(matches!(
        err,
        GkrmError::InstalledEntryReparsePoint { .. } | GkrmError::InstalledEntrySymlink { .. }
    ));
}

#[cfg(unix)]
#[test]
fn rejects_inaccessible_directories_on_unix_when_permissions_apply() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    let private = root.join("private");
    fs::create_dir_all(&private).expect("private dir should be created");
    let original = fs::metadata(&private)
        .expect("private metadata should read")
        .permissions();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o000))
        .expect("private dir should become inaccessible");

    let result = scan_installed_resources(&root, limits());

    fs::set_permissions(&private, original).expect("permissions should be restored");
    if result.is_ok() {
        return;
    }
    assert!(matches!(
        result.expect_err("inaccessible dir should fail"),
        GkrmError::InstalledDirectoryRead { .. }
    ));
}

#[cfg(unix)]
#[test]
fn rejects_non_utf8_selected_root_basename() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp = tempdir().expect("temp dir should be created");
    let mut root = PathBuf::from(temp.path());
    root.push(OsString::from_vec(b"bad\xffroot".to_vec()));
    write_file(&root.join("fxmanifest.lua"), b"manifest");

    let err = scan_installed_resources(&root, limits()).expect_err("root name should fail");

    assert!(matches!(err, GkrmError::InstalledRootNameNonUtf8 { .. }));
}

#[test]
fn scan_does_not_modify_or_create_installation_files() {
    let temp = tempdir().expect("temp dir should be created");
    let root = temp.path().join("resource");
    write_file(&root.join("fxmanifest.lua"), b"manifest");
    write_file(&root.join("client.lua"), b"client");
    let before = snapshot_files(&root);

    scan_installed_resources(&root, limits()).expect("resource should scan");

    let after = snapshot_files(&root);
    assert_eq!(before, after);
}

fn snapshot_files(root: &Path) -> Vec<(String, Vec<u8>, std::time::SystemTime)> {
    let mut pending = vec![PathBuf::from(root)];
    let mut files = Vec::new();

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("directory should read") {
            let entry = entry.expect("entry should read");
            let metadata = entry.metadata().expect("metadata should read");
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .expect("entry should be below root")
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((
                    relative,
                    fs::read(entry.path()).expect("file should read"),
                    metadata.modified().expect("mtime should read"),
                ));
            }
        }
    }

    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[cfg(unix)]
fn try_symlink_file(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn try_symlink_file(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

#[cfg(unix)]
fn try_symlink_dir(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn try_symlink_dir(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_dir(target, link).is_ok()
}
