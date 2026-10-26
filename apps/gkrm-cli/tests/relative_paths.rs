use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'config.lua',\n}\n";

fn gkrm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gkrm"))
}

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    fs::write(path, contents).expect("write file");
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    let file = fs::File::create(path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, contents) in entries {
        writer.start_file(*name, options).expect("zip entry");
        writer.write_all(contents).expect("zip bytes");
    }
    writer.finish().expect("finish zip");
}

/// A workspace whose installed root and package are only ever addressed relatively.
fn relative_workspace() -> tempfile::TempDir {
    let temp = tempdir().expect("temp dir");
    write_file(
        &temp
            .path()
            .join("installed")
            .join("gksphone")
            .join("fxmanifest.lua"),
        MANIFEST,
    );
    write_file(
        &temp
            .path()
            .join("installed")
            .join("gksphone")
            .join("config.lua"),
        b"Config = {}\nConfig.Locale = 'tr'\n",
    );
    write_zip(
        &temp.path().join("packages").join("update.zip"),
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            (
                "gksphone/config.lua",
                b"Config = {}\nConfig.Locale = 'en'\n",
            ),
        ],
    );
    temp
}

fn run_in(directory: &Path, args: &[&str]) -> Output {
    Command::new(gkrm())
        .current_dir(directory)
        .args(args)
        .output()
        .expect("gkrm should run")
}

#[test]
fn inspect_and_plan_accept_dot_slash_prefixed_relative_paths() {
    let temp = relative_workspace();

    for (command, resources_key) in [("inspect", "matched_resources"), ("plan", "resources")] {
        for (installed, package) in [
            ("./installed", "./packages/update.zip"),
            ("installed", "packages/update.zip"),
            ("./installed/.", "./packages/./update.zip"),
        ] {
            let output = run_in(
                temp.path(),
                &[
                    command,
                    "--installed",
                    installed,
                    "--package",
                    package,
                    "--output",
                    "json",
                ],
            );

            assert!(
                output.status.success(),
                "{command} {installed} {package}: stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
            let json: Value = serde_json::from_slice(&output.stdout).expect("valid json on stdout");
            assert_eq!(json["schema_version"], 1);
            assert_eq!(
                json[resources_key]
                    .as_array()
                    .expect("resource array")
                    .len(),
                1
            );
        }
    }
}

#[test]
fn relative_paths_still_reject_parent_directory_traversal() {
    let temp = relative_workspace();
    let leaf = temp
        .path()
        .file_name()
        .expect("temp leaf name")
        .to_str()
        .expect("utf-8 leaf name")
        .to_owned();

    let traversed_installed = format!("../{leaf}/installed");
    let traversed_package = format!("../{leaf}/packages/update.zip");

    for (installed, package) in [
        (traversed_installed.as_str(), "./packages/update.zip"),
        ("./installed", traversed_package.as_str()),
    ] {
        let output = run_in(
            temp.path(),
            &[
                "inspect",
                "--installed",
                installed,
                "--package",
                package,
                "--output",
                "json",
            ],
        );

        assert!(
            !output.status.success(),
            "parent traversal must stay rejected for {installed} {package}"
        );
        assert!(output.stdout.is_empty());
    }
}
