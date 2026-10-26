use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'";

fn gkrm() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gkrm"))
}

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("test path should have parent"))
        .expect("parent should be created");
    fs::write(path, contents).expect("file should be written");
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("zip should be created");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    for (name, contents) in entries {
        writer
            .start_file(*name, options)
            .expect("zip entry should start");
        writer
            .write_all(contents)
            .expect("zip entry should be written");
    }

    writer.finish().expect("zip should finish");
}

fn run_inspect(installed: &Path, package: &Path, output: &str) -> Output {
    Command::new(gkrm())
        .args([
            "inspect",
            "--installed",
            installed.to_str().expect("path should be UTF-8"),
            "--package",
            package.to_str().expect("path should be UTF-8"),
            "--output",
            output,
        ])
        .output()
        .expect("gkrm should run")
}

fn successful_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), b"fx_version 'cerulean'");
    write_file(&installed.join("same.lua"), b"same");
    write_file(&installed.join("changed.lua"), b"installed");
    write_file(&installed.join("old.lua"), b"old");
    write_file(&installed.join("config.lua"), b"installed config");

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            (
                "gksphone/fxmanifest.lua",
                b"fx_version 'cerulean'\nescrow_ignore 'config.lua'",
            ),
            ("gksphone/same.lua", b"same"),
            ("gksphone/changed.lua", b"incoming"),
            ("gksphone/new.lua", b"new"),
            ("gksphone/config.lua", b"incoming config"),
            ("gksphone/html/index.html", b"html"),
            ("unmatched/fxmanifest.lua", b"escrow_ignore 'extra.lua'"),
            ("unmatched/extra.lua", b"ignored unmatched"),
            ("unmatched/client.lua", b"protected unmatched"),
            ("unmatched/html/index.html", b"unsupported unmatched"),
        ],
    );

    (temp, installed, package)
}

fn snapshot_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut pending = vec![root.to_path_buf()];
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
                    .expect("file should be below root")
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((relative, fs::read(entry.path()).expect("file should read")));
            }
        }
    }

    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[test]
fn successful_text_output_is_concise_and_deterministic() {
    let (_temp, installed, package) = successful_fixture();

    let first = run_inspect(&installed, &package, "text");
    let second = run_inspect(&installed, &package, "text");

    assert!(first.status.success());
    assert!(second.status.success());
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);

    let stdout = String::from_utf8(first.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("Resource Manager - Inspection"));
    assert!(stdout.contains("Installed resources: 1"));
    assert!(stdout.contains("Incoming resources: 2"));
    assert!(stdout.contains("Matched resources: 1"));
    assert!(stdout.contains("Unmatched incoming resources: 1"));
    assert!(stdout.contains("Unchanged: 1"));
    assert!(stdout.contains("Incoming only: 2"));
    assert!(stdout.contains("Installed only: 1"));
    assert!(stdout.contains("Escrow - Matched resources only"));
    assert!(!stdout.contains("Escrow â"));
    assert!(stdout.contains("Protected: 4"));
    assert!(stdout.contains("Ignored/editable: 1"));
    assert!(stdout.contains("Not supported: 1"));
    assert!(stdout.contains("gksphone -> gksphone (exact_name)"));
    assert!(!stdout.contains("same.lua"));
}

#[test]
fn successful_json_output_has_schema_counts_and_no_internal_metadata() {
    let (_temp, installed, package) = successful_fixture();

    let first = run_inspect(&installed, &package, "json");
    let second = run_inspect(&installed, &package, "json");

    assert!(first.status.success());
    assert!(second.status.success());
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);

    let stdout = String::from_utf8(first.stdout).expect("stdout should be UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["counts"]["installed_resources"], 1);
    assert_eq!(json["counts"]["incoming_resources"], 2);
    assert_eq!(json["counts"]["matched_resources"], 1);
    assert_eq!(json["counts"]["unmatched_incoming_resources"], 1);
    assert_eq!(json["counts"]["unchanged_files"], 1);
    assert_eq!(json["counts"]["changed_files"], 3);
    assert_eq!(json["counts"]["incoming_only_files"], 2);
    assert_eq!(json["counts"]["installed_only_files"], 1);
    assert_eq!(json["counts"]["matched_protected_incoming_files"], 4);
    assert_eq!(json["counts"]["matched_ignored_incoming_files"], 1);
    assert_eq!(json["counts"]["matched_unsupported_incoming_files"], 1);
    assert_eq!(json["matched_resources"][0]["match_kind"], "exact_name");
    assert!(json["counts"].get("protected_incoming_files").is_none());
    assert!(json["counts"].get("ignored_incoming_files").is_none());
    assert!(json["counts"].get("unsupported_incoming_files").is_none());
    assert!(!stdout.contains("archive_index"));
    assert!(!stdout.contains("sha256"));
    assert!(!stdout.contains("file_index"));
    assert!(!stdout.contains(installed.to_str().expect("path should be UTF-8")));
}

#[test]
fn root_resource_fallback_uses_stable_warning_code() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), MANIFEST);
    let package = temp.path().join("update.zip");
    write_zip(&package, &[("fxmanifest.lua", MANIFEST)]);

    let output = run_inspect(&installed, &package, "json");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(
        json["matched_resources"][0]["match_kind"],
        "single_resource_fallback"
    );
    assert_eq!(
        json["warnings"]["comparison"][0]["code"],
        "single_resource_fallback"
    );
    assert_eq!(json["warnings"]["comparison"][0]["resource"], "gksphone");
}

#[test]
fn multiple_and_unmatched_resources_are_reported() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("resources");
    write_file(&installed.join("gksphone/fxmanifest.lua"), MANIFEST);
    write_file(&installed.join("tablet/fxmanifest.lua"), MANIFEST);
    write_file(&installed.join("installed-only/fxmanifest.lua"), MANIFEST);
    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("tablet/fxmanifest.lua", MANIFEST),
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("incoming-only/fxmanifest.lua", MANIFEST),
        ],
    );

    let output = run_inspect(&installed, &package, "json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(json["counts"]["matched_resources"], 2);
    assert_eq!(json["counts"]["unmatched_installed_resources"], 1);
    assert_eq!(json["counts"]["unmatched_incoming_resources"], 1);
    assert_eq!(
        json["matched_resources"][0]["installed_resource"],
        "gksphone"
    );
    assert_eq!(json["matched_resources"][1]["installed_resource"], "tablet");
    assert_eq!(
        json["unmatched_installed_resources"][0]["resource"],
        "installed-only"
    );
    assert_eq!(
        json["unmatched_incoming_resources"][0]["resource"],
        "incoming-only"
    );
}

#[test]
fn invalid_cli_arguments_exit_twenty() {
    let output = Command::new(gkrm())
        .args(["inspect", "--output", "xml"])
        .output()
        .expect("gkrm should run");

    assert_eq!(output.status.code(), Some(20));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn expected_pipeline_failure_exits_three_with_empty_stdout() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), MANIFEST);
    let package = temp.path().join("update.zip");
    write_zip(&package, &[("../evil.lua", b"evil")]);

    let output = run_inspect(&installed, &package, "json");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert_eq!(
        stderr.trim(),
        "error[unsafe_zip_entry]: ZIP contains an unsafe path."
    );
}

#[test]
fn malformed_manifest_is_reported_without_partial_output() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), MANIFEST);
    let package = temp.path().join("update.zip");
    write_zip(&package, &[("gksphone/fxmanifest.lua", b"client_script(")]);

    let output = run_inspect(&installed, &package, "text");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert_eq!(
        stderr.trim(),
        "error[manifest_parse_failed]: Incoming resource manifest could not be parsed."
    );
}

#[test]
fn inspect_does_not_extract_zip_or_modify_installed_files() {
    let (temp, installed, package) = successful_fixture();
    let before = snapshot_files(&installed);

    let output = run_inspect(&installed, &package, "json");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(snapshot_files(&installed), before);
    assert!(!temp.path().join("gksphone").join("new.lua").exists());
}
