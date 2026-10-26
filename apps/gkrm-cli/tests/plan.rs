use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = br#"
fx_version 'cerulean'
escrow_ignore {
  'config.lua',
  'new_config.lua',
}
"#;

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

fn run_plan(installed: &Path, package: &Path, output: &str) -> Output {
    Command::new(gkrm())
        .args([
            "plan",
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
    let installed = temp.path().join("resources");
    write_file(&installed.join("gksphone/fxmanifest.lua"), MANIFEST);
    write_file(&installed.join("gksphone/same.lua"), b"same");
    write_file(
        &installed.join("gksphone/changed.lua"),
        b"installed protected",
    );
    write_file(&installed.join("gksphone/config.lua"), b"installed config");
    write_file(
        &installed.join("gksphone/unsupported.txt"),
        b"installed unsupported",
    );
    write_file(&installed.join("gksphone/old.lua"), b"old");
    write_file(
        &installed.join("installed-only/fxmanifest.lua"),
        b"fx_version 'cerulean'",
    );

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/same.lua", b"same"),
            ("gksphone/changed.lua", b"incoming protected"),
            ("gksphone/config.lua", b"incoming config"),
            ("gksphone/unsupported.txt", b"incoming unsupported"),
            ("gksphone/new.lua", b"new protected"),
            ("gksphone/new_config.lua", b"new config"),
            ("gksphone/new_unsupported.txt", b"new unsupported"),
            ("incoming-only/fxmanifest.lua", b"fx_version 'cerulean'"),
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

fn disposition_counts(files: &[Value]) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for file in files {
        let disposition = file["disposition"]
            .as_str()
            .expect("disposition should be a string");
        *counts.entry(disposition).or_insert(0) += 1;
    }
    counts
}

#[test]
fn successful_text_output_is_concise_read_only_and_deterministic() {
    let (temp, installed, package) = successful_fixture();
    let before = snapshot_files(&installed);

    let first = run_plan(&installed, &package, "text");
    let second = run_plan(&installed, &package, "text");

    assert!(first.status.success());
    assert!(second.status.success());
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(snapshot_files(&installed), before);
    assert!(!temp.path().join("resources/gksphone/new.lua").exists());

    let stdout = String::from_utf8(first.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("Resource Manager - Baseline-Free Update Plan"));
    assert!(stdout.contains("These are conservative recommendations only. No files were changed."));
    assert!(stdout.contains("Recommendations"));
    assert!(!stdout.contains("Actions"));
    assert!(stdout.contains("Resources planned: 1"));
    assert!(stdout.contains("Unmatched installed resources: 1"));
    assert!(stdout.contains("Unmatched incoming resources: 1"));
    assert!(stdout.contains("No change: 2"));
    assert!(stdout.contains("Replace candidates: 1"));
    assert!(stdout.contains("Add candidates: 3"));
    assert!(stdout.contains("Merge candidates: 1"));
    assert!(stdout.contains("Preserve: 1"));
    assert!(stdout.contains("Conflict review: 1"));
    assert!(stdout.contains("[baseline_unavailable]"));
    assert!(stdout.contains("gksphone -> gksphone (exact_name)"));
    assert!(stdout.contains("[replace_candidate] changed.lua"));
    assert!(stdout.contains("protected_file_changed"));
    assert!(stdout.contains("[merge_candidate] config.lua"));
    assert!(stdout.contains("editable_file_changed_without_baseline"));
    assert!(stdout.contains("[conflict_review] unsupported.txt"));
    assert!(stdout.contains("[preserve] old.lua"));
    assert!(stdout.contains("Unmatched installed resources"));
    assert!(stdout.contains("installed-only"));
    assert!(stdout.contains("Unmatched incoming resources"));
    assert!(stdout.contains("incoming-only"));
    assert!(!stdout.contains("[no_change]"));
    assert!(!stdout.contains("same.lua"));
    assert!(!stdout.contains("sha256"));
    assert!(!stdout.contains(installed.to_str().expect("path should be UTF-8")));
    assert!(!stdout.contains(temp.path().to_str().expect("path should be UTF-8")));
    assert!(!stdout.contains("archive_index"));
    assert!(!stdout.contains("file_index"));
    assert!(!stdout.contains("identity"));
    assert!(!stdout.contains("escrow_ignore"));
    assert!(!stdout.contains("matching_patterns"));
    assert!(!stdout.contains("matching_ignore_patterns"));
}

#[test]
fn successful_json_output_has_complete_safe_schema_and_is_deterministic() {
    let (temp, installed, package) = successful_fixture();

    let first = run_plan(&installed, &package, "json");
    let second = run_plan(&installed, &package, "json");

    assert!(first.status.success());
    assert!(second.status.success());
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);

    let stdout = String::from_utf8(first.stdout).expect("stdout should be UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["plan_type"], "baseline_free");
    assert_eq!(json["counts"]["resources_planned"], 1);
    assert_eq!(json["counts"]["no_change_files"], 2);
    assert_eq!(json["counts"]["replace_candidates"], 1);
    assert_eq!(json["counts"]["add_candidates"], 3);
    assert_eq!(json["counts"]["merge_candidates"], 1);
    assert_eq!(json["counts"]["preserved_files"], 1);
    assert_eq!(json["counts"]["conflict_review_files"], 1);
    assert_eq!(json["counts"]["unmatched_installed_resources"], 1);
    assert_eq!(json["counts"]["unmatched_incoming_resources"], 1);
    assert_eq!(
        json["counts"]["total_warnings"],
        json["warnings"]
            .as_array()
            .expect("warnings should be array")
            .len()
    );

    let warnings = json["warnings"]
        .as_array()
        .expect("warnings should be array");
    assert_eq!(
        warnings
            .iter()
            .filter(|warning| warning["code"] == "baseline_unavailable")
            .count(),
        1
    );
    assert!(warnings[0]["message"]
        .as_str()
        .expect("message should be a string")
        .contains("No baseline exists"));

    let resource = &json["resources"][0];
    assert_eq!(resource["installed_resource"], "gksphone");
    assert_eq!(resource["incoming_resource"], "gksphone");
    assert_eq!(resource["match_kind"], "exact_name");

    let files = resource["files"].as_array().expect("files should be array");
    assert_eq!(files.len(), 9);
    let counts = disposition_counts(files);
    assert_eq!(resource["counts"]["no_change"], counts["no_change"]);
    assert_eq!(
        resource["counts"]["replace_candidate"],
        counts["replace_candidate"]
    );
    assert_eq!(resource["counts"]["add_candidate"], counts["add_candidate"]);
    assert_eq!(
        resource["counts"]["merge_candidate"],
        counts["merge_candidate"]
    );
    assert_eq!(resource["counts"]["preserve"], counts["preserve"]);
    assert_eq!(
        resource["counts"]["conflict_review"],
        counts["conflict_review"]
    );

    let dispositions = files
        .iter()
        .map(|file| file["disposition"].as_str().expect("disposition string"))
        .collect::<Vec<_>>();
    assert!(dispositions.contains(&"no_change"));
    assert!(dispositions.contains(&"replace_candidate"));
    assert!(dispositions.contains(&"add_candidate"));
    assert!(dispositions.contains(&"merge_candidate"));
    assert!(dispositions.contains(&"preserve"));
    assert!(dispositions.contains(&"conflict_review"));

    let reasons = files
        .iter()
        .map(|file| file["reason"].as_str().expect("reason string"))
        .collect::<Vec<_>>();
    assert!(reasons.contains(&"hashes_match"));
    assert!(reasons.contains(&"protected_file_changed"));
    assert!(reasons.contains(&"editable_file_changed_without_baseline"));
    assert!(reasons.contains(&"unsupported_file_changed_without_profile"));
    assert!(reasons.contains(&"incoming_file_has_no_installed_counterpart"));
    assert!(reasons.contains(&"installed_file_has_no_incoming_counterpart"));

    assert!(files.iter().any(|file| {
        file["path"] == "old.lua" && file.get("incoming_escrow_classification").is_none()
    }));
    assert!(files.iter().all(|file| !file["path"]
        .as_str()
        .expect("path should be string")
        .contains('\\')));
    assert_eq!(
        json["unmatched_installed_resources"][0]["resource"],
        "installed-only"
    );
    assert_eq!(
        json["unmatched_incoming_resources"][0]["resource"],
        "incoming-only"
    );
    assert!(!stdout.contains("sha256"));
    assert!(!stdout.contains(installed.to_str().expect("path should be UTF-8")));
    assert!(!stdout.contains(temp.path().to_str().expect("path should be UTF-8")));
    assert!(!stdout.contains("archive_index"));
    assert!(!stdout.contains("file_index"));
    assert!(!stdout.contains("identity"));
    assert!(!stdout.contains("escrow_ignore"));
    assert!(!stdout.contains("matching_patterns"));
    assert!(!stdout.contains("matching_ignore_patterns"));
    assert!(!stdout.contains("unsupported_extension"));
}

#[test]
fn fallback_warning_is_rendered_with_safe_resource_labels() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), b"fx_version 'cerulean'");

    let package = temp.path().join("update.zip");
    write_zip(&package, &[("fxmanifest.lua", b"fx_version 'cerulean'")]);

    let output = run_plan(&installed, &package, "json");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    assert_eq!(
        json["resources"][0]["match_kind"],
        "single_resource_fallback"
    );
    assert_eq!(json["warnings"][1]["code"], "single_resource_fallback");
    assert_eq!(json["warnings"][1]["installed_resource"], "gksphone");
    assert_eq!(json["warnings"][1]["incoming_resource"], "zip_root");
}

#[test]
fn invalid_arguments_exit_twenty_with_empty_stdout() {
    let output = Command::new(gkrm())
        .args(["plan", "--output", "xml"])
        .output()
        .expect("gkrm should run");

    assert_eq!(output.status.code(), Some(20));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn inspection_failure_exits_three_with_empty_stdout() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), b"fx_version 'cerulean'");
    let package = temp.path().join("update.zip");
    write_zip(&package, &[("../evil.lua", b"evil")]);

    let output = run_plan(&installed, &package, "json");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert_eq!(
        stderr.trim(),
        "error[unsafe_zip_entry]: ZIP contains an unsafe path."
    );
}
