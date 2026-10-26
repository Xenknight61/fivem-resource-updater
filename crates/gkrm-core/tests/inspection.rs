use std::fs;
use std::io::Write;
use std::path::Path;

use gkrm_core::{inspect_installation_update, InspectionOptions, ResourceMatchKind};
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'";

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
            .expect("entry should start");
        writer.write_all(contents).expect("entry should be written");
    }

    writer.finish().expect("zip should finish");
}

#[test]
fn orchestrates_complete_read_only_pipeline() {
    let temp = tempdir().expect("temp dir should be created");
    let installed = temp.path().join("gksphone");
    write_file(&installed.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed.join("client.lua"), b"installed");

    let package = temp.path().join("update.zip");
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/client.lua", b"incoming"),
        ],
    );

    let report = inspect_installation_update(&installed, &package, InspectionOptions::default())
        .expect("inspection should succeed");

    assert_eq!(report.incoming_inspection().entries.len(), 2);
    assert_eq!(report.incoming_discovery().resources.len(), 1);
    assert_eq!(report.manifests().resources.len(), 1);
    assert_eq!(report.escrow().resources.len(), 1);
    assert_eq!(report.installed().resources.len(), 1);
    assert_eq!(report.comparison().matched_resources.len(), 1);
    assert_eq!(
        report.comparison().matched_resources[0]
            .resource_match
            .match_kind,
        ResourceMatchKind::ExactName
    );
    assert!(!temp.path().join("gksphone").join("new.lua").exists());
}
