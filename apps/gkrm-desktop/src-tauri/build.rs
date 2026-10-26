fn main() {
    // The generated resource script names the icon by path, so the icon is read when the script
    // is compiled and not afterwards. Without this, replacing the artwork changes nothing: the
    // build reuses the cached resource and the executable keeps the icon it was built with, which
    // is a very convincing way to believe a new logo did not work.
    println!("cargo:rerun-if-changed=icons");
    for entry in std::fs::read_dir("icons").into_iter().flatten().flatten() {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }

    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "app_get_info",
            "select_installed_root",
            "select_package_file",
            "session_list_selections",
            "session_release_selection",
            "scan_installed_root",
            "scan_get_summary",
            "scan_list_resources",
            "scan_get_resource_detail",
            "scan_release",
            "update_recovery_overview",
            "update_recovery_retire_terminal",
            "update_recovery_status",
            "update_recovery_list_candidates",
            "update_recovery_execute",
            "update_recovery_release",
            "update_two_way_preview",
            "update_two_way_get_diff",
            "update_two_way_apply",
            "update_two_way_release",
            "update_history_list",
            "update_history_undo",
            "storage_report",
            "storage_release",
        ]),
    ))
    .expect("tauri build script should complete");
}
