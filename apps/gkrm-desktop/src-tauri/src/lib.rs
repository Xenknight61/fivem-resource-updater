pub mod commands;
pub mod diagnostics;
pub mod dto;
pub mod error;
pub mod history;
pub mod installed_baseline;
#[cfg(test)]
mod lifecycle_tests;
pub mod operation;
pub mod recovery;
pub mod scan;
pub mod selection;
pub mod state;
pub mod storage;
pub mod undo;
pub mod update;

use commands::{
    app_get_info, scan_get_resource_detail, scan_get_summary, scan_installed_root,
    scan_list_resources, scan_release, select_installed_root, select_package_file,
    session_list_selections, session_release_selection, storage_release, storage_report,
    update_history_list, update_history_undo, update_recovery_execute,
    update_recovery_list_candidates, update_recovery_overview, update_recovery_release,
    update_recovery_retire_terminal, update_recovery_status, update_two_way_apply,
    update_two_way_get_diff, update_two_way_preview, update_two_way_release,
};
use state::DesktopAppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DesktopAppState::default())
        // Where the record of what was asked for lives. Beside the workspace it describes, and
        // failing to find it costs the log rather than the application.
        .setup(|app| {
            use tauri::Manager;
            if let Ok(app_data_root) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&app_data_root);
                diagnostics::init(&app_data_root);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_get_info,
            select_installed_root,
            select_package_file,
            session_list_selections,
            session_release_selection,
            scan_installed_root,
            scan_get_summary,
            scan_list_resources,
            scan_get_resource_detail,
            scan_release,
            update_recovery_overview,
            update_recovery_retire_terminal,
            update_recovery_status,
            update_recovery_list_candidates,
            update_recovery_execute,
            update_recovery_release,
            update_two_way_preview,
            update_two_way_get_diff,
            update_two_way_apply,
            update_two_way_release,
            update_history_list,
            update_history_undo,
            storage_report,
            storage_release,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run FiveM Resource Updater");
}
