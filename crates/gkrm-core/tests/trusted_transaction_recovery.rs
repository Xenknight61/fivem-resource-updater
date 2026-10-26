//! Integration tests for Task 24 trusted transaction recovery (public API only).

use std::fs;
use std::path::Path;

use gkrm_core::{scan_trusted_transactions, TrustedRecoveryScanOptions, TrustedTransactionRoot};
use tempfile::tempdir;

#[test]
fn trusted_transaction_recovery_scan_empty_root_is_read_only() {
    let dir = tempdir().unwrap();
    let root_path = dir.path().join("txn-root");
    fs::create_dir_all(&root_path).unwrap();
    let before: Vec<_> = fs::read_dir(&root_path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let root = TrustedTransactionRoot::try_open(&root_path).unwrap();
    let scan = scan_trusted_transactions(&root, TrustedRecoveryScanOptions::default()).unwrap();
    assert!(scan.candidates().is_empty());
    let after: Vec<_> = fs::read_dir(&root_path)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    let _ = Path::new(".");
}
