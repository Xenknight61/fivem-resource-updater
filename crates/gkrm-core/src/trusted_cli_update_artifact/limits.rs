//! Validated CLI update limits bounded by core hard maxima.

use crate::{GkrmError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedCliUpdateOptions {
    pub max_package_entries: usize,
    pub max_package_bytes: u64,
    pub max_resources: usize,
    pub max_baseline_bytes: u64,
    pub max_decision_document_bytes: usize,
    pub max_decision_entries: usize,
    pub max_operator_merge_files: usize,
    pub max_operator_merge_bytes_per_file: u64,
    pub max_operator_merge_total_bytes: u64,
    pub max_staging_files: usize,
    pub max_staging_bytes: u64,
    pub max_transactions: usize,
    pub max_journal_records: usize,
    pub max_backup_bytes: u64,
    pub max_recovery_steps: usize,
    pub max_artifact_bytes: usize,
    pub max_json_report_entries: usize,
}

impl Default for TrustedCliUpdateOptions {
    fn default() -> Self {
        Self {
            max_package_entries: 100_000,
            max_package_bytes: 512 * 1024 * 1024,
            max_resources: 256,
            max_baseline_bytes: 512 * 1024 * 1024,
            max_decision_document_bytes: 4 * 1024 * 1024,
            max_decision_entries: 100_000,
            max_operator_merge_files: 10_000,
            max_operator_merge_bytes_per_file: 32 * 1024 * 1024,
            max_operator_merge_total_bytes: 256 * 1024 * 1024,
            max_staging_files: 100_000,
            max_staging_bytes: 512 * 1024 * 1024,
            max_transactions: 10_000,
            max_journal_records: 200_000,
            max_backup_bytes: 512 * 1024 * 1024,
            max_recovery_steps: 200_000,
            max_artifact_bytes: 4 * 1024 * 1024,
            max_json_report_entries: 100_000,
        }
    }
}

impl TrustedCliUpdateOptions {
    pub fn validate(self) -> Result<Self> {
        for (name, value) in [
            ("max_package_entries", self.max_package_entries as u64),
            ("max_package_bytes", self.max_package_bytes),
            ("max_resources", self.max_resources as u64),
            ("max_baseline_bytes", self.max_baseline_bytes),
            (
                "max_decision_document_bytes",
                self.max_decision_document_bytes as u64,
            ),
            ("max_decision_entries", self.max_decision_entries as u64),
            (
                "max_operator_merge_files",
                self.max_operator_merge_files as u64,
            ),
            (
                "max_operator_merge_bytes_per_file",
                self.max_operator_merge_bytes_per_file,
            ),
            (
                "max_operator_merge_total_bytes",
                self.max_operator_merge_total_bytes,
            ),
            ("max_staging_files", self.max_staging_files as u64),
            ("max_staging_bytes", self.max_staging_bytes),
            ("max_transactions", self.max_transactions as u64),
            ("max_journal_records", self.max_journal_records as u64),
            ("max_backup_bytes", self.max_backup_bytes),
            ("max_recovery_steps", self.max_recovery_steps as u64),
            ("max_artifact_bytes", self.max_artifact_bytes as u64),
            (
                "max_json_report_entries",
                self.max_json_report_entries as u64,
            ),
        ] {
            if value == 0 {
                return Err(GkrmError::TrustedCliUpdateOptionsInvalid { limit: name });
            }
        }
        Ok(self)
    }
}
