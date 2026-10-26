/// Hard limits applied while inspecting untrusted ZIP packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageLimits {
    pub max_entries: usize,
    pub max_entry_uncompressed_size: u64,
    pub max_total_uncompressed_size: u64,
    pub max_compression_ratio: u64,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_entry_uncompressed_size: 512 * 1024 * 1024,
            max_total_uncompressed_size: 2 * 1024 * 1024 * 1024,
            max_compression_ratio: 100,
        }
    }
}
