use crate::{GkrmError, Result};

pub const MAX_RECOVERY_AUTHORITY_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryAuthorityParserMemoryEstimate {
    pub input_buffer: usize,
    pub path_arena: usize,
    pub node_index: usize,
    pub path_scratch: usize,
    pub decoded_metadata: usize,
    pub hashing_scratch: usize,
    pub other_bounded_allocations: usize,
    pub total: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryAuthorityLimits {
    pub max_files: usize,
    pub max_directories: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_component_bytes: usize,
    pub max_path_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for RecoveryAuthorityLimits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_directories: 20_000,
            max_nodes: 40_000,
            max_depth: 64,
            max_component_bytes: 255,
            max_path_bytes: 16_383,
            max_body_bytes: MAX_RECOVERY_AUTHORITY_BODY_BYTES,
        }
    }
}

impl RecoveryAuthorityLimits {
    pub fn validate(self) -> Result<Self> {
        for (limit, value) in [
            ("max_files", self.max_files),
            ("max_directories", self.max_directories),
            ("max_nodes", self.max_nodes),
            ("max_depth", self.max_depth),
            ("max_component_bytes", self.max_component_bytes),
            ("max_path_bytes", self.max_path_bytes),
            ("max_body_bytes", self.max_body_bytes),
        ] {
            if value == 0 {
                return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded { limit });
            }
        }
        if self.max_files > 20_000
            || self.max_directories > 20_000
            || self.max_nodes > 40_000
            || self.max_depth > 64
            || self.max_component_bytes > 255
            || self.max_path_bytes > 16_383
            || self.max_body_bytes > MAX_RECOVERY_AUTHORITY_BODY_BYTES
        {
            return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
                limit: "hard_maximum",
            });
        }
        Ok(self)
    }

    /// Conservative parser-owned live-memory ceiling. Allocator implementation overhead is
    /// charged at 16 bytes per retained path allocation in `other_bounded_allocations`.
    pub fn parser_memory_estimate(self) -> Result<RecoveryAuthorityParserMemoryEstimate> {
        let limits = self.validate()?;
        let input_buffer = 36usize;
        let path_arena = limits.max_body_bytes;
        let node_index = limits
            .max_nodes
            .checked_mul(std::mem::size_of::<super::body::RecoveryAuthorityNode>())
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        let path_scratch = limits.max_path_bytes;
        let decoded_metadata = std::mem::size_of::<super::body::RecoveryAuthorityBodyV1>();
        let hashing_scratch = 512usize;
        let collision_index = limits
            .max_nodes
            .checked_mul(32)
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        let allocation_overhead = limits
            .max_nodes
            .checked_mul(16)
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        let other_bounded_allocations = collision_index
            .checked_add(allocation_overhead)
            .and_then(|value| value.checked_add(4_096))
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        let total = input_buffer
            .checked_add(path_arena)
            .and_then(|value| value.checked_add(node_index))
            .and_then(|value| value.checked_add(path_scratch))
            .and_then(|value| value.checked_add(decoded_metadata))
            .and_then(|value| value.checked_add(hashing_scratch))
            .and_then(|value| value.checked_add(other_bounded_allocations))
            .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
        Ok(RecoveryAuthorityParserMemoryEstimate {
            input_buffer,
            path_arena,
            node_index,
            path_scratch,
            decoded_metadata,
            hashing_scratch,
            other_bounded_allocations,
            total,
        })
    }
}
