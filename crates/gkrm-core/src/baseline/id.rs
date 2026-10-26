use std::fmt;

use crate::{GkrmError, Result, Sha256Digest};

/// Content-derived baseline identifier (lowercase SHA-256 hex).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaselineId(String);

impl BaselineId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest.to_string())
    }

    pub fn parse(value: &str) -> Result<Self> {
        let digest =
            Sha256Digest::from_lowercase_hex(value).map_err(|_| GkrmError::BaselineInvalidId {
                value: value.to_owned(),
            })?;
        Ok(Self(digest.to_string()))
    }
}

impl fmt::Display for BaselineId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
