use std::fmt;

use crate::installed_path::validate_relative_component;
use crate::{GkrmError, Result};

/// Single safe filesystem component identifying a resource in the baseline store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeResourceKey(String);

impl SafeResourceKey {
    pub fn parse(value: &str) -> Result<Self> {
        validate_relative_component(value, value).map_err(|_| {
            GkrmError::BaselineUnsafeResourceKey {
                value: value.to_owned(),
            }
        })?;
        if value.contains('/') || value.contains('\\') {
            return Err(GkrmError::BaselineUnsafeResourceKey {
                value: value.to_owned(),
            });
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeResourceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
