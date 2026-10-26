use std::ffi::OsStr;
use std::fmt;
use std::path::{Component, Path};

use crate::{GkrmError, Result};
use unicode_casefold::{Locale, UnicodeCaseFold, Variant};
use unicode_normalization::UnicodeNormalization;

/// UTF-8, slash-separated path relative to the selected installation root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstallationRelativePath(String);

/// UTF-8, slash-separated path relative to one installed resource root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceRelativePath(String);

/// SHA-256 digest stored as raw bytes and rendered as lowercase hexadecimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl InstallationRelativePath {
    pub fn from_path(path: &Path) -> Result<Self> {
        normalize_relative_path(path).map(Self)
    }

    pub fn from_component(component: &OsStr) -> Result<Self> {
        let component = component_to_str(component, ".")?;
        validate_relative_component(component, component)?;
        Ok(Self(component.to_owned()))
    }

    pub(crate) fn from_components(components: &[std::ffi::OsString]) -> Result<Self> {
        let mut path = std::path::PathBuf::new();
        for component in components {
            path.push(component);
        }
        Self::from_path(&path)
    }

    pub fn join_component(&self, component: &str) -> Result<Self> {
        validate_relative_component(component, component)?;
        Ok(Self(format!("{}/{component}", self.0)))
    }

    pub fn parent(&self) -> Option<Self> {
        self.0
            .rsplit_once('/')
            .map(|(parent, _)| Self(parent.to_owned()))
    }

    pub fn file_name(&self) -> &str {
        self.0
            .rsplit_once('/')
            .map_or(self.0.as_str(), |(_, name)| name)
    }

    pub fn depth(&self) -> usize {
        self.0.split('/').count()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ResourceRelativePath {
    pub(crate) fn from_safe_slash_path(path: String) -> Self {
        Self(path)
    }

    /// Validate a resource-relative path already expressed with `/` separators.
    pub(crate) fn try_from_slash_str(path: &str) -> Result<Self> {
        if path.is_empty() {
            return Err(GkrmError::BaselineUnsafeRelativePath {
                path: path.to_owned(),
            });
        }
        if path.starts_with('/') || path.starts_with('\\') {
            return Err(GkrmError::BaselineUnsafeRelativePath {
                path: path.to_owned(),
            });
        }
        if path.contains('\\') {
            return Err(GkrmError::BaselineUnsafeRelativePath {
                path: path.to_owned(),
            });
        }

        let mut components = Vec::new();
        for component in path.split('/') {
            if let Err(error) = validate_relative_component(component, path) {
                let _ = error;
                return Err(GkrmError::BaselineUnsafeRelativePath {
                    path: path.to_owned(),
                });
            }
            components.push(component.to_owned());
        }
        Ok(Self(components.join("/")))
    }

    /// Validate an already-owned slash path without cloning the complete path.
    pub(crate) fn try_from_slash_string(path: String) -> Result<Self> {
        if path.is_empty() || path.starts_with('/') || path.starts_with('\\') || path.contains('\\')
        {
            return Err(GkrmError::BaselineUnsafeRelativePath { path });
        }
        for component in path.split('/') {
            if validate_relative_component(component, &path).is_err() {
                return Err(GkrmError::BaselineUnsafeRelativePath { path });
            }
        }
        Ok(Self(path))
    }

    pub fn from_installation_path(
        resource_root: &crate::InstalledResourceRoot,
        file_path: &InstallationRelativePath,
    ) -> Result<Self> {
        match resource_root {
            crate::InstalledResourceRoot::Root => Ok(Self(file_path.0.clone())),
            crate::InstalledResourceRoot::Path(root) => {
                if file_path == root {
                    return Err(GkrmError::InstalledResourceRelativePath {
                        root: root.to_string(),
                        path: file_path.to_string(),
                    });
                }

                let suffix = file_path
                    .as_str()
                    .strip_prefix(root.as_str())
                    .and_then(|suffix| suffix.strip_prefix('/'))
                    .ok_or_else(|| GkrmError::InstalledResourceRelativePath {
                        root: root.to_string(),
                        path: file_path.to_string(),
                    })?;

                Ok(Self(suffix.to_owned()))
            }
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Sha256Digest {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a lowercase hex-encoded SHA-256 digest.
    pub fn from_lowercase_hex(value: &str) -> Result<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(GkrmError::BaselineInvalidHash {
                value: value.to_owned(),
            });
        }

        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(chunk[0]).ok_or_else(|| GkrmError::BaselineInvalidHash {
                value: value.to_owned(),
            })?;
            let low = hex_nibble(chunk[1]).ok_or_else(|| GkrmError::BaselineInvalidHash {
                value: value.to_owned(),
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for InstallationRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for ResourceRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn normalize_relative_path(path: &Path) -> Result<String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => {
                let current = components.join("/");
                let display_path = if current.is_empty() {
                    component_to_str(component, ".")?.to_owned()
                } else {
                    format!("{current}/{}", component_to_str(component, &current)?)
                };
                let component = component_to_str(component, &display_path)?;
                validate_relative_component(component, &display_path)?;
                components.push(component.to_owned());
            }
            Component::CurDir => {
                return Err(GkrmError::InstalledPathCurrentDirectory {
                    path: path.display().to_string(),
                });
            }
            Component::ParentDir => {
                return Err(GkrmError::InstalledPathParentTraversal {
                    path: path.display().to_string(),
                });
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(GkrmError::InstalledPathAbsolute {
                    path: path.display().to_string(),
                });
            }
        }
    }

    if components.is_empty() {
        return Err(GkrmError::InstalledPathEmpty {
            path: path.display().to_string(),
        });
    }

    Ok(components.join("/"))
}

pub(crate) fn component_to_str<'a>(component: &'a OsStr, path: &str) -> Result<&'a str> {
    component
        .to_str()
        .ok_or_else(|| GkrmError::InstalledPathNonUtf8 {
            path: path.to_owned(),
        })
}

pub(crate) fn validate_relative_component(component: &str, path: &str) -> Result<()> {
    if component.is_empty() {
        return Err(GkrmError::InstalledPathEmptyComponent {
            path: path.to_owned(),
        });
    }

    match component {
        "." => {
            return Err(GkrmError::InstalledPathCurrentDirectory {
                path: path.to_owned(),
            });
        }
        ".." => {
            return Err(GkrmError::InstalledPathParentTraversal {
                path: path.to_owned(),
            });
        }
        _ => {}
    }

    if let Some(character) = component.chars().find(|character| character.is_control()) {
        return Err(GkrmError::InstalledPathControlCharacter {
            path: path.to_owned(),
            codepoint: character as u32,
        });
    }

    if let Some(character) = component.chars().find(|character| {
        matches!(
            *character,
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
        )
    }) {
        return Err(GkrmError::InstalledPathWindowsInvalidCharacter {
            path: path.to_owned(),
            character,
        });
    }

    if component.ends_with('.') || component.ends_with(' ') {
        return Err(GkrmError::InstalledPathWindowsTrailingDotOrSpace {
            path: path.to_owned(),
            component: component.to_owned(),
        });
    }

    let device_name = component
        .split_once('.')
        .map_or(component, |(name, _)| name);
    if is_windows_reserved_device_name(device_name) {
        return Err(GkrmError::InstalledPathWindowsReservedName {
            path: path.to_owned(),
            component: component.to_owned(),
        });
    }

    Ok(())
}

pub(crate) fn case_collision_key(path: &str) -> String {
    // Conservative cross-platform collision prevention, not an exact model of
    // NTFS, APFS, ext4, or every filesystem's folding/normalization behavior.
    path.nfkc()
        .case_fold_with(Variant::Full, Locale::NonTurkic)
        .nfc()
        .collect::<String>()
}

fn is_windows_reserved_device_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || is_numbered_reserved_device(&upper, "COM")
        || is_numbered_reserved_device(&upper, "LPT")
}

fn is_numbered_reserved_device(name: &str, prefix: &str) -> bool {
    let suffix = name.strip_prefix(prefix);
    matches!(
        suffix,
        Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(path: &str) -> Result<InstallationRelativePath> {
        InstallationRelativePath::from_path(Path::new(path))
    }

    #[test]
    fn accepts_safe_relative_paths() {
        assert_eq!(
            normalize("resource/client/main.lua")
                .expect("path should normalize")
                .as_str(),
            "resource/client/main.lua"
        );
    }

    #[test]
    fn rejects_parent_and_current_directory_components() {
        assert!(matches!(
            normalize("resource/../file.lua"),
            Err(GkrmError::InstalledPathParentTraversal { .. })
        ));
        assert!(matches!(
            normalize("./file.lua"),
            Err(GkrmError::InstalledPathCurrentDirectory { .. })
        ));
    }

    #[test]
    fn rejects_control_characters() {
        assert!(matches!(
            normalize("resource/config\n.lua"),
            Err(GkrmError::InstalledPathControlCharacter { codepoint: 10, .. })
        ));
        assert!(matches!(
            normalize("resource/config\u{85}.lua"),
            Err(GkrmError::InstalledPathControlCharacter {
                codepoint: 0x85,
                ..
            })
        ));
    }

    #[test]
    fn rejects_windows_unsafe_components() {
        for path in [
            "resource/file?.lua",
            "resource/CON",
            "resource/file.",
            "resource/file ",
        ] {
            assert!(normalize(path).is_err(), "{path:?} should be rejected");
        }
    }

    #[test]
    fn sha256_digest_formats_lowercase_hex() {
        let digest = Sha256Digest::new([0xab; 32]);

        assert_eq!(
            digest.to_string(),
            "abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn collision_key_folds_ascii_and_unicode() {
        assert_eq!(
            case_collision_key("Config.lua"),
            case_collision_key("config.lua")
        );
        assert_eq!(
            case_collision_key("Straße.lua"),
            case_collision_key("strasse.lua")
        );
        assert_eq!(case_collision_key("ΟΣ.lua"), case_collision_key("ος.lua"));
        assert_eq!(case_collision_key("οσ.lua"), case_collision_key("ος.lua"));
        assert_eq!(
            case_collision_key("Cafe\u{301}.lua"),
            case_collision_key("Café.lua")
        );
    }
}
