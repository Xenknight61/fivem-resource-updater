use std::fmt;

use crate::{GkrmError, Result};

/// A normalized ZIP-relative path that is safe to inventory without extraction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZipRelativePath(String);

impl ZipRelativePath {
    pub fn new(index: usize, raw: &[u8]) -> Result<Self> {
        let entry =
            std::str::from_utf8(raw).map_err(|_| GkrmError::ZipEntryNameInvalidUtf8 { index })?;

        normalize_zip_entry_path(index, entry).map(Self)
    }

    /// Parse a caller-supplied package-relative path (no archive index).
    ///
    /// Accepts the same normalization rules as ZIP inventory paths. Failures map to
    /// structured capture/path errors without exposing archive indexes.
    pub fn parse_canonical(path: &str) -> Result<Self> {
        normalize_caller_zip_path(path).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ZipRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn normalize_zip_entry_path(index: usize, entry: &str) -> Result<String> {
    if entry.is_empty() {
        return Err(GkrmError::ZipEntryPathEmpty { index });
    }

    if let Some(character) = entry
        .chars()
        .find(|character| *character == '\0' || matches!(*character, '\u{1}'..='\u{1f}' | '\u{7f}'))
    {
        return Err(GkrmError::ZipEntryControlCharacter {
            index,
            entry: entry.to_owned(),
            codepoint: character as u32,
        });
    }

    if starts_with_windows_drive(entry) {
        return Err(GkrmError::ZipEntryWindowsDrivePath {
            index,
            entry: entry.to_owned(),
        });
    }

    if entry.starts_with("\\\\") || entry.starts_with("//") {
        return Err(GkrmError::ZipEntryUncPath {
            index,
            entry: entry.to_owned(),
        });
    }

    if entry.starts_with('\\') {
        return Err(GkrmError::ZipEntryWindowsRootPath {
            index,
            entry: entry.to_owned(),
        });
    }

    if entry.starts_with('/') {
        return Err(GkrmError::ZipEntryUnixAbsolutePath {
            index,
            entry: entry.to_owned(),
        });
    }

    let normalized = entry.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');

    if trimmed.is_empty() {
        return Err(GkrmError::ZipEntryPathEmpty { index });
    }

    for component in trimmed.split('/') {
        match component {
            "" => {
                return Err(GkrmError::ZipEntryEmptyComponent {
                    index,
                    entry: entry.to_owned(),
                });
            }
            "." => {
                return Err(GkrmError::ZipEntryCurrentDirectory {
                    index,
                    entry: entry.to_owned(),
                });
            }
            ".." => {
                return Err(GkrmError::ZipEntryParentTraversal {
                    index,
                    entry: entry.to_owned(),
                });
            }
            _ => validate_windows_component(index, entry, component)?,
        }
    }

    Ok(trimmed.to_owned())
}

fn normalize_caller_zip_path(entry: &str) -> Result<String> {
    normalize_zip_entry_path(0, entry).map_err(|_| GkrmError::BaselineCaptureUnsafeResourceIdentity)
}

fn starts_with_windows_drive(entry: &str) -> bool {
    let bytes = entry.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_windows_component(index: usize, entry: &str, component: &str) -> Result<()> {
    if let Some(character) = component
        .chars()
        .find(|character| matches!(*character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return Err(GkrmError::ZipEntryWindowsInvalidCharacter {
            index,
            entry: entry.to_owned(),
            character,
        });
    }

    if component.ends_with('.') || component.ends_with(' ') {
        return Err(GkrmError::ZipEntryWindowsTrailingDotOrSpace {
            index,
            entry: entry.to_owned(),
            component: component.to_owned(),
        });
    }

    let device_name = component
        .split_once('.')
        .map_or(component, |(name, _)| name);
    if is_windows_reserved_device_name(device_name) {
        return Err(GkrmError::ZipEntryWindowsReservedName {
            index,
            entry: entry.to_owned(),
            component: component.to_owned(),
        });
    }

    Ok(())
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

    fn normalize(entry: &str) -> Result<ZipRelativePath> {
        ZipRelativePath::new(0, entry.as_bytes())
    }

    #[test]
    fn accepts_relative_paths() {
        assert_eq!(
            normalize("resource/fxmanifest.lua")
                .expect("path should normalize")
                .as_str(),
            "resource/fxmanifest.lua"
        );
    }

    #[test]
    fn normalizes_backslashes() {
        assert_eq!(
            normalize("resource\\client\\main.lua")
                .expect("path should normalize")
                .as_str(),
            "resource/client/main.lua"
        );
    }

    #[test]
    fn normalizes_trailing_directory_slash() {
        assert_eq!(
            normalize("resource/html/")
                .expect("path should normalize")
                .as_str(),
            "resource/html"
        );
    }

    #[test]
    fn rejects_parent_traversal() {
        assert!(matches!(
            normalize("../evil.txt"),
            Err(GkrmError::ZipEntryParentTraversal { .. })
        ));
        assert!(matches!(
            normalize("resource/../evil.txt"),
            Err(GkrmError::ZipEntryParentTraversal { .. })
        ));
    }

    #[test]
    fn rejects_unix_absolute_path() {
        assert!(matches!(
            normalize("/tmp/evil.txt"),
            Err(GkrmError::ZipEntryUnixAbsolutePath { .. })
        ));
    }

    #[test]
    fn rejects_windows_drive_path() {
        assert!(matches!(
            normalize("C:\\evil.txt"),
            Err(GkrmError::ZipEntryWindowsDrivePath { .. })
        ));
        assert!(matches!(
            normalize("C:/evil.txt"),
            Err(GkrmError::ZipEntryWindowsDrivePath { .. })
        ));
        assert!(matches!(
            normalize("C:evil.txt"),
            Err(GkrmError::ZipEntryWindowsDrivePath { .. })
        ));
    }

    #[test]
    fn rejects_unc_path() {
        assert!(matches!(
            normalize("\\\\server\\share\\evil.txt"),
            Err(GkrmError::ZipEntryUncPath { .. })
        ));
        assert!(matches!(
            normalize("//server/share/evil.txt"),
            Err(GkrmError::ZipEntryUncPath { .. })
        ));
    }

    #[test]
    fn rejects_empty_path() {
        assert!(matches!(
            normalize(""),
            Err(GkrmError::ZipEntryPathEmpty { .. })
        ));
    }

    #[test]
    fn rejects_current_directory_component() {
        assert!(matches!(
            normalize("./file.txt"),
            Err(GkrmError::ZipEntryCurrentDirectory { .. })
        ));
    }

    #[test]
    fn rejects_empty_component() {
        assert!(matches!(
            normalize("resource//file.txt"),
            Err(GkrmError::ZipEntryEmptyComponent { .. })
        ));
    }

    #[test]
    fn rejects_nul_and_control_characters() {
        assert!(matches!(
            normalize("resource/config.lua\0.txt"),
            Err(GkrmError::ZipEntryControlCharacter { codepoint: 0, .. })
        ));
        assert!(matches!(
            normalize("resource/config\n.lua"),
            Err(GkrmError::ZipEntryControlCharacter { codepoint: 10, .. })
        ));
        assert!(matches!(
            normalize("resource/config\r.lua"),
            Err(GkrmError::ZipEntryControlCharacter { codepoint: 13, .. })
        ));
        assert!(matches!(
            normalize("resource/config\t.lua"),
            Err(GkrmError::ZipEntryControlCharacter { codepoint: 9, .. })
        ));
        assert!(matches!(
            normalize("resource/config\u{7f}.lua"),
            Err(GkrmError::ZipEntryControlCharacter { codepoint: 127, .. })
        ));
    }

    #[test]
    fn rejects_single_leading_backslash() {
        assert!(matches!(
            normalize("\\resource\\file.lua"),
            Err(GkrmError::ZipEntryWindowsRootPath { .. })
        ));
    }

    #[test]
    fn rejects_windows_invalid_characters() {
        for character in ['<', '>', ':', '"', '|', '?', '*'] {
            let path = format!("resource/file{character}.lua");
            assert!(
                matches!(
                    normalize(&path),
                    Err(GkrmError::ZipEntryWindowsInvalidCharacter { .. })
                ),
                "{path:?} should be rejected"
            );
        }

        assert!(matches!(
            normalize("resource/file.txt:ads"),
            Err(GkrmError::ZipEntryWindowsInvalidCharacter { .. })
        ));
    }

    #[test]
    fn rejects_components_ending_in_dot_or_space() {
        assert!(matches!(
            normalize("resource/file."),
            Err(GkrmError::ZipEntryWindowsTrailingDotOrSpace { .. })
        ));
        assert!(matches!(
            normalize("resource/file "),
            Err(GkrmError::ZipEntryWindowsTrailingDotOrSpace { .. })
        ));
    }

    #[test]
    fn rejects_windows_reserved_device_names() {
        for component in [
            "CON", "con", "CON.txt", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9",
        ] {
            let path = format!("resource/{component}");
            assert!(
                matches!(
                    normalize(&path),
                    Err(GkrmError::ZipEntryWindowsReservedName { .. })
                ),
                "{path:?} should be rejected"
            );
        }
    }
}
