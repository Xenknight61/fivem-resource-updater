use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use crate::{GkrmError, Result};

/// Drop a leading `.` component from a relative path's components.
///
/// Every capability-relative opener anchors a relative path at the current directory and then
/// requires each remaining component to be `Component::Normal`. Rust emits `Component::CurDir`
/// only for an explicit leading `./`, and that component names the anchor directory that was
/// just opened, so walking it as a traversal step is meaningless and rejects the path.
///
/// This is not a boundary relaxation: `./name` becomes exactly `name` relative to the same
/// anchor, and `..`, prefixes, and every other non-`Normal` component stay rejected.
pub(crate) fn strip_leading_current_dir(components: Vec<Component<'_>>) -> Vec<Component<'_>> {
    if matches!(components.first(), Some(Component::CurDir)) {
        return components.into_iter().skip(1).collect();
    }
    components
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectRequest {
    pub installed: PathBuf,
    pub package: PathBuf,
}

impl InspectRequest {
    pub fn new(installed: impl Into<PathBuf>, package: impl Into<PathBuf>) -> Self {
        Self {
            installed: installed.into(),
            package: package.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_cli_installed_argument(&self.installed)?;
        validate_cli_package_argument(&self.package)
    }
}

/// Validate only CLI argument shape.
///
/// This is not a security boundary. The installed scanner performs no-follow
/// traversal and reparse-point rejection before trusting installed paths.
pub fn validate_cli_installed_argument(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|source| match source.kind() {
        ErrorKind::NotFound => GkrmError::InstalledPathMissing {
            path: path.to_path_buf(),
        },
        _ => GkrmError::InstalledPathMetadata {
            path: path.to_path_buf(),
            cause: source,
        },
    })?;

    if !metadata.file_type().is_dir() {
        return Err(GkrmError::InstalledPathNotDirectory {
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

/// Validate only CLI argument shape.
///
/// This is not a security boundary. Secure package snapshot creation opens
/// parent components and the final package with no-follow semantics.
pub fn validate_cli_package_argument(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|source| match source.kind() {
        ErrorKind::NotFound => GkrmError::PackagePathMissing {
            path: path.to_path_buf(),
        },
        _ => GkrmError::PackagePathMetadata {
            path: path.to_path_buf(),
            cause: source,
        },
    })?;

    if !metadata.file_type().is_file() {
        return Err(GkrmError::PackagePathNotFile {
            path: path.to_path_buf(),
        });
    }

    let is_zip = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"));

    if !is_zip {
        return Err(GkrmError::PackagePathNotZip {
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

pub fn validate_installed_path(path: &Path) -> Result<()> {
    validate_cli_installed_argument(path)
}

pub fn validate_package_path(path: &Path) -> Result<()> {
    validate_cli_package_argument(path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    fn components_of(path: &str) -> Vec<Component<'_>> {
        Path::new(path).components().collect()
    }

    #[test]
    fn strips_only_a_leading_current_directory_component() {
        assert_eq!(
            strip_leading_current_dir(components_of("./installed/gksphone")),
            components_of("installed/gksphone")
        );
        assert_eq!(
            strip_leading_current_dir(components_of("installed/gksphone")),
            components_of("installed/gksphone")
        );
        assert!(strip_leading_current_dir(components_of(".")).is_empty());
    }

    #[test]
    fn keeps_traversal_and_absolute_components_for_the_caller_to_reject() {
        assert_eq!(
            strip_leading_current_dir(components_of("./../installed")),
            components_of("../installed")
        );
        assert_eq!(
            strip_leading_current_dir(components_of("installed/../other")),
            components_of("installed/../other")
        );
        let absolute = components_of(if cfg!(windows) {
            r"C:\installed"
        } else {
            "/installed"
        });
        assert_eq!(strip_leading_current_dir(absolute.clone()), absolute);
    }

    #[test]
    fn validates_existing_installed_directory_and_zip_package() {
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).expect("installed dir should be created");
        let package = temp.path().join("update.zip");
        fs::write(&package, b"synthetic zip placeholder").expect("package should be created");

        let request = InspectRequest::new(installed, package);

        request.validate().expect("paths should validate");
    }

    #[test]
    fn accepts_uppercase_zip_extension() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("UPDATE.ZIP");
        fs::write(&package, b"synthetic zip placeholder").expect("package should be created");

        validate_cli_package_argument(&package).expect("uppercase zip extension should validate");
    }

    #[test]
    fn rejects_missing_installed_path() {
        let temp = tempdir().expect("temp dir should be created");

        let err = validate_cli_installed_argument(&temp.path().join("missing"))
            .expect_err("missing installed path should fail");

        assert!(matches!(err, GkrmError::InstalledPathMissing { .. }));
    }

    #[test]
    fn rejects_installed_path_that_is_not_directory() {
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("installed.txt");
        fs::write(&installed, b"not a directory").expect("installed file should be created");

        let err = validate_cli_installed_argument(&installed)
            .expect_err("installed file path should fail");

        assert!(matches!(err, GkrmError::InstalledPathNotDirectory { .. }));
    }

    #[test]
    fn rejects_missing_package_path() {
        let temp = tempdir().expect("temp dir should be created");

        let err = validate_cli_package_argument(&temp.path().join("missing.zip"))
            .expect_err("missing package path should fail");

        assert!(matches!(err, GkrmError::PackagePathMissing { .. }));
    }

    #[test]
    fn rejects_package_path_that_is_not_file() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package-dir.zip");
        fs::create_dir(&package).expect("package dir should be created");

        let err =
            validate_cli_package_argument(&package).expect_err("package directory should fail");

        assert!(matches!(err, GkrmError::PackagePathNotFile { .. }));
    }

    #[test]
    fn rejects_package_without_zip_extension() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("update.txt");
        fs::write(&package, b"not a zip").expect("package should be created");

        let err =
            validate_cli_package_argument(&package).expect_err("package without .zip should fail");

        assert!(matches!(err, GkrmError::PackagePathNotZip { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_package_symlink_as_cli_shape_validation_only() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("temp dir should be created");
        let target = temp.path().join("target.zip");
        let package = temp.path().join("package.zip");
        fs::write(&target, b"synthetic zip placeholder").expect("package should be created");
        symlink(&target, &package).expect("package symlink should be created");

        validate_cli_package_argument(&package)
            .expect("CLI shape validation should not reject symlinks");
    }
}
