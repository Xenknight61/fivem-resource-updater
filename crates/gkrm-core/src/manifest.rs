use std::io::Read;

use full_moon::ast::{
    Block, Call, Expression, Field, FunctionArgs, FunctionCall, GenericFor, If, NumericFor, Prefix,
    Repeat, Stmt, Suffix, TableConstructor, While,
};
use full_moon::node::Node;
use full_moon::tokenizer::{Position, StringLiteralQuoteType, TokenReference, TokenType};
use zip::ZipArchive;

use crate::{
    package_source::PackageSnapshot, GkrmError, Result, ZipEntryInfo, ZipEntryKind, ZipInspection,
    ZipRelativePath, ZipResourceDiscovery, ZipResourceRoot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestLimits {
    pub max_manifest_size: u64,
    pub max_tokens: usize,
}

impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_manifest_size: 1024 * 1024,
            max_tokens: 50_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipManifestParseReport {
    pub resources: Vec<ParsedZipResourceManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedZipResourceManifest {
    pub resource_root: ZipResourceRoot,
    pub manifest_path: ZipRelativePath,
    pub manifest: FxManifest,
    pub warnings: Vec<FxManifestWarning>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FxManifest {
    pub fx_versions: Vec<ManifestString>,
    pub games: Vec<ManifestString>,
    pub versions: Vec<ManifestString>,
    pub client_scripts: Vec<ManifestString>,
    pub server_scripts: Vec<ManifestString>,
    pub shared_scripts: Vec<ManifestString>,
    pub files: Vec<ManifestString>,
    pub ui_pages: Vec<ManifestString>,
    pub escrow_ignore: Vec<ManifestString>,
    pub dependencies: Vec<ManifestString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestString {
    pub value: String,
    pub declaration: ManifestDeclarationKind,
    pub order: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestDeclarationKind {
    FxVersion,
    Game,
    Games,
    Version,
    ClientScript,
    ClientScripts,
    ServerScript,
    ServerScripts,
    SharedScript,
    SharedScripts,
    File,
    Files,
    UiPage,
    EscrowIgnore,
    Dependency,
    Dependencies,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FxManifestWarning {
    UnsupportedExpression {
        declaration: ManifestDeclarationKind,
        line: usize,
        column: usize,
    },
    TableContainsNonStringValue {
        declaration: ManifestDeclarationKind,
        line: usize,
        column: usize,
    },
    NestedDeclarationIgnored {
        declaration: ManifestDeclarationKind,
        line: usize,
        column: usize,
    },
}

pub fn parse_zip_resource_manifests(
    inspection: &ZipInspection,
    discovery: &ZipResourceDiscovery,
    limits: ManifestLimits,
) -> Result<ZipManifestParseReport> {
    validate_manifest_entries(inspection, discovery)?;
    let snapshot =
        PackageSnapshot::create(&inspection.path, u64::MAX).map_err(|source| match source {
            GkrmError::ComparisonPackageOpen {
                path,
                cause: source,
            } => GkrmError::ManifestZipOpen {
                path,
                cause: source,
            },
            GkrmError::ZipPackageOpen {
                path,
                cause: source,
            } => GkrmError::ManifestZipOpen {
                path,
                cause: source,
            },
            GkrmError::ZipArchiveRead {
                path,
                cause: source,
            } => GkrmError::ManifestZipArchiveRead {
                path,
                cause: source,
            },
            other => other,
        })?;
    parse_zip_resource_manifests_from_snapshot(&snapshot, inspection, discovery, limits)
}

fn validate_manifest_entries(
    inspection: &ZipInspection,
    discovery: &ZipResourceDiscovery,
) -> Result<()> {
    for resource in &discovery.resources {
        let manifest_entry = inspection
            .entries
            .iter()
            .find(|entry| entry.path == resource.manifest_path)
            .ok_or_else(|| GkrmError::ManifestEntryMissing {
                entry: resource.manifest_path.to_string(),
            })?;

        if manifest_entry.kind != ZipEntryKind::File {
            return Err(GkrmError::ManifestEntryNotFile {
                entry: manifest_entry.path.to_string(),
            });
        }
    }

    Ok(())
}

pub(crate) fn parse_zip_resource_manifests_from_snapshot(
    snapshot: &PackageSnapshot,
    inspection: &ZipInspection,
    discovery: &ZipResourceDiscovery,
    limits: ManifestLimits,
) -> Result<ZipManifestParseReport> {
    let mut manifest_entries = Vec::with_capacity(discovery.resources.len());
    for resource in &discovery.resources {
        let manifest_entry = inspection
            .entries
            .iter()
            .find(|entry| entry.path == resource.manifest_path)
            .ok_or_else(|| GkrmError::ManifestEntryMissing {
                entry: resource.manifest_path.to_string(),
            })?;

        if manifest_entry.kind != ZipEntryKind::File {
            return Err(GkrmError::ManifestEntryNotFile {
                entry: manifest_entry.path.to_string(),
            });
        }

        manifest_entries.push(manifest_entry);
    }

    let mut archive = snapshot.open_zip_archive().map_err(|source| match source {
        GkrmError::ZipPackageOpen {
            path,
            cause: source,
        } => GkrmError::ManifestZipOpen {
            path,
            cause: source,
        },
        GkrmError::ZipArchiveRead {
            path,
            cause: source,
        } => GkrmError::ManifestZipArchiveRead {
            path,
            cause: source,
        },
        other => other,
    })?;

    let mut resources = Vec::with_capacity(discovery.resources.len());

    for (resource, manifest_entry) in discovery.resources.iter().zip(manifest_entries) {
        let contents = read_manifest_entry(&mut archive, manifest_entry, limits)?;
        let (manifest, warnings) = parse_manifest_source(&manifest_entry.path, contents, limits)?;

        resources.push(ParsedZipResourceManifest {
            resource_root: resource.root.clone(),
            manifest_path: resource.manifest_path.clone(),
            manifest,
            warnings,
        });
    }

    Ok(ZipManifestParseReport { resources })
}

/// Parse only the selected discovered resource's `fxmanifest.lua` from a snapshot.
pub(crate) fn parse_selected_zip_resource_manifest_from_snapshot(
    snapshot: &PackageSnapshot,
    inspection: &ZipInspection,
    resource: &crate::DiscoveredZipResource,
    limits: ManifestLimits,
) -> Result<ParsedZipResourceManifest> {
    let manifest_entry = inspection
        .entries
        .iter()
        .find(|entry| entry.path == resource.manifest_path)
        .ok_or_else(|| GkrmError::ManifestEntryMissing {
            entry: resource.manifest_path.to_string(),
        })?;
    if manifest_entry.kind != ZipEntryKind::File {
        return Err(GkrmError::ManifestEntryNotFile {
            entry: manifest_entry.path.to_string(),
        });
    }

    let mut archive = snapshot.open_zip_archive().map_err(|source| match source {
        GkrmError::ZipPackageOpen {
            path,
            cause: source,
        } => GkrmError::ManifestZipOpen {
            path,
            cause: source,
        },
        GkrmError::ZipArchiveRead {
            path,
            cause: source,
        } => GkrmError::ManifestZipArchiveRead {
            path,
            cause: source,
        },
        other => other,
    })?;
    let contents = read_manifest_entry(&mut archive, manifest_entry, limits)?;
    let (manifest, warnings) = parse_manifest_source(&manifest_entry.path, contents, limits)?;
    Ok(ParsedZipResourceManifest {
        resource_root: resource.root.clone(),
        manifest_path: resource.manifest_path.clone(),
        manifest,
        warnings,
    })
}

fn read_manifest_entry<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    expected: &ZipEntryInfo,
    limits: ManifestLimits,
) -> Result<String> {
    if expected.uncompressed_size > limits.max_manifest_size {
        return Err(GkrmError::ManifestSizeLimitExceeded {
            entry: expected.path.to_string(),
            limit: limits.max_manifest_size,
            actual: expected.uncompressed_size,
        });
    }

    {
        let entry = archive
            .by_index_raw(expected.archive_index)
            .map_err(|source| GkrmError::ManifestZipEntryChanged {
                entry: expected.path.to_string(),
                reason: source.to_string(),
            })?;
        let actual_path =
            ZipRelativePath::new(expected.archive_index, entry.name_raw()).map_err(|source| {
                GkrmError::ManifestZipEntryChanged {
                    entry: expected.path.to_string(),
                    reason: source.to_string(),
                }
            })?;
        let actual_kind = if entry.is_dir() {
            ZipEntryKind::Directory
        } else {
            ZipEntryKind::File
        };

        if actual_path != expected.path
            || actual_kind != expected.kind
            || entry.compressed_size() != expected.compressed_size
            || entry.size() != expected.uncompressed_size
            || entry.crc32() != expected.crc32
            || entry.compression() != expected.compression_method
            || entry.encrypted() != expected.encrypted
            || entry.unix_mode() != expected.unix_mode
        {
            return Err(GkrmError::ManifestZipEntryChanged {
                entry: expected.path.to_string(),
                reason: "path, kind, size, CRC32, compression, encryption, or Unix mode metadata no longer matches inspection".to_owned(),
            });
        }
    }

    let mut entry = archive.by_index(expected.archive_index).map_err(|source| {
        GkrmError::ManifestZipEntryRead {
            entry: expected.path.to_string(),
            cause: source,
        }
    })?;
    let mut contents = Vec::new();
    let mut limited = (&mut entry).take(limits.max_manifest_size.saturating_add(1));
    limited
        .read_to_end(&mut contents)
        .map_err(|source| GkrmError::ManifestRead {
            entry: expected.path.to_string(),
            cause: source,
        })?;

    if contents.len() as u64 > limits.max_manifest_size {
        return Err(GkrmError::ManifestSizeLimitExceeded {
            entry: expected.path.to_string(),
            limit: limits.max_manifest_size,
            actual: contents.len() as u64,
        });
    }

    if contents.len() as u64 != expected.uncompressed_size {
        return Err(GkrmError::ManifestZipEntryChanged {
            entry: expected.path.to_string(),
            reason: "streamed manifest size no longer matches inspection".to_owned(),
        });
    }

    String::from_utf8(contents).map_err(|source| GkrmError::ManifestInvalidUtf8 {
        entry: expected.path.to_string(),
        cause: source,
    })
}

/// Parse a resource manifest that did not come out of a package.
///
/// The manifest is read, never executed — the same bounded, panic-guarded parse a packaged one
/// gets. `entry` names it only so a failure can say which file it was.
pub fn parse_resource_manifest_source(
    entry: &str,
    source: String,
    limits: ManifestLimits,
) -> Result<(FxManifest, Vec<FxManifestWarning>)> {
    parse_manifest_entry(entry.to_owned(), source, limits)
}

/// The `version` a manifest declares, if it declares exactly one.
///
/// A manifest with none has nothing to report; one with several is describing something this
/// cannot summarise honestly, so it reports nothing either.
pub fn declared_manifest_version(manifest: &FxManifest) -> Option<&str> {
    match manifest.versions.as_slice() {
        [only] => Some(only.value.as_str()),
        _ => None,
    }
}

fn parse_manifest_source(
    manifest_path: &ZipRelativePath,
    source: String,
    limits: ManifestLimits,
) -> Result<(FxManifest, Vec<FxManifestWarning>)> {
    parse_manifest_entry(manifest_path.to_string(), source, limits)
}

fn parse_manifest_entry(
    entry: String,
    source: String,
    limits: ManifestLimits,
) -> Result<(FxManifest, Vec<FxManifestWarning>)> {
    let parsed = std::panic::catch_unwind(|| full_moon::parse(&source))
        .map_err(|_| GkrmError::ManifestParserPanic {
            entry: entry.clone(),
        })?
        .map_err(|errors| GkrmError::ManifestLuaSyntax {
            entry: entry.clone(),
            errors: format!("{errors:?}"),
        })?;

    enforce_token_limit(&parsed, &entry, limits.max_tokens)?;

    extract_manifest(parsed.nodes(), &entry)
}

fn enforce_token_limit(parsed: &full_moon::ast::Ast, entry: &str, limit: usize) -> Result<()> {
    let mut actual = 0_usize;
    for _ in parsed.tokens() {
        actual += 1;
        if actual > limit {
            return Err(GkrmError::ManifestTokenLimitExceeded {
                entry: entry.to_owned(),
                limit,
                actual,
            });
        }
    }

    Ok(())
}

fn extract_manifest(block: &Block, entry: &str) -> Result<(FxManifest, Vec<FxManifestWarning>)> {
    let mut extractor = ManifestExtractor::default();

    for stmt in block.stmts() {
        match stmt {
            Stmt::FunctionCall(call) => extractor.extract_top_level_call(call, entry)?,
            _ => {
                if let Some((declaration, position)) = nested_supported_declaration(stmt) {
                    extractor
                        .warnings
                        .push(FxManifestWarning::NestedDeclarationIgnored {
                            declaration,
                            line: position.line(),
                            column: position.character(),
                        });
                }
            }
        }
    }

    Ok((extractor.manifest, extractor.warnings))
}

#[derive(Default)]
struct ManifestExtractor {
    manifest: FxManifest,
    warnings: Vec<FxManifestWarning>,
    next_order: usize,
}

impl ManifestExtractor {
    fn extract_top_level_call(&mut self, call: &FunctionCall, entry: &str) -> Result<()> {
        let Some((name, args, position)) = supported_call(call) else {
            return Ok(());
        };
        let Some(declaration) = ManifestDeclarationKind::from_name(&name) else {
            return Ok(());
        };
        let Some(args) = args else {
            self.warnings
                .push(FxManifestWarning::UnsupportedExpression {
                    declaration,
                    line: position.line(),
                    column: position.character(),
                });
            return Ok(());
        };

        match extract_values(declaration, args, entry)? {
            ValueExtraction::Values(values) => {
                for value in values {
                    self.push_value(declaration, value);
                }
            }
            ValueExtraction::UnsupportedExpression => {
                self.warnings
                    .push(FxManifestWarning::UnsupportedExpression {
                        declaration,
                        line: position.line(),
                        column: position.character(),
                    });
            }
            ValueExtraction::TableContainsNonStringValue => {
                self.warnings
                    .push(FxManifestWarning::TableContainsNonStringValue {
                        declaration,
                        line: position.line(),
                        column: position.character(),
                    });
            }
        }

        Ok(())
    }

    fn push_value(&mut self, declaration: ManifestDeclarationKind, value: String) {
        let manifest_string = ManifestString {
            value,
            declaration,
            order: self.next_order,
        };
        self.next_order += 1;

        match declaration.normalized_field() {
            NormalizedManifestField::FxVersions => self.manifest.fx_versions.push(manifest_string),
            NormalizedManifestField::Games => self.manifest.games.push(manifest_string),
            NormalizedManifestField::Versions => self.manifest.versions.push(manifest_string),
            NormalizedManifestField::ClientScripts => {
                self.manifest.client_scripts.push(manifest_string);
            }
            NormalizedManifestField::ServerScripts => {
                self.manifest.server_scripts.push(manifest_string);
            }
            NormalizedManifestField::SharedScripts => {
                self.manifest.shared_scripts.push(manifest_string);
            }
            NormalizedManifestField::Files => self.manifest.files.push(manifest_string),
            NormalizedManifestField::UiPages => self.manifest.ui_pages.push(manifest_string),
            NormalizedManifestField::EscrowIgnore => {
                self.manifest.escrow_ignore.push(manifest_string);
            }
            NormalizedManifestField::Dependencies => {
                self.manifest.dependencies.push(manifest_string);
            }
        }
    }
}

enum ValueExtraction {
    Values(Vec<String>),
    UnsupportedExpression,
    TableContainsNonStringValue,
}

fn extract_values(
    declaration: ManifestDeclarationKind,
    args: &FunctionArgs,
    entry: &str,
) -> Result<ValueExtraction> {
    match args {
        FunctionArgs::String(token) => Ok(string_literal_value(token, entry)?
            .map(|value| ValueExtraction::Values(vec![value]))
            .unwrap_or(ValueExtraction::UnsupportedExpression)),
        FunctionArgs::TableConstructor(table) => extract_table_values(declaration, table, entry),
        FunctionArgs::Parentheses { arguments, .. } => {
            let mut arguments = arguments.iter();
            let Some(argument) = arguments.next() else {
                return Ok(ValueExtraction::UnsupportedExpression);
            };
            if arguments.next().is_some() {
                return Ok(ValueExtraction::UnsupportedExpression);
            }

            Ok(match argument {
                Expression::String(token) => string_literal_value(token, entry)?
                    .map(|value| ValueExtraction::Values(vec![value]))
                    .unwrap_or(ValueExtraction::UnsupportedExpression),
                Expression::TableConstructor(table) => {
                    return extract_table_values(declaration, table, entry);
                }
                Expression::Parentheses { expression, .. } => match expression.as_ref() {
                    Expression::String(token) => string_literal_value(token, entry)?
                        .map(|value| ValueExtraction::Values(vec![value]))
                        .unwrap_or(ValueExtraction::UnsupportedExpression),
                    Expression::TableConstructor(table) => {
                        return extract_table_values(declaration, table, entry);
                    }
                    _ => ValueExtraction::UnsupportedExpression,
                },
                _ => ValueExtraction::UnsupportedExpression,
            })
        }
        _ => Ok(ValueExtraction::UnsupportedExpression),
    }
}

fn extract_table_values(
    _declaration: ManifestDeclarationKind,
    table: &TableConstructor,
    entry: &str,
) -> Result<ValueExtraction> {
    let mut values = Vec::new();

    for field in table.fields().iter() {
        let Field::NoKey(Expression::String(token)) = field else {
            return Ok(ValueExtraction::TableContainsNonStringValue);
        };
        let Some(value) = string_literal_value(token, entry)? else {
            return Ok(ValueExtraction::TableContainsNonStringValue);
        };
        values.push(value);
    }

    Ok(ValueExtraction::Values(values))
}

fn supported_call(call: &FunctionCall) -> Option<(String, Option<&FunctionArgs>, Position)> {
    let Prefix::Name(name) = call.prefix() else {
        return None;
    };
    let name_text = name.token().to_string();
    let mut suffixes = call.suffixes();
    let first_suffix = suffixes.next()?;
    if suffixes.next().is_some() {
        return Some((name_text, None, name.token().start_position()));
    }

    match first_suffix {
        Suffix::Call(Call::AnonymousCall(args)) => {
            Some((name_text, Some(args), name.token().start_position()))
        }
        _ => Some((name_text, None, name.token().start_position())),
    }
}

fn string_literal_value(token: &TokenReference, entry: &str) -> Result<Option<String>> {
    match token.token().token_type() {
        TokenType::StringLiteral {
            literal,
            quote_type: StringLiteralQuoteType::Single | StringLiteralQuoteType::Double,
            ..
        } => decode_lua_string_literal(literal.as_str(), entry).map(Some),
        _ => Ok(None),
    }
}

fn decode_lua_string_literal(literal: &str, entry: &str) -> Result<String> {
    let mut output = String::new();
    let mut chars = literal.chars().peekable();

    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }

        let Some(escaped) = chars.next() else {
            return invalid_escape(entry, "incomplete escape sequence");
        };

        match escaped {
            'a' => output.push('\u{0007}'),
            'b' => output.push('\u{0008}'),
            'f' => output.push('\u{000c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{000b}'),
            '\\' => output.push('\\'),
            '\'' => output.push('\''),
            '"' => output.push('"'),
            '\n' => output.push('\n'),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                output.push('\n');
            }
            'z' => {
                while chars
                    .peek()
                    .is_some_and(|character| character.is_whitespace())
                {
                    chars.next();
                }
            }
            'x' => {
                let high = take_hex_digit(&mut chars, entry, "incomplete hexadecimal escape")?;
                let low = take_hex_digit(&mut chars, entry, "incomplete hexadecimal escape")?;
                let value = high * 16 + low;
                push_byte_escape(&mut output, value as u8);
            }
            'u' => {
                decode_unicode_escape(&mut output, &mut chars, entry)?;
            }
            digit if digit.is_ascii_digit() => {
                let mut value =
                    digit
                        .to_digit(10)
                        .ok_or_else(|| GkrmError::ManifestInvalidStringEscape {
                            entry: entry.to_owned(),
                            message: "decimal escape contains a non-decimal digit".to_owned(),
                        })?;
                for _ in 0..2 {
                    let Some(next) = chars.peek().copied() else {
                        break;
                    };
                    if !next.is_ascii_digit() {
                        break;
                    }
                    chars.next();
                    value = value * 10
                        + next.to_digit(10).ok_or_else(|| {
                            GkrmError::ManifestInvalidStringEscape {
                                entry: entry.to_owned(),
                                message: "decimal escape contains a non-decimal digit".to_owned(),
                            }
                        })?;
                }
                if value > u8::MAX as u32 {
                    return invalid_escape(entry, "decimal escape exceeds 255");
                }
                push_byte_escape(&mut output, value as u8);
            }
            _ => return invalid_escape(entry, "unsupported escape sequence"),
        }
    }

    Ok(output)
}

fn take_hex_digit<I>(chars: &mut std::iter::Peekable<I>, entry: &str, message: &str) -> Result<u32>
where
    I: Iterator<Item = char>,
{
    let Some(character) = chars.next() else {
        return invalid_escape(entry, message);
    };

    character
        .to_digit(16)
        .ok_or_else(|| GkrmError::ManifestInvalidStringEscape {
            entry: entry.to_owned(),
            message: message.to_owned(),
        })
}

fn decode_unicode_escape<I>(
    output: &mut String,
    chars: &mut std::iter::Peekable<I>,
    entry: &str,
) -> Result<()>
where
    I: Iterator<Item = char>,
{
    if chars.next() != Some('{') {
        return invalid_escape(entry, "Unicode escape must start with '{'");
    }

    let mut digits = 0_usize;
    let mut value = 0_u32;
    loop {
        let Some(character) = chars.next() else {
            return invalid_escape(entry, "unterminated Unicode escape");
        };
        if character == '}' {
            break;
        }

        let Some(digit) = character.to_digit(16) else {
            return invalid_escape(entry, "Unicode escape contains a non-hex digit");
        };
        digits += 1;
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| GkrmError::ManifestInvalidStringEscape {
                entry: entry.to_owned(),
                message: "Unicode escape overflows".to_owned(),
            })?;
    }

    if digits == 0 {
        return invalid_escape(entry, "Unicode escape has no digits");
    }

    let Some(character) = char::from_u32(value) else {
        return invalid_escape(entry, "Unicode escape is not a valid scalar value");
    };
    output.push(character);

    Ok(())
}

fn push_byte_escape(output: &mut String, value: u8) {
    output.push(char::from(value));
}

fn invalid_escape<T>(entry: &str, message: &str) -> Result<T> {
    Err(GkrmError::ManifestInvalidStringEscape {
        entry: entry.to_owned(),
        message: message.to_owned(),
    })
}

fn nested_supported_declaration(stmt: &Stmt) -> Option<(ManifestDeclarationKind, Position)> {
    match stmt {
        Stmt::Do(stmt) => block_contains_supported_declaration(stmt.block()),
        Stmt::FunctionDeclaration(stmt) => {
            block_contains_supported_declaration(stmt.body().block())
        }
        Stmt::GenericFor(stmt) => generic_for_contains_supported_declaration(stmt),
        Stmt::If(stmt) => if_contains_supported_declaration(stmt),
        Stmt::LocalFunction(stmt) => block_contains_supported_declaration(stmt.body().block()),
        Stmt::NumericFor(stmt) => numeric_for_contains_supported_declaration(stmt),
        Stmt::Repeat(stmt) => repeat_contains_supported_declaration(stmt),
        Stmt::While(stmt) => while_contains_supported_declaration(stmt),
        _ => None,
    }
}

fn block_contains_supported_declaration(
    block: &Block,
) -> Option<(ManifestDeclarationKind, Position)> {
    for stmt in block.stmts() {
        if let Stmt::FunctionCall(call) = stmt {
            let Some((name, _, position)) = supported_call(call) else {
                continue;
            };
            if let Some(declaration) = ManifestDeclarationKind::from_name(&name) {
                return Some((declaration, position));
            }
        }

        if let Some(nested) = nested_supported_declaration(stmt) {
            return Some(nested);
        }
    }

    None
}

fn if_contains_supported_declaration(stmt: &If) -> Option<(ManifestDeclarationKind, Position)> {
    block_contains_supported_declaration(stmt.block())
        .or_else(|| {
            stmt.else_if()?
                .iter()
                .find_map(|else_if| block_contains_supported_declaration(else_if.block()))
        })
        .or_else(|| {
            stmt.else_block()
                .and_then(block_contains_supported_declaration)
        })
}

fn generic_for_contains_supported_declaration(
    stmt: &GenericFor,
) -> Option<(ManifestDeclarationKind, Position)> {
    block_contains_supported_declaration(stmt.block())
}

fn numeric_for_contains_supported_declaration(
    stmt: &NumericFor,
) -> Option<(ManifestDeclarationKind, Position)> {
    block_contains_supported_declaration(stmt.block())
}

fn repeat_contains_supported_declaration(
    stmt: &Repeat,
) -> Option<(ManifestDeclarationKind, Position)> {
    block_contains_supported_declaration(stmt.block())
}

fn while_contains_supported_declaration(
    stmt: &While,
) -> Option<(ManifestDeclarationKind, Position)> {
    block_contains_supported_declaration(stmt.block())
}

impl ManifestDeclarationKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "fx_version" => Some(Self::FxVersion),
            "game" => Some(Self::Game),
            "games" => Some(Self::Games),
            "version" => Some(Self::Version),
            "client_script" => Some(Self::ClientScript),
            "client_scripts" => Some(Self::ClientScripts),
            "server_script" => Some(Self::ServerScript),
            "server_scripts" => Some(Self::ServerScripts),
            "shared_script" => Some(Self::SharedScript),
            "shared_scripts" => Some(Self::SharedScripts),
            "file" => Some(Self::File),
            "files" => Some(Self::Files),
            "ui_page" => Some(Self::UiPage),
            "escrow_ignore" => Some(Self::EscrowIgnore),
            "dependency" => Some(Self::Dependency),
            "dependencies" => Some(Self::Dependencies),
            _ => None,
        }
    }

    fn normalized_field(self) -> NormalizedManifestField {
        match self {
            Self::FxVersion => NormalizedManifestField::FxVersions,
            Self::Game | Self::Games => NormalizedManifestField::Games,
            Self::Version => NormalizedManifestField::Versions,
            Self::ClientScript | Self::ClientScripts => NormalizedManifestField::ClientScripts,
            Self::ServerScript | Self::ServerScripts => NormalizedManifestField::ServerScripts,
            Self::SharedScript | Self::SharedScripts => NormalizedManifestField::SharedScripts,
            Self::File | Self::Files => NormalizedManifestField::Files,
            Self::UiPage => NormalizedManifestField::UiPages,
            Self::EscrowIgnore => NormalizedManifestField::EscrowIgnore,
            Self::Dependency | Self::Dependencies => NormalizedManifestField::Dependencies,
        }
    }
}

enum NormalizedManifestField {
    FxVersions,
    Games,
    Versions,
    ClientScripts,
    ServerScripts,
    SharedScripts,
    Files,
    UiPages,
    EscrowIgnore,
    Dependencies,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use zip::CompressionMethod;

    fn limits() -> ManifestLimits {
        ManifestLimits {
            max_manifest_size: 4096,
            max_tokens: 512,
        }
    }

    fn parse(source: &str) -> Result<(FxManifest, Vec<FxManifestWarning>)> {
        let path = ZipRelativePath::new(0, b"fxmanifest.lua").expect("path should be valid");
        parse_manifest_source(&path, source.to_owned(), limits())
    }

    fn values(strings: &[ManifestString]) -> Vec<&str> {
        strings.iter().map(|value| value.value.as_str()).collect()
    }

    fn entry(path: &str, kind: ZipEntryKind) -> ZipEntryInfo {
        ZipEntryInfo {
            archive_index: 0,
            path: ZipRelativePath::new(0, path.as_bytes()).expect("path should be valid"),
            compressed_size: 0,
            uncompressed_size: 0,
            crc32: 0,
            compression_method: CompressionMethod::Stored,
            encrypted: false,
            unix_mode: None,
            kind,
        }
    }

    #[test]
    fn parses_singular_and_plural_declarations() {
        let (manifest, warnings) = parse(
            r#"
            fx_version 'cerulean'
            game 'gta5'
            games { 'gta5', 'rdr3' }
            version '2.5.0'
            client_script 'client/main.lua'
            client_scripts { 'client/*.lua', 'client/apps/**/*.lua' }
            server_script 'server/main.lua'
            server_scripts { 'server/*.lua' }
            shared_script 'shared/main.lua'
            shared_scripts { 'shared/*.lua' }
            file 'html/index.html'
            files { 'html/assets/*' }
            ui_page 'html/index.html'
            escrow_ignore { 'config.lua' }
            dependency 'oxmysql'
            dependencies { 'qb-core' }
            "#,
        )
        .expect("manifest should parse");

        assert!(warnings.is_empty());
        assert_eq!(values(&manifest.fx_versions), vec!["cerulean"]);
        assert_eq!(values(&manifest.games), vec!["gta5", "gta5", "rdr3"]);
        assert_eq!(values(&manifest.versions), vec!["2.5.0"]);
        assert_eq!(
            values(&manifest.client_scripts),
            vec!["client/main.lua", "client/*.lua", "client/apps/**/*.lua"]
        );
        assert_eq!(
            values(&manifest.server_scripts),
            vec!["server/main.lua", "server/*.lua"]
        );
        assert_eq!(
            values(&manifest.shared_scripts),
            vec!["shared/main.lua", "shared/*.lua"]
        );
        assert_eq!(
            values(&manifest.files),
            vec!["html/index.html", "html/assets/*"]
        );
        assert_eq!(values(&manifest.ui_pages), vec!["html/index.html"]);
        assert_eq!(values(&manifest.escrow_ignore), vec!["config.lua"]);
        assert_eq!(values(&manifest.dependencies), vec!["oxmysql", "qb-core"]);
    }

    #[test]
    fn parses_parenthesized_and_shorthand_calls() {
        let (manifest, warnings) = parse(
            r#"
            client_script('client/a.lua')
            client_script "client/b.lua"
            files({
                'html/index.html',
                'html/assets/*',
            })
            "#,
        )
        .expect("manifest should parse");

        assert!(warnings.is_empty());
        assert_eq!(
            values(&manifest.client_scripts),
            vec!["client/a.lua", "client/b.lua"]
        );
        assert_eq!(
            values(&manifest.files),
            vec!["html/index.html", "html/assets/*"]
        );
    }

    #[test]
    fn supports_comments_trailing_commas_and_valid_lua_escapes() {
        let (manifest, warnings) = parse(
            r#"
            -- client_script 'commented.lua'
            --[[
            server_script 'commented.lua'
            ]]
            client_scripts {
                "client\nmain.lua",
                'client\'quoted.lua',
            }
            "#,
        )
        .expect("manifest should parse");

        assert!(warnings.is_empty());
        assert_eq!(
            values(&manifest.client_scripts),
            vec!["client\nmain.lua", "client'quoted.lua"]
        );
        assert!(manifest.server_scripts.is_empty());
    }

    #[test]
    fn decodes_lua_string_escapes() {
        let (manifest, warnings) = parse(
            r#"
            files {
                '\\',
                '\'',
                "\"",
                '\a',
                '\b',
                '\f',
                '\n',
                '\r',
                '\t',
                '\v',
                '\65',
                '\x41',
                '\u{1F600}',
                'a\z
                   b',
                'a\
b',
            }
            "#,
        )
        .expect("manifest should parse");

        assert!(warnings.is_empty());
        assert_eq!(
            values(&manifest.files),
            vec![
                "\\", "'", "\"", "\u{0007}", "\u{0008}", "\u{000c}", "\n", "\r", "\t", "\u{000b}",
                "A", "A", "😀", "ab", "a\nb",
            ]
        );
    }

    #[test]
    fn malformed_lua_string_escapes_are_hard_errors() {
        for source in [
            r"file '\q'",
            r"file '\x4'",
            r"file '\999'",
            r"file '\u{}'",
            r"file '\u{D800}'",
            r"file '\u{110000}'",
        ] {
            let err = parse(source).expect_err("malformed escape should fail");

            assert!(matches!(
                err,
                GkrmError::ManifestInvalidStringEscape { .. } | GkrmError::ManifestLuaSyntax { .. }
            ));
        }
    }

    #[test]
    fn preserves_duplicate_declaration_order() {
        let (manifest, warnings) = parse(
            r#"
            client_script 'a.lua'
            server_script 'server.lua'
            client_script 'b.lua'
            "#,
        )
        .expect("manifest should parse");

        assert!(warnings.is_empty());
        assert_eq!(values(&manifest.client_scripts), vec!["a.lua", "b.lua"]);
        assert_eq!(manifest.client_scripts[0].order, 0);
        assert_eq!(manifest.server_scripts[0].order, 1);
        assert_eq!(manifest.client_scripts[1].order, 2);
    }

    #[test]
    fn ignores_custom_metadata_without_warnings() {
        let (manifest, warnings) = parse(
            r#"
            author 'GKSHOP'
            description 'FiveM Phone'
            custom_metadata 'value'
            "#,
        )
        .expect("manifest should parse");

        assert!(warnings.is_empty());
        assert_eq!(manifest, FxManifest::default());
    }

    #[test]
    fn warns_for_dynamic_supported_declarations() {
        let (manifest, warnings) = parse(
            r#"
            local folder = 'client'
            client_script(folder .. '/main.lua')
            escrow_ignore(getIgnoredFiles())
            "#,
        )
        .expect("manifest should parse");

        assert!(manifest.client_scripts.is_empty());
        assert!(manifest.escrow_ignore.is_empty());
        assert_eq!(warnings.len(), 2);
        assert!(matches!(
            warnings[0],
            FxManifestWarning::UnsupportedExpression {
                declaration: ManifestDeclarationKind::ClientScript,
                ..
            }
        ));
        assert!(matches!(
            warnings[1],
            FxManifestWarning::UnsupportedExpression {
                declaration: ManifestDeclarationKind::EscrowIgnore,
                ..
            }
        ));
    }

    #[test]
    fn warns_and_extracts_no_values_for_tables_with_non_string_values() {
        let (manifest, warnings) = parse(
            r#"
            client_scripts { 'safe.lua', getFiles() }
            "#,
        )
        .expect("manifest should parse");

        assert!(manifest.client_scripts.is_empty());
        assert_eq!(
            warnings,
            vec![FxManifestWarning::TableContainsNonStringValue {
                declaration: ManifestDeclarationKind::ClientScripts,
                line: 2,
                column: 13
            }]
        );
    }

    #[test]
    fn nested_conditional_declarations_are_not_extracted() {
        let (manifest, warnings) = parse(
            r#"
            if Config.EnableSomething then
                client_script 'client/optional.lua'
            end
            "#,
        )
        .expect("manifest should parse");

        assert!(manifest.client_scripts.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            warnings[0],
            FxManifestWarning::NestedDeclarationIgnored {
                declaration: ManifestDeclarationKind::ClientScript,
                ..
            }
        ));
    }

    #[test]
    fn supported_declarations_in_nested_blocks_are_not_extracted() {
        for source in [
            r#"
            function register()
                escrow_ignore { 'config.lua' }
            end
            "#,
            r#"
            do
                client_script 'client/do.lua'
            end
            "#,
            r#"
            while Config.Enabled do
                client_script 'client/while.lua'
            end
            "#,
            r#"
            repeat
                client_script 'client/repeat.lua'
            until Config.Done
            "#,
            r#"
            for i = 1, 2 do
                client_script 'client/numeric.lua'
            end
            "#,
            r#"
            for _, file in pairs(files) do
                client_script(file)
            end
            "#,
            r#"
            if Config.Enabled then
                client_script 'client/if.lua'
            end
            "#,
        ] {
            let (manifest, warnings) = parse(source).expect("manifest should parse");

            assert!(manifest.client_scripts.is_empty());
            assert!(manifest.escrow_ignore.is_empty());
            assert_eq!(warnings.len(), 1, "{source}");
            assert!(matches!(
                warnings[0],
                FxManifestWarning::NestedDeclarationIgnored { .. }
            ));
        }
    }

    #[test]
    fn malformed_lua_is_hard_error() {
        let err = parse("client_script(").expect_err("malformed Lua should fail");

        assert!(matches!(err, GkrmError::ManifestLuaSyntax { .. }));
    }

    #[test]
    fn token_traversal_limit_is_hard_error() {
        let path = ZipRelativePath::new(0, b"fxmanifest.lua").expect("path should be valid");
        let err = parse_manifest_source(
            &path,
            "client_script 'client/main.lua'".to_owned(),
            ManifestLimits {
                max_manifest_size: 4096,
                max_tokens: 1,
            },
        )
        .expect_err("token limit should fail");

        assert!(matches!(err, GkrmError::ManifestTokenLimitExceeded { .. }));
    }

    #[test]
    fn manifest_entry_must_be_present_and_file() {
        let inspection = ZipInspection {
            path: PathBuf::from("package.zip"),
            entries: vec![entry("fxmanifest.lua", ZipEntryKind::Directory)],
        };
        let discovery = ZipResourceDiscovery {
            resources: vec![crate::DiscoveredZipResource {
                name: crate::ZipResourceName::ZipRoot,
                root: ZipResourceRoot::Root,
                manifest_path: ZipRelativePath::new(0, b"fxmanifest.lua")
                    .expect("path should be valid"),
                entries: Vec::new(),
            }],
            unassigned_entries: Vec::new(),
            warnings: Vec::new(),
        };

        let err = parse_zip_resource_manifests(&inspection, &discovery, limits())
            .expect_err("directory manifest should fail");

        assert!(matches!(err, GkrmError::ManifestEntryNotFile { .. }));
    }
}
