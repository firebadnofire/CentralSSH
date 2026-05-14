use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionError {
    message: &'static str,
}

impl VersionError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for VersionError {}

pub fn normalize_release_tag(tag: &str) -> Result<String, VersionError> {
    let version = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .ok_or_else(|| VersionError::new("release tag must start with v or V"))?;
    validate_semver(version)?;
    Ok(version.to_string())
}

#[allow(dead_code)]
pub fn runtime_version(version: &str, dist_build: bool) -> String {
    if dist_build {
        format!("{version}-distrb")
    } else {
        version.to_string()
    }
}

#[allow(dead_code)]
pub fn rewrite_manifest_version(contents: &str, version: &str) -> Result<String, VersionError> {
    let mut output = String::with_capacity(contents.len() + version.len());
    let mut in_package = false;
    let mut replaced = false;

    for line in contents.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let section = trimmed.trim();
        if section.starts_with('[') && section.ends_with(']') {
            in_package = section == "[package]";
        }

        if in_package && !replaced && trimmed.starts_with("version = ") {
            output.push_str("version = \"");
            output.push_str(version);
            output.push_str("\"\n");
            replaced = true;
            continue;
        }

        output.push_str(line);
    }

    if !replaced {
        return Err(VersionError::new(
            "failed to locate package version in Cargo.toml",
        ));
    }

    Ok(output)
}

fn validate_semver(version: &str) -> Result<(), VersionError> {
    let (core, prerelease, build) = split_version(version)?;
    validate_core(core)?;
    if let Some(prerelease) = prerelease {
        validate_identifiers(prerelease, true)?;
    }
    if let Some(build) = build {
        validate_identifiers(build, false)?;
    }
    Ok(())
}

fn split_version(version: &str) -> Result<(&str, Option<&str>, Option<&str>), VersionError> {
    let (core_and_pre, build) = match version.split_once('+') {
        Some((left, right)) => {
            if right.is_empty() || right.contains('+') {
                return Err(VersionError::new("invalid semantic version build metadata"));
            }
            (left, Some(right))
        }
        None => (version, None),
    };

    let (core, prerelease) = match core_and_pre.split_once('-') {
        Some((left, right)) => {
            if right.is_empty() {
                return Err(VersionError::new("invalid semantic version prerelease"));
            }
            (left, Some(right))
        }
        None => (core_and_pre, None),
    };

    Ok((core, prerelease, build))
}

fn validate_core(core: &str) -> Result<(), VersionError> {
    let mut parts = core.split('.');
    for _ in 0..3 {
        let part = parts
            .next()
            .ok_or_else(|| VersionError::new("semantic version must have major.minor.patch"))?;
        validate_numeric_identifier(part, false)?;
    }
    if parts.next().is_some() {
        return Err(VersionError::new("semantic version must have major.minor.patch"));
    }
    Ok(())
}

fn validate_identifiers(value: &str, forbid_leading_zero: bool) -> Result<(), VersionError> {
    for ident in value.split('.') {
        if ident.is_empty() {
            return Err(VersionError::new("semantic version identifiers must not be empty"));
        }
        if !ident
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(VersionError::new(
                "semantic version identifiers must be ASCII alphanumeric or hyphen",
            ));
        }
        if forbid_leading_zero && ident.chars().all(|c| c.is_ascii_digit()) {
            validate_numeric_identifier(ident, true)?;
        }
    }
    Ok(())
}

fn validate_numeric_identifier(value: &str, prerelease: bool) -> Result<(), VersionError> {
    if value.is_empty() {
        return Err(VersionError::new("semantic version identifiers must not be empty"));
    }
    if !value.chars().all(|c| c.is_ascii_digit()) {
        return Err(VersionError::new(
            "semantic version core identifiers must be numeric",
        ));
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(VersionError::new(
            "semantic version numeric identifiers must not have leading zeros",
        ));
    }
    if prerelease && value.starts_with('0') && value.len() > 1 {
        return Err(VersionError::new(
            "semantic version prerelease numeric identifiers must not have leading zeros",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_tag() {
        assert_eq!(
            normalize_release_tag("v0.0.36").unwrap(),
            "0.0.36"
        );
    }

    #[test]
    fn rejects_invalid_tag_prefix() {
        assert!(normalize_release_tag("0.0.36").is_err());
    }

    #[test]
    fn rejects_invalid_semver() {
        assert!(normalize_release_tag("v01.0.0").is_err());
    }

    #[test]
    fn formats_distribution_version() {
        assert_eq!(runtime_version("0.0.36", false), "0.0.36");
        assert_eq!(runtime_version("0.0.36", true), "0.0.36-distrb");
    }

    #[test]
    fn rewrites_manifest_package_version() {
        let input = r#"[package]
name = "centralssh"
version = "0.0.0-dev"
edition = "2024"

[dependencies]
foo = "1"
"#;
        let output = rewrite_manifest_version(input, "0.0.36").unwrap();
        assert!(output.contains("version = \"0.0.36\""));
        assert!(!output.contains("version = \"0.0.0-dev\""));
    }
}
