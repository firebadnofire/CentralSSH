use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{
    validate_directory_security, validate_file_security, validate_path_has_no_symlinks,
};
use crate::error::{CentralSshError, Result};

const PRIVATE_KEY_FILENAME: &str = "id_ed25519";

pub fn resolve_user_server_private_key_path(
    user_key_root: &Path,
    username: &str,
    server_name: &str,
    enforce_strict_security: bool,
) -> Result<PathBuf> {
    validate_component(username, "username")?;
    validate_component(server_name, "server name")?;

    let user_dir = user_key_root.join(username);
    let server_dir = user_dir.join(server_name);
    let private_key_path = server_dir.join(PRIVATE_KEY_FILENAME);

    if enforce_strict_security {
        validate_directory_security(user_key_root, 0o700, true)?;
        validate_directory_security(&user_dir, 0o700, true)?;
        validate_directory_security(&server_dir, 0o700, true)?;
        validate_file_security(&private_key_path, 0o600, true)?;
    } else {
        validate_existing_regular_directory(user_key_root)?;
        validate_existing_regular_directory(&user_dir)?;
        validate_existing_regular_directory(&server_dir)?;
        validate_existing_regular_file(&private_key_path)?;
    }

    Ok(private_key_path)
}

fn validate_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 {
        return Err(CentralSshError::InvalidConfig(format!(
            "invalid {label}: length must be 1-64 characters"
        )));
    }

    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err(CentralSshError::InvalidConfig(format!(
            "invalid {label}: only [a-zA-Z0-9._-] are allowed"
        )));
    }

    Ok(())
}

fn validate_existing_regular_directory(path: &Path) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "expected a real directory".to_string(),
        });
    }
    Ok(())
}

fn validate_existing_regular_file(path: &Path) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "expected a real file".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    #[test]
    fn resolve_private_key_path_uses_user_and_server_directories() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let root = base.join("keys");
        let server_dir = root.join("alice").join("git");
        fs::create_dir_all(&server_dir).expect("mkdir");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod root");
        fs::set_permissions(root.join("alice"), fs::Permissions::from_mode(0o700))
            .expect("chmod user");
        fs::set_permissions(&server_dir, fs::Permissions::from_mode(0o700)).expect("chmod server");
        let key = server_dir.join("id_ed25519");
        fs::write(&key, b"key").expect("write key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("chmod key");

        let resolved =
            resolve_user_server_private_key_path(&root, "alice", "git", false).expect("resolve");
        assert_eq!(resolved, key);
    }

    #[test]
    fn resolve_private_key_path_rejects_symlink() {
        let tempdir = TempDir::new().expect("tempdir");
        let base = fs::canonicalize(tempdir.path()).expect("canonicalize");
        let root = base.join("keys");
        let server_dir = root.join("alice").join("git");
        fs::create_dir_all(&server_dir).expect("mkdir");
        let key = server_dir.join("id_ed25519");
        let real_key = base.join("real-key");
        fs::write(&real_key, b"key").expect("write");
        symlink(&real_key, &key).expect("symlink");

        let result = resolve_user_server_private_key_path(&root, "alice", "git", false);
        assert!(result.is_err());
    }
}
