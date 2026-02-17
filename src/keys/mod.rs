use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use ssh_key::{LineEnding, PrivateKey};

use crate::error::{CentralSshError, Result};

#[derive(Debug, Clone, Serialize)]
pub struct KeyProvisionResult {
    pub username: String,
    pub created_directory: bool,
    pub created_keypair: bool,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
}

pub fn reconcile_user_keys(
    user_key_root: &Path,
    usernames: &[String],
) -> Result<Vec<KeyProvisionResult>> {
    if !user_key_root.exists() {
        fs::create_dir_all(user_key_root)?;
        fs::set_permissions(user_key_root, fs::Permissions::from_mode(0o700))?;
    }

    let mut report = Vec::with_capacity(usernames.len());

    for username in usernames {
        report.push(ensure_user_keypair(user_key_root, username)?);
    }

    Ok(report)
}

pub fn ensure_user_keypair(user_key_root: &Path, username: &str) -> Result<KeyProvisionResult> {
    let user_dir = user_key_root.join(username);
    let private_key_path = user_dir.join("id_ed25519");
    let public_key_path = user_dir.join("id_ed25519.pub");

    let mut created_directory = false;
    let mut created_keypair = false;

    if !user_dir.exists() {
        fs::create_dir_all(&user_dir)?;
        fs::set_permissions(&user_dir, fs::Permissions::from_mode(0o700))?;
        created_directory = true;
    }

    if !private_key_path.exists() || !public_key_path.exists() {
        write_new_keypair(&private_key_path, &public_key_path)?;
        created_keypair = true;
    } else {
        enforce_key_permissions(&private_key_path, &public_key_path)?;
    }

    Ok(KeyProvisionResult {
        username: username.to_string(),
        created_directory,
        created_keypair,
        private_key_path,
        public_key_path,
    })
}

fn write_new_keypair(private_key_path: &Path, public_key_path: &Path) -> Result<()> {
    let private_key =
        PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519).map_err(
            |e| CentralSshError::InvalidConfig(format!("failed to generate keypair: {e}")),
        )?;

    let private_encoded = private_key.to_openssh(LineEnding::LF).map_err(|e| {
        CentralSshError::InvalidConfig(format!("failed to encode private key: {e}"))
    })?;

    let public_encoded = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| CentralSshError::InvalidConfig(format!("failed to encode public key: {e}")))?;

    let mut private_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(private_key_path)?;
    private_file.write_all(private_encoded.as_bytes())?;
    private_file.sync_all()?;

    let mut public_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(public_key_path)?;
    public_file.write_all(public_encoded.as_bytes())?;
    public_file.write_all(b"\n")?;
    public_file.sync_all()?;

    enforce_key_permissions(private_key_path, public_key_path)?;
    Ok(())
}

fn enforce_key_permissions(private_key_path: &Path, public_key_path: &Path) -> Result<()> {
    fs::set_permissions(private_key_path, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(public_key_path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}
