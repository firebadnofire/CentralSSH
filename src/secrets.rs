use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chrono::DateTime;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CentralSshError, Result};

const MASTER_KEY_VERSION: u32 = 1;
const ENVELOPE_PREFIX: &str = "centralssh:v1";
const MASTER_KEY_LEN: usize = 32;
const AES_GCM_NONCE_LEN: usize = 12;
const MAC_PREFIX: &str = "hmac-sha256:";
const HKDF_SALT: &[u8] = b"CentralSSH secret storage v1";
const MASTER_KEY_WRAP_AAD_PREFIX: &str = "centralssh/master-key/wrap/v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SecurityConfig {
    pub master_key_path: Option<PathBuf>,
    pub encrypted_config: Option<bool>,
    pub encrypted_keys: Option<bool>,
    pub allow_insecure_boot: Option<bool>,
    #[serde(default)]
    pub kek_provider: Option<KekProviderConfig>,
}

impl SecurityConfig {
    pub fn is_empty(&self) -> bool {
        self.master_key_path.is_none()
            && self.encrypted_config.is_none()
            && self.encrypted_keys.is_none()
            && self.allow_insecure_boot.is_none()
            && self.kek_provider.is_none()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct KekProviderConfig {
    pub kind: String,
    pub env: Option<String>,
    pub command_path: Option<PathBuf>,
    #[serde(default)]
    pub command_args: Vec<String>,
    #[serde(default)]
    pub allowed_command_args: Vec<String>,
    pub expected_sha256: Option<String>,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SecretManager {
    inner: Arc<SecretManagerInner>,
}

#[derive(Debug)]
struct SecretManagerInner {
    master_key_path: PathBuf,
    provider: KekProviderConfig,
    encrypted_config: bool,
    encrypted_keys: bool,
    allow_insecure_boot: bool,
    strict: bool,
}

#[derive(Debug, Deserialize)]
struct MasterKeyFile {
    version: u32,
    active_key_id: String,
    keys: Vec<MasterKeyEntry>,
    mac: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct MasterKeyEntry {
    key_id: String,
    wrapped_key: String,
    provider: String,
    created_at: String,
}

#[derive(Debug)]
struct SecretEnvelope {
    key_id: String,
    nonce: [u8; AES_GCM_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SecretManager {
    pub fn new(
        security: &SecurityConfig,
        default_master_key_path: PathBuf,
        strict: bool,
    ) -> Result<Option<Self>> {
        let allow_insecure_boot = security.allow_insecure_boot.unwrap_or(false);
        let encrypted_config = security.encrypted_config.unwrap_or(false);
        let encrypted_keys = security.encrypted_keys.unwrap_or(false);

        let Some(provider) = security.kek_provider.clone() else {
            if strict && !allow_insecure_boot {
                return Err(CentralSshError::InvalidConfig(
                    "strict mode requires security.kek_provider before bootstrap".to_string(),
                ));
            }
            if encrypted_config || encrypted_keys {
                return Err(CentralSshError::InvalidConfig(
                    "encrypted_config/encrypted_keys require security.kek_provider".to_string(),
                ));
            }
            return Ok(None);
        };

        if strict && !encrypted_config && !allow_insecure_boot {
            return Err(CentralSshError::InvalidConfig(
                "strict mode requires security.encrypted_config=true".to_string(),
            ));
        }
        if strict && !encrypted_keys && !allow_insecure_boot {
            return Err(CentralSshError::InvalidConfig(
                "strict mode requires security.encrypted_keys=true".to_string(),
            ));
        }

        if strict && provider.kind == "raw-file" {
            return Err(CentralSshError::InvalidConfig(
                "strict mode rejects the raw-file KEK provider".to_string(),
            ));
        }

        validate_provider_config(&provider, strict)?;

        Ok(Some(Self {
            inner: Arc::new(SecretManagerInner {
                master_key_path: security
                    .master_key_path
                    .clone()
                    .unwrap_or(default_master_key_path),
                provider,
                encrypted_config,
                encrypted_keys,
                allow_insecure_boot,
                strict,
            }),
        }))
    }

    pub fn readiness_check(&self) -> Result<()> {
        let _active = self.load_master_key(None)?;
        Ok(())
    }

    pub fn encrypted_config_required(&self) -> bool {
        self.inner.strict && !self.inner.allow_insecure_boot
    }

    pub fn encrypted_keys_required(&self) -> bool {
        self.inner.strict && !self.inner.allow_insecure_boot
    }

    pub fn encrypted_config_enabled(&self) -> bool {
        self.inner.encrypted_config
    }

    pub fn encrypted_keys_enabled(&self) -> bool {
        self.inner.encrypted_keys
    }

    pub fn allow_insecure_boot(&self) -> bool {
        self.inner.allow_insecure_boot
    }

    pub fn decrypt_string(
        &self,
        context: &str,
        subject: &str,
        stored_value: &str,
    ) -> Result<Zeroizing<String>> {
        if !is_encrypted_value(stored_value) {
            return Ok(Zeroizing::new(stored_value.to_string()));
        }

        let mut plaintext = self.decrypt_bytes(context, subject, stored_value)?;
        match String::from_utf8(std::mem::take(&mut *plaintext)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                Err(CentralSshError::InvalidConfig(format!(
                    "decrypted {context} value for '{subject}' is not UTF-8"
                )))
            }
        }
    }

    pub fn encrypt_string(&self, context: &str, subject: &str, plaintext: &str) -> Result<String> {
        self.encrypt_bytes(context, subject, plaintext.as_bytes())
    }

    pub fn decrypt_bytes(
        &self,
        context: &str,
        subject: &str,
        stored_value: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let envelope = parse_envelope(stored_value)?;
        let master_key = self.load_master_key(Some(&envelope.key_id))?;
        let content_key = derive_content_key(&master_key, context, subject)?;
        let aad = aad_for_secret(context, subject, &envelope.key_id);
        decrypt_aes_gcm(&content_key, &envelope.nonce, &aad, &envelope.ciphertext)
    }

    pub fn encrypt_bytes(&self, context: &str, subject: &str, plaintext: &[u8]) -> Result<String> {
        let (active_key_id, master_key) = self.load_active_master_key_with_id()?;
        let content_key = derive_content_key(&master_key, context, subject)?;

        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);

        let aad = aad_for_secret(context, subject, &active_key_id);
        let ciphertext = encrypt_aes_gcm(&content_key, &nonce, &aad, plaintext)?;

        Ok(format!(
            "{ENVELOPE_PREFIX}:{}:{}:{}",
            active_key_id,
            encode_hex(&nonce),
            encode_hex(&ciphertext)
        ))
    }

    pub fn validate_envelope_key_is_known(&self, stored_value: &str) -> Result<()> {
        if !is_encrypted_value(stored_value) {
            return Ok(());
        }
        let envelope = parse_envelope(stored_value)?;
        let keyset = self.load_keyset()?;
        if keyset
            .keys
            .iter()
            .any(|entry| entry.key_id == envelope.key_id)
        {
            Ok(())
        } else {
            Err(CentralSshError::InvalidConfig(format!(
                "encrypted blob references orphaned key_id '{}'",
                envelope.key_id
            )))
        }
    }

    fn load_active_master_key_with_id(&self) -> Result<(String, Zeroizing<[u8; MASTER_KEY_LEN]>)> {
        let keyset = self.load_keyset()?;
        let key_id = keyset.active_key_id.clone();
        let key = self.load_master_key_from_keyset(&keyset, &key_id)?;
        Ok((key_id, key))
    }

    fn load_master_key(&self, key_id: Option<&str>) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
        let keyset = self.load_keyset()?;
        let requested = key_id.unwrap_or(&keyset.active_key_id);
        self.load_master_key_from_keyset(&keyset, requested)
    }

    fn load_master_key_from_keyset(
        &self,
        keyset: &MasterKeyFile,
        requested_key_id: &str,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
        let active_entry = keyset
            .keys
            .iter()
            .find(|entry| entry.key_id == keyset.active_key_id)
            .ok_or_else(|| {
                CentralSshError::InvalidConfig(
                    "master.key active_key_id does not match any key entry".to_string(),
                )
            })?;
        let active_key = self.unwrap_master_key_entry(active_entry)?;
        verify_keyset_mac(keyset, &active_key)?;

        if requested_key_id == active_entry.key_id {
            return Ok(active_key);
        }

        let requested_entry = keyset
            .keys
            .iter()
            .find(|entry| entry.key_id == requested_key_id)
            .ok_or_else(|| {
                CentralSshError::InvalidConfig(format!(
                    "encrypted blob references unknown key_id '{requested_key_id}'"
                ))
            })?;
        self.unwrap_master_key_entry(requested_entry)
    }

    fn unwrap_master_key_entry(
        &self,
        entry: &MasterKeyEntry,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
        if entry.provider != self.inner.provider.kind {
            return Err(CentralSshError::InvalidConfig(format!(
                "master.key entry '{}' requires provider '{}', but configured provider is '{}'",
                entry.key_id, entry.provider, self.inner.provider.kind
            )));
        }

        match self.inner.provider.kind.as_str() {
            "passphrase-env" => unwrap_with_passphrase_env(&self.inner.provider, entry),
            "external-command" | "tpm2-command" => {
                unwrap_with_external_command(&self.inner.provider, entry, self.inner.strict)
            }
            "raw-file" => unwrap_with_raw_file(&self.inner.provider, self.inner.strict),
            other => Err(CentralSshError::InvalidConfig(format!(
                "unsupported KEK provider kind '{other}'"
            ))),
        }
    }

    fn load_keyset(&self) -> Result<MasterKeyFile> {
        validate_master_key_file(&self.inner.master_key_path, self.inner.strict)?;
        let bytes = fs::read(&self.inner.master_key_path)?;
        let keyset: MasterKeyFile = toml::from_slice(&bytes)?;
        validate_keyset_schema(&keyset)?;
        Ok(keyset)
    }
}

pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with(ENVELOPE_PREFIX)
}

fn validate_provider_config(provider: &KekProviderConfig, strict: bool) -> Result<()> {
    if provider.kind.trim().is_empty() {
        return Err(CentralSshError::InvalidConfig(
            "security.kek_provider.kind is required".to_string(),
        ));
    }

    match provider.kind.as_str() {
        "passphrase-env" => {
            let env = provider.env.as_deref().ok_or_else(|| {
                CentralSshError::InvalidConfig("passphrase-env provider requires env".to_string())
            })?;
            if env.trim().is_empty() {
                return Err(CentralSshError::InvalidConfig(
                    "passphrase-env provider env must not be empty".to_string(),
                ));
            }
        }
        "external-command" | "tpm2-command" => {
            let path = provider.command_path.as_deref().ok_or_else(|| {
                CentralSshError::InvalidConfig(format!(
                    "{} provider requires command_path",
                    provider.kind
                ))
            })?;
            if !path.is_absolute() {
                return Err(CentralSshError::InvalidConfig(format!(
                    "{} provider command_path must be absolute",
                    provider.kind
                )));
            }
            validate_existing_regular_file(path, strict)?;
            if !provider.command_args.is_empty()
                && provider.command_args != provider.allowed_command_args
            {
                return Err(CentralSshError::InvalidConfig(format!(
                    "{} provider command_args must exactly match allowed_command_args",
                    provider.kind
                )));
            }
            if let Some(expected) = &provider.expected_sha256 {
                let _ = decode_hex_fixed(expected, 32, "expected_sha256")?;
            }
        }
        "raw-file" => {
            if strict {
                return Err(CentralSshError::InvalidConfig(
                    "strict mode rejects raw-file provider".to_string(),
                ));
            }
            let path = provider.path.as_deref().ok_or_else(|| {
                CentralSshError::InvalidConfig("raw-file provider requires path".to_string())
            })?;
            validate_existing_regular_file(path, false)?;
        }
        other => {
            return Err(CentralSshError::InvalidConfig(format!(
                "unsupported KEK provider kind '{other}'"
            )));
        }
    }

    Ok(())
}

fn validate_keyset_schema(keyset: &MasterKeyFile) -> Result<()> {
    if keyset.version != MASTER_KEY_VERSION {
        return Err(CentralSshError::InvalidConfig(format!(
            "master.key version must be {MASTER_KEY_VERSION}, found {}",
            keyset.version
        )));
    }
    validate_identifier(&keyset.active_key_id, "master.key active_key_id")?;
    if keyset.keys.is_empty() {
        return Err(CentralSshError::InvalidConfig(
            "master.key must contain at least one key".to_string(),
        ));
    }

    let mut seen = HashSet::new();
    let mut active_count = 0usize;
    for entry in &keyset.keys {
        validate_identifier(&entry.key_id, "master.key key_id")?;
        validate_identifier(&entry.provider, "master.key provider")?;
        if !seen.insert(entry.key_id.clone()) {
            return Err(CentralSshError::InvalidConfig(format!(
                "master.key contains duplicate key_id '{}'",
                entry.key_id
            )));
        }
        if entry.key_id == keyset.active_key_id {
            active_count += 1;
        }
        let _ = decode_hex(&entry.wrapped_key, "wrapped_key")?;
        DateTime::parse_from_rfc3339(&entry.created_at).map_err(|error| {
            CentralSshError::InvalidConfig(format!(
                "master.key key '{}' has invalid created_at: {error}",
                entry.key_id
            ))
        })?;
        ensure_no_newline(&entry.wrapped_key, "wrapped_key")?;
        ensure_no_newline(&entry.created_at, "created_at")?;
    }

    if active_count != 1 {
        return Err(CentralSshError::InvalidConfig(format!(
            "master.key must contain exactly one active key entry, found {active_count}"
        )));
    }

    if keyset.mac.is_none() {
        return Err(CentralSshError::InvalidConfig(
            "master.key mac is required".to_string(),
        ));
    }

    Ok(())
}

fn unwrap_with_passphrase_env(
    provider: &KekProviderConfig,
    entry: &MasterKeyEntry,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    let env_name = provider.env.as_deref().ok_or_else(|| {
        CentralSshError::InvalidConfig("passphrase-env provider requires env".to_string())
    })?;
    let passphrase = Zeroizing::new(std::env::var(env_name).map_err(|_| {
        CentralSshError::InvalidConfig(format!(
            "required passphrase environment variable '{env_name}' is not set"
        ))
    })?);
    if passphrase.is_empty() {
        return Err(CentralSshError::InvalidConfig(format!(
            "required passphrase environment variable '{env_name}' is empty"
        )));
    }

    let wrapping_key = derive_provider_key(passphrase.as_bytes(), env_name)?;
    let wrapped = decode_hex(&entry.wrapped_key, "wrapped_key")?;
    let (nonce, ciphertext) = split_nonce_and_ciphertext(&wrapped, "wrapped_key")?;
    let aad = format!("{MASTER_KEY_WRAP_AAD_PREFIX}:{}", entry.key_id);
    let plaintext = decrypt_aes_gcm(&wrapping_key, &nonce, aad.as_bytes(), ciphertext)?;
    bytes_to_master_key(plaintext, "passphrase-env provider output")
}

fn unwrap_with_external_command(
    provider: &KekProviderConfig,
    entry: &MasterKeyEntry,
    strict: bool,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    let path = provider.command_path.as_deref().ok_or_else(|| {
        CentralSshError::InvalidConfig(format!("{} provider requires command_path", provider.kind))
    })?;
    validate_existing_regular_file(path, strict)?;
    verify_command_attestation(path, provider.expected_sha256.as_deref())?;

    let wrapped = decode_hex(&entry.wrapped_key, "wrapped_key")?;
    let mut child = Command::new(path)
        .args(&provider.command_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            CentralSshError::InvalidConfig(format!(
                "failed to start {} provider command: {error}",
                provider.kind
            ))
        })?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(&wrapped)?;
    }
    drop(child.stdin.take());

    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    let mut stdout = child.stdout.take().ok_or_else(|| {
        CentralSshError::InvalidConfig("provider command stdout was not captured".to_string())
    })?;
    stdout.read_exact(&mut *key).map_err(|error| {
        CentralSshError::InvalidConfig(format!(
            "{} provider must write exactly 32 bytes to stdout: {error}",
            provider.kind
        ))
    })?;
    let mut extra = [0u8; 1];
    match stdout.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => {
            return Err(CentralSshError::InvalidConfig(format!(
                "{} provider wrote more than 32 bytes to stdout",
                provider.kind
            )));
        }
        Err(error) => return Err(CentralSshError::Io(error)),
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(CentralSshError::InvalidConfig(format!(
            "{} provider command exited with status {status}",
            provider.kind
        )));
    }

    Ok(key)
}

fn unwrap_with_raw_file(
    provider: &KekProviderConfig,
    strict: bool,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    if strict {
        return Err(CentralSshError::InvalidConfig(
            "strict mode rejects raw-file provider".to_string(),
        ));
    }
    let path = provider.path.as_deref().ok_or_else(|| {
        CentralSshError::InvalidConfig("raw-file provider requires path".to_string())
    })?;
    validate_existing_regular_file(path, false)?;
    let bytes = Zeroizing::new(fs::read(path)?);
    bytes_to_master_key(bytes, "raw-file provider output")
}

fn verify_command_attestation(path: &Path, expected_sha256: Option<&str>) -> Result<()> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(());
    };
    let expected = decode_hex_fixed(expected_sha256, 32, "expected_sha256")?;
    let bytes = fs::read(path)?;
    let actual = Sha256::digest(&bytes);
    if !constant_time_eq::constant_time_eq(&actual, &expected) {
        return Err(CentralSshError::InvalidConfig(format!(
            "provider command '{}' does not match expected_sha256",
            path.display()
        )));
    }
    Ok(())
}

fn verify_keyset_mac(
    keyset: &MasterKeyFile,
    active_key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
) -> Result<()> {
    let expected_mac = keyset
        .mac
        .as_deref()
        .ok_or_else(|| CentralSshError::InvalidConfig("master.key mac is required".to_string()))?;
    let expected_hex = expected_mac.strip_prefix(MAC_PREFIX).ok_or_else(|| {
        CentralSshError::InvalidConfig("master.key mac must use hmac-sha256:<hex>".to_string())
    })?;
    let expected = decode_hex_fixed(expected_hex, 32, "master.key mac")?;
    let actual = compute_keyset_mac(keyset, active_key)?;
    if !constant_time_eq::constant_time_eq(&actual, &expected) {
        return Err(CentralSshError::InvalidConfig(
            "master.key mac verification failed".to_string(),
        ));
    }
    Ok(())
}

fn compute_keyset_mac(
    keyset: &MasterKeyFile,
    active_key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
) -> Result<[u8; 32]> {
    let mac_key = derive_content_key(active_key, "master.key/mac", &keyset.active_key_id)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&mac_key[..]).map_err(|_| {
        CentralSshError::InvalidConfig("failed to initialize master.key mac".to_string())
    })?;
    mac.update(canonical_keyset_body(keyset)?.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn canonical_keyset_body(keyset: &MasterKeyFile) -> Result<String> {
    let mut body = String::new();
    body.push_str(&format!("version={}\n", keyset.version));
    body.push_str(&format!("active_key_id={}\n", keyset.active_key_id));
    for entry in &keyset.keys {
        ensure_no_newline(&entry.key_id, "key_id")?;
        ensure_no_newline(&entry.provider, "provider")?;
        ensure_no_newline(&entry.wrapped_key, "wrapped_key")?;
        ensure_no_newline(&entry.created_at, "created_at")?;
        body.push_str("[[keys]]\n");
        body.push_str(&format!("key_id={}\n", entry.key_id));
        body.push_str(&format!("wrapped_key={}\n", entry.wrapped_key));
        body.push_str(&format!("provider={}\n", entry.provider));
        body.push_str(&format!("created_at={}\n", entry.created_at));
    }
    Ok(body)
}

fn parse_envelope(value: &str) -> Result<SecretEnvelope> {
    let mut parts = value.split(':');
    let prefix = format!(
        "{}:{}",
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default()
    );
    if prefix != ENVELOPE_PREFIX {
        return Err(CentralSshError::InvalidConfig(
            "secret value is not a CentralSSH encrypted envelope".to_string(),
        ));
    }
    let key_id = parts.next().ok_or_else(|| {
        CentralSshError::InvalidConfig("encrypted envelope is missing key_id".to_string())
    })?;
    validate_identifier(key_id, "encrypted envelope key_id")?;
    let nonce_hex = parts.next().ok_or_else(|| {
        CentralSshError::InvalidConfig("encrypted envelope is missing nonce".to_string())
    })?;
    let ciphertext_hex = parts.next().ok_or_else(|| {
        CentralSshError::InvalidConfig("encrypted envelope is missing ciphertext".to_string())
    })?;
    if parts.next().is_some() {
        return Err(CentralSshError::InvalidConfig(
            "encrypted envelope has unexpected trailing fields".to_string(),
        ));
    }

    let nonce_vec = decode_hex_fixed(nonce_hex, AES_GCM_NONCE_LEN, "encrypted envelope nonce")?;
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    nonce.copy_from_slice(&nonce_vec);
    let ciphertext = decode_hex(ciphertext_hex, "encrypted envelope ciphertext")?;
    Ok(SecretEnvelope {
        key_id: key_id.to_string(),
        nonce,
        ciphertext: (*ciphertext).clone(),
    })
}

fn encrypt_aes_gcm(
    key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
    nonce: &[u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| {
        CentralSshError::InvalidConfig("failed to initialize AES-256-GCM".to_string())
    })?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CentralSshError::InvalidConfig("secret encryption failed".to_string()))
}

fn decrypt_aes_gcm(
    key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
    nonce: &[u8; AES_GCM_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| {
        CentralSshError::InvalidConfig("failed to initialize AES-256-GCM".to_string())
    })?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CentralSshError::InvalidConfig("secret decryption failed".to_string()))?;
    Ok(Zeroizing::new(plaintext))
}

fn split_nonce_and_ciphertext<'a>(
    wrapped: &'a Zeroizing<Vec<u8>>,
    label: &str,
) -> Result<([u8; AES_GCM_NONCE_LEN], &'a [u8])> {
    if wrapped.len() <= AES_GCM_NONCE_LEN {
        return Err(CentralSshError::InvalidConfig(format!(
            "{label} must contain a nonce and ciphertext"
        )));
    }
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    nonce.copy_from_slice(&wrapped[..AES_GCM_NONCE_LEN]);
    Ok((nonce, &wrapped[AES_GCM_NONCE_LEN..]))
}

fn derive_provider_key(
    passphrase: &[u8],
    env_name: &str,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), passphrase);
    let mut out = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    let info = format!("centralssh/provider/passphrase-env/v1/{env_name}");
    hkdf.expand(info.as_bytes(), &mut *out).map_err(|_| {
        CentralSshError::InvalidConfig("failed to derive provider wrapping key".to_string())
    })?;
    Ok(out)
}

fn derive_content_key(
    master_key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
    context: &str,
    subject: &str,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), &master_key[..]);
    let mut out = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    let info = format!("centralssh/secret/v1/{context}\0{subject}");
    hkdf.expand(info.as_bytes(), &mut *out).map_err(|_| {
        CentralSshError::InvalidConfig("failed to derive context secret key".to_string())
    })?;
    Ok(out)
}

fn aad_for_secret(context: &str, subject: &str, key_id: &str) -> Vec<u8> {
    format!("centralssh/secret/v1/{context}\0{subject}\0{key_id}").into_bytes()
}

fn bytes_to_master_key(
    bytes: Zeroizing<Vec<u8>>,
    label: &str,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    if bytes.len() != MASTER_KEY_LEN {
        return Err(CentralSshError::InvalidConfig(format!(
            "{label} must be exactly 32 bytes"
        )));
    }
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 {
        return Err(CentralSshError::InvalidConfig(format!(
            "{label} must be 1-64 characters"
        )));
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err(CentralSshError::InvalidConfig(format!(
            "{label} contains invalid characters"
        )));
    }
    Ok(())
}

fn ensure_no_newline(value: &str, label: &str) -> Result<()> {
    if value.contains('\n') || value.contains('\r') {
        return Err(CentralSshError::InvalidConfig(format!(
            "master.key {label} must not contain newlines"
        )));
    }
    Ok(())
}

fn validate_master_key_file(path: &Path, strict: bool) -> Result<()> {
    validate_existing_regular_file(path, strict)?;
    if strict {
        let metadata = fs::symlink_metadata(path)?;
        let mode = metadata.mode() & 0o777;
        if mode != 0o600 {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: format!("master.key mode must be 600, found {:o}", mode),
            });
        }
        if metadata.uid() != 0 {
            return Err(CentralSshError::SecurityPolicy {
                path: path.to_path_buf(),
                message: format!("master.key owner uid must be 0, found {}", metadata.uid()),
            });
        }
    }
    Ok(())
}

fn validate_existing_regular_file(path: &Path, strict: bool) -> Result<()> {
    validate_path_has_no_symlinks(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "expected a real regular file".to_string(),
        });
    }
    if strict && metadata.uid() != 0 {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: format!("owner uid must be 0, found {}", metadata.uid()),
        });
    }
    if strict && (metadata.mode() & 0o022) != 0 {
        return Err(CentralSshError::SecurityPolicy {
            path: path.to_path_buf(),
            message: "must not be group- or world-writable".to_string(),
        });
    }
    Ok(())
}

fn validate_path_has_no_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(CentralSshError::SecurityPolicy {
                    path: path.to_path_buf(),
                    message: "parent directory traversal is not allowed".to_string(),
                });
            }
            Component::Normal(part) => current.push(part),
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CentralSshError::SecurityPolicy {
                    path: current.clone(),
                    message: "symlink path components are not allowed".to_string(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(CentralSshError::Io(error)),
        }
    }

    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_fixed(value: &str, expected_len: usize, label: &str) -> Result<Vec<u8>> {
    let bytes = decode_hex(value, label)?;
    if bytes.len() != expected_len {
        return Err(CentralSshError::InvalidConfig(format!(
            "{label} must decode to {expected_len} bytes"
        )));
    }
    Ok((*bytes).clone())
}

fn decode_hex(value: &str, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    if !value.len().is_multiple_of(2) {
        return Err(CentralSshError::InvalidConfig(format!(
            "{label} must be even-length hex"
        )));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let high = hex_value(bytes[index], label)?;
        let low = hex_value(bytes[index + 1], label)?;
        out.push((high << 4) | low);
        index += 2;
    }
    Ok(Zeroizing::new(out))
}

fn hex_value(value: u8, label: &str) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(CentralSshError::InvalidConfig(format!(
            "{label} contains non-hex characters"
        ))),
    }
}

#[cfg(test)]
pub(crate) fn test_raw_file_manager(
    root: &Path,
    encrypted_config: bool,
    encrypted_keys: bool,
) -> SecretManager {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(root).expect("test secret root");
    let master_key_path = root.join("master.key");
    let raw_path = root.join("raw.key");
    fs::write(&raw_path, [7u8; MASTER_KEY_LEN]).expect("write raw key");
    fs::set_permissions(&raw_path, fs::Permissions::from_mode(0o600)).expect("chmod raw key");

    let mut keyset = MasterKeyFile {
        version: MASTER_KEY_VERSION,
        active_key_id: "active".to_string(),
        keys: vec![MasterKeyEntry {
            key_id: "active".to_string(),
            wrapped_key: encode_hex(&[0u8; MASTER_KEY_LEN]),
            provider: "raw-file".to_string(),
            created_at: "2026-05-05T00:00:00Z".to_string(),
        }],
        mac: None,
    };
    let mac = compute_keyset_mac(&keyset, &Zeroizing::new([7u8; MASTER_KEY_LEN])).expect("mac");
    keyset.mac = Some(format!("{MAC_PREFIX}{}", encode_hex(&mac)));
    let contents = format!(
        "version = 1\nactive_key_id = \"active\"\nmac = \"{}\"\n\n[[keys]]\nkey_id = \"active\"\nwrapped_key = \"{}\"\nprovider = \"raw-file\"\ncreated_at = \"2026-05-05T00:00:00Z\"\n",
        keyset.mac.as_deref().expect("mac"),
        keyset.keys[0].wrapped_key
    );
    fs::write(&master_key_path, contents).expect("write master key");
    fs::set_permissions(&master_key_path, fs::Permissions::from_mode(0o600))
        .expect("chmod master key");

    SecretManager::new(
        &SecurityConfig {
            master_key_path: Some(master_key_path),
            encrypted_config: Some(encrypted_config),
            encrypted_keys: Some(encrypted_keys),
            allow_insecure_boot: Some(true),
            kek_provider: Some(KekProviderConfig {
                kind: "raw-file".to_string(),
                path: Some(raw_path),
                ..KekProviderConfig::default()
            }),
        },
        root.join("unused-master.key"),
        false,
    )
    .expect("test manager")
    .expect("test manager present")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn test_root(tempdir: &TempDir) -> PathBuf {
        fs::canonicalize(tempdir.path()).expect("canonical tempdir")
    }

    fn fixed_master_key() -> Zeroizing<[u8; MASTER_KEY_LEN]> {
        Zeroizing::new([7u8; MASTER_KEY_LEN])
    }

    fn write_raw_master_key(path: &Path) -> PathBuf {
        let raw_path = path.with_extension("raw");
        fs::write(&raw_path, [7u8; MASTER_KEY_LEN]).expect("write raw key");
        fs::set_permissions(&raw_path, fs::Permissions::from_mode(0o600)).expect("chmod raw");
        raw_path
    }

    fn write_master_key_file(path: &Path, raw_path: &Path, active_key_id: &str) {
        let wrapped_key = encode_hex(&[0u8; MASTER_KEY_LEN]);
        let mut keyset = MasterKeyFile {
            version: MASTER_KEY_VERSION,
            active_key_id: active_key_id.to_string(),
            keys: vec![MasterKeyEntry {
                key_id: active_key_id.to_string(),
                wrapped_key,
                provider: "raw-file".to_string(),
                created_at: "2026-05-05T00:00:00Z".to_string(),
            }],
            mac: None,
        };
        let mac = compute_keyset_mac(&keyset, &fixed_master_key()).expect("mac");
        keyset.mac = Some(format!("{MAC_PREFIX}{}", encode_hex(&mac)));
        let contents = format!(
            "version = 1\nactive_key_id = \"{}\"\nmac = \"{}\"\n\n[[keys]]\nkey_id = \"{}\"\nwrapped_key = \"{}\"\nprovider = \"raw-file\"\ncreated_at = \"2026-05-05T00:00:00Z\"\n",
            keyset.active_key_id,
            keyset.mac.as_deref().expect("mac"),
            keyset.keys[0].key_id,
            keyset.keys[0].wrapped_key,
        );
        fs::write(path, contents).expect("write master key");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod master");
        assert!(raw_path.is_file());
    }

    fn raw_file_manager(master_key_path: PathBuf, raw_path: PathBuf) -> SecretManager {
        SecretManager::new(
            &SecurityConfig {
                master_key_path: Some(master_key_path),
                encrypted_config: Some(true),
                encrypted_keys: Some(true),
                allow_insecure_boot: Some(true),
                kek_provider: Some(KekProviderConfig {
                    kind: "raw-file".to_string(),
                    path: Some(raw_path),
                    ..KekProviderConfig::default()
                }),
            },
            PathBuf::from("/unused/master.key"),
            false,
        )
        .expect("manager")
        .expect("some manager")
    }

    #[test]
    fn envelope_round_trips_with_context_binding() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = test_root(&tempdir);
        let master_key_path = root.join("master.key");
        let raw_path = write_raw_master_key(&master_key_path);
        write_master_key_file(&master_key_path, &raw_path, "active");
        let manager = raw_file_manager(master_key_path, raw_path);

        let encrypted = manager
            .encrypt_string("config/totp", "alice", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
            .expect("encrypt");
        assert!(is_encrypted_value(&encrypted));
        let decrypted = manager
            .decrypt_string("config/totp", "alice", &encrypted)
            .expect("decrypt");
        assert_eq!(decrypted.as_str(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        assert!(
            manager
                .decrypt_string("config/password", "alice", &encrypted)
                .is_err()
        );
    }

    #[test]
    fn master_key_rejects_duplicate_key_ids() {
        let keyset = MasterKeyFile {
            version: MASTER_KEY_VERSION,
            active_key_id: "active".to_string(),
            keys: vec![
                MasterKeyEntry {
                    key_id: "active".to_string(),
                    wrapped_key: encode_hex(&[0u8; MASTER_KEY_LEN]),
                    provider: "raw-file".to_string(),
                    created_at: "2026-05-05T00:00:00Z".to_string(),
                },
                MasterKeyEntry {
                    key_id: "active".to_string(),
                    wrapped_key: encode_hex(&[1u8; MASTER_KEY_LEN]),
                    provider: "raw-file".to_string(),
                    created_at: "2026-05-05T00:00:00Z".to_string(),
                },
            ],
            mac: Some(format!("{MAC_PREFIX}{}", encode_hex(&[0u8; 32]))),
        };

        assert!(validate_keyset_schema(&keyset).is_err());
    }

    #[test]
    fn corrupted_master_key_mac_is_rejected() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = test_root(&tempdir);
        let master_key_path = root.join("master.key");
        let raw_path = write_raw_master_key(&master_key_path);
        write_master_key_file(&master_key_path, &raw_path, "active");
        let mut contents = fs::read_to_string(&master_key_path).expect("read");
        contents = contents.replace("active_key_id = \"active\"", "active_key_id = \"other\"");
        fs::write(&master_key_path, contents).expect("write corrupt");

        let manager = raw_file_manager(master_key_path, raw_path);
        assert!(manager.readiness_check().is_err());
    }

    #[test]
    fn encrypted_blob_with_orphaned_key_id_is_rejected() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = test_root(&tempdir);
        let master_key_path = root.join("master.key");
        let raw_path = write_raw_master_key(&master_key_path);
        write_master_key_file(&master_key_path, &raw_path, "active");
        let manager = raw_file_manager(master_key_path, raw_path);

        let result = manager.validate_envelope_key_is_known(&format!(
            "{ENVELOPE_PREFIX}:missing:{}:{}",
            encode_hex(&[0u8; AES_GCM_NONCE_LEN]),
            encode_hex(&[0u8; 16])
        ));

        assert!(matches!(
            result,
            Err(CentralSshError::InvalidConfig(message)) if message.contains("orphaned key_id")
        ));
    }

    #[test]
    fn external_command_args_must_be_allowlisted() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = test_root(&tempdir);
        let command = root.join("provider");
        fs::write(&command, "#!/bin/sh\nexit 0\n").expect("write command");
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).expect("chmod command");

        let config = KekProviderConfig {
            kind: "external-command".to_string(),
            command_path: Some(command),
            command_args: vec!["--unexpected".to_string()],
            allowed_command_args: Vec::new(),
            ..KekProviderConfig::default()
        };

        assert!(validate_provider_config(&config, false).is_err());
    }

    #[test]
    fn external_command_provider_rejects_wrong_output_length() {
        let tempdir = TempDir::new().expect("tempdir");
        let root = test_root(&tempdir);
        let command = root.join("provider");
        fs::write(&command, "#!/bin/sh\nprintf short\n").expect("write command");
        fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).expect("chmod command");
        let provider = KekProviderConfig {
            kind: "external-command".to_string(),
            command_path: Some(command),
            ..KekProviderConfig::default()
        };
        let entry = MasterKeyEntry {
            key_id: "active".to_string(),
            wrapped_key: encode_hex(&[1u8; 16]),
            provider: "external-command".to_string(),
            created_at: "2026-05-05T00:00:00Z".to_string(),
        };

        assert!(unwrap_with_external_command(&provider, &entry, false).is_err());
    }
}
