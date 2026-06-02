use std::borrow::Cow;
use std::collections::HashSet;
use std::time::Duration;

use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};
use russh::{Limits, Preferred, cipher, compression, kex, mac};

use crate::config::KexPolicyConfig;
use crate::error::{CentralSshError, Result};

pub const SSH_REKEY_BYTES: usize = 512 * 1024 * 1024;
pub const SSH_REKEY_TIME: Duration = Duration::from_secs(30 * 60);
pub const MLKEM768X25519_SHA256_NAME: &str = "mlkem768x25519-sha256";
pub const SNTRUP761X25519_SHA512_NAME: &str = "sntrup761x25519-sha512";
pub const CURVE25519_SHA256_NAME: &str = "curve25519-sha256";
pub const CURVE25519_SHA256_LIBSSH_NAME: &str = "curve25519-sha256@libssh.org";

const SERVER_KEX_EXTENSIONS: &[kex::Name] = &[
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

const SSH_HOST_KEY_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
];

const SSH_CIPHERS: &[cipher::Name] = &[cipher::CHACHA20_POLY1305, cipher::AES_256_GCM];
const SSH_MACS: &[mac::Name] = &[mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM];
const SSH_COMPRESSION: &[compression::Name] = &[compression::NONE];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexPolicySummary {
    pub offered_algorithms: Vec<String>,
    pub require_post_quantum: bool,
    pub classical_fallback: bool,
}

#[derive(Clone, Copy)]
struct SupportedKex {
    name: &'static str,
    algorithm: kex::Name,
    post_quantum: bool,
}

const CONFIGURABLE_FRONTEND_KEX: &[SupportedKex] = &[
    SupportedKex {
        name: MLKEM768X25519_SHA256_NAME,
        algorithm: kex::MLKEM768X25519_SHA256,
        post_quantum: true,
    },
    SupportedKex {
        name: CURVE25519_SHA256_NAME,
        algorithm: kex::CURVE25519,
        post_quantum: false,
    },
    SupportedKex {
        name: CURVE25519_SHA256_LIBSSH_NAME,
        algorithm: kex::CURVE25519_PRE_RFC_8731,
        post_quantum: false,
    },
];

pub fn is_post_quantum_kex_name(name: &str) -> bool {
    matches!(
        name,
        MLKEM768X25519_SHA256_NAME | SNTRUP761X25519_SHA512_NAME
    )
}

pub fn is_hybrid_kex_name(name: &str) -> bool {
    is_post_quantum_kex_name(name)
}

pub fn hardened_ssh_limits() -> Limits {
    Limits::new(SSH_REKEY_BYTES, SSH_REKEY_BYTES, SSH_REKEY_TIME)
}

pub fn validate_kex_policy(policy: &KexPolicyConfig) -> Result<()> {
    let _ = frontend_kex_policy_summary(policy)?;
    let _ = backend_kex_policy_summary(policy)?;
    Ok(())
}

pub fn apply_server_transport_crypto_policy(
    config: &mut russh::server::Config,
    policy: &KexPolicyConfig,
) -> Result<KexPolicySummary> {
    let summary = frontend_kex_policy_summary(policy)?;
    config.preferred = frontend_server_preferred(policy)?;
    config.limits = hardened_ssh_limits();
    Ok(summary)
}

pub fn apply_client_transport_crypto_policy(
    config: &mut russh::client::Config,
    policy: &KexPolicyConfig,
) -> Result<KexPolicySummary> {
    let summary = backend_kex_policy_summary(policy)?;
    config.preferred = backend_client_preferred(policy)?;
    config.limits = hardened_ssh_limits();
    Ok(summary)
}

fn frontend_server_preferred(policy: &KexPolicyConfig) -> Result<Preferred> {
    let mut kex_names = resolve_preferred_kex(
        &policy.frontend_preferred,
        policy.frontend_require_post_quantum,
        "kex_policy.frontend_preferred",
        "kex_policy.frontend_require_post_quantum",
    )?;
    kex_names.extend_from_slice(SERVER_KEX_EXTENSIONS);

    Ok(Preferred {
        kex: Cow::Owned(kex_names),
        key: Cow::Borrowed(SSH_HOST_KEY_ALGORITHMS),
        cipher: Cow::Borrowed(SSH_CIPHERS),
        mac: Cow::Borrowed(SSH_MACS),
        compression: Cow::Borrowed(SSH_COMPRESSION),
    })
}

fn backend_client_preferred(policy: &KexPolicyConfig) -> Result<Preferred> {
    let mut kex_names = resolve_preferred_kex(
        &policy.backend_preferred,
        policy.backend_require_post_quantum,
        "kex_policy.backend_preferred",
        "kex_policy.backend_require_post_quantum",
    )?;
    kex_names.extend_from_slice(SERVER_KEX_EXTENSIONS);

    Ok(Preferred {
        kex: Cow::Owned(kex_names),
        key: Cow::Borrowed(SSH_HOST_KEY_ALGORITHMS),
        cipher: Cow::Borrowed(SSH_CIPHERS),
        mac: Cow::Borrowed(SSH_MACS),
        compression: Cow::Borrowed(SSH_COMPRESSION),
    })
}

pub fn frontend_kex_policy_summary(policy: &KexPolicyConfig) -> Result<KexPolicySummary> {
    policy_summary(
        &policy.frontend_preferred,
        policy.frontend_require_post_quantum,
        "kex_policy.frontend_preferred",
        "kex_policy.frontend_require_post_quantum",
    )
}

pub fn backend_kex_policy_summary(policy: &KexPolicyConfig) -> Result<KexPolicySummary> {
    policy_summary(
        &policy.backend_preferred,
        policy.backend_require_post_quantum,
        "kex_policy.backend_preferred",
        "kex_policy.backend_require_post_quantum",
    )
}

fn policy_summary(
    preferred: &[String],
    require_post_quantum: bool,
    preferred_field: &str,
    require_field: &str,
) -> Result<KexPolicySummary> {
    let offered_algorithms = resolve_preferred_kex(
        preferred,
        require_post_quantum,
        preferred_field,
        require_field,
    )?
    .into_iter()
    .map(|name| name.as_ref().to_string())
    .collect::<Vec<_>>();

    Ok(KexPolicySummary {
        classical_fallback: offered_algorithms
            .iter()
            .any(|name| !is_post_quantum_kex_name(name)),
        offered_algorithms,
        require_post_quantum,
    })
}

fn resolve_preferred_kex(
    preferred: &[String],
    require_post_quantum: bool,
    preferred_field: &str,
    require_field: &str,
) -> Result<Vec<kex::Name>> {
    if preferred.is_empty() {
        return Err(CentralSshError::InvalidConfig(format!(
            "{preferred_field} must not be empty"
        )));
    }

    let mut seen = HashSet::new();
    let mut resolved = Vec::new();

    for configured_name in preferred {
        let supported = resolve_supported_kex(configured_name, preferred_field)?;
        if require_post_quantum && !supported.post_quantum {
            continue;
        }
        if seen.insert(supported.name) {
            resolved.push(supported.algorithm);
        }
    }

    if resolved.is_empty() {
        if require_post_quantum {
            return Err(CentralSshError::InvalidConfig(format!(
                "{require_field}=true requires at least one supported post-quantum KEX in {preferred_field}"
            )));
        }
        return Err(CentralSshError::InvalidConfig(format!(
            "{preferred_field} did not resolve to any supported KEX"
        )));
    }

    Ok(resolved)
}

fn resolve_supported_kex(name: &str, field_name: &str) -> Result<SupportedKex> {
    if name == SNTRUP761X25519_SHA512_NAME {
        return Err(CentralSshError::InvalidConfig(format!(
            "{field_name} includes 'sntrup761x25519-sha512', but the pinned russh dependency does not currently expose that KEX"
        )));
    }

    CONFIGURABLE_FRONTEND_KEX
        .iter()
        .find(|supported| supported.name == name)
        .copied()
        .ok_or_else(|| {
            let supported_names = CONFIGURABLE_FRONTEND_KEX
                .iter()
                .map(|supported| supported.name)
                .collect::<Vec<_>>()
                .join(", ");
            CentralSshError::InvalidConfig(format!(
                "unsupported {field_name} entry '{name}'; supported values: {supported_names}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kex_names(preferred: &Preferred) -> Vec<&str> {
        preferred.kex.iter().map(kex::Name::as_ref).collect()
    }

    fn cipher_names(preferred: &Preferred) -> Vec<&str> {
        preferred.cipher.iter().map(cipher::Name::as_ref).collect()
    }

    fn mac_names(preferred: &Preferred) -> Vec<&str> {
        preferred.mac.iter().map(mac::Name::as_ref).collect()
    }

    fn compression_names(preferred: &Preferred) -> Vec<&str> {
        preferred
            .compression
            .iter()
            .map(compression::Name::as_ref)
            .collect()
    }

    #[test]
    fn default_client_policy_prefers_mlkem_then_curve25519() {
        let preferred = backend_client_preferred(&KexPolicyConfig::default()).expect("preferred");
        let names = kex_names(&preferred);

        assert_eq!(names[0], MLKEM768X25519_SHA256_NAME);
        assert!(names.contains(&CURVE25519_SHA256_NAME));
        assert!(names.contains(&CURVE25519_SHA256_LIBSSH_NAME));
        assert!(names.contains(&"kex-strict-c-v00@openssh.com"));
        assert!(names.contains(&"kex-strict-s-v00@openssh.com"));
        assert!(!names.iter().any(|name| name.contains("diffie-hellman")));
    }

    #[test]
    fn frontend_policy_can_require_post_quantum_only() {
        let preferred = frontend_server_preferred(&KexPolicyConfig {
            frontend_preferred: vec![
                MLKEM768X25519_SHA256_NAME.to_string(),
                CURVE25519_SHA256_NAME.to_string(),
            ],
            frontend_require_post_quantum: true,
            ..KexPolicyConfig::default()
        })
        .expect("preferred");

        assert_eq!(
            kex_names(&preferred),
            vec![
                MLKEM768X25519_SHA256_NAME,
                "ext-info-c",
                "ext-info-s",
                "kex-strict-c-v00@openssh.com",
                "kex-strict-s-v00@openssh.com",
            ]
        );
    }

    #[test]
    fn validate_kex_policy_rejects_unsupported_sntrup() {
        let error = validate_kex_policy(&KexPolicyConfig {
            frontend_preferred: vec![SNTRUP761X25519_SHA512_NAME.to_string()],
            frontend_require_post_quantum: false,
            ..KexPolicyConfig::default()
        })
        .expect_err("sntrup should fail");

        assert!(error.to_string().contains("does not currently expose"));
    }

    #[test]
    fn validate_kex_policy_rejects_unknown_name() {
        let error = validate_kex_policy(&KexPolicyConfig {
            frontend_preferred: vec!["weird-kex".to_string()],
            frontend_require_post_quantum: false,
            ..KexPolicyConfig::default()
        })
        .expect_err("unknown kex should fail");

        assert!(
            error
                .to_string()
                .contains("unsupported kex_policy.frontend_preferred")
        );
    }

    #[test]
    fn frontend_policy_summary_marks_classical_fallback() {
        let summary = frontend_kex_policy_summary(&KexPolicyConfig::default()).expect("summary");

        assert!(
            summary
                .offered_algorithms
                .iter()
                .any(|name| name == CURVE25519_SHA256_NAME)
        );
        assert!(summary.classical_fallback);
        assert!(!summary.require_post_quantum);
    }

    #[test]
    fn backend_policy_can_require_post_quantum_only() {
        let preferred = backend_client_preferred(&KexPolicyConfig {
            backend_preferred: vec![
                MLKEM768X25519_SHA256_NAME.to_string(),
                CURVE25519_SHA256_NAME.to_string(),
            ],
            backend_require_post_quantum: true,
            ..KexPolicyConfig::default()
        })
        .expect("preferred");

        assert_eq!(
            kex_names(&preferred),
            vec![
                MLKEM768X25519_SHA256_NAME,
                "ext-info-c",
                "ext-info-s",
                "kex-strict-c-v00@openssh.com",
                "kex-strict-s-v00@openssh.com",
            ]
        );
    }

    #[test]
    fn validate_kex_policy_rejects_unsupported_backend_sntrup() {
        let error = validate_kex_policy(&KexPolicyConfig {
            backend_preferred: vec![SNTRUP761X25519_SHA512_NAME.to_string()],
            ..KexPolicyConfig::default()
        })
        .expect_err("backend sntrup should fail");

        assert!(error.to_string().contains("kex_policy.backend_preferred"));
    }

    #[test]
    fn backend_policy_summary_marks_classical_fallback() {
        let summary = backend_kex_policy_summary(&KexPolicyConfig::default()).expect("summary");

        assert!(
            summary
                .offered_algorithms
                .iter()
                .any(|name| name == CURVE25519_SHA256_NAME)
        );
        assert!(summary.classical_fallback);
        assert!(!summary.require_post_quantum);
    }

    #[test]
    fn ssh_policy_uses_aead_ciphers_without_legacy_mac_fallbacks() {
        let preferred = backend_client_preferred(&KexPolicyConfig::default()).expect("preferred");

        assert_eq!(
            cipher_names(&preferred),
            vec!["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
        );
        assert_eq!(
            mac_names(&preferred),
            vec![
                "hmac-sha2-512-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com"
            ]
        );
        assert_eq!(compression_names(&preferred), vec!["none"]);
    }

    #[test]
    fn ssh_policy_disables_ssh_rsa_sha1_host_key_algorithm() {
        let key_algorithms = backend_client_preferred(&KexPolicyConfig::default())
            .expect("preferred")
            .key
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert!(key_algorithms.contains(&"ssh-ed25519".to_string()));
        assert!(key_algorithms.contains(&"rsa-sha2-512".to_string()));
        assert!(key_algorithms.contains(&"rsa-sha2-256".to_string()));
        assert!(!key_algorithms.contains(&"ssh-rsa".to_string()));
    }

    #[test]
    fn transport_configs_apply_rekey_limits() {
        let mut server_config = russh::server::Config::default();
        let mut client_config = russh::client::Config::default();

        apply_server_transport_crypto_policy(&mut server_config, &KexPolicyConfig::default())
            .expect("server policy");
        apply_client_transport_crypto_policy(&mut client_config, &KexPolicyConfig::default())
            .expect("client policy");

        assert_eq!(server_config.limits.rekey_write_limit, SSH_REKEY_BYTES);
        assert_eq!(server_config.limits.rekey_read_limit, SSH_REKEY_BYTES);
        assert_eq!(server_config.limits.rekey_time_limit, SSH_REKEY_TIME);
        assert_eq!(client_config.limits.rekey_write_limit, SSH_REKEY_BYTES);
        assert_eq!(client_config.limits.rekey_read_limit, SSH_REKEY_BYTES);
        assert_eq!(client_config.limits.rekey_time_limit, SSH_REKEY_TIME);
    }

    #[test]
    fn keyscan_helper_does_not_accept_md5_fingerprints() {
        let helper = std::fs::read_to_string("tools/cssh-keyscan").expect("read cssh-keyscan");

        assert!(!helper.contains("-E md5"));
        assert!(!helper.contains("MD5:<fingerprint>"));
        assert!(!helper.contains("MD5:[0-9A-Fa-f:]"));
    }
}
