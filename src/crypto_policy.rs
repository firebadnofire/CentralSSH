use std::borrow::Cow;
use std::time::Duration;

use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};
use russh::{Limits, Preferred, cipher, compression, kex, mac};

pub const SSH_REKEY_BYTES: usize = 512 * 1024 * 1024;
pub const SSH_REKEY_TIME: Duration = Duration::from_secs(30 * 60);

const SSH_KEX_ALGORITHMS: &[kex::Name] = &[
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
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

pub fn hardened_ssh_preferred() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(SSH_KEX_ALGORITHMS),
        key: Cow::Borrowed(SSH_HOST_KEY_ALGORITHMS),
        cipher: Cow::Borrowed(SSH_CIPHERS),
        mac: Cow::Borrowed(SSH_MACS),
        compression: Cow::Borrowed(SSH_COMPRESSION),
    }
}

pub fn hardened_ssh_limits() -> Limits {
    Limits::new(SSH_REKEY_BYTES, SSH_REKEY_BYTES, SSH_REKEY_TIME)
}

pub fn apply_server_transport_crypto_policy(config: &mut russh::server::Config) {
    config.preferred = hardened_ssh_preferred();
    config.limits = hardened_ssh_limits();
}

pub fn apply_client_transport_crypto_policy(config: &mut russh::client::Config) {
    config.preferred = hardened_ssh_preferred();
    config.limits = hardened_ssh_limits();
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
    fn ssh_policy_uses_ephemeral_curve25519_and_strict_kex_only() {
        let preferred = hardened_ssh_preferred();
        let names = kex_names(&preferred);

        assert!(names.contains(&"curve25519-sha256"));
        assert!(names.contains(&"curve25519-sha256@libssh.org"));
        assert!(names.contains(&"kex-strict-c-v00@openssh.com"));
        assert!(names.contains(&"kex-strict-s-v00@openssh.com"));
        assert!(
            !names
                .iter()
                .any(|name| name.contains("diffie-hellman") || name.contains("ecdh"))
        );
        assert!(!names.contains(&"none"));
    }

    #[test]
    fn ssh_policy_uses_aead_ciphers_without_legacy_mac_fallbacks() {
        let preferred = hardened_ssh_preferred();

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
        let key_algorithms = hardened_ssh_preferred()
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

        apply_server_transport_crypto_policy(&mut server_config);
        apply_client_transport_crypto_policy(&mut client_config);

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
