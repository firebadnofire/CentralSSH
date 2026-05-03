use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::UserRecord;
use crate::error::{CentralSshError, Result};
use argon2::password_hash::rand_core::RngCore;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base32::Alphabet;
use tokio::sync::Mutex;
use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};

const ARGON_MEMORY_KIB: u32 = 65_536;
const ARGON_ITERATIONS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const DUMMY_PASSWORD: &str = "centralssh-dummy-password";
const DEFAULT_TOTP_DIGITS: usize = 6;
const DEFAULT_TOTP_PERIOD: u64 = 30;
const DEFAULT_TOTP_SKEW: u8 = 1;
const USER_RATE_LIMIT_CAPACITY: f64 = 10.0;
const USER_RATE_LIMIT_REFILL_PER_SEC: f64 = 1.0 / 30.0;
const IP_RATE_LIMIT_CAPACITY: f64 = 30.0;
const IP_RATE_LIMIT_REFILL_PER_SEC: f64 = 1.0;
const RATE_LIMIT_MAX_ENTRIES: usize = 8192;
const RATE_LIMIT_IDLE_TTL: Duration = Duration::from_secs(60 * 30);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RateLimitKey {
    ip: IpAddr,
    username: String,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_rate_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn consume_one(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }

        let refill_amount = elapsed * self.refill_rate_per_sec;
        self.tokens = (self.tokens + refill_amount).min(self.capacity);
        self.last_refill = Instant::now();
    }
}

#[derive(Clone)]
pub struct AuthEngine {
    argon2: Argon2<'static>,
    rate_limits: std::sync::Arc<Mutex<HashMap<RateLimitKey, TokenBucket>>>,
    ip_rate_limits: std::sync::Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    dummy_hash: std::sync::Arc<String>,
}

impl AuthEngine {
    pub fn new() -> Result<Self> {
        let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_PARALLELISM, None)
            .map_err(|e| CentralSshError::InvalidConfig(format!("invalid argon2 params: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let dummy_hash = Self::hash_with_engine(&argon2, DUMMY_PASSWORD)?;

        Ok(Self {
            argon2,
            rate_limits: std::sync::Arc::new(Mutex::new(HashMap::new())),
            ip_rate_limits: std::sync::Arc::new(Mutex::new(HashMap::new())),
            dummy_hash: std::sync::Arc::new(dummy_hash),
        })
    }

    pub fn is_hash_format(&self, value: &str) -> bool {
        value.starts_with("$argon2id$")
    }

    pub fn hash_password(&self, password: &str) -> Result<String> {
        Self::hash_with_engine(&self.argon2, password)
    }

    fn hash_with_engine(engine: &Argon2<'_>, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let hash = engine
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
        Ok(hash)
    }

    pub async fn consume_rate_limit_token(&self, ip: IpAddr, username: &str) -> Result<()> {
        self.consume_ip_rate_limit_token(ip).await?;

        let key = RateLimitKey {
            ip,
            username: username.to_ascii_lowercase(),
        };

        let now = Instant::now();
        let mut guard = self.rate_limits.lock().await;
        prune_buckets(&mut guard, now);
        if !guard.contains_key(&key) && guard.len() >= RATE_LIMIT_MAX_ENTRIES {
            return Err(CentralSshError::RateLimitExceeded);
        }
        let bucket = guard.entry(key).or_insert_with(|| {
            TokenBucket::new(USER_RATE_LIMIT_CAPACITY, USER_RATE_LIMIT_REFILL_PER_SEC)
        });

        if bucket.consume_one() {
            Ok(())
        } else {
            Err(CentralSshError::RateLimitExceeded)
        }
    }

    async fn consume_ip_rate_limit_token(&self, ip: IpAddr) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.ip_rate_limits.lock().await;
        prune_buckets(&mut guard, now);
        if !guard.contains_key(&ip) && guard.len() >= RATE_LIMIT_MAX_ENTRIES {
            return Err(CentralSshError::RateLimitExceeded);
        }

        let bucket = guard.entry(ip).or_insert_with(|| {
            TokenBucket::new(IP_RATE_LIMIT_CAPACITY, IP_RATE_LIMIT_REFILL_PER_SEC)
        });
        if bucket.consume_one() {
            Ok(())
        } else {
            Err(CentralSshError::RateLimitExceeded)
        }
    }

    pub fn verify_password_constant_time(
        &self,
        users: &[UserRecord],
        requested_username: &str,
        requested_password: &str,
    ) -> Result<UserRecord> {
        let mut matched_user: Option<UserRecord> = None;

        for user in users {
            if secure_username_match(&user.name, requested_username) {
                matched_user = Some(user.clone());
            }
        }

        let target_hash = matched_user
            .as_ref()
            .map(|u| u.password.as_str())
            .unwrap_or_else(|| self.dummy_hash.as_str());

        // Always execute an Argon2 verify path to avoid account enumeration timing leaks.
        let parsed_hash = PasswordHash::new(target_hash)?;
        let verification = self
            .argon2
            .verify_password(requested_password.as_bytes(), &parsed_hash);

        if verification.is_ok() && matched_user.is_some() {
            if let Some(user) = matched_user {
                Ok(user)
            } else {
                Err(CentralSshError::AuthenticationFailed)
            }
        } else {
            Err(CentralSshError::AuthenticationFailed)
        }
    }

    pub fn verify_password_and_optional_totp_constant_time(
        &self,
        users: &[UserRecord],
        requested_username: &str,
        requested_password: &str,
        requested_totp: &str,
    ) -> Result<UserRecord> {
        let user =
            self.verify_password_constant_time(users, requested_username, requested_password)?;

        if let Some(secret) = &user.totp_secret {
            self.verify_totp_code(secret, requested_totp)?;
        }

        Ok(user)
    }

    pub fn enforce_password_policy(
        &self,
        new_password: &str,
        old_hash: &str,
        min_length: usize,
    ) -> Result<()> {
        let min_length = min_length.min(256);

        if new_password.len() < min_length {
            return Err(CentralSshError::InvalidConfig(
                format!("password must be at least {min_length} characters"),
            ));
        }

        if new_password.len() > 256 {
            return Err(CentralSshError::InvalidConfig(
                "password must be <= 256 characters".to_string(),
            ));
        }

        let old_hash = PasswordHash::new(old_hash)?;
        if self
            .argon2
            .verify_password(new_password.as_bytes(), &old_hash)
            .is_ok()
        {
            return Err(CentralSshError::InvalidConfig(
                "new password must be different from current password".to_string(),
            ));
        }

        Ok(())
    }

    pub fn generate_totp_secret(&self) -> String {
        let mut bytes = [0u8; 32];
        argon2::password_hash::rand_core::OsRng.fill_bytes(&mut bytes);
        base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes)
    }

    pub fn build_totp(&self, base32_secret: &str) -> Result<TOTP> {
        build_totp_from_secret(base32_secret)
    }

    pub fn verify_totp_code(&self, base32_secret: &str, code: &str) -> Result<()> {
        let totp = self.build_totp(base32_secret)?;
        if totp.check_current(code).unwrap_or(false) {
            Ok(())
        } else {
            Err(CentralSshError::TotpInvalid)
        }
    }

    pub fn otpauth_url(&self, issuer: &str, account: &str, secret: &str) -> Result<String> {
        let secret_bytes = Secret::Encoded(secret.to_owned())
            .to_bytes()
            .map_err(|e| CentralSshError::InvalidConfig(format!("invalid totp secret: {e}")))?;

        let totp = TOTP::new(
            TotpAlgorithm::SHA1,
            DEFAULT_TOTP_DIGITS,
            DEFAULT_TOTP_SKEW,
            DEFAULT_TOTP_PERIOD,
            secret_bytes,
            Some(issuer.to_string()),
            account.to_string(),
        )
        .map_err(|e| CentralSshError::InvalidConfig(format!("failed to build totp: {e}")))?;
        Ok(totp.get_url())
    }
}

pub fn build_totp_from_secret(base32_secret: &str) -> Result<TOTP> {
    let secret_bytes = Secret::Encoded(base32_secret.to_owned())
        .to_bytes()
        .map_err(|error| CentralSshError::InvalidConfig(format!("invalid totp secret: {error}")))?;

    TOTP::new(
        TotpAlgorithm::SHA1,
        DEFAULT_TOTP_DIGITS,
        DEFAULT_TOTP_SKEW,
        DEFAULT_TOTP_PERIOD,
        secret_bytes,
        None,
        String::new(),
    )
    .map_err(|error| CentralSshError::InvalidConfig(format!("failed to build totp: {error}")))
}

fn secure_username_match(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        // Keep a constant-time compare on fixed bytes so mismatched lengths don't short-circuit.
        return constant_time_eq::constant_time_eq(left.as_bytes(), left.as_bytes())
            && constant_time_eq::constant_time_eq(right.as_bytes(), right.as_bytes())
            && false;
    }

    constant_time_eq::constant_time_eq(left.as_bytes(), right.as_bytes())
}

fn prune_buckets<K>(buckets: &mut HashMap<K, TokenBucket>, now: Instant)
where
    K: std::hash::Hash + Eq,
{
    buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) <= RATE_LIMIT_IDLE_TTL);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_MIN_PASSWORD_POLICY;

    #[test]
    fn build_totp_from_secret_accepts_runtime_valid_secret() {
        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        assert!(build_totp_from_secret(secret).is_ok());
    }

    #[test]
    fn build_totp_from_secret_rejects_short_decodable_secret() {
        let secret = "JBSWY3DPEHPK3PXP";
        assert!(build_totp_from_secret(secret).is_err());
    }

    #[test]
    fn verify_password_and_optional_totp_accepts_valid_combination() {
        let auth = AuthEngine::new().expect("engine");
        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let totp = build_totp_from_secret(secret).expect("totp");
        let user = UserRecord {
            name: "alice".to_string(),
            password: auth
                .hash_password("correct horse battery staple")
                .expect("hash"),
            totp_secret: Some(secret.to_string()),
            must_change_password: false,
            allowed_servers: vec!["git".to_string()],
        };

        let code = totp.generate_current().expect("code");
        let verified = auth
            .verify_password_and_optional_totp_constant_time(
                &[user.clone()],
                "alice",
                "correct horse battery staple",
                &code,
            )
            .expect("valid combo");

        assert_eq!(verified.name, user.name);
    }

    #[test]
    fn verify_password_and_optional_totp_rejects_invalid_totp() {
        let auth = AuthEngine::new().expect("engine");
        let user = UserRecord {
            name: "alice".to_string(),
            password: auth
                .hash_password("correct horse battery staple")
                .expect("hash"),
            totp_secret: Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
            must_change_password: false,
            allowed_servers: vec!["git".to_string()],
        };

        let result = auth.verify_password_and_optional_totp_constant_time(
            &[user],
            "alice",
            "correct horse battery staple",
            "000000",
        );

        assert!(matches!(result, Err(CentralSshError::TotpInvalid)));
    }

    #[test]
    fn verify_password_and_optional_totp_allows_unenrolled_users() {
        let auth = AuthEngine::new().expect("engine");
        let user = UserRecord {
            name: "alice".to_string(),
            password: auth
                .hash_password("correct horse battery staple")
                .expect("hash"),
            totp_secret: None,
            must_change_password: true,
            allowed_servers: vec!["git".to_string()],
        };

        let verified = auth
            .verify_password_and_optional_totp_constant_time(
                &[user.clone()],
                "alice",
                "correct horse battery staple",
                "ignored",
            )
            .expect("password-only user");

        assert_eq!(verified.name, user.name);
    }

    #[test]
    fn verify_password_constant_time_rejects_invalid_password() {
        let auth = AuthEngine::new().expect("engine");
        let user = UserRecord {
            name: "alice".to_string(),
            password: auth
                .hash_password("correct horse battery staple")
                .expect("hash"),
            totp_secret: None,
            must_change_password: true,
            allowed_servers: vec!["git".to_string()],
        };

        let result =
            auth.verify_password_constant_time(&[user], "alice", "definitely the wrong password");

        assert!(matches!(result, Err(CentralSshError::AuthenticationFailed)));
    }

    #[tokio::test]
    async fn token_bucket_depletes() {
        let auth = AuthEngine::new().expect("engine");
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");

        for _ in 0..10 {
            assert!(auth.consume_rate_limit_token(ip, "alice").await.is_ok());
        }

        assert!(matches!(
            auth.consume_rate_limit_token(ip, "alice").await,
            Err(CentralSshError::RateLimitExceeded)
        ));
    }

    #[test]
    fn enforce_password_policy_uses_configured_minimum_length() {
        let auth = AuthEngine::new().expect("engine");
        let old_hash = auth.hash_password("current-password").expect("hash");

        let result = auth.enforce_password_policy("short", &old_hash, DEFAULT_MIN_PASSWORD_POLICY);
        assert!(matches!(result, Err(CentralSshError::InvalidConfig(message)) if message == "password must be at least 12 characters"));

        auth.enforce_password_policy("long enough for policy", &old_hash, 20)
            .expect("policy should pass");
    }
}
