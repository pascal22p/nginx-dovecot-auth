
use argon2::{
    password_hash::phc::PasswordHash,
    password_hash::PasswordVerifier,
    Algorithm, Argon2, Params, Version,
};

/// Verify a plaintext password against a Dovecot-style stored hash.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    if password.is_empty() {
        tracing::warn!("Authentication failed: empty password");
        return false;
    }

    if stored_hash.is_empty() {
        tracing::error!("Authentication failed: stored password hash is empty");
        return false;
    }

    if let Some(hash) = stored_hash.strip_prefix("{ARGON2I}") {
        return verify_argon2i(password, hash);
    }

    // Log the prefix only, never the full stored hash.
    let prefix = if stored_hash.starts_with('{') {
        stored_hash
            .split_once('}')
            .map(|(prefix, _)| format!("{prefix}}}"))
            .unwrap_or_else(|| "malformed prefix".to_string())
    } else {
        "missing prefix".to_string()
    };

    tracing::warn!(
        hash_prefix = %prefix,
        "Authentication failed: unsupported hash prefix"
    );

    false
}

fn verify_argon2i(password: &str, encoded_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(encoded_hash) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::error!(
                error = %error,
                "Authentication failed: malformed Argon2 hash"
            );
            return false;
        }
    };

    // Do not accept Argon2id or Argon2d under an {ARGON2I} prefix.
    if parsed_hash.algorithm.as_str() != "argon2i" {
        tracing::warn!(
            algorithm = %parsed_hash.algorithm,
            "Authentication failed: hash algorithm is not Argon2i"
        );
        return false;
    }

    // Keep this configuration aligned with your Dovecot hash parameters.
    let argon2 = Argon2::new(
        Algorithm::Argon2i,
        Version::V0x13,
        Params::default(),
    );

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => {
            tracing::debug!("Password verification succeeded");
            true
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Authentication failed: Argon2 verification failed"
            );
            false
        }
    }
}
