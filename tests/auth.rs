use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use nginx_dovecot_auth::auth::verify_password;

fn make_argon2i_hash(password: &[u8]) -> String {
    let salt = SaltString::encode_b64(b"unit-test-salt").expect("valid test salt");

    let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, Params::default());

    let hash = argon2
        .hash_password(password, &salt)
        .expect("hash password");

    format!("{{ARGON2I}}{hash}")
}

#[test]
fn argon2i_accepts_correct_password() {
    let stored_hash = make_argon2i_hash(b"correct-password");

    assert!(verify_password("correct-password", &stored_hash));
}

#[test]
fn argon2i_rejects_wrong_password() {
    let stored_hash = make_argon2i_hash(b"correct-password");

    assert!(!verify_password("wrong-password", &stored_hash));
}

#[test]
fn argon2i_rejects_malformed_hash() {
    assert!(!verify_password("password", "{ARGON2I}not-a-valid-hash"));
}

#[test]
fn argon2i_prefix_rejects_argon2id_hash() {
    let salt = SaltString::encode_b64(b"unit-test-salt").expect("valid test salt");

    let argon2id = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());

    let hash = argon2id
        .hash_password(b"correct-password", &salt)
        .expect("hash password")
        .to_string();

    // An Argon2id hash must not be accepted under an Argon2i prefix.
    let stored_hash = format!("{{ARGON2I}}{hash}");

    assert!(!verify_password("correct-password", &stored_hash));
}

#[test]
fn argon2i_accepts_correct_dovecot_password() {
    let stored_hash = "{ARGON2I}$argon2i$v=19$m=32768,t=4,p=1$AlYX+c1kpYZfaYz0+eikeg$iG21Ar3pP2AZ+A5X1hvLS1BCHzPuwfnSeo3DlPrIljE";

    assert!(verify_password("password", stored_hash));
}

#[test]
fn unsupported_hash_prefix_is_rejected() {
    assert!(!verify_password("password", "{UNKNOWN}some-hash"));
}

#[test]
fn empty_password_is_rejected() {
    let stored_hash = make_argon2i_hash(b"correct-password");

    assert!(!verify_password("", &stored_hash));
}
