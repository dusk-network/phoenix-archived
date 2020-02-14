use crate::{crypto, utils, Note, NoteGenerator, ObfuscatedNote, SecretKey};

use curve25519_dalek::constants;

#[test]
fn ristretto_to_montgomery() {
    let sk = SecretKey::default();

    let a_g_ristretto = utils::mul_by_basepoint_ristretto(&sk.a);
    let a_g_edwards = &constants::ED25519_BASEPOINT_TABLE * &sk.a;

    let montgomery_ristretto = utils::ristretto_to_montgomery(a_g_ristretto);
    let montgomery_edwards = a_g_edwards.to_montgomery();

    assert_eq!(montgomery_ristretto, montgomery_edwards);
}

#[test]
fn decrypt() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();
    let nonce = utils::gen_nonce();

    let (r, r_g, _) = ObfuscatedNote::generate_pk_r(&pk);

    let bytes = b"some data";
    let encrypted = crypto::encrypt(&r, &pk, &nonce, bytes);
    let decrypted = crypto::decrypt(&r_g, &vk, &nonce, encrypted.as_slice());

    assert_eq!(&bytes[..], decrypted.as_slice());
}

#[test]
fn decrypt_with_wrong_key_should_fail() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();
    let nonce = utils::gen_nonce();
    let wrong_vk = SecretKey::default().view_key();

    assert_ne!(vk, wrong_vk);

    let (r, r_g, _) = ObfuscatedNote::generate_pk_r(&pk);

    let bytes = b"some data";
    let encrypted = crypto::encrypt(&r, &pk, &nonce, bytes);
    let decrypted = crypto::decrypt(&r_g, &wrong_vk, &nonce, encrypted.as_slice());

    assert_ne!(&bytes[..], decrypted.as_slice());
}

#[test]
fn decrypt_obfuscated_note() {
    let value = 25;

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();

    let (note, _) = ObfuscatedNote::output(&pk, value);
    let decrypt_value = note.value(Some(&vk));

    assert_eq!(decrypt_value, value);
}
