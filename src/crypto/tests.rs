use crate::{crypto, utils, Note, NoteGenerator, ObfuscatedNote, SecretKey};

#[test]
fn decrypt() {
    utils::init();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();
    let nonce = utils::gen_nonce();

    let (r, R, _) = ObfuscatedNote::generate_pk_r(&pk);

    let bytes = b"some data";
    let encrypted = crypto::encrypt(&r, &pk, &nonce, bytes);
    let decrypted = crypto::decrypt(&R, &vk, &nonce, encrypted.as_slice());

    assert_eq!(&bytes[..], decrypted.as_slice());
}

#[test]
fn decrypt_with_wrong_key_should_fail() {
    utils::init();

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
    utils::init();

    let value = 25;

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();

    let (note, _) = ObfuscatedNote::output(&pk, value);
    let decrypt_value = note.value(Some(&vk));

    assert_eq!(decrypt_value, value);
}
