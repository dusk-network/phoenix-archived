use crate::{PublicKey, SecretKey, ViewKey};

use std::convert::TryFrom;

#[test]
fn sk_from_bytes() {
    let bytes = b"some bytes".to_vec();

    let sk_a = SecretKey::from(bytes.clone());
    let sk_b = SecretKey::from(bytes);

    assert_eq!(sk_a, sk_b);
}

#[test]
fn keys_encoding() {
    let bytes = b"some bytes".to_vec();

    let sk = SecretKey::from(bytes.clone());
    let vk = sk.view_key();
    let pk = sk.public_key();

    assert_eq!(vk, ViewKey::try_from(format!("{}", vk)).unwrap());
    assert_eq!(pk, PublicKey::try_from(format!("{}", pk)).unwrap());
}
