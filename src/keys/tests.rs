use crate::{utils, JubJubExtended, JubJubScalar, PublicKey, SecretKey, ViewKey};

use std::convert::TryFrom;
use std::ops::Mul;

#[test]
fn sk_from_bytes() {
    utils::init();

    let bytes = b"some bytes".to_vec();

    let sk_a = SecretKey::from(bytes.as_slice());
    let sk_b = SecretKey::from(bytes.as_slice());

    assert_eq!(sk_a, sk_b);
}

#[test]
fn keys_encoding() {
    utils::init();

    let bytes = b"some bytes".to_vec();

    let sk = SecretKey::from(bytes.as_slice());
    let vk = sk.view_key();
    let pk = sk.public_key();

    assert_eq!(vk, ViewKey::try_from(format!("{}", vk)).unwrap());
    assert_eq!(pk, PublicKey::try_from(format!("{}", pk)).unwrap());
}

#[test]
fn scalar_and_point_encoding() {
    utils::init();

    fn serde(p: &JubJubExtended) -> JubJubExtended {
        let mut bytes = [0x00u8; utils::COMPRESSED_JUBJUB_SERIALIZED_SIZE];

        utils::serialize_compressed_jubjub(p, &mut bytes).unwrap();
        utils::deserialize_compressed_jubjub(&bytes).unwrap()
    }

    fn serde_scalar(s: &JubJubScalar) -> JubJubScalar {
        let mut bytes = [0x00u8; utils::JUBJUB_SCALAR_SERIALIZED_SIZE];

        utils::serialize_jubjub_scalar(s, &mut bytes).unwrap();
        utils::deserialize_jubjub_scalar(&bytes).unwrap()
    }

    let a = utils::gen_random_scalar();
    let b = utils::gen_random_scalar();
    let r = utils::gen_random_scalar();
    let x = utils::gen_random_scalar();

    let a_s = serde_scalar(&a);
    let x_s = serde_scalar(&x);

    assert_eq!(a, a_s);
    assert_eq!(x, x_s);
    assert_ne!(a, x_s);

    let A = utils::mul_by_basepoint_jubjub(&a);
    let B = utils::mul_by_basepoint_jubjub(&b);
    let R = utils::mul_by_basepoint_jubjub(&r);
    let X = utils::mul_by_basepoint_jubjub(&x);

    let A_s = serde(&A);
    let B_s = serde(&B);
    let R_s = serde(&R);

    let r_A_B = A.mul(&r) + B;
    let a_R_B = R.mul(&a) + B;
    let x_R_B = R.mul(&x) + B;
    let a_X_B = X.mul(&a) + B;

    let r_A_s_B = A_s.mul(&r) + B;
    let a_R_s_B = R_s.mul(&a) + B;
    let r_A_B_s = A.mul(&r) + B_s;
    let a_R_s_B_s = R_s.mul(&a) + B_s;

    assert_eq!(r_A_B, a_R_B);
    assert_eq!(r_A_B, r_A_s_B);
    assert_eq!(r_A_B, a_R_s_B);
    assert_eq!(r_A_B, r_A_B_s);
    assert_eq!(r_A_B, a_R_s_B_s);
    assert_ne!(r_A_B, x_R_B);
    assert_ne!(r_A_B, a_X_B);
}
