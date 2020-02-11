use crate::{EdwardsPoint, MontgomeryPoint, Nonce, RistrettoPoint, Scalar};

use std::cmp;

use curve25519_dalek::constants;
use rand::rngs::OsRng;
use rand::RngCore;
use sodiumoxide::crypto::box_;

/// Generate a random scalar from [`OsRng`]
pub fn gen_random_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);
    Scalar::from_bits(s)
}

/// Generate a random key-clamped scalar from [`OsRng`]
pub fn gen_random_clamped_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);

    clamp_bytes(&mut s);

    Scalar::from_bits(s)
}

/// Clamp a slice of bytes for key generation
pub fn clamp_bytes(b: &mut [u8; 32]) {
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
}

/// Generate a ed field element from a scalar
pub fn mul_by_basepoint_edwards(s: &Scalar) -> EdwardsPoint {
    &constants::ED25519_BASEPOINT_TABLE * s
}

/// Get the Y coordinate of a ed field element and return it as a scalar
pub fn edwards_to_scalar(p: EdwardsPoint) -> Scalar {
    Scalar::from_bits(p.compress().to_bytes())
}

/// Generate a new random nonce
pub fn gen_nonce() -> Nonce {
    box_::gen_nonce()
}

/// Safely transpose a slice of any size to a `[u8; 32]`
pub fn safe_32_chunk(bytes: &[u8]) -> [u8; 32] {
    let mut s = [0x00u8; 32];
    let chunk = cmp::min(bytes.len(), 32);

    (&mut s[0..chunk]).copy_from_slice(&bytes[0..chunk]);

    s
}

/// Generate a ristretto field element from a scalar
pub fn mul_by_basepoint_ristretto(s: &Scalar) -> RistrettoPoint {
    &constants::RISTRETTO_BASEPOINT_TABLE * s
}

/// Unsafely extract the Montgomery model form a ristretto point.
///
/// Assumes `(Z + Y) / (Z - Y)` stands also for ristretto points, considering it is a subgroup of
/// edwards
pub fn ristretto_to_montgomery(point: RistrettoPoint) -> MontgomeryPoint {
    unsafe { std::mem::transmute::<RistrettoPoint, EdwardsPoint>(point).to_montgomery() }
}
