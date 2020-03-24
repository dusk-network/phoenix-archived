use crate::{utils, JubJubScalar, PublicKey, ViewKey};

use std::fmt;

use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

/// Secret pair of a and b
///
/// It is used to create a note nullifier via secret b
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretKey {
    /// Secret scalar
    pub a: JubJubScalar,
    /// Secret scalar
    pub b: JubJubScalar,
}

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey {
            a: utils::gen_random_scalar(),
            b: utils::gen_random_scalar(),
        }
    }
}

impl SecretKey {
    /// [`SecretKey`] constructor
    pub fn new(a: JubJubScalar, b: JubJubScalar) -> Self {
        SecretKey { a, b }
    }

    /// Deterministically create a new [`SecretKey`] from a random number generator
    pub fn from_rng<R: RngCore>(rng: &mut R) -> Self {
        let a = utils::gen_random_scalar_from_rng(rng);
        let b = utils::gen_random_scalar_from_rng(rng);

        SecretKey::new(a, b)
    }

    /// Derive the secret to deterministically construct a [`PublicKey`]
    pub fn public_key(&self) -> PublicKey {
        let A = utils::mul_by_basepoint_jubjub(&self.a);
        let B = utils::mul_by_basepoint_jubjub(&self.b);

        PublicKey::new(A, B)
    }

    /// Derive the secret to deterministically construct a [`ViewKey`]
    pub fn view_key(&self) -> ViewKey {
        let B = utils::mul_by_basepoint_jubjub(&self.b);

        ViewKey::new(self.a, B)
    }
}
////
////impl From<rpc::SecretKey> for SecretKey {
////    fn from(k: rpc::SecretKey) -> Self {
////        Self::new(
////            k.a.unwrap_or_default().into(),
////            k.b.unwrap_or_default().into(),
////        )
////    }
////}
////
////impl From<SecretKey> for rpc::SecretKey {
////    fn from(k: SecretKey) -> Self {
////        Self {
////            a: Some(rpc::Scalar::from(k.a)),
////            b: Some(rpc::Scalar::from(k.b)),
////        }
////    }
////}
////
//

const SK_SIZE: usize = utils::JUBJUB_SCALAR_SERIALIZED_SIZE * 2;

impl Into<[u8; SK_SIZE]> for &SecretKey {
    fn into(self) -> [u8; SK_SIZE] {
        let mut bytes = [0x00u8; SK_SIZE];

        utils::serialize_jubjub_scalar(&self.a, &mut bytes[0..SK_SIZE / 2])
            .expect("In-memory write");

        utils::serialize_jubjub_scalar(&self.b, &mut bytes[SK_SIZE / 2..SK_SIZE])
            .expect("In-memory write");

        bytes
    }
}

impl From<&[u8]> for SecretKey {
    fn from(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::default();
        hasher.input(bytes);
        let bytes = hasher.result();

        let mut seed = [0x00u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        let mut rng = StdRng::from_seed(seed);

        SecretKey::from_rng(&mut rng)
    }
}

impl From<String> for SecretKey {
    fn from(s: String) -> Self {
        Self::from(s.into_bytes().as_slice())
    }
}

impl fmt::LowerHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; SK_SIZE] = self.into();

        let a = hex::encode(&bytes[0..SK_SIZE / 2]);
        let b = hex::encode(&bytes[SK_SIZE / 2..SK_SIZE]);

        write!(f, "{}{}", a, b)
    }
}

impl fmt::UpperHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; SK_SIZE] = self.into();

        let a = hex::encode_upper(&bytes[0..SK_SIZE / 2]);
        let b = hex::encode_upper(&bytes[SK_SIZE / 2..SK_SIZE]);

        write!(f, "{}{}", a, b)
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
