use super::{PublicKey, ViewKey};
use crate::{rpc, utils, Scalar};

use std::fmt;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Secret pair of a and b
///
/// It is used to create a note nullifier via secret b
pub struct SecretKey {
    /// Secret scalar
    pub a: Scalar,
    /// Secret scalar
    pub b: Scalar,
}

impl Default for SecretKey {
    fn default() -> Self {
        SecretKey {
            a: utils::gen_random_clamped_scalar(),
            b: utils::gen_random_clamped_scalar(),
        }
    }
}

impl SecretKey {
    /// [`SecretKey`] constructor
    pub fn new(a: Scalar, b: Scalar) -> Self {
        SecretKey { a, b }
    }

    /// Derive the secret to deterministically construct a [`PublicKey`]
    pub fn public_key(&self) -> PublicKey {
        let a_g = utils::mul_by_basepoint_ristretto(&self.a);
        let b_g = utils::mul_by_basepoint_ristretto(&self.b);

        PublicKey::new(a_g, b_g)
    }

    /// Derive the secret to deterministically construct a [`ViewKey`]
    pub fn view_key(&self) -> ViewKey {
        let b_g = utils::mul_by_basepoint_ristretto(&self.b);

        ViewKey::new(self.a, b_g)
    }
}

impl From<rpc::SecretKey> for SecretKey {
    fn from(k: rpc::SecretKey) -> Self {
        Self::new(
            k.a.unwrap_or_default().into(),
            k.b.unwrap_or_default().into(),
        )
    }
}

impl From<SecretKey> for rpc::SecretKey {
    fn from(k: SecretKey) -> Self {
        Self {
            a: Some(rpc::Scalar::from(k.a)),
            b: Some(rpc::Scalar::from(k.b)),
        }
    }
}

impl From<Vec<u8>> for SecretKey {
    fn from(bytes: Vec<u8>) -> Self {
        let mut hasher = Sha512::default();

        hasher.input(bytes.as_slice());

        let s = Scalar::from_hash(hasher);
        let mut rng = StdRng::from_seed(s.to_bytes());

        let mut a = [0x00u8; 32];
        rng.fill_bytes(&mut a);
        utils::clamp_bytes(&mut a);
        let a = Scalar::from_bits(a);

        let mut b = [0x00u8; 32];
        rng.fill_bytes(&mut b);
        utils::clamp_bytes(&mut b);
        let b = Scalar::from_bits(b);

        SecretKey::new(a, b)
    }
}

impl From<String> for SecretKey {
    fn from(s: String) -> Self {
        Self::from(s.into_bytes())
    }
}

impl fmt::LowerHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = hex::encode(self.a.as_bytes());
        let b = hex::encode(self.b.as_bytes());

        write!(f, "{}{}", a, b)
    }
}

impl fmt::UpperHex for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = hex::encode_upper(self.a.as_bytes());
        let b = hex::encode_upper(self.b.as_bytes());

        write!(f, "{}{}", a, b)
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}
