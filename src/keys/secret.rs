use super::{PublicKey, ViewKey};
use crate::{rpc, utils, Scalar};

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretKey {
    pub a: Scalar,
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
    pub fn new(a: Scalar, b: Scalar) -> Self {
        SecretKey { a, b }
    }

    pub fn public_key(&self) -> PublicKey {
        let a_g = utils::mul_by_basepoint_edwards(&self.a);
        let b_g = utils::mul_by_basepoint_edwards(&self.b);

        PublicKey::new(a_g, b_g)
    }

    pub fn view_key(&self) -> ViewKey {
        let b_g = utils::mul_by_basepoint_edwards(&self.b);

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
        let a = Scalar::from_bits(a);

        let mut b = [0x00u8; 32];
        rng.fill_bytes(&mut b);
        let b = Scalar::from_bits(b);

        SecretKey::new(a, b)
    }
}
