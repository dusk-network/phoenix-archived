use super::{PublicKey, ViewKey};
use crate::{rpc, utils, Scalar};

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
        // TODO - Tonic is generating Option attributes for syntax = proto3, wait for fix
        Self::new(k.a.unwrap().into(), k.b.unwrap().into())
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
