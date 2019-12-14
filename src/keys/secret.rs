use super::{PublicKey, ViewKey};
use crate::{hash, utils, RistrettoPoint, Scalar};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SecretKey {
    pub a: Scalar,
    pub b: Scalar,
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
    pub fn new(a: Scalar, b: Scalar) -> Self {
        SecretKey { a, b }
    }

    pub fn public_key(&self) -> PublicKey {
        let a_p = utils::scalar_to_field(&self.a);
        let b_p = utils::scalar_to_field(&self.b);

        PublicKey::new(a_p, b_p)
    }

    pub fn view_key(&self) -> ViewKey {
        let b_p = utils::scalar_to_field(&self.b);

        ViewKey::new(self.a, b_p)
    }

    pub fn r_p(&self, r_p: &RistrettoPoint) -> RistrettoPoint {
        let a_r = hash::hash_in_p(&self.a * r_p);
        let b_r = utils::scalar_to_field(&self.b);

        a_r + b_r
    }
}
