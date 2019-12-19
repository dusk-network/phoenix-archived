use super::{PublicKey, ViewKey};
use crate::{utils, Scalar};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
        let a_g = utils::mul_by_basepoint(&self.a);
        let b_g = utils::mul_by_basepoint(&self.b);

        PublicKey::new(a_g, b_g)
    }

    pub fn view_key(&self) -> ViewKey {
        let b_g = utils::mul_by_basepoint(&self.b);

        ViewKey::new(self.a, b_g)
    }
}
