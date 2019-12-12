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
        let a_p = utils::scalar_to_field(&self.a).compress();
        let b_p = utils::scalar_to_field(&self.b).compress();

        PublicKey::new(a_p, b_p)
    }

    pub fn view_key(&self) -> ViewKey {
        let b_p = utils::scalar_to_field(&self.b).compress();

        ViewKey::new(self.a, b_p)
    }
}
