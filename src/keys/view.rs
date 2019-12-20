use super::{PublicKey, SecretKey};
use crate::{utils, EdwardsPoint, Scalar};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewKey {
    pub a: Scalar,
    pub b_g: EdwardsPoint,
}

impl ViewKey {
    pub fn new(a: Scalar, b_g: EdwardsPoint) -> Self {
        ViewKey { a, b_g }
    }

    pub fn public_key(&self) -> PublicKey {
        let a_g = utils::mul_by_basepoint_edwards(&self.a);

        PublicKey::new(a_g, self.b_g)
    }
}

impl From<SecretKey> for ViewKey {
    fn from(secret: SecretKey) -> Self {
        secret.view_key()
    }
}

impl From<&SecretKey> for ViewKey {
    fn from(secret: &SecretKey) -> Self {
        secret.view_key()
    }
}
