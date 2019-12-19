use super::{PublicKey, SecretKey};
use crate::{utils, MontgomeryPoint, Scalar};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct ViewKey {
    pub a: Scalar,
    pub b_g: MontgomeryPoint,
}

impl ViewKey {
    pub fn new(a: Scalar, b_g: MontgomeryPoint) -> Self {
        ViewKey { a, b_g }
    }

    pub fn public_key(&self) -> PublicKey {
        let a_g = utils::mul_by_basepoint(&self.a);

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
