use super::{PublicKey, SecretKey};
use crate::{utils, RistrettoPoint, Scalar};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct ViewKey {
    pub a: Scalar,
    pub b_p: RistrettoPoint,
}

impl ViewKey {
    pub fn new(a: Scalar, b_p: RistrettoPoint) -> Self {
        ViewKey { a, b_p }
    }

    pub fn public_key(&self) -> PublicKey {
        let a_p = utils::mul_by_basepoint(&self.a);

        PublicKey::new(a_p, self.b_p)
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
