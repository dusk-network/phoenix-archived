use super::SecretKey;
use crate::MontgomeryPoint;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct PublicKey {
    pub a_g: MontgomeryPoint,
    pub b_g: MontgomeryPoint,
}

impl PublicKey {
    pub fn new(a_g: MontgomeryPoint, b_g: MontgomeryPoint) -> Self {
        PublicKey { a_g, b_g }
    }
}

impl From<SecretKey> for PublicKey {
    fn from(secret: SecretKey) -> Self {
        secret.public_key()
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret: &SecretKey) -> Self {
        secret.public_key()
    }
}
