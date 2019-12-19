use super::SecretKey;
use crate::RistrettoPoint;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct PublicKey {
    pub a_g: RistrettoPoint,
    pub b_g: RistrettoPoint,
}

impl PublicKey {
    pub fn new(a_g: RistrettoPoint, b_g: RistrettoPoint) -> Self {
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
