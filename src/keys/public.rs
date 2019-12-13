use super::SecretKey;
use crate::RistrettoPoint;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// TODO - Serialization and deserialization should be based on compressed points
pub struct PublicKey {
    pub a_p: RistrettoPoint,
    pub b_p: RistrettoPoint,
}

impl PublicKey {
    pub fn new(a_p: RistrettoPoint, b_p: RistrettoPoint) -> Self {
        PublicKey { a_p, b_p }
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
