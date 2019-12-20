use super::SecretKey;
use crate::EdwardsPoint;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub a_g: EdwardsPoint,
    pub b_g: EdwardsPoint,
}

impl PublicKey {
    pub fn new(a_g: EdwardsPoint, b_g: EdwardsPoint) -> Self {
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
