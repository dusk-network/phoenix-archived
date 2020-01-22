use super::SecretKey;
use crate::EdwardsPoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    pub a_g: EdwardsPoint,
    pub b_g: EdwardsPoint,
}

impl Default for PublicKey {
    fn default() -> Self {
        SecretKey::default().public_key()
    }
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
