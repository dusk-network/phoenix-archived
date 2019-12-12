use super::SecretKey;
use crate::CompressedRistretto;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PublicKey {
    pub a_p: CompressedRistretto,
    pub b_p: CompressedRistretto,
}

impl PublicKey {
    pub fn new(a_p: CompressedRistretto, b_p: CompressedRistretto) -> Self {
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
