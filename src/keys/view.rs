use super::SecretKey;
use crate::{CompressedRistretto, Scalar};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ViewKey {
    pub a: Scalar,
    pub b_p: CompressedRistretto,
}

impl ViewKey {
    pub fn new(a: Scalar, b_p: CompressedRistretto) -> Self {
        ViewKey { a, b_p }
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
