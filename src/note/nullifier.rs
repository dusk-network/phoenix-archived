use crate::Scalar;

use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, Default, Eq)]
// Will be
// r - b * H(R || idx)
//
// Verified by
// H(R || idx) == H( ( (n * B^H(R || idx)) * G) || idx )
pub struct Nullifier {
    pub x: Scalar,
}

impl Nullifier {
    pub fn new(x: Scalar) -> Self {
        Self { x }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // Idx
    pub fn point(&self) -> &Scalar {
        &self.x
    }
}

impl Hash for Nullifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.x.as_bytes().hash(state);
    }
}

impl PartialEq for Nullifier {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x
    }
}
