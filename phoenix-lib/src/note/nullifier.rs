use crate::Scalar;

use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, Default, Eq)]
/// Nullifier deterministically constructed from a given note and its secret. One, and only one,
/// Nullifier can be constructed from Note + secret
///
/// Only the owner of the secret is able to construct a nullifier for a given note
pub struct Nullifier {
    /// Scalar representing the nullifier
    pub x: Scalar,
}

impl Nullifier {
    /// [`Nullifier`] constructor
    pub fn new(x: Scalar) -> Self {
        Self { x }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // Idx
    /// Inner scalar representation of the nullifier
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
