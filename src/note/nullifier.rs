use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Eq, Serialize, Deserialize)]
// Will be
// r - b * H(R || idx)
//
// Verified by
// H(R || idx) == H( ( (n * B^H(R || idx)) * G) || idx )
pub struct Nullifier {
    // TODO - Use a EdwardsPoint and hash the note
    point: u64,
}

impl Nullifier {
    pub fn new(point: u64) -> Self {
        Self { point }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // Idx
    pub fn point(&self) -> u64 {
        self.point
    }
}

impl Hash for Nullifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.point.hash(state);
    }
}

impl PartialEq for Nullifier {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}
