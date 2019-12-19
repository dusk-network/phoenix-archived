use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullifier {
    // TODO - Use a MontgomeryPoint and hash the note
    point: u64,
}

impl Nullifier {
    pub fn new(point: u64) -> Self {
        Self { point }
    }

    pub fn point(&self) -> u64 {
        self.point
    }
}

impl Hash for Nullifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.point.hash(state);
    }
}
