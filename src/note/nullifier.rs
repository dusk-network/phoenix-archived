use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nullifier {
    // TODO - Use a RistrettoPoint and hash the note
    point: u64,
}

impl Hash for Nullifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.point.hash(state);
    }
}
