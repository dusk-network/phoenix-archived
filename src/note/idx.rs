use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Idx(pub u64);

impl From<u64> for Idx {
    fn from(idx: u64) -> Self {
        Idx(idx)
    }
}

impl Hash for Idx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
