use crate::rpc;

use std::hash::{Hash, Hasher};

use rpc::Idx;

impl Idx {
    pub fn as_vec(self) -> Vec<u8> {
        self.into()
    }
}

impl From<u64> for Idx {
    fn from(idx: u64) -> Self {
        Idx { pos: idx }
    }
}

impl Into<u64> for Idx {
    fn into(self) -> u64 {
        self.pos
    }
}

impl Into<Vec<u8>> for Idx {
    fn into(self) -> Vec<u8> {
        self.pos.to_le_bytes().to_vec()
    }
}

impl Eq for Idx {}

impl Hash for Idx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pos.hash(state);
    }
}
