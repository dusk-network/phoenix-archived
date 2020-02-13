use crate::rpc;

use kelvin::{ByteHash, Content, Sink, Source};
use rpc::Idx;
use std::hash::{Hash, Hasher};
use std::io;

impl Idx {
    /// Convert the [`Idx`] to bytes
    pub fn into_vec(self) -> Vec<u8> {
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

impl AsMut<u64> for Idx {
    fn as_mut(&mut self) -> &mut u64 {
        &mut self.pos
    }
}

impl Into<Vec<u8>> for Idx {
    fn into(self) -> Vec<u8> {
        self.pos.to_le_bytes().to_vec()
    }
}

impl Eq for Idx {}

#[deny(clippy::derive_hash_xor_eq)]
impl Hash for Idx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pos.hash(state);
    }
}

impl<H: ByteHash> Content<H> for Idx {
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        u64::persist(self.as_mut(), sink)
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        Ok(u64::restore(source)?.into())
    }
}
