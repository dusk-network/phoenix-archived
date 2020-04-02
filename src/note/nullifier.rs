use crate::BlsScalar;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nullifier(pub BlsScalar);

impl From<BlsScalar> for Nullifier {
    fn from(s: BlsScalar) -> Self {
        Nullifier(s)
    }
}

impl Into<BlsScalar> for Nullifier {
    fn into(self) -> BlsScalar {
        self.0
    }
}

impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        unimplemented!()
    }
}
