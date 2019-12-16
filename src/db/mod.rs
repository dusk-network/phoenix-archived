use crate::{Error, Idx, Note, Nullifier};

pub struct Db {}

impl Db {
    pub fn store_note<N: Note>(_note: N) -> Result<Idx, Error> {
        unimplemented!()
    }

    pub fn fetch_note<N: Note>(_idx: &Idx) -> Result<N, Error> {
        unimplemented!()
    }

    pub fn nullifier(_nullifier: &Nullifier) -> Result<Option<()>, Error> {
        unimplemented!()
    }
}
