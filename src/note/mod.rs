use crate::{Error, PublicKey};

use serde::{Deserialize, Serialize};

pub mod obfuscated;
pub mod transparent;

pub use transparent::TransparentNote;

pub trait PhoenixIdx: Copy + for<'de> Deserialize<'de> {}
pub trait PhoenixNote: Sized {
    fn utxo(&self) -> NoteUtxoType;
    fn note(&self) -> NoteType;
    fn output(pk: &PublicKey, value: u64) -> Result<Self, Error>;
}

impl PhoenixIdx for () {}
impl PhoenixIdx for u64 {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NoteUtxoType {
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NoteType {
    Transparent,
    Obfuscated,
}
