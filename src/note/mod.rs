use crate::PublicKey;

use serde::{Deserialize, Serialize};

pub mod obfuscated;
pub mod transparent;

pub use transparent::TransparentNote;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PhoenixIdx(pub u64);

impl From<u64> for PhoenixIdx {
    fn from(idx: u64) -> Self {
        PhoenixIdx(idx)
    }
}

pub trait PhoenixNote: Sized {
    fn utxo(&self) -> NoteUtxoType;
    fn note(&self) -> NoteType;
    fn output(pk: &PublicKey, value: u64) -> Self;
}

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
