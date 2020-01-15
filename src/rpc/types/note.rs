use crate::{
    Db, Error, Note as BaseNote, NoteType as BaseNoteType, Nullifier, ObfuscatedNote,
    TransparentNote, ViewKey,
};

use std::cmp;
use std::convert::TryFrom;

use prost::{Enumeration, Message};

#[derive(Clone, Copy, Debug, PartialEq, Enumeration)]
pub enum NoteType {
    TRANSPARENT = 0,
    OBFUSCATED = 1,
}

impl From<BaseNoteType> for NoteType {
    fn from(t: BaseNoteType) -> Self {
        match t {
            BaseNoteType::Transparent => NoteType::TRANSPARENT,
            BaseNoteType::Obfuscated => NoteType::OBFUSCATED,
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Note {
    #[prost(enumeration = "NoteType", required, tag = "1")]
    pub note_type: i32,
    #[prost(uint64, required, tag = "2")]
    pub pos: u64,
    #[prost(uint64, required, tag = "3")]
    pub value: u64,
    #[prost(bool, required, tag = "4")]
    pub unspent: bool,
    #[prost(bytes, required, tag = "5")]
    pub raw: Vec<u8>,
}

impl Note {
    pub fn new(note_type: i32, pos: u64, value: u64, unspent: bool, raw: Vec<u8>) -> Self {
        Self {
            note_type,
            pos,
            value,
            unspent,
            raw,
        }
    }
}
