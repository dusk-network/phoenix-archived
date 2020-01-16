use crate::{Error, Idx as BaseIdx, NoteType as BaseNoteType};

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

impl TryFrom<i32> for NoteType {
    type Error = Error;

    fn try_from(t: i32) -> Result<Self, Self::Error> {
        match t {
            0 => Ok(NoteType::TRANSPARENT),
            1 => Ok(NoteType::OBFUSCATED),
            _ => Err(Error::InvalidParameters),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Idx {
    #[prost(uint64, required, tag = "1")]
    pub pos: u64,
}

impl From<BaseIdx> for Idx {
    fn from(i: BaseIdx) -> Self {
        Self { pos: i.0 }
    }
}

impl Into<BaseIdx> for Idx {
    fn into(self) -> BaseIdx {
        BaseIdx::from(self.pos)
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Note {
    #[prost(enumeration = "NoteType", required, tag = "1")]
    pub note_type: i32,
    #[prost(message, required, tag = "2")]
    pub pos: Idx,
    #[prost(uint64, required, tag = "3")]
    pub value: u64,
    #[prost(bool, required, tag = "4")]
    pub unspent: bool,
    #[prost(bytes, required, tag = "5")]
    pub raw: Vec<u8>,
}

impl Note {
    pub fn new(note_type: i32, pos: Idx, value: u64, unspent: bool, raw: Vec<u8>) -> Self {
        Self {
            note_type,
            pos,
            value,
            unspent,
            raw,
        }
    }
}
