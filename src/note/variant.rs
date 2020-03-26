use crate::{
    rpc, BlsScalar, Error, JubJubProjective, Nonce, Note, NoteType, ObfuscatedNote,
    TransparentNote, ViewKey,
};

use std::convert::{TryFrom, TryInto};
use std::io;

use kelvin::{ByteHash, Content, Sink, Source};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteVariant {
    Transparent(TransparentNote),
    Obfuscated(ObfuscatedNote),
}

impl Default for NoteVariant {
    fn default() -> Self {
        NoteVariant::Transparent(TransparentNote::default())
    }
}

impl From<TransparentNote> for NoteVariant {
    fn from(note: TransparentNote) -> Self {
        NoteVariant::Transparent(note)
    }
}

impl TryFrom<NoteVariant> for TransparentNote {
    type Error = Error;

    fn try_from(variant: NoteVariant) -> Result<Self, Self::Error> {
        match variant {
            NoteVariant::Transparent(note) => Ok(note),
            NoteVariant::Obfuscated(_) => Err(Error::InvalidParameters),
        }
    }
}

impl From<ObfuscatedNote> for NoteVariant {
    fn from(note: ObfuscatedNote) -> Self {
        NoteVariant::Obfuscated(note)
    }
}

impl TryFrom<NoteVariant> for ObfuscatedNote {
    type Error = Error;

    fn try_from(variant: NoteVariant) -> Result<Self, Self::Error> {
        match variant {
            NoteVariant::Transparent(_) => Err(Error::InvalidParameters),
            NoteVariant::Obfuscated(note) => Ok(note),
        }
    }
}

impl TryFrom<rpc::Note> for NoteVariant {
    type Error = Error;

    fn try_from(note: rpc::Note) -> Result<Self, Self::Error> {
        match note.note_type.try_into()? {
            NoteType::Transparent => Ok(NoteVariant::Transparent(note.try_into()?)),
            NoteType::Obfuscated => Ok(NoteVariant::Obfuscated(note.try_into()?)),
        }
    }
}

impl From<NoteVariant> for rpc::Note {
    fn from(note: NoteVariant) -> Self {
        match note {
            NoteVariant::Transparent(note) => note.into(),
            NoteVariant::Obfuscated(note) => note.into(),
        }
    }
}

impl Note for NoteVariant {
    fn note(&self) -> NoteType {
        match self {
            NoteVariant::Transparent(note) => note.note(),
            NoteVariant::Obfuscated(note) => note.note(),
        }
    }

    fn idx(&self) -> u64 {
        match self {
            NoteVariant::Transparent(note) => note.idx(),
            NoteVariant::Obfuscated(note) => note.idx(),
        }
    }

    fn set_idx(&mut self, idx: u64) {
        match self {
            NoteVariant::Transparent(note) => note.set_idx(idx),
            NoteVariant::Obfuscated(note) => note.set_idx(idx),
        }
    }

    fn nonce(&self) -> &Nonce {
        match self {
            NoteVariant::Transparent(note) => note.nonce(),
            NoteVariant::Obfuscated(note) => note.nonce(),
        }
    }

    fn R(&self) -> &JubJubProjective {
        match self {
            NoteVariant::Transparent(note) => note.R(),
            NoteVariant::Obfuscated(note) => note.R(),
        }
    }

    fn pk_r(&self) -> &JubJubProjective {
        match self {
            NoteVariant::Transparent(note) => note.pk_r(),
            NoteVariant::Obfuscated(note) => note.pk_r(),
        }
    }

    fn value(&self, vk: Option<&ViewKey>) -> u64 {
        match self {
            NoteVariant::Transparent(note) => note.value(vk),
            NoteVariant::Obfuscated(note) => note.value(vk),
        }
    }

    fn encrypted_value(&self) -> Option<&[u8; 24]> {
        match self {
            NoteVariant::Transparent(note) => note.encrypted_value(),
            NoteVariant::Obfuscated(note) => note.encrypted_value(),
        }
    }

    fn value_commitment(&self) -> &BlsScalar {
        match self {
            NoteVariant::Transparent(note) => note.value_commitment(),
            NoteVariant::Obfuscated(note) => note.value_commitment(),
        }
    }

    fn blinding_factor(&self, vk: Option<&ViewKey>) -> BlsScalar {
        match self {
            NoteVariant::Transparent(note) => note.blinding_factor(vk),
            NoteVariant::Obfuscated(note) => note.blinding_factor(vk),
        }
    }

    fn encrypted_blinding_factor(&self) -> &[u8; 48] {
        match self {
            NoteVariant::Transparent(note) => note.encrypted_blinding_factor(),
            NoteVariant::Obfuscated(note) => note.encrypted_blinding_factor(),
        }
    }
}

impl<H: ByteHash> Content<H> for NoteVariant {
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        match self {
            NoteVariant::Transparent(t) => {
                false.persist(sink)?;
                t.persist(sink)
            }
            NoteVariant::Obfuscated(o) => {
                true.persist(sink)?;
                o.persist(sink)
            }
        }
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        Ok(match bool::restore(source)? {
            false => NoteVariant::Transparent(TransparentNote::restore(source)?),
            true => NoteVariant::Obfuscated(ObfuscatedNote::restore(source)?),
        })
    }
}
