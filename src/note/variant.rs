use crate::{
    crypto, rpc, BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar, Nonce, Note,
    NoteGenerator, NoteType, ObfuscatedNote, SecretKey, TransactionInput, TransparentNote, ViewKey,
};

use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write};

use kelvin::{ByteHash, Content, Sink, Source};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteVariant {
    Transparent(TransparentNote),
    Obfuscated(ObfuscatedNote),
}

impl NoteVariant {
    /// Create a new transaction input item provided the secret key for the nullifier generation
    /// and value / blinding factor decrypt
    pub fn to_transaction_input(
        self,
        merkle_opening: crypto::MerkleProof,
        sk: SecretKey,
    ) -> Result<TransactionInput, Error> {
        match self {
            NoteVariant::Transparent(note) => note.to_transaction_input(merkle_opening, sk),
            NoteVariant::Obfuscated(note) => note.to_transaction_input(merkle_opening, sk),
        }
    }
}

impl Read for NoteVariant {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Err(Error::InvalidParameters.into());
        }

        let mut n = 0;

        buf[0] = match self {
            NoteVariant::Transparent(_) => 0x00,
            NoteVariant::Obfuscated(_) => 0x01,
        };
        n += 1;
        buf = &mut buf[1..];

        n += match self {
            NoteVariant::Transparent(n) => n.read(buf)?,
            NoteVariant::Obfuscated(n) => n.read(buf)?,
        };

        Ok(n)
    }
}

impl Write for NoteVariant {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Err(Error::InvalidParameters.into());
        }

        let mut n = 0;

        let note = buf[0];
        n += 1;
        buf = &buf[1..];

        match note {
            0x00 => {
                let mut note = TransparentNote::default();
                n += note.write(buf)?;
                *self = NoteVariant::Transparent(note);
            }
            0x01 => {
                let mut note = ObfuscatedNote::default();
                n += note.write(buf)?;
                *self = NoteVariant::Obfuscated(note);
            }
            _ => return Err(Error::InvalidParameters.into()),
        };

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            NoteVariant::Transparent(n) => n.flush(),
            NoteVariant::Obfuscated(n) => n.flush(),
        }
    }
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

    fn R(&self) -> &JubJubExtended {
        match self {
            NoteVariant::Transparent(note) => note.R(),
            NoteVariant::Obfuscated(note) => note.R(),
        }
    }

    fn pk_r(&self) -> &JubJubExtended {
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

    fn value_commitment(&self) -> &JubJubAffine {
        match self {
            NoteVariant::Transparent(note) => note.value_commitment(),
            NoteVariant::Obfuscated(note) => note.value_commitment(),
        }
    }

    fn blinding_factor(&self, vk: Option<&ViewKey>) -> Result<JubJubScalar, Error> {
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
