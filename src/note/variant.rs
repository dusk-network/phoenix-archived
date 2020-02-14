use crate::{
    rpc, CompressedRistretto, Error, Idx, Nonce, Note, NoteGenerator, NoteType, NoteUtxoType,
    Nullifier, ObfuscatedNote, PublicKey, R1CSProof, RistrettoPoint, Scalar, SecretKey,
    TransactionItem, TransparentNote, ViewKey,
};

use std::convert::{TryFrom, TryInto};
use std::io;

use kelvin::{ByteHash, Content, Sink, Source};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteVariant {
    Transparent(TransparentNote),
    Obfuscated(ObfuscatedNote),
}

impl NoteVariant {
    // TODO - Duplicated code, maybe split NoteGenerator trait?
    /// Create a new transaction input item provided the secret key for the nullifier generation
    /// and value / blinding factor decrypt
    pub fn to_transaction_input(self, sk: SecretKey) -> TransactionItem {
        match self {
            NoteVariant::Transparent(note) => note.to_transaction_input(sk),
            NoteVariant::Obfuscated(note) => note.to_transaction_input(sk),
        }
    }

    /// Create a new transaction output item provided the target value, blinding factor and pk for
    /// the proof construction.
    ///
    /// The parameters are not present on the note; hence they need to be provided.
    pub fn to_transaction_output(
        self,
        value: u64,
        blinding_factor: Scalar,
        pk: PublicKey,
    ) -> TransactionItem {
        match self {
            NoteVariant::Transparent(note) => {
                note.to_transaction_output(value, blinding_factor, pk)
            }
            NoteVariant::Obfuscated(note) => note.to_transaction_output(value, blinding_factor, pk),
        }
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

impl TryFrom<NoteVariant> for ObfuscatedNote {
    type Error = Error;

    fn try_from(variant: NoteVariant) -> Result<Self, Self::Error> {
        match variant {
            NoteVariant::Transparent(_) => Err(Error::InvalidParameters),
            NoteVariant::Obfuscated(note) => Ok(note),
        }
    }
}

impl Note for NoteVariant {
    fn prove_value(&self, vk: &ViewKey) -> Result<R1CSProof, Error> {
        match self {
            NoteVariant::Transparent(note) => note.prove_value(vk),
            NoteVariant::Obfuscated(note) => note.prove_value(vk),
        }
    }

    fn verify_value(&self, proof: &R1CSProof) -> Result<(), Error> {
        match self {
            NoteVariant::Transparent(note) => note.verify_value(proof),
            NoteVariant::Obfuscated(note) => note.verify_value(proof),
        }
    }

    fn generate_nullifier(&self, sk: &SecretKey) -> Nullifier {
        match self {
            NoteVariant::Transparent(note) => note.generate_nullifier(sk),
            NoteVariant::Obfuscated(note) => note.generate_nullifier(sk),
        }
    }

    fn validate_nullifier(&self, nullifier: &Nullifier) -> Result<(), Error> {
        match self {
            NoteVariant::Transparent(note) => note.validate_nullifier(nullifier),
            NoteVariant::Obfuscated(note) => note.validate_nullifier(nullifier),
        }
    }

    fn rpc_decrypted_note(&self, vk: &ViewKey) -> rpc::DecryptedNote {
        match self {
            NoteVariant::Transparent(note) => note.rpc_decrypted_note(vk),
            NoteVariant::Obfuscated(note) => note.rpc_decrypted_note(vk),
        }
    }

    fn zk_preimage(&self) -> (Scalar, Scalar) {
        match self {
            NoteVariant::Transparent(note) => note.zk_preimage(),
            NoteVariant::Obfuscated(note) => note.zk_preimage(),
        }
    }

    fn hash(&self) -> Scalar {
        match self {
            NoteVariant::Transparent(note) => note.hash(),
            NoteVariant::Obfuscated(note) => note.hash(),
        }
    }

    fn utxo(&self) -> NoteUtxoType {
        match self {
            NoteVariant::Transparent(note) => note.utxo(),
            NoteVariant::Obfuscated(note) => note.utxo(),
        }
    }

    fn set_utxo(&mut self, utxo: NoteUtxoType) {
        match self {
            NoteVariant::Transparent(note) => note.set_utxo(utxo),
            NoteVariant::Obfuscated(note) => note.set_utxo(utxo),
        }
    }

    fn note(&self) -> NoteType {
        match self {
            NoteVariant::Transparent(note) => note.note(),
            NoteVariant::Obfuscated(note) => note.note(),
        }
    }

    fn idx(&self) -> &Idx {
        match self {
            NoteVariant::Transparent(note) => note.idx(),
            NoteVariant::Obfuscated(note) => note.idx(),
        }
    }

    fn set_idx(&mut self, idx: Idx) {
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

    fn value(&self, vk: Option<&ViewKey>) -> u64 {
        match self {
            NoteVariant::Transparent(note) => note.value(vk),
            NoteVariant::Obfuscated(note) => note.value(vk),
        }
    }

    fn encrypted_value(&self) -> Option<&Vec<u8>> {
        match self {
            NoteVariant::Transparent(note) => note.encrypted_value(),
            NoteVariant::Obfuscated(note) => note.encrypted_value(),
        }
    }

    fn commitment(&self) -> &CompressedRistretto {
        match self {
            NoteVariant::Transparent(note) => note.commitment(),
            NoteVariant::Obfuscated(note) => note.commitment(),
        }
    }

    fn blinding_factor(&self, vk: &ViewKey) -> Scalar {
        match self {
            NoteVariant::Transparent(note) => note.blinding_factor(vk),
            NoteVariant::Obfuscated(note) => note.blinding_factor(vk),
        }
    }

    fn encrypted_blinding_factor(&self) -> &Vec<u8> {
        match self {
            NoteVariant::Transparent(note) => note.encrypted_blinding_factor(),
            NoteVariant::Obfuscated(note) => note.encrypted_blinding_factor(),
        }
    }

    fn r_g(&self) -> &RistrettoPoint {
        match self {
            NoteVariant::Transparent(note) => note.r_g(),
            NoteVariant::Obfuscated(note) => note.r_g(),
        }
    }

    fn pk_r(&self) -> &RistrettoPoint {
        match self {
            NoteVariant::Transparent(note) => note.pk_r(),
            NoteVariant::Obfuscated(note) => note.pk_r(),
        }
    }

    fn sk_r(&self, sk: &SecretKey) -> Scalar {
        match self {
            NoteVariant::Transparent(note) => note.sk_r(sk),
            NoteVariant::Obfuscated(note) => note.sk_r(sk),
        }
    }

    fn is_owned_by(&self, vk: &ViewKey) -> bool {
        match self {
            NoteVariant::Transparent(note) => note.is_owned_by(vk),
            NoteVariant::Obfuscated(note) => note.is_owned_by(vk),
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
