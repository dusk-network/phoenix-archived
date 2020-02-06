use crate::{
    rpc, Db, Error, Idx, Note, NoteGenerator, NoteType, NoteUtxoType, Nullifier, ObfuscatedNote,
    PublicKey, Scalar, SecretKey, TransparentNote,
};

use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};

use sha2::{Digest, Sha512};

#[derive(Debug)]
/// A transaction item constains sensitive data for a proof creation, and must be obfuscated before
/// network propagation.
///
/// The secret is required on this structure for the proof generation
pub struct TransactionItem {
    note: Box<dyn Note>,
    nullifier: Nullifier,
    value: u64,
    blinding_factor: Scalar,
    sk: Option<SecretKey>,
    pk: PublicKey,
}

impl PartialEq for TransactionItem {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.nullifier == other.nullifier
            && self.blinding_factor == other.blinding_factor
            && self.sk == other.sk
            && self.pk == other.pk
            && self.note.hash() == other.note.hash()
    }
}
impl Eq for TransactionItem {}

impl Ord for TransactionItem {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.note.utxo() != other.note.utxo() {
            self.note.utxo().cmp(&other.note.utxo())
        } else if self.value != other.value {
            self.value.cmp(&other.value)
        } else {
            self.note
                .hash()
                .as_bytes()
                .cmp(other.note.hash().as_bytes())
        }
    }
}

impl PartialOrd for TransactionItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.note.utxo() != other.note.utxo() {
            self.note.utxo().partial_cmp(&other.note.utxo())
        } else if self.value != other.value {
            self.value.partial_cmp(&other.value)
        } else {
            self.note
                .hash()
                .as_bytes()
                .partial_cmp(other.note.hash().as_bytes())
        }
    }
}

impl Clone for TransactionItem {
    fn clone(&self) -> Self {
        TransactionItem {
            note: self.note.box_clone(),
            nullifier: self.nullifier,
            value: self.value,
            blinding_factor: self.blinding_factor,
            sk: None,
            pk: self.pk,
        }
    }
}

impl Default for TransactionItem {
    fn default() -> Self {
        let note = TransparentNote::default();
        let nullifier = Nullifier::default();
        let value = 0;
        let blinding_factor = Scalar::one();
        let sk = Some(SecretKey::default());
        let pk = PublicKey::default();

        TransactionItem::new(note, nullifier, value, blinding_factor, sk, pk)
    }
}

impl TransactionItem {
    /// [`TransactionItem`] constructor
    pub fn new<N: Note>(
        note: N,
        nullifier: Nullifier,
        value: u64,
        blinding_factor: Scalar,
        sk: Option<SecretKey>,
        pk: PublicKey,
    ) -> Self {
        TransactionItem {
            note: note.box_clone(),
            nullifier,
            value,
            blinding_factor,
            sk,
            pk,
        }
    }

    /// Deterministically hash the tx item to a [`Scalar`]
    pub fn hash(&self) -> Scalar {
        // TODO - Use poseidon sponge, when available
        let mut hasher = Sha512::default();

        hasher.input(self.note.hash().as_bytes());
        hasher.input(self.nullifier.x.as_bytes());
        hasher.input(&self.value.to_le_bytes()[..]);
        hasher.input(self.blinding_factor.as_bytes());
        if let Some(sk) = self.sk.as_ref() {
            hasher.input(sk.a.as_bytes());
            hasher.input(sk.b.as_bytes());
        } else {
            hasher.input(Scalar::one().as_bytes());
            hasher.input(Scalar::one().as_bytes());
        }
        hasher.input(self.pk.a_g.compress().as_bytes());
        hasher.input(self.pk.b_g.compress().as_bytes());

        Scalar::from_hash(hasher)
    }

    /// The note value of the tx item
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Set the note value. Doesn't change the note, for it can be either obfuscated or transparent
    pub fn set_value(&mut self, value: u64) {
        self.value = value;
    }

    /// Public key used to construct the tx output
    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }

    /// Set the public key used to construct the tx output
    pub fn set_pk(&mut self, pk: PublicKey) {
        self.pk = pk;
    }

    /// Position of the input on the notes tree
    pub fn idx(&self) -> &Idx {
        self.note.idx()
    }

    /// Blinding factor used to construct the i/o value
    pub fn blinding_factor(&self) -> &Scalar {
        &self.blinding_factor
    }

    /// Set the blinding factor used to construct the i/o value
    pub fn set_blinding_factor(&mut self, blinding_factor: Scalar) {
        self.blinding_factor = blinding_factor;
    }

    /// Type of the note
    pub fn note_type(&self) -> NoteType {
        self.note.note()
    }

    /// Direction of the transaction item
    pub fn utxo(&self) -> NoteUtxoType {
        self.note.utxo()
    }

    /// Inner implementation of the note
    pub fn note(&self) -> Box<dyn Note> {
        self.note.box_clone()
    }

    /// Set the inner implementation of the note. Will update only the note attribute
    pub fn set_note(&mut self, note: Box<dyn Note>) {
        self.note = note;
    }

    /// Nullifier generated on the transaction input creation process
    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    /// Attempt to generate a transaction input from a provided database and rpc item with the
    /// position of the note and its secret
    pub fn try_from_rpc_transaction_input(
        db: &Db,
        item: rpc::TransactionInput,
    ) -> Result<Self, Error> {
        let sk: SecretKey = item.sk.map(|k| k.into()).unwrap_or_default();
        let note = db.fetch_box_note(&item.pos.ok_or(Error::InvalidParameters)?)?;

        let item = match note.note() {
            NoteType::Transparent => {
                Db::note_box_into::<TransparentNote>(note).to_transaction_input(sk)
            }
            NoteType::Obfuscated => {
                Db::note_box_into::<ObfuscatedNote>(note).to_transaction_input(sk)
            }
        };

        Ok(item)
    }
}

impl TryFrom<rpc::TransactionOutput> for TransactionItem {
    type Error = Error;

    fn try_from(txo: rpc::TransactionOutput) -> Result<Self, Self::Error> {
        let pk: PublicKey = txo
            .pk
            .ok_or(Error::InvalidParameters)
            .and_then(|k| k.try_into())?;

        let note: Box<dyn Note> = txo.note.ok_or(Error::InvalidParameters)?.try_into()?;

        let mut item = TransactionItem::default();

        item.set_value(txo.value);
        item.set_pk(pk);
        item.set_note(note);
        item.set_blinding_factor(txo.blinding_factor.ok_or(Error::InvalidParameters)?.into());

        Ok(item)
    }
}

impl From<TransactionItem> for rpc::TransactionInput {
    fn from(item: TransactionItem) -> rpc::TransactionInput {
        rpc::TransactionInput {
            pos: Some(item.note().idx().clone()),
            sk: item.sk.map(|sk| sk.into()),
        }
    }
}

impl From<TransactionItem> for rpc::TransactionOutput {
    fn from(item: TransactionItem) -> rpc::TransactionOutput {
        rpc::TransactionOutput {
            note: Some(item.note().into()),
            pk: Some(item.pk.into()),
            value: item.value,
            blinding_factor: Some((*item.blinding_factor()).into()),
        }
    }
}
