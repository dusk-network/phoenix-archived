use crate::{
    crypto, db, rpc, BlsScalar, Error, JubJubScalar, MerkleProofProvider, Nonce, Note,
    NoteGenerator, NoteVariant, Nullifier, PublicKey, SecretKey, TransparentNote,
};

use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::{self, Read, Write};

use kelvin::ByteHash;

/// A transaction item constains sensitive data for a proof creation, and must be obfuscated before
/// network propagation.
///
/// The secret is required on this structure for the proof generation
pub trait TransactionItem:
    fmt::Debug + Default + Clone + Copy + PartialEq + Eq + PartialOrd + Ord + io::Read + io::Write
{
    fn note(&self) -> &NoteVariant;
    fn value(&self) -> u64;
    fn blinding_factor(&self) -> &BlsScalar;

    fn as_input(&self) -> Option<&Self>;
    fn as_output(&self) -> Option<&Self>;

    fn hash(&self) -> BlsScalar {
        self.note().hash()
    }

    fn clear_sensitive_info(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionInput {
    note: NoteVariant,
    value: u64,
    blinding_factor: BlsScalar,
    pub nullifier: Nullifier,
    pub sk: SecretKey,
    pub merkle_opening: crypto::MerkleProof,
    pub merkle_root: BlsScalar,
}

impl Default for TransactionInput {
    fn default() -> Self {
        let sk = SecretKey::from(&b"default-tx-input"[..]);
        let pk = sk.public_key();
        let value = 0;

        let r = JubJubScalar::from(3u64);
        let nonce = Nonce([5u8; 24]);
        let blinding_factor = BlsScalar::from(7u64);

        let merkle_opening = crypto::MerkleProof::default();

        TransparentNote::deterministic_output(&r, nonce, &pk, value, blinding_factor)
            .to_transaction_input(merkle_opening, sk)
    }
}

impl TransactionInput {
    pub fn new(
        note: NoteVariant,
        nullifier: Nullifier,
        value: u64,
        blinding_factor: BlsScalar,
        sk: SecretKey,
        merkle_opening: crypto::MerkleProof,
        merkle_root: BlsScalar,
    ) -> Self {
        Self {
            note,
            nullifier,
            value,
            blinding_factor,
            sk,
            merkle_opening,
            merkle_root,
        }
    }

    pub fn obfuscated(nullifier: Nullifier, merkle_root: BlsScalar) -> Self {
        let note = Default::default();
        let value = Default::default();
        let blinding_factor = Default::default();
        let sk = Default::default();
        let merkle_opening = Default::default();

        Self {
            note,
            nullifier,
            value,
            blinding_factor,
            sk,
            merkle_opening,
            merkle_root,
        }
    }

    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    pub fn sk(&self) -> &SecretKey {
        &self.sk
    }

    /// Attempt to generate a transaction input from a provided database and rpc item with the
    /// position of the note and its secret
    pub fn try_from_rpc_transaction_input<H: ByteHash>(
        db: &db::Db<H>,
        item: rpc::TransactionInput,
    ) -> Result<Self, Error> {
        let sk: SecretKey = item.sk.ok_or(Error::InvalidParameters)?.try_into()?;

        let note = db.fetch_note(item.pos)?;
        let merkle_opening = db.opening(&note)?;

        let txi = match note {
            NoteVariant::Transparent(n) => n.to_transaction_input(merkle_opening, sk),
            NoteVariant::Obfuscated(n) => n.to_transaction_input(merkle_opening, sk),
        };

        Ok(txi)
    }
}

impl Read for TransactionInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.nullifier.read(buf)
    }
}

impl Write for TransactionInput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.nullifier.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.nullifier.flush()
    }
}

impl TransactionItem for TransactionInput {
    fn note(&self) -> &NoteVariant {
        &self.note
    }

    fn value(&self) -> u64 {
        self.value
    }

    fn blinding_factor(&self) -> &BlsScalar {
        &self.blinding_factor
    }

    fn as_input(&self) -> Option<&Self> {
        Some(&self)
    }

    fn as_output(&self) -> Option<&Self> {
        None
    }

    fn clear_sensitive_info(&mut self) {
        self.note = NoteVariant::default();
        self.value = 0;
        self.blinding_factor = BlsScalar::zero();
        self.sk = SecretKey::default();
        self.merkle_opening = crypto::MerkleProof::default();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionOutput {
    pub note: NoteVariant,
    pub value: u64,
    pub blinding_factor: BlsScalar,
    pub pk: PublicKey,
}

impl Default for TransactionOutput {
    fn default() -> Self {
        let sk = SecretKey::from(&b"default-tx-input"[..]);
        let pk = sk.public_key();
        let value = 0;

        let r = JubJubScalar::from(11u64);
        let nonce = Nonce([13u8; 24]);
        let blinding_factor = BlsScalar::from(17u64);

        TransparentNote::deterministic_output(&r, nonce, &pk, value, blinding_factor)
            .to_transaction_output(value, blinding_factor, pk)
    }
}

impl TransactionOutput {
    pub fn new(note: NoteVariant, value: u64, blinding_factor: BlsScalar, pk: PublicKey) -> Self {
        Self {
            note,
            value,
            blinding_factor,
            pk,
        }
    }

    pub fn pk(&self) -> &PublicKey {
        &self.pk
    }
}

impl Read for TransactionOutput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.note.read(buf)
    }
}

impl Write for TransactionOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.note.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.note.flush()
    }
}

impl TransactionItem for TransactionOutput {
    fn note(&self) -> &NoteVariant {
        &self.note
    }

    fn value(&self) -> u64 {
        self.value
    }

    fn blinding_factor(&self) -> &BlsScalar {
        &self.blinding_factor
    }

    fn as_input(&self) -> Option<&Self> {
        None
    }

    fn as_output(&self) -> Option<&Self> {
        Some(&self)
    }

    fn clear_sensitive_info(&mut self) {
        self.value = 0;
        self.blinding_factor = BlsScalar::zero();
        self.pk = PublicKey::default();
    }
}

impl PartialOrd for TransactionInput {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.nullifier.partial_cmp(&other.nullifier)
    }
}

impl Ord for TransactionInput {
    fn cmp(&self, other: &Self) -> Ordering {
        self.nullifier.cmp(&other.nullifier)
    }
}

impl PartialOrd for TransactionOutput {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.note().hash().partial_cmp(&other.note().hash())
    }
}

impl Ord for TransactionOutput {
    fn cmp(&self, other: &Self) -> Ordering {
        self.note().hash().cmp(&other.note().hash())
    }
}

impl From<TransactionInput> for rpc::TransactionInput {
    fn from(item: TransactionInput) -> rpc::TransactionInput {
        let merkle_root = *item.merkle_opening.root();
        let merkle_root = Some(merkle_root.into());

        let nullifier = Some(item.nullifier.into());
        let note = Some(item.note.into());

        rpc::TransactionInput {
            merkle_root,
            note,
            nullifier,
            pos: item.note().idx(),
            sk: Some(item.sk.into()),
        }
    }
}

impl From<TransactionInput> for rpc::Nullifier {
    fn from(item: TransactionInput) -> Self {
        let mut scalar_buf = [0u8; 32];
        scalar_buf.copy_from_slice(&item.nullifier.s().to_bytes()[..]);

        rpc::Nullifier {
            h: Some(rpc::Scalar {
                data: scalar_buf.to_vec(),
            }),
        }
    }
}

impl TryFrom<rpc::TransactionInput> for TransactionInput {
    type Error = Error;

    fn try_from(txi: rpc::TransactionInput) -> Result<Self, Self::Error> {
        let note = txi.note.unwrap_or_default().try_into()?;
        let nullifier = txi.nullifier.unwrap_or_default().try_into()?;
        let sk = txi.sk.unwrap_or_default().try_into()?;
        let merkle_root = txi.merkle_root.unwrap_or_default().try_into()?;

        let merkle_opening = Default::default();
        let value = Default::default();
        let blinding_factor = Default::default();

        Ok(Self::new(
            note,
            nullifier,
            value,
            blinding_factor,
            sk,
            merkle_opening,
            merkle_root,
        ))
    }
}

impl TryFrom<rpc::TransactionOutput> for TransactionOutput {
    type Error = Error;

    fn try_from(txo: rpc::TransactionOutput) -> Result<Self, Self::Error> {
        let note = txo
            .note
            .ok_or(Error::InvalidParameters)
            .and_then(|n| n.try_into())?;

        let pk = txo
            .pk
            .ok_or(Error::InvalidParameters)
            .and_then(|k| k.try_into())?;

        let blinding_factor = txo
            .blinding_factor
            .ok_or(Error::InvalidParameters)?
            .try_into()?;

        Ok(TransactionOutput::new(note, txo.value, blinding_factor, pk))
    }
}

impl From<TransactionOutput> for rpc::TransactionOutput {
    fn from(item: TransactionOutput) -> rpc::TransactionOutput {
        rpc::TransactionOutput {
            note: Some(item.note().clone().into()),
            pk: Some(item.pk.into()),
            value: item.value,
            blinding_factor: Some((*item.blinding_factor()).into()),
        }
    }
}
