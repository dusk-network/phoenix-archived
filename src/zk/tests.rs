use crate::{
    crypto, utils, zk, Note, NoteGenerator, SecretKey, Transaction, TransparentNote,
    TX_SERIALIZED_SIZE,
};

use std::io::{Read, Write};

#[test]
fn proof_serialization() {
    utils::init();
    zk::init();

    let mut tx = Transaction::default();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 100;
    let note = TransparentNote::output(&pk, value).0;
    let merkle_opening = crypto::MerkleProof::mock(note.hash());
    tx.push_input(note.to_transaction_input(merkle_opening, sk))
        .unwrap();

    // TODO - Test also with a single output
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 95;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 2;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 3;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

    tx.prove().unwrap();
    tx.verify().unwrap();

    let mut bytes = vec![0x00u8; TX_SERIALIZED_SIZE - 1];
    assert!(tx.read(bytes.as_mut_slice()).is_err());

    let mut bytes = vec![0x00u8; TX_SERIALIZED_SIZE];
    tx.read(bytes.as_mut_slice()).unwrap();

    let mut tx = Transaction::default();
    tx.write(bytes.as_slice()).unwrap();

    tx.verify().unwrap();
}
