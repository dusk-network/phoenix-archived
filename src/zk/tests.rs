use crate::{utils, zk, NoteGenerator, SecretKey, Transaction, TransparentNote};

#[test]
fn proof_serialization() {
    utils::init();
    zk::init();

    let mut tx = Transaction::default();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 100;
    let note = TransparentNote::output(&pk, value).0;
    tx.push_input(note.to_transaction_input(sk)).unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 97;
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

    let bytes = zk::proof_to_bytes(tx.proof().unwrap()).unwrap();
    let proof = zk::bytes_to_proof(&bytes).unwrap();

    assert!(zk::verify(&proof));
}
