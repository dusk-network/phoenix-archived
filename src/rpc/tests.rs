use crate::{
    db, rpc, MerkleProofProvider, NoteGenerator, NoteVariant, ObfuscatedNote, SecretKey,
    Transaction, TransactionItem, TransparentNote,
};

use kelvin::Blake2b;

#[test]
#[ignore]
fn rpc_transaction() {
    let mut db = db::Db::<Blake2b>::default();

    let mut tx = Transaction::default();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 100;
    let note = TransparentNote::output(&pk, value).0;
    let variant: NoteVariant = note.into();
    db.store_unspent_note(variant).unwrap();
    let merkle_opening = db.opening(&variant).unwrap();
    tx.push_input(note.to_transaction_input(merkle_opening, sk).unwrap())
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 95;
    let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
    tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 2;
    let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
    tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 3;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    let fee = note.to_transaction_output(value, blinding_factor, pk);
    tx.set_fee(fee);

    tx.prove().unwrap();
    tx.verify().unwrap();

    let mut rpc_transaction = rpc::Transaction::default();

    tx.inputs()
        .iter()
        .for_each(|i| rpc_transaction.inputs.push(i.clone().into()));

    tx.outputs()
        .iter()
        .for_each(|o| rpc_transaction.outputs.push(o.clone().into()));

    rpc_transaction.fee = Some(fee.into());

    let mut transaction = Transaction::try_from_rpc_transaction_db(&db, rpc_transaction).unwrap();

    // It is not possible to verify an unproven transaction
    assert!(transaction.verify().is_err());

    transaction.prove().unwrap();
    transaction.verify().unwrap();

    transaction.clear_sensitive_info();

    assert_eq!(3, transaction.fee().value());
    transaction.verify().unwrap();
}
