use crate::{
    db, rpc, utils, zk, NoteGenerator, NoteVariant, ObfuscatedNote, SecretKey, Transaction,
    TransactionItem, TransparentNote,
};

use std::fs;

use tempdir::TempDir;

#[test]
fn rpc_transaction() {
    zk::init();

    let db_path = TempDir::new("rpc_transaction").unwrap();

    let mut tx = Transaction::default();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 100;
    let note = TransparentNote::output(&pk, value).0;
    let variant: NoteVariant = note.into();
    db::store_unspent_note(&db_path, variant).unwrap();
    let merkle_opening = db::merkle_opening(&db_path, &variant).unwrap();
    tx.push_input(note.to_transaction_input(merkle_opening, sk))
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

    let mut transaction =
        Transaction::try_from_rpc_transaction_db(&db_path, rpc_transaction).unwrap();

    // It is not possible to verify an unproven transaction
    assert!(transaction.verify().is_err());

    transaction.prove().unwrap();
    transaction.verify().unwrap();

    transaction.clear_sensitive_info();

    assert_eq!(3, transaction.fee().value());
    transaction.verify().unwrap();

    // Clean up the db
    fs::remove_dir_all(db_path).expect("could not remove temp db");
}
