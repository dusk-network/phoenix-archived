use crate::{
    db, utils, zk, Note, NoteGenerator, NoteVariant, NotesDb, ObfuscatedNote, SecretKey,
    Transaction, TransparentNote,
};

use std::fs;

use kelvin::{Blake2b, Root};
use tempdir::TempDir;

#[test]
fn transparent_note_serialization() {
    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();
    let value = 25312u64;

    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    let note_variant = NoteVariant::Transparent(note);

    let db = TempDir::new("transparent_note_serialization").unwrap();

    let mut root = Root::<_, Blake2b>::new(db.path()).unwrap();
    let mut state: NotesDb = root.restore().unwrap();

    let idx = state.store_unspent_note(note_variant).unwrap();

    root.set_root(&mut state).unwrap();

    let root = Root::<_, Blake2b>::new(db.path()).unwrap();
    let state: NotesDb = root.restore().unwrap();

    let db_note_variant = state.fetch_note(idx).unwrap();

    let db_note = match db_note_variant {
        NoteVariant::Transparent(n) => n,
        _ => panic!("Note deserialized to wrong type"),
    };

    assert_eq!(note, db_note);
    assert!(db_note.is_owned_by(&vk));
    assert_eq!(value, db_note.value(Some(&vk)));
    assert_eq!(blinding_factor, db_note.blinding_factor(Some(&vk)));

    // Clean up the db
    fs::remove_dir_all(&db).expect("could not remove temp db");
}

#[test]
fn obfuscated_note_serialization() {
    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();
    let value = 25313u64;

    let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
    let note_variant = NoteVariant::Obfuscated(note);

    let db = TempDir::new("obfuscated_note_serialization").unwrap();

    let mut root = Root::<_, Blake2b>::new(db.path()).unwrap();
    let mut state: NotesDb = root.restore().unwrap();

    let idx = state.store_unspent_note(note_variant).unwrap();

    root.set_root(&mut state).unwrap();

    let root = Root::<_, Blake2b>::new(db.path()).unwrap();
    let state: NotesDb = root.restore().unwrap();

    let db_note_variant = state.fetch_note(idx).unwrap();

    let db_note = match db_note_variant {
        NoteVariant::Obfuscated(n) => n,
        _ => panic!("Note deserialized to wrong type"),
    };

    assert_eq!(note, db_note);
    assert!(db_note.is_owned_by(&vk));
    assert_eq!(value, db_note.value(Some(&vk)));
    assert_eq!(blinding_factor, db_note.blinding_factor(Some(&vk)));

    // Clean up the db
    fs::remove_dir_all(&db).expect("could not remove temp db");
}

#[test]
#[ignore]
fn double_spending() {
    zk::init();

    let db_path = TempDir::new("double_spending").unwrap();

    let mut tx = Transaction::default();

    let sk_base = SecretKey::default();
    let pk = sk_base.public_key();
    let value = 100;
    let note = TransparentNote::output(&pk, value).0;
    let variant: NoteVariant = note.into();
    let base_note_idx = db::store_unspent_note(&db_path, variant).unwrap();
    let merkle_opening = db::merkle_opening(&db_path, &variant).unwrap();
    tx.push_input(note.to_transaction_input(merkle_opening, sk_base))
        .unwrap();

    let sk_receiver = SecretKey::default();
    let pk = sk_receiver.public_key();
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

    let inserted = db::store_bulk_transactions(&db_path, &[tx]).unwrap();

    let mut tx_ok = Transaction::default();

    let vk = sk_receiver.view_key();
    let note: Vec<NoteVariant> = inserted
        .into_iter()
        .map(|idx| db::fetch_note(&db_path, idx).unwrap())
        .filter(|note| note.is_owned_by(&vk))
        .collect();
    assert_eq!(1, note.len());
    let note = note[0];
    assert_eq!(95, note.value(Some(&vk)));
    let variant: NoteVariant = note.into();
    let merkle_opening = db::merkle_opening(&db_path, &variant).unwrap();
    tx_ok
        .push_input(note.to_transaction_input(merkle_opening, sk_receiver))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 85;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx_ok
        .push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 7;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx_ok
        .push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 3;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx_ok.set_fee(note.to_transaction_output(value, blinding_factor, pk));

    tx_ok.prove().unwrap();
    tx_ok.verify().unwrap();

    let mut tx_double_spending = Transaction::default();

    let vk = sk_base.view_key();
    let note = db::fetch_note(&db_path, base_note_idx).unwrap();
    assert_eq!(100, note.value(Some(&vk)));
    let merkle_opening = db::merkle_opening(&db_path, &note).unwrap();
    tx_double_spending
        .push_input(note.to_transaction_input(merkle_opening, sk_base))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 95;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx_double_spending
        .push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 2;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx_double_spending
        .push_output(note.to_transaction_output(value, blinding_factor, pk))
        .unwrap();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 3;
    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    tx_double_spending.set_fee(note.to_transaction_output(value, blinding_factor, pk));

    tx_double_spending.prove().unwrap();
    tx_double_spending.verify().unwrap();

    assert!(db::store_bulk_transactions(&db_path, &[tx_ok, tx_double_spending]).is_err());

    // Clean up the db
    fs::remove_dir_all(&db_path).expect("could not remove temp db");
}
