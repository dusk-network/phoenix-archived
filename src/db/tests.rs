use crate::{
    db, MerkleProofProvider, Note, NoteGenerator, NoteVariant, ObfuscatedNote, SecretKey,
    Transaction, TransparentNote,
};

use kelvin::Blake2b;

#[test]
fn transparent_note_serialization() {
    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();
    let value = 25312u64;

    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    let note_variant = NoteVariant::Transparent(note);

    let mut db = db::Db::<Blake2b>::default();

    let idx = db.store_unspent_note(note_variant).unwrap();

    let db_note_variant = db.fetch_note(idx).unwrap();

    let db_note = match db_note_variant {
        NoteVariant::Transparent(n) => n,
        _ => panic!("Note deserialized to wrong type"),
    };

    assert_eq!(note, db_note);
    assert!(db_note.is_owned_by(&vk));
    assert_eq!(value, db_note.value(Some(&vk)));
    assert_eq!(blinding_factor, db_note.blinding_factor(Some(&vk)).unwrap());
}

#[test]
fn obfuscated_note_serialization() {
    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();
    let value = 25313u64;

    let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
    let note_variant = NoteVariant::Obfuscated(note);

    let mut db = db::Db::<Blake2b>::default();

    let idx = db.store_unspent_note(note_variant).unwrap();

    let db_note_variant = db.fetch_note(idx).unwrap();

    let db_note = match db_note_variant {
        NoteVariant::Obfuscated(n) => n,
        _ => panic!("Note deserialized to wrong type"),
    };

    assert_eq!(note, db_note);
    assert!(db_note.is_owned_by(&vk));
    assert_eq!(value, db_note.value(Some(&vk)));
    assert_eq!(blinding_factor, db_note.blinding_factor(Some(&vk)).unwrap());
}

#[test]
#[ignore]
fn double_spending() {
    let mut db = db::Db::<Blake2b>::default();

    let mut tx = Transaction::default();

    let sk_base = SecretKey::default();
    let pk = sk_base.public_key();
    let value = 100;
    let note = TransparentNote::output(&pk, value).0;
    let variant: NoteVariant = note.into();
    let base_note_idx = db.store_unspent_note(variant).unwrap();
    let merkle_opening = db.opening(&variant).unwrap();
    tx.push_input(note.to_transaction_input(merkle_opening, sk_base).unwrap())
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

    let inserted = db.store_bulk_transactions(&[tx]).unwrap();

    let mut tx_ok = Transaction::default();

    let vk = sk_receiver.view_key();
    let note: Vec<NoteVariant> = inserted
        .into_iter()
        .map(|idx| db.fetch_note(idx).unwrap())
        .filter(|note| note.is_owned_by(&vk))
        .collect();
    assert_eq!(1, note.len());
    let note = note[0];
    assert_eq!(95, note.value(Some(&vk)));
    let variant: NoteVariant = note.into();
    let merkle_opening = db.opening(&variant).unwrap();
    tx_ok
        .push_input(
            note.to_transaction_input(merkle_opening, sk_receiver)
                .unwrap(),
        )
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
    let note = db.fetch_note(base_note_idx).unwrap();
    assert_eq!(100, note.value(Some(&vk)));
    let merkle_opening = db.opening(&note).unwrap();
    tx_double_spending
        .push_input(note.to_transaction_input(merkle_opening, sk_base).unwrap())
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

    assert!(db
        .store_bulk_transactions(&[tx_ok, tx_double_spending])
        .is_err());
}
