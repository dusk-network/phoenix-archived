use crate::{db, Db, Idx, Note, NoteGenerator, ObfuscatedNote, SecretKey, TransparentNote};

use kelvin::{Blake2b, Root};
use std::convert::TryInto;
use std::env::temp_dir;
use std::fs;

#[test]
fn store_notes() {
    // Since we're only working with notes, the db is instantiated here
    // directly and used in the test, as there is no API for directly
    // storing notes without having a `Db` around.
    let mut db = temp_dir();
    db.push("db_store_notes");
    let mut root = Root::<_, Blake2b>::new(db.as_path()).unwrap();
    let mut state: Db<_> = root.restore().unwrap();

    let transparent_notes: Vec<(Idx, TransparentNote)> = (0..20)
        .map(|i| {
            let sk = SecretKey::default();
            let pk = sk.public_key();
            let value = (i * i) as u64;

            let (note, blinding_factor) = TransparentNote::output(&pk, value);
            let idx = state
                .store_transaction_item(&note.clone().to_transaction_output(
                    value,
                    blinding_factor,
                    pk,
                ))
                .unwrap()
                .unwrap();

            (idx, note)
        })
        .collect();

    let obfuscated_notes: Vec<(Idx, ObfuscatedNote)> = (0..20)
        .map(|i| {
            let sk = SecretKey::default();
            let pk = sk.public_key();
            let value = (i * i) as u64;

            let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
            let idx = state
                .store_transaction_item(&note.clone().to_transaction_output(
                    value,
                    blinding_factor,
                    pk,
                ))
                .unwrap()
                .unwrap();

            (idx, note)
        })
        .collect();

    root.set_root(&mut state).unwrap();

    transparent_notes.iter().for_each(|(idx, note)| {
        let db_note: TransparentNote = db::fetch_note(db.as_path(), idx)
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(note.utxo(), db_note.utxo());
        assert_eq!(note.note(), db_note.note());
        assert_eq!(note.value(None), db_note.value(None));
        assert_eq!(idx, db_note.idx());
    });

    obfuscated_notes.iter().for_each(|(idx, note)| {
        let db_note: ObfuscatedNote = db::fetch_note(db.as_path(), idx)
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(note.utxo(), db_note.utxo());
        assert_eq!(note.note(), db_note.note());
        assert_eq!(note.commitment(), db_note.commitment());
        assert_eq!(note.encrypted_value, db_note.encrypted_value);
        assert_eq!(
            &note.encrypted_blinding_factor[..],
            &db_note.encrypted_blinding_factor[..]
        );
        assert_eq!(idx, db_note.idx());
    });

    // Clean up the db
    fs::remove_dir_all(db.as_path()).expect("could not remove temp db");
}
