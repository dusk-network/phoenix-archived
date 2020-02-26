use crate::{Db, Idx, Note, NoteGenerator, ObfuscatedNote, SecretKey, TransparentNote};

use std::convert::TryInto;

#[test]
fn store_notes() {
    let mut db = Db::new().unwrap();

    let transaparent_notes: Vec<(Idx, TransparentNote)> = (0..20)
        .map(|i| {
            let sk = SecretKey::default();
            let pk = sk.public_key();
            let value = (i * i) as u64;

            let (note, blinding_factor) = TransparentNote::output(&pk, value);
            let idx = db
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
            let idx = db
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

    transaparent_notes.iter().for_each(|(idx, note)| {
        let db_note: TransparentNote = db.fetch_note(idx).unwrap().try_into().unwrap();

        assert_eq!(note.utxo(), db_note.utxo());
        assert_eq!(note.note(), db_note.note());
        assert_eq!(note.value(None), db_note.value(None));
        assert_eq!(idx, db_note.idx());
    });

    obfuscated_notes.iter().for_each(|(idx, note)| {
        let db_note: ObfuscatedNote = db.fetch_note(idx).unwrap().try_into().unwrap();

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
}
