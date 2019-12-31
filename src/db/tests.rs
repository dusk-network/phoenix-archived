use crate::{Db, Idx, Note, NoteGenerator, ObfuscatedNote, SecretKey, TransparentNote};

#[test]
fn store_notes() {
    let db = Db::new().unwrap();

    let transaparent_notes: Vec<(Idx, TransparentNote)> = (0..20)
        .map(|i| {
            let sk = SecretKey::default();
            let vk = sk.view_key();
            let pk = sk.public_key();
            let value = (i * i) as u64;

            let note = TransparentNote::output(&pk, value);
            let idx = db
                .store_transaction_item(&note.to_transaction_output(vk))
                .unwrap()
                .unwrap();

            (idx, note)
        })
        .collect();

    let obfuscated_notes: Vec<(Idx, ObfuscatedNote)> = (0..20)
        .map(|i| {
            let sk = SecretKey::default();
            let vk = sk.view_key();
            let pk = sk.public_key();
            let value = (i * i) as u64;

            let note = ObfuscatedNote::output(&pk, value);
            let idx = db
                .store_transaction_item(&note.clone().to_transaction_output(vk))
                .unwrap()
                .unwrap();

            (idx, note)
        })
        .collect();

    transaparent_notes.iter().for_each(|(idx, note)| {
        let db_note: TransparentNote = db.fetch_note(idx).unwrap();

        assert_eq!(note.utxo(), db_note.utxo());
        assert_eq!(note.note(), db_note.note());
        assert_eq!(note.value(None), db_note.value(None));
        assert_eq!(idx, db_note.idx());
    });

    obfuscated_notes.iter().for_each(|(idx, note)| {
        let db_note: ObfuscatedNote = db.fetch_note(idx).unwrap();

        assert_eq!(note.utxo(), db_note.utxo());
        assert_eq!(note.note(), db_note.note());
        assert_eq!(note.commitments, db_note.commitments);
        assert_eq!(note.encrypted_value, db_note.encrypted_value);
        assert_eq!(
            note.encrypted_blinding_factors,
            db_note.encrypted_blinding_factors
        );
        assert_eq!(idx, db_note.idx());
    });
}
