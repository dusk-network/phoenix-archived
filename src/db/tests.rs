use crate::{
    utils, Db, Note, NoteGenerator, NoteVariant, ObfuscatedNote, SecretKey, TransparentNote,
};

use std::env::temp_dir;
use std::fs;

use kelvin::{Blake2b, Root};

#[test]
fn transparent_note_serialization() {
    utils::init();

    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();
    let value = 25312u64;

    let (note, blinding_factor) = TransparentNote::output(&pk, value);
    let note_variant = NoteVariant::Transparent(note);

    let mut db = temp_dir();
    db.push("transparent_note_serialization");

    let mut root = Root::<_, Blake2b>::new(db.as_path()).unwrap();
    let mut state: Db<_> = root.restore().unwrap();

    let idx = state.store_unspent_note(note_variant).unwrap();

    root.set_root(&mut state).unwrap();

    let root = Root::<_, Blake2b>::new(db.as_path()).unwrap();
    let state: Db<_> = root.restore().unwrap();

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
    fs::remove_dir_all(db.as_path()).expect("could not remove temp db");
}

#[test]
fn obfuscated_note_serialization() {
    utils::init();

    let sk = SecretKey::default();
    let vk = sk.view_key();
    let pk = sk.public_key();
    let value = 25313u64;

    let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
    let note_variant = NoteVariant::Obfuscated(note);

    let mut db = temp_dir();
    db.push("obfuscated_note_serialization");

    let mut root = Root::<_, Blake2b>::new(db.as_path()).unwrap();
    let mut state: Db<_> = root.restore().unwrap();

    let idx = state.store_unspent_note(note_variant).unwrap();

    root.set_root(&mut state).unwrap();

    let root = Root::<_, Blake2b>::new(db.as_path()).unwrap();
    let state: Db<_> = root.restore().unwrap();

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
    fs::remove_dir_all(db.as_path()).expect("could not remove temp db");
}
