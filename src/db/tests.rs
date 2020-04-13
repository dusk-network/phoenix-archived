use crate::{
    utils, Note, NoteGenerator, NoteVariant, NotesDb, ObfuscatedNote, SecretKey, TransparentNote,
};

use std::fs;

use kelvin::{Blake2b, Root};
use tempdir::TempDir;

#[test]
fn transparent_note_serialization() {
    utils::init();

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
    utils::init();

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
