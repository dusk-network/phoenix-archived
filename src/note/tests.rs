use crate::{
    Note, NoteGenerator, NoteType, NoteUtxoType, ObfuscatedNote, SecretKey, TransparentNote,
};

#[test]
fn transparent_note() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 25;

    let note = TransparentNote::output(&pk, value);
    let note = bincode::serialize(&note).unwrap();
    let note: TransparentNote = bincode::deserialize(note.as_slice()).unwrap();

    assert_eq!(note.utxo(), NoteUtxoType::Output);
    assert_eq!(note.note(), NoteType::Transparent);
    assert_eq!(value, note.value());
}

#[test]
fn obfuscated_note() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 25;

    let note = ObfuscatedNote::output(&pk, value);

    assert_eq!(note.utxo(), NoteUtxoType::Output);
    assert_eq!(note.note(), NoteType::Obfuscated);

    let proof = note.prove_value(&sk).unwrap();

    let note = bincode::serialize(&note).unwrap();
    let note: ObfuscatedNote = bincode::deserialize(note.as_slice()).unwrap();
    note.verify_value(&proof).unwrap();
}
