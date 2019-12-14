use crate::{NoteType, NoteUtxoType, ObfuscatedNote, PhoenixNote, SecretKey, TransparentNote};

#[test]
fn transparent_note() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 25;

    let note = TransparentNote::output(&pk, value);
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
    note.verify_value(&proof).unwrap();
}
