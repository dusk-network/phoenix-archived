use crate::{
    utils, Note, NoteGenerator, NoteType, NoteUtxoType, ObfuscatedNote, SecretKey, TransparentNote,
};

#[test]
fn transparent_note() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 25;

    let (note, _) = TransparentNote::output(&pk, value);

    assert_eq!(note.utxo(), NoteUtxoType::Output);
    assert_eq!(note.note(), NoteType::Transparent);
    assert_eq!(value, note.value(None));
}

#[test]
fn obfuscated_note() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();
    let value = 25;

    let (note, _) = ObfuscatedNote::output(&pk, value);

    assert_eq!(note.utxo(), NoteUtxoType::Output);
    assert_eq!(note.note(), NoteType::Obfuscated);

    let proof = note.prove_value(&vk).unwrap();

    note.verify_value(&proof).unwrap();
}

#[test]
fn note_keys_consistency() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();
    let value = 25;
    let wrong_sk = SecretKey::default();
    let wrong_vk = wrong_sk.view_key();

    assert_ne!(sk, wrong_sk);
    assert_ne!(vk, wrong_vk);

    let (note, _) = ObfuscatedNote::output(&pk, value);

    assert!(!note.is_owned_by(&wrong_vk));
    assert!(note.is_owned_by(&vk));

    let pk_r = note.pk_r();
    let sk_r = note.sk_r(&sk);
    let sk_r_g = utils::mul_by_basepoint_edwards(&sk_r);

    assert_eq!(pk_r, &sk_r_g);

    let wrong_sk_r = note.sk_r(&wrong_sk);
    let wrong_sk_r_g = utils::mul_by_basepoint_edwards(&wrong_sk_r);

    assert_ne!(pk_r, &wrong_sk_r_g);
}
