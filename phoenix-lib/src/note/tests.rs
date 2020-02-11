use crate::{
    rpc, utils, Note, NoteGenerator, NoteType, NoteUtxoType, ObfuscatedNote, SecretKey,
    TransparentNote,
};

use std::convert::TryFrom;

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

    let rpc_note = rpc::Note::from(note.clone());
    let deserialized_note = ObfuscatedNote::try_from(rpc_note).unwrap();
    assert_eq!(deserialized_note, note);

    let rpc_decrypted_note = note.clone().rpc_decrypted_note(&vk);
    let deserialized_note = ObfuscatedNote::try_from(rpc_decrypted_note).unwrap();
    assert_eq!(deserialized_note, note);

    assert_eq!(value, note.value(Some(&vk)));
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
    let sk_r_g = utils::mul_by_basepoint_ristretto(&sk_r);

    assert_eq!(pk_r, &sk_r_g);

    let wrong_sk_r = note.sk_r(&wrong_sk);
    let wrong_sk_r_g = utils::mul_by_basepoint_ristretto(&wrong_sk_r);

    assert_ne!(pk_r, &wrong_sk_r_g);
}
