use crate::{
    rpc, utils, Note, NoteGenerator, NoteType, NoteVariant, ObfuscatedNote, PublicKey, SecretKey,
    TransparentNote,
};

use std::convert::TryFrom;
use std::io::{Read, Write};

use kelvin::{
    tests::{arbitrary as a, fuzz_content, fuzz_content_iterations},
    Blake2b,
};

#[test]
fn transparent_note() {
    utils::init();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 25;

    let (mut note, _) = TransparentNote::output(&pk, value);

    let mut bytes = vec![0x00u8; 2048];
    note.read(bytes.as_mut_slice()).unwrap();

    let mut deser_note = TransparentNote::default();
    assert_ne!(note, deser_note);

    deser_note.write(bytes.as_slice()).unwrap();
    assert_eq!(note, deser_note);

    let note = deser_note;
    assert_eq!(note.note(), NoteType::Transparent);
    assert_eq!(value, note.value(None));
}

#[test]
fn obfuscated_note() {
    utils::init();

    let sk = SecretKey::default();
    let pk = sk.public_key();
    let vk = sk.view_key();
    let value = 25;

    let (mut note, _) = ObfuscatedNote::output(&pk, value);

    let mut bytes = vec![0x00u8; 2048];
    note.read(bytes.as_mut_slice()).unwrap();

    let mut deser_note = ObfuscatedNote::default();
    assert_ne!(note, deser_note);

    deser_note.write(bytes.as_slice()).unwrap();
    assert_eq!(note, deser_note);

    let note = deser_note;
    assert_eq!(note.note(), NoteType::Obfuscated);

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
    utils::init();

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

    let sk_r = note.sk_r(&sk);
    let wrong_sk_r = note.sk_r(&wrong_sk);

    assert_eq!(note.pk_r(), &utils::mul_by_basepoint_jubjub(&sk_r));
    assert_ne!(note.pk_r(), &utils::mul_by_basepoint_jubjub(&wrong_sk_r));
}

#[test]
fn content_implementations() {
    utils::init();

    impl a::Arbitrary for TransparentNote {
        fn arbitrary(u: &mut a::Unstructured<'_>) -> Result<Self, a::Error> {
            let vec: Vec<u8> = a::Arbitrary::arbitrary(u)?;
            let pubkey: PublicKey = SecretKey::from(vec.as_slice()).into();
            let note = TransparentNote::output(&pubkey, a::Arbitrary::arbitrary(u)?).0;
            Ok(note)
        }
    }

    impl a::Arbitrary for ObfuscatedNote {
        fn arbitrary(u: &mut a::Unstructured<'_>) -> Result<Self, a::Error> {
            let vec: Vec<u8> = a::Arbitrary::arbitrary(u)?;
            let pubkey: PublicKey = SecretKey::from(vec.as_slice()).into();
            let note = ObfuscatedNote::output(&pubkey, a::Arbitrary::arbitrary(u)?).0;
            Ok(note)
        }
    }

    impl a::Arbitrary for NoteVariant {
        fn arbitrary(u: &mut a::Unstructured<'_>) -> Result<Self, a::Error> {
            let transparent: bool = a::Arbitrary::arbitrary(u)?;

            if transparent {
                Ok(NoteVariant::Transparent(a::Arbitrary::arbitrary(u)?))
            } else {
                Ok(NoteVariant::Obfuscated(a::Arbitrary::arbitrary(u)?))
            }
        }
    }

    fuzz_content::<u64, Blake2b>();
    fuzz_content_iterations::<NoteVariant, Blake2b>(64);
}
