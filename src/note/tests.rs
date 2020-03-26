use crate::{
    rpc, Note, NoteGenerator, NoteType, NoteVariant, ObfuscatedNote, PublicKey, SecretKey,
    TransparentNote,
};

use std::convert::TryFrom;

use kelvin::{
    tests::{arbitrary as a, fuzz_content, fuzz_content_iterations},
    Blake2b,
};

#[test]
fn transparent_note() {
    let sk = SecretKey::default();
    let pk = sk.public_key();
    let value = 25;

    let (note, _) = TransparentNote::output(&pk, value);

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
}

#[test]
fn content_implementations() {
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
