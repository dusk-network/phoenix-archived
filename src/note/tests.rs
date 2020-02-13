use crate::{
    rpc, utils, Note, NoteGenerator, NoteType, NoteUtxoType, ObfuscatedNote, PublicKey, SecretKey,
    TransparentNote,
};

use kelvin::{
    tests::{arbitrary as a, fuzz_content, fuzz_content_iterations},
    Blake2b,
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
    let sk_r_g = utils::mul_by_basepoint_edwards(&sk_r);

    assert_eq!(pk_r, &sk_r_g);

    let wrong_sk_r = note.sk_r(&wrong_sk);
    let wrong_sk_r_g = utils::mul_by_basepoint_edwards(&wrong_sk_r);

    assert_ne!(pk_r, &wrong_sk_r_g);
}

#[test]
fn content_implementations() {
    use crate::note::NoteVariant;
    use rpc::Idx;

    impl a::Arbitrary for Idx {
        fn arbitrary(u: &mut a::Unstructured<'_>) -> Result<Self, a::Error> {
            Ok(Idx {
                pos: a::Arbitrary::arbitrary(u)?,
            })
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

    impl a::Arbitrary for NoteUtxoType {
        fn arbitrary(u: &mut a::Unstructured<'_>) -> Result<Self, a::Error> {
            Ok(if a::Arbitrary::arbitrary(u)? {
                NoteUtxoType::Input
            } else {
                NoteUtxoType::Output
            })
        }
    }

    impl a::Arbitrary for TransparentNote {
        fn arbitrary(u: &mut a::Unstructured<'_>) -> Result<Self, a::Error> {
            let vec: Vec<u8> = a::Arbitrary::arbitrary(u)?;
            let pubkey: PublicKey = SecretKey::from(vec).into();
            let note = TransparentNote::output(&pubkey, a::Arbitrary::arbitrary(u)?).0;
            Ok(note)
        }
    }

    impl a::Arbitrary for ObfuscatedNote {
        fn arbitrary(u: &mut a::Unstructured<'_>) -> Result<Self, a::Error> {
            let vec: Vec<u8> = a::Arbitrary::arbitrary(u)?;
            let pubkey: PublicKey = SecretKey::from(vec).into();
            let note = ObfuscatedNote::output(&pubkey, a::Arbitrary::arbitrary(u)?).0;
            Ok(note)
        }
    }

    fuzz_content::<Idx, Blake2b>();
    fuzz_content_iterations::<NoteVariant, Blake2b>(64);
}
