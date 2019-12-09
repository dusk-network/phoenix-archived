use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use dusk_phoenix::{commitments, prove, verify};
use dusk_tlv::{TlvReader, TlvWriter};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

fn main() {
    let mut buf = vec![];
    let mut writer = TlvWriter::new(&mut buf);

    let idx = 25u64;
    let value = Scalar::from(37u64);
    idx.serialize(&mut writer).unwrap();
    value.serialize(&mut writer).unwrap();

    let buf = writer.into_inner();
    let mut cursor = Cursor::new(buf);
    commitments(&mut cursor);

    let buf = cursor.into_inner();
    let mut reader = TlvReader::new(buf.as_slice());

    let de_idx: u64 = Deserialize::deserialize(&mut reader).unwrap();
    let de_value: Scalar = Deserialize::deserialize(&mut reader).unwrap();
    assert_eq!(idx, de_idx);
    assert_eq!(value, de_value);

    let success: bool = Deserialize::deserialize(&mut reader).unwrap();
    assert!(success);

    let commitments: Vec<Vec<u8>> = reader.read_list().unwrap();
    let commitments: Vec<CompressedRistretto> = commitments
        .iter()
        .map(|c| CompressedRistretto::from_slice(c.as_slice()))
        .collect();
    let correct_commitments = commitments.clone();

    let blinding_factors: Vec<Vec<u8>> = reader.read_list().unwrap();
    let blinding_factors: Vec<Scalar> = blinding_factors
        .iter()
        .map(|b| {
            let mut s = [0x00u8; 32];
            s.copy_from_slice(b.as_slice());
            Scalar::from_bits(s)
        })
        .collect();

    let mut buf = vec![];
    let mut writer = TlvWriter::new(&mut buf);

    idx.serialize(&mut writer).unwrap();
    value.serialize(&mut writer).unwrap();
    blinding_factors[0].serialize(&mut writer).unwrap();

    let buf = writer.into_inner();
    let mut cursor = Cursor::new(buf);
    prove(&mut cursor);

    let buf = cursor.into_inner();
    let mut reader = TlvReader::new(buf.as_slice());

    let de_idx: u64 = Deserialize::deserialize(&mut reader).unwrap();
    let de_value: Scalar = Deserialize::deserialize(&mut reader).unwrap();
    let _de_blinding: Scalar = Deserialize::deserialize(&mut reader).unwrap();
    assert_eq!(idx, de_idx);
    assert_eq!(value, de_value);

    let success: bool = Deserialize::deserialize(&mut reader).unwrap();
    assert!(success);

    let proof: R1CSProof = Deserialize::deserialize(&mut reader).unwrap();

    println!("Proof size: {}", proof.serialized_size());
    println!("Commitments: {}", commitments.len());
    println!("Blinding factors: {}", blinding_factors.len());

    let mut buf = vec![];
    let mut writer = TlvWriter::new(&mut buf);

    proof.serialize(&mut writer).unwrap();
    let commitments: Vec<Vec<u8>> = commitments
        .iter()
        .map(|c| c.to_bytes()[..].to_vec())
        .collect();
    writer.write_list(commitments.as_slice()).unwrap();

    let buf = writer.into_inner();
    let mut cursor = Cursor::new(buf);
    verify(&mut cursor);

    let buf = cursor.into_inner();
    let mut reader = TlvReader::new(buf.as_slice());

    let _de_proof: R1CSProof = Deserialize::deserialize(&mut reader).unwrap();
    let de_commitments: Vec<Vec<u8>> = reader.read_list().unwrap();
    assert_eq!(commitments, de_commitments);

    let success: bool = Deserialize::deserialize(&mut reader).unwrap();
    assert!(success);

    let mut buf = vec![];
    let mut writer = TlvWriter::new(&mut buf);

    idx.serialize(&mut writer).unwrap();
    let wrong_value = Scalar::from(1002u64);
    wrong_value.serialize(&mut writer).unwrap();
    blinding_factors[0].serialize(&mut writer).unwrap();

    let buf = writer.into_inner();
    let mut cursor = Cursor::new(buf);
    prove(&mut cursor);

    let buf = cursor.into_inner();
    let mut reader = TlvReader::new(buf.as_slice());

    let de_idx: u64 = Deserialize::deserialize(&mut reader).unwrap();
    let de_value: Scalar = Deserialize::deserialize(&mut reader).unwrap();
    let _de_blinding: Scalar = Deserialize::deserialize(&mut reader).unwrap();
    assert_eq!(idx, de_idx);
    assert_eq!(wrong_value, de_value);

    let success: bool = Deserialize::deserialize(&mut reader).unwrap();
    assert!(success);

    let proof: R1CSProof = Deserialize::deserialize(&mut reader).unwrap();

    println!("Proof size: {}", proof.serialized_size());
    println!("Commitments: {}", commitments.len());
    println!("Blinding factors: {}", blinding_factors.len());

    let mut buf = vec![];
    let mut writer = TlvWriter::new(&mut buf);

    proof.serialize(&mut writer).unwrap();
    let commitments: Vec<Vec<u8>> = correct_commitments
        .iter()
        .map(|c| c.to_bytes()[..].to_vec())
        .collect();
    writer.write_list(commitments.as_slice()).unwrap();

    let buf = writer.into_inner();
    let mut cursor = Cursor::new(buf);
    verify(&mut cursor);

    let buf = cursor.into_inner();
    let mut reader = TlvReader::new(buf.as_slice());

    let _de_proof: R1CSProof = Deserialize::deserialize(&mut reader).unwrap();
    let de_commitments: Vec<Vec<u8>> = reader.read_list().unwrap();
    assert_eq!(commitments, de_commitments);

    let success: bool = Deserialize::deserialize(&mut reader).unwrap();
    assert!(!success);
}
