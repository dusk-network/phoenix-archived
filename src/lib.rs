use std::io::{self, Write};

use bulletproofs::r1cs::{Prover, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use dusk_tlv::{Error as TlvError, TlvReader, TlvWriter};
use log::error;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub use curve25519_dalek::ristretto::CompressedRistretto;
pub use curve25519_dalek::scalar::Scalar;

pub fn prove<S: io::Read + io::Write>(mut stream: S) {
    _commitments(&mut stream, true)
        .and_then(|(proof, _, _)| {
            let mut writer = TlvWriter::new(&mut stream);

            let proof = proof.ok_or(io::Error::new(
                io::ErrorKind::Other,
                "The ZK proof was not provided!",
            ))?;

            // Success status
            writer.write(&[0x01])?;
            proof.serialize(&mut writer).map_err(error_tlv_to_io)?;

            Ok(())
        })
        .unwrap_or_else(|e| {
            error!("{}", e);

            let mut writer = TlvWriter::new(&mut stream);

            // Error status
            writer.write(&[0x00]).unwrap_or(0);
        });
}

pub fn commitments<S: io::Read + io::Write>(mut stream: S) {
    _commitments(&mut stream, false)
        .and_then(|(_, commitments, blinding_factors)| {
            let mut writer = TlvWriter::new(&mut stream);

            // Success status
            writer.write(&[0x01])?;

            write_commitments(&mut writer, commitments, blinding_factors)?;

            Ok(())
        })
        .unwrap_or_else(|e| {
            error!("{}", e);

            let mut writer = TlvWriter::new(&mut stream);

            // Error status
            writer.write(&[0x00]).unwrap_or(0);
        });
}

fn _commitments<R: io::Read>(
    reader: R,
    generate_proof: bool,
) -> Result<(Option<R1CSProof>, Vec<CompressedRistretto>, Vec<Scalar>), io::Error> {
    let mut reader = TlvReader::new(reader);

    let _idx: u64 = Deserialize::deserialize(&mut reader).map_err(error_tlv_to_io)?;
    let value: Scalar = Deserialize::deserialize(&mut reader).map_err(error_tlv_to_io)?;
    let blinding: Scalar = if generate_proof {
        Deserialize::deserialize(&mut reader).map_err(error_tlv_to_io)?
    } else {
        gen_random_scalar()
    };

    gen_proof_data(value, blinding, generate_proof)
}

pub fn verify<S: io::Read + io::Write>(mut stream: S) {
    _verify(&mut stream)
        .and_then(|_| {
            let mut writer = TlvWriter::new(&mut stream);

            // Success status
            writer.write(&[0x01])?;

            Ok(())
        })
        .unwrap_or_else(|e| {
            error!("{}", e);

            let mut writer = TlvWriter::new(&mut stream);

            // Error status
            writer.write(&[0x00]).unwrap_or(0);
        });
}

fn _verify<R: io::Read>(reader: R) -> Result<(), io::Error> {
    let mut reader = TlvReader::new(reader);

    let proof: R1CSProof = Deserialize::deserialize(&mut reader).map_err(error_tlv_to_io)?;
    let commitments: Vec<Vec<u8>> = reader.read_list().map_err(error_tlv_to_io)?;
    let commitments: Vec<CompressedRistretto> = commitments
        .iter()
        .map(|c| CompressedRistretto::from_slice(c.as_slice()))
        .collect();

    let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
    let mut verifier = Verifier::new(&mut transcript);

    for c in commitments {
        verifier.commit(c);
    }

    verifier
        .verify(&proof, &pc_gens, &bp_gens)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    Ok(())
}

fn write_commitments<W: io::Write>(
    writer: &mut TlvWriter<W>,
    commitments: Vec<CompressedRistretto>,
    blinding_factors: Vec<Scalar>,
) -> Result<(), io::Error> {
    writer
        .write_list(
            commitments
                .iter()
                .map(|c| c.to_bytes()[..].to_vec())
                .collect::<Vec<Vec<u8>>>()
                .as_slice(),
        )
        .map_err(error_tlv_to_io)?;

    writer
        .write_list(
            blinding_factors
                .iter()
                .map(|b| b.to_bytes()[..].to_vec())
                .collect::<Vec<Vec<u8>>>()
                .as_slice(),
        )
        .map_err(error_tlv_to_io)?;

    Ok(())
}

fn gen_proof_data(
    value: Scalar,
    blinding: Scalar,
    generate_proof: bool,
) -> Result<(Option<R1CSProof>, Vec<CompressedRistretto>, Vec<Scalar>), io::Error> {
    let (pc_gens, bp_gens, mut transcript) = gen_cs_transcript();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let mut commitments = vec![];
    let mut blinding_factors = vec![];

    let (commitment, _) = prover.commit(value, blinding);

    commitments.push(commitment);
    blinding_factors.push(blinding);

    let proof = if generate_proof {
        let proof = prover
            .prove(&bp_gens)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Some(proof)
    } else {
        None
    };

    Ok((proof, commitments, blinding_factors))
}

fn error_tlv_to_io(e: TlvError) -> io::Error {
    match e {
        TlvError::Io(e) => e,
    }
}

/// Generate the constraint system and the transcript for the zk proofs
fn gen_cs_transcript() -> (PedersenGens, BulletproofGens, Transcript) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let transcript = Transcript::new(b"big-merkle-bp");

    (pc_gens, bp_gens, transcript)
}

fn gen_random_scalar() -> Scalar {
    let mut s = [0x00u8; 32];
    OsRng.fill_bytes(&mut s);
    Scalar::from_bits(s)
}
