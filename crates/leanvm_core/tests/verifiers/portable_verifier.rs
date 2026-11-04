//! Pins the portable `verifier` crate against `leanvm_core::cpu::prove`, on the
//! proof the Python verifier is pinned on and through the same two encodings.

use crate::python_verifier::{encode, fixture};
use leanvm_core::cpu::{prove, public_input_bytes, scalar_proof, verify};
use leanvm_core::tables::N_TABLES;
use primitives::field::F192;
use verifier::{Bytecode, MerkleOpenings, Proof, replay_unchecked, verify_execution};

#[test]
fn test_portable_verifier() {
    let fixture = fixture();
    let table = fixture.bytecode_table();
    let bytecode = Bytecode::new(&table);
    let public_input = public_input_bytes(&fixture.public_input);
    let (stream, openings) = encode(&fixture.proof.stream, &fixture.summary.merkle_paths);
    let proof = Proof::load(&stream, &openings).expect("load the honest proof");

    // The raw form leaves what the wire form left, its own paths included.
    let summary = verify_execution(&bytecode, &public_input, &proof);
    assert_eq!(summary.as_ref(), Ok(&fixture.summary));

    // The wire form of the same proof: one pruned batch per level, the level-0 rows without their zero lanes.
    let wire_proof = scalar_proof(&fixture.proof);
    let MerkleOpenings::Pruned(batches) = &wire_proof.merkle_openings else {
        panic!("built from the wire proof");
    };
    assert!(batches[0].leaf_data[0].len() < 64, "level 0 drops lanes");
    assert_eq!(
        verify_execution(&bytecode, &public_input, &wire_proof).as_ref(),
        Ok(&fixture.summary)
    );

    // The other rates walk other rows of the tabulated query counts and another ladder of level rates.
    for log_inv_rate in 2..=4 {
        let (proof, _) = prove(&fixture.program, fixture.public_input, log_inv_rate).unwrap();
        let summary = verify(&fixture.program, &fixture.public_input, &proof).expect("the wire form verifies");
        let (stream, openings) = encode(&proof.stream, &summary.merkle_paths);
        let proof = Proof::load(&stream, &openings).expect("load the honest proof");
        assert_eq!(
            verify_execution(&bytecode, &public_input, &proof),
            Ok(summary),
            "rate {log_inv_rate}"
        );
    }
}

/// The replay reads out of an honest proof what verifying it leaves, in either form.
#[test]
fn replay_reads_the_summary_unchecked() {
    let fixture = fixture();
    let table = fixture.bytecode_table();
    let bytecode = Bytecode::new(&table);
    let public_input = public_input_bytes(&fixture.public_input);
    let replay = |proof: &Proof| replay_unchecked(&bytecode, &public_input, proof);
    assert_eq!(replay(&scalar_proof(&fixture.proof)).as_ref(), Ok(&fixture.summary));
    let (stream, openings) = encode(&fixture.proof.stream, &fixture.summary.merkle_paths);
    let raw_proof = Proof::load(&stream, &openings).expect("load the honest proof");
    assert_eq!(replay(&raw_proof).as_ref(), Ok(&fixture.summary));
}

/// What the transcript absorbs and squeezes is fixed by the bytecode and the announced sizes (`sec:e2e-fiat-shamir`):
/// with every later scalar changed, and so every challenge, the replay still reads the stream and the openings to
/// their end, the Keccak reduction's scalars where they were.
#[test]
fn only_the_sizes_shape_the_transcript() {
    let fixture = fixture();
    let table = fixture.bytecode_table();
    let bytecode = Bytecode::new(&table);
    let public_input = public_input_bytes(&fixture.public_input);
    let mut stream = fixture.proof.stream.clone();
    for scalar in &mut stream[2 + N_TABLES..] {
        *scalar += F192::ONE;
    }
    let (stream, openings) = encode(&stream, &fixture.summary.merkle_paths);
    let proof = Proof::load(&stream, &openings).expect("load the changed proof");
    let summary = replay_unchecked(&bytecode, &public_input, &proof).expect("the changed proof walks whole");
    assert_eq!(summary.keccak_scalars, fixture.summary.keccak_scalars);
    assert_ne!(
        summary.bytecode_point, fixture.summary.bytecode_point,
        "the challenges changed"
    );
}
