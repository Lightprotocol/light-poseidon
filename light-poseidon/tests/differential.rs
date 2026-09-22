//! Differential test against a frozen oracle.
//!
//! The vectors in `fixtures/reference_vectors.rs` were captured from the
//! implementation as it stood before the zero-allocation rewrite. They pin the
//! hash outputs of every supported width across the field API and both byte
//! endiannesses.
//!
//! This crate backs the Solana `sol_poseidon` syscall, so a change in any of
//! these outputs is a consensus-affecting change. If a vector fails, the fix is
//! the code, never the fixture.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher};

include!("fixtures/reference_vectors.rs");

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex: {s}");
    (0..s.len() / 2)
        .map(|i| {
            let byte = s.get(i * 2..i * 2 + 2).expect("hex pair in range");
            u8::from_str_radix(byte, 16).expect("valid hex")
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn be_bytes_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[test]
fn vectors_are_present_for_every_width() {
    for width in 2usize..=13 {
        let n = VECTORS.iter().filter(|(w, ..)| *w == width).count();
        assert!(n > 0, "no vectors for width {width}");
    }
    assert_eq!(VECTORS.len(), 144, "unexpected vector count");
}

#[test]
fn field_api_matches_frozen_oracle() {
    for (width, inputs_hex, expected_be, _) in VECTORS {
        let inputs: Vec<Fr> = inputs_hex
            .iter()
            .map(|h| be_bytes_to_fr(&from_hex(h)))
            .collect();
        assert_eq!(inputs.len() + 1, *width, "input count for width {width}");

        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("hasher");
        let got = hasher.hash(&inputs).expect("hash");
        let got_hex = to_hex(&got.into_bigint().to_bytes_be());

        assert_eq!(
            &got_hex, expected_be,
            "field hash changed at width {width} for inputs {inputs_hex:?}"
        );
    }
}

#[test]
fn hash_bytes_be_matches_frozen_oracle() {
    for (width, inputs_hex, expected_be, _) in VECTORS {
        let owned: Vec<Vec<u8>> = inputs_hex.iter().map(|h| from_hex(h)).collect();
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();

        let mut hasher = Poseidon::<Fr>::new_circom(refs.len()).expect("hasher");
        let got = hasher.hash_bytes_be(&refs).expect("hash_bytes_be");

        assert_eq!(
            &to_hex(&got),
            expected_be,
            "hash_bytes_be changed at width {width} for inputs {inputs_hex:?}"
        );
    }
}

#[test]
fn hash_bytes_le_matches_frozen_oracle() {
    for (width, inputs_hex, _, expected_le) in VECTORS {
        // The fixture stores inputs big-endian; the LE API needs them reversed.
        let owned: Vec<Vec<u8>> = inputs_hex
            .iter()
            .map(|h| {
                let mut v = from_hex(h);
                v.reverse();
                v
            })
            .collect();
        let refs: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();

        let mut hasher = Poseidon::<Fr>::new_circom(refs.len()).expect("hasher");
        let got = hasher.hash_bytes_le(&refs).expect("hash_bytes_le");

        assert_eq!(
            &to_hex(&got),
            expected_le,
            "hash_bytes_le changed at width {width} for inputs {inputs_hex:?}"
        );
    }
}

#[test]
fn repeated_hashing_is_stable() {
    // A reused hasher must produce the same result every time.
    for (width, inputs_hex, expected_be, _) in VECTORS.iter().take(12) {
        let inputs: Vec<Fr> = inputs_hex
            .iter()
            .map(|h| be_bytes_to_fr(&from_hex(h)))
            .collect();
        let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("hasher");
        for round in 0..3 {
            let got = hasher.hash(&inputs).expect("hash");
            let got_hex = to_hex(&got.into_bigint().to_bytes_be());
            assert_eq!(
                &got_hex, expected_be,
                "width {width} diverged on reuse {round}"
            );
        }
    }
}
