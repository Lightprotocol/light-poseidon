//! The sparse factorization of the partial rounds is an exact rewrite, so it
//! must not change a single hash. These tests compare it against the
//! unoptimized permutation directly, for every bundled width.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use light_poseidon::{
    parameters::{bn254_x5, bn254_x5_sparse},
    Poseidon, PoseidonBytesHasher, PoseidonError, PoseidonHasher, SparseMdsParameters,
};
use rand::{rngs::StdRng, SeedableRng};

const WIDTHS: std::ops::RangeInclusive<u8> = 2..=13;

/// Random inputs compared per width. Deterministically seeded, so a failure
/// reproduces.
const SAMPLES: usize = 512;

/// Builds the two hashers for a width: one running the sparse partial rounds,
/// one running the unoptimized ones.
fn hashers(t: u8) -> (Poseidon<Fr>, Poseidon<Fr>) {
    let sparse_params = bn254_x5::get_poseidon_parameters(t)
        .unwrap()
        .with_sparse_mds(bn254_x5_sparse::get_sparse_mds_parameters(t).unwrap())
        .unwrap();
    let reference_params = bn254_x5::get_poseidon_parameters(t).unwrap();
    assert!(reference_params.sparse.is_none());
    (
        Poseidon::new(sparse_params).unwrap(),
        Poseidon::new(reference_params).unwrap(),
    )
}

#[test]
fn every_bundled_width_has_a_factorization() {
    for t in WIDTHS {
        let params = bn254_x5::get_poseidon_parameters(t).unwrap();
        let sparse = bn254_x5_sparse::get_sparse_mds_parameters(t)
            .unwrap_or_else(|| panic!("no sparse parameters bundled for width {t}"));

        // The dimensions the permutation relies on.
        assert_eq!(sparse.pre.len(), params.width * params.width);
        assert_eq!(
            sparse.matrices.len(),
            params.partial_rounds * (2 * params.width - 1)
        );
        assert_eq!(sparse.ark.len(), params.partial_rounds);
        assert_eq!(sparse.post.len(), params.width);

        assert!(sparse.fits(params.width, params.full_rounds, params.partial_rounds));
    }
}

#[test]
fn new_circom_uses_the_sparse_parameters() {
    for nr_inputs in 1..=12 {
        let hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();
        assert!(
            hasher.parameters().sparse.is_some(),
            "new_circom({nr_inputs}) did not attach the sparse parameters"
        );
    }
}

#[test]
fn sparse_matches_the_reference_on_random_inputs() {
    let mut rng = StdRng::seed_from_u64(0x5041_5253_4530_0001);
    for t in WIDTHS {
        let (mut sparse, mut reference) = hashers(t);
        let width = usize::from(t);
        for sample in 0..SAMPLES {
            let inputs: Vec<Fr> = (0..width - 1).map(|_| Fr::rand(&mut rng)).collect();
            assert_eq!(
                sparse.hash(&inputs).unwrap(),
                reference.hash(&inputs).unwrap(),
                "width {t}, sample {sample}"
            );
        }
    }
}

#[test]
fn sparse_matches_the_reference_on_boundary_inputs() {
    let modulus_minus_one = Fr::zero() - Fr::from(1u64);
    for t in WIDTHS {
        let (mut sparse, mut reference) = hashers(t);
        let width = usize::from(t);
        for value in [
            Fr::zero(),
            Fr::from(1u64),
            Fr::from(2u64),
            modulus_minus_one,
        ] {
            let inputs = vec![value; width - 1];
            assert_eq!(
                sparse.hash(&inputs).unwrap(),
                reference.hash(&inputs).unwrap(),
                "width {t}, input {value}"
            );
        }
    }
}

#[test]
fn sparse_matches_the_reference_on_both_byte_endiannesses() {
    let mut rng = StdRng::seed_from_u64(0x5041_5253_4530_0002);
    for t in WIDTHS {
        let (mut sparse, mut reference) = hashers(t);
        let width = usize::from(t);
        for sample in 0..64 {
            // The same elements in both encodings: reusing one encoding for
            // both calls would reinterpret the bytes as a different, possibly
            // out-of-range, element.
            let elements: Vec<Fr> = (0..width - 1).map(|_| Fr::rand(&mut rng)).collect();
            let big_endian: Vec<Vec<u8>> = elements
                .iter()
                .map(|element| element.into_bigint().to_bytes_be())
                .collect();
            let little_endian: Vec<Vec<u8>> = elements
                .iter()
                .map(|element| element.into_bigint().to_bytes_le())
                .collect();
            let be: Vec<&[u8]> = big_endian.iter().map(|input| input.as_slice()).collect();
            let le: Vec<&[u8]> = little_endian.iter().map(|input| input.as_slice()).collect();

            assert_eq!(
                sparse.hash_bytes_be(&be).unwrap(),
                reference.hash_bytes_be(&be).unwrap(),
                "width {t}, sample {sample}, big endian"
            );
            assert_eq!(
                sparse.hash_bytes_le(&le).unwrap(),
                reference.hash_bytes_le(&le).unwrap(),
                "width {t}, sample {sample}, little endian"
            );
        }
    }
}

#[test]
fn a_hasher_can_be_reused_across_hashes() {
    // The sparse path mutates the state in place, so a stale state would show
    // up as a second hash differing from a fresh hasher's.
    let mut rng = StdRng::seed_from_u64(0x5041_5253_4530_0003);
    for t in WIDTHS {
        let (mut sparse, _) = hashers(t);
        let width = usize::from(t);
        for _ in 0..8 {
            let inputs: Vec<Fr> = (0..width - 1).map(|_| Fr::rand(&mut rng)).collect();
            let repeated = sparse.hash(&inputs).unwrap();
            let fresh = {
                let (mut hasher, _) = hashers(t);
                hasher.hash(&inputs).unwrap()
            };
            assert_eq!(repeated, fresh, "width {t}");
        }
    }
}

#[test]
fn mismatched_sparse_parameters_are_rejected() {
    let params = bn254_x5::get_poseidon_parameters(3).unwrap();
    // Width 2's factorization has the wrong dimensions for width 3.
    let wrong = bn254_x5_sparse::get_sparse_mds_parameters(2).unwrap();
    let error = match params.with_sparse_mds(wrong) {
        Err(error) => error,
        Ok(_) => panic!("width 2 parameters were accepted for width 3"),
    };
    assert_eq!(
        error,
        PoseidonError::InvalidWidthCircom {
            width: 3,
            max_limit: 13,
        }
    );
}

#[test]
fn too_few_full_rounds_is_rejected() {
    let mut params = bn254_x5::get_poseidon_parameters(3).unwrap();
    let sparse = bn254_x5_sparse::get_sparse_mds_parameters(3).unwrap();
    // The pre-sparse matrix has to be absorbed by a full round before the
    // partial ones, so there must be at least one on each side.
    params.full_rounds = 0;
    let error = match params.with_sparse_mds(sparse) {
        Err(error) => error,
        Ok(_) => panic!("sparse parameters were accepted without full rounds"),
    };
    assert_eq!(
        error,
        PoseidonError::InvalidWidthCircom {
            width: 3,
            max_limit: 13,
        }
    );
}

#[test]
fn empty_sparse_parameters_are_rejected() {
    let params = bn254_x5::get_poseidon_parameters(3).unwrap();
    let empty: SparseMdsParameters<Fr> = SparseMdsParameters::new_unchecked(&[], &[], &[], &[]);
    assert!(params.with_sparse_mds(empty).is_err());
}
