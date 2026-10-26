//! Compare the optimized public APIs with the original dense round schedule.
//!
//! Run a million cases with:
//! `PROPTEST_CASES=1000000 cargo test --release -p light-poseidon --test proptest`

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use light_poseidon::{
    parameters::bn254_x5::get_poseidon_parameters, Poseidon, PoseidonBytesHasher, PoseidonHasher,
    MAX_X5_LEN,
};
use proptest::prelude::*;

fn field_element() -> impl Strategy<Value = Fr> {
    prop_oneof![
        1 => Just(Fr::zero()),
        1 => Just(Fr::from(1u64)),
        1 => Just(-Fr::from(1u64)),
        17 => any::<[u8; 32]>().prop_map(|bytes| Fr::from_le_bytes_mod_order(&bytes)),
    ]
}

// Deliberately uses scalar products, full MDS matrices, and Field::pow rather
// than the optimized cores, their S-box chains, or their sparse constants.
fn dense_reference(inputs: &[Fr], domain_tag: Fr) -> Fr {
    let width = inputs.len() + 1;
    let params = get_poseidon_parameters(width as u8).expect("supported width");
    let mut state = [Fr::zero(); MAX_X5_LEN];
    state[0] = domain_tag;
    state
        .get_mut(1..width)
        .expect("supported width")
        .copy_from_slice(inputs);

    let half = params.full_rounds / 2;
    for (round, constants) in params.ark.chunks_exact(width).enumerate() {
        for (lane, constant) in state.iter_mut().take(width).zip(constants) {
            *lane += constant;
        }
        if round < half || round >= half + params.partial_rounds {
            for lane in state.iter_mut().take(width) {
                *lane = lane.pow([params.alpha]);
            }
        } else {
            state[0] = state[0].pow([params.alpha]);
        }

        let mut next = [Fr::zero(); MAX_X5_LEN];
        for (out, row) in next
            .iter_mut()
            .take(width)
            .zip(params.mds.chunks_exact(width))
        {
            for (value, coefficient) in state.iter().take(width).zip(row) {
                *out += *value * coefficient;
            }
        }
        state = next;
    }
    state[0]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: ProptestConfig::default().cases.max(1_024),
        ..ProptestConfig::default()
    })]

    #[test]
    fn optimized_apis_match_dense_reference(
        inputs in prop::collection::vec(field_element(), 1..MAX_X5_LEN),
        domain_tag in field_element(),
    ) {
        let expected = dense_reference(&inputs, domain_tag);
        let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), domain_tag)
            .expect("supported width");
        prop_assert_eq!(hasher.hash(&inputs).expect("field hash"), expected);

        let be: Vec<Vec<u8>> = inputs.iter()
            .map(|input| input.into_bigint().to_bytes_be()).collect();
        let le: Vec<Vec<u8>> = inputs.iter()
            .map(|input| input.into_bigint().to_bytes_le()).collect();
        let be_refs: Vec<&[u8]> = be.iter().map(Vec::as_slice).collect();
        let le_refs: Vec<&[u8]> = le.iter().map(Vec::as_slice).collect();

        // Reuse the same hasher across the field and both byte APIs.
        let expected_be: [u8; 32] = expected.into_bigint().to_bytes_be()
            .try_into().expect("BN254 output length");
        let expected_le: [u8; 32] = expected.into_bigint().to_bytes_le()
            .try_into().expect("BN254 output length");
        prop_assert_eq!(hasher.hash_bytes_be(&be_refs).expect("big-endian hash"), expected_be);
        prop_assert_eq!(hasher.hash_bytes_le(&le_refs).expect("little-endian hash"), expected_le);
    }
}
