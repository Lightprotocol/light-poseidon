//! Width and input-count boundaries.
//!
//! The permutation keeps its state in a fixed-size stack array, so every path
//! that could overrun it must return an error rather than panic. These tests
//! exercise the counts and widths just past each limit.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use light_poseidon::{
    parameters::bn254_x5::get_poseidon_parameters, Poseidon, PoseidonBytesHasher, PoseidonError,
    PoseidonHasher, PoseidonParameters, MAX_X5_LEN,
};

/// Builds a structurally valid parameter set of the requested width.
///
/// The values are an identity MDS and zero round constants: enough to exercise
/// dimensions and capacity, and explicitly not a secure parameter set.
fn structural_params(width: usize, full: usize, partial: usize) -> PoseidonParameters<Fr> {
    let ark: &'static [Fr] =
        Box::leak(vec![Fr::zero(); width * (full + partial)].into_boxed_slice());
    let mut mds = vec![Fr::zero(); width * width];
    for (i, row) in mds.chunks_exact_mut(width).enumerate() {
        if let Some(cell) = row.get_mut(i) {
            *cell = Fr::from(1u64);
        }
    }
    let mds: &'static [Fr] = Box::leak(mds.into_boxed_slice());

    PoseidonParameters::new_unchecked(ark, mds, full, partial, width, 5)
}

#[test]
fn new_circom_accepts_every_supported_width() {
    for nr_inputs in 1..=(MAX_X5_LEN - 1) {
        let hasher = Poseidon::<Fr>::new_circom(nr_inputs);
        assert!(hasher.is_ok(), "new_circom({nr_inputs}) should succeed");
    }
}

#[test]
fn new_circom_rejects_widths_past_the_limit() {
    for nr_inputs in [MAX_X5_LEN, MAX_X5_LEN + 1, 32, 1000] {
        let result = Poseidon::<Fr>::new_circom(nr_inputs);
        assert!(
            matches!(result, Err(PoseidonError::InvalidWidthCircom { .. })),
            "new_circom({nr_inputs}) should be rejected, got {result:?}"
        );
    }
}

#[test]
fn generic_constructor_rejects_out_of_range_widths() {
    // Below the minimum.
    for width in [0usize, 1] {
        let params = structural_params(width.max(1), 2, 1);
        let params = PoseidonParameters::new_unchecked(
            params.ark,
            params.mds,
            params.full_rounds,
            params.partial_rounds,
            width,
            params.alpha,
        );
        assert!(
            matches!(
                Poseidon::new(params),
                Err(PoseidonError::InvalidWidth { .. })
            ),
            "width {width} should be rejected"
        );
    }

    // At the maximum: accepted.
    let params = structural_params(MAX_X5_LEN, 2, 1);
    assert!(Poseidon::new(params).is_ok(), "width 13 should be accepted");

    // Past the maximum: rejected, not a panic on the first push.
    for width in [MAX_X5_LEN + 1, MAX_X5_LEN + 2, 32] {
        let params = structural_params(width, 2, 1);
        let result = Poseidon::new(params);
        assert!(
            matches!(result, Err(PoseidonError::InvalidWidth { .. })),
            "width {width} should be rejected, got {result:?}"
        );
    }
}

#[test]
fn parameter_validation_rejects_inconsistent_dimensions() {
    let width = 3usize;
    let (full, partial) = (2usize, 1usize);
    let good = structural_params(width, full, partial);

    // A correctly sized set is accepted.
    assert!(PoseidonParameters::new(good.ark, good.mds, full, partial, width, 5).is_ok());

    // A truncated MDS is rejected rather than silently hashing with missing
    // terms.
    let short_mds: &'static [Fr] =
        Box::leak(vec![Fr::zero(); width * width - 1].into_boxed_slice());
    assert!(matches!(
        PoseidonParameters::new(good.ark, short_mds, full, partial, width, 5),
        Err(PoseidonError::InvalidParameterDimensions { .. })
    ));

    // An empty MDS likewise.
    assert!(matches!(
        PoseidonParameters::new(good.ark, &[], full, partial, width, 5),
        Err(PoseidonError::InvalidParameterDimensions { .. })
    ));

    // Too few round constants.
    let short_ark: &'static [Fr] =
        Box::leak(vec![Fr::zero(); width * (full + partial) - 1].into_boxed_slice());
    assert!(matches!(
        PoseidonParameters::new(short_ark, good.mds, full, partial, width, 5),
        Err(PoseidonError::InvalidParameterDimensions { .. })
    ));
}

#[test]
fn hashing_with_a_truncated_mds_errors_instead_of_panicking() {
    // Construction with new_unchecked skips validation, so the error has to
    // surface at hash time rather than as an out-of-bounds panic.
    let width = 3usize;
    let ark: &'static [Fr] = Box::leak(vec![Fr::zero(); width * 3].into_boxed_slice());
    let mds: &'static [Fr] = Box::leak(vec![Fr::zero(); 1].into_boxed_slice());
    let params = PoseidonParameters::new_unchecked(ark, mds, 2, 1, width, 5);

    let mut hasher = Poseidon::new(params).expect("width is in range");
    let result = hasher.hash(&[Fr::zero(), Fr::zero()]);
    assert!(
        matches!(
            result,
            Err(PoseidonError::InvalidParameterDimensions { .. })
        ),
        "expected a dimension error, got {result:?}"
    );
}

#[test]
fn field_api_rejects_every_wrong_input_count() {
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("hasher");
    // The hasher takes exactly 2 inputs (width 3).
    for count in [0usize, 1, 3, 4, 12, 13, 14, 32, 200] {
        let inputs = vec![Fr::zero(); count];
        let result = hasher.hash(&inputs);
        assert!(
            matches!(result, Err(PoseidonError::InvalidNumberOfInputs { .. })),
            "count {count} should be rejected, got {result:?}"
        );
    }
}

#[test]
fn byte_api_rejects_every_wrong_input_count() {
    let zero = [0u8; 32];
    for count in [0usize, 1, 3, 4, 12, 13, 14, 32, 200] {
        let owned = vec![zero; count];
        let refs: Vec<&[u8]> = owned.iter().map(|b| b.as_slice()).collect();

        let mut be = Poseidon::<Fr>::new_circom(2).expect("hasher");
        let result = be.hash_bytes_be(&refs);
        assert!(
            matches!(result, Err(PoseidonError::InvalidNumberOfInputs { .. })),
            "be count {count} should be rejected, got {result:?}"
        );

        let mut le = Poseidon::<Fr>::new_circom(2).expect("hasher");
        let result = le.hash_bytes_le(&refs);
        assert!(
            matches!(result, Err(PoseidonError::InvalidNumberOfInputs { .. })),
            "le count {count} should be rejected, got {result:?}"
        );
    }
}

#[test]
fn a_rejected_call_does_not_corrupt_the_next_one() {
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("hasher");
    let inputs = [Fr::from(1u64), Fr::from(2u64)];

    let expected = hasher.hash(&inputs).expect("baseline");

    // Wrong counts, an oversized byte input, and an empty one.
    assert!(hasher.hash(&[Fr::zero(); 13]).is_err());
    assert!(hasher.hash(&[]).is_err());
    let modulus = Fr::MODULUS.to_bytes_be();
    assert!(hasher.hash_bytes_be(&[&modulus, &modulus]).is_err());
    assert!(hasher.hash_bytes_be(&[&[], &[]]).is_err());

    let after = hasher.hash(&inputs).expect("after rejections");
    assert_eq!(expected, after, "state leaked between calls");
}

#[test]
fn every_supported_width_hashes_without_panicking() {
    for nr_inputs in 1..=(MAX_X5_LEN - 1) {
        let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).expect("hasher");
        let inputs = vec![Fr::from(7u64); nr_inputs];
        assert!(hasher.hash(&inputs).is_ok(), "width {nr_inputs} + 1 failed");
    }
}

#[test]
fn generated_parameters_have_consistent_dimensions() {
    for t in 2u8..=13 {
        let params = get_poseidon_parameters(t).expect("generated params");
        let width = usize::from(t);
        assert_eq!(params.width, width);
        assert_eq!(
            params.mds.len(),
            width * width,
            "mds dimensions for width {width}"
        );
        assert_eq!(
            params.ark.len(),
            width * (params.full_rounds + params.partial_rounds),
            "ark dimensions for width {width}"
        );
        // Revalidating through the checked constructor must agree.
        assert!(PoseidonParameters::new(
            params.ark,
            params.mds,
            params.full_rounds,
            params.partial_rounds,
            params.width,
            params.alpha,
        )
        .is_ok());
    }

    for t in [0u8, 1, 14, 255] {
        assert!(matches!(
            get_poseidon_parameters(t),
            Err(PoseidonError::InvalidWidthCircom { .. })
        ));
    }
}
