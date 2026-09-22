//! **light-poseidon** is a [Poseidon](https://eprint.iacr.org/2019/458) hash
//! implementation in Rust created for [Light Protocol](https://www.lightprotocol.com/).
//!
//! # Parameters
//!
//! The library provides pre-generated parameters over the BN254 curve, however
//! it can work with any parameters provided as long as developers take care
//! of generating the round constants.
//!
//! Parameters provided by the library are:
//!
//! * *x^5* S-boxes
//! * width - *2 ≤ t ≤ 13*
//! * inputs - *1 ≤ n ≤ 12*
//! * 8 full rounds and partial rounds depending on *t*: *[56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65]*
//!
//! The parameters can be generated with:
//!
//! ```bash
//! cargo xtask generate-poseidon-parameters
//! ````
//!
//! # Output type
//!
//! [`Poseidon`](crate::Poseidon) type implements two traits which serve the purpose
//! of returning the calculated hash in different representations:
//!
//! * [`PoseidonBytesHasher`](crate::PoseidonBytesHasher) with the
//!   `hash_bytes_be` and `hash_bytes_le` methods which returns a byte array.
//! * [`PoseidonHasher`](crate::PoseidonHasher) with the `hash` method which returns
//!   [`ark_ff::PrimeField`](ark_ff::PrimeField). Might be useful if you want
//!   to immediately process the result with an another library which works with
//!   [`ark_ff::PrimeField`](ark_ff::PrimeField) types.
//!
//! # Examples
//!
//! Example with two simple big-endian byte inputs (converted to field elements)
//! and BN254-based parameters provided by the library, with
//! [`PoseidonBytesHasher`](crate::PoseidonHasher) trait and a byte array
//! result:
//!
//! ```rust
//! use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5};
//! use ark_bn254::Fr;
//! use ark_ff::{BigInteger, PrimeField};
//!
//! let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
//!
//! let hash = poseidon.hash_bytes_be(&[&[1u8; 32], &[2u8; 32]]).unwrap();
//!
//! println!("{:?}", hash);
//! // Should print:
//! // [
//! //     13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
//! //     254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
//! // ]
//! ```
//!
//! With [`PoseidonHasher`](crate::PoseidonHasher) trait and
//! [`ark_ff::PrimeField`](ark_ff::PrimeField) result:
//!
//! ```rust
//! use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};
//! use ark_bn254::Fr;
//! use ark_ff::{BigInteger, PrimeField};
//!
//! let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
//!
//! let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
//! let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);
//!
//! let hash = poseidon.hash(&[input1, input2]).unwrap();
//!
//! // Do something with `hash`.
//! ```
//!
//! # Implementation
//!
//! The implementation is compatible with the
//! [original SageMath implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master/),
//! but it was also inspired by the following ones:
//!
//! * [circomlibjs](https://github.com/iden3/circomlibjs)
//! * [zero-knowledge-gadgets](https://github.com/webb-tools/zero-knowledge-gadgets)
//!
//! # Performance
//!
//! This repository contains a benchmark measuring the performance of this
//! Poseidon implementation for given 1 - 12 random 32 bytes inputs.
//!
//! To run them, simply use:
//!
//! ```bash
//! cargo bench
//! ```
//!
//! This is the result from a host with the following hardware:
//!
//! * AMD Ryzen™ 9 7945HX with Radeon™ Graphics × 32
//!
//! ```norust
//! poseidon_bn254_x5_1     time:   [12.710 µs 12.735 µs 12.754 µs]
//!
//! poseidon_bn254_x5_2     time:   [18.948 µs 18.963 µs 18.990 µs]
//!
//! poseidon_bn254_x5_3     time:   [26.607 µs 26.611 µs 26.615 µs]
//!
//! poseidon_bn254_x5_4     time:   [38.507 µs 38.513 µs 38.519 µs]
//!
//! poseidon_bn254_x5_5     time:   [51.024 µs 51.031 µs 51.039 µs]
//!
//! poseidon_bn254_x5_6     time:   [68.368 µs 68.375 µs 68.385 µs]
//!
//! poseidon_bn254_x5_7     time:   [86.819 µs 86.886 µs 86.968 µs]
//!
//! poseidon_bn254_x5_8     time:   [105.38 µs 105.49 µs 105.61 µs]
//!
//! poseidon_bn254_x5_9     time:   [121.99 µs 122.00 µs 122.01 µs]
//!
//! poseidon_bn254_x5_10    time:   [157.00 µs 157.02 µs 157.05 µs]
//!
//! poseidon_bn254_x5_11    time:   [170.01 µs 170.04 µs 170.07 µs]
//!
//! poseidon_bn254_x5_12    time:   [210.78 µs 210.81 µs 210.84 µs]
//! ```
//!
//! # Security
//!
//! This library has been audited by [Veridise](https://veridise.com/). You can
//! read the audit report [here](https://github.com/Lightprotocol/light-poseidon/blob/main/assets/audit.pdf).
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use thiserror::Error;

pub mod parameters;

pub const HASH_LEN: usize = 32;
pub const MAX_X5_LEN: usize = 13;

#[derive(Error, Debug, PartialEq)]
pub enum PoseidonError {
    #[error("Invalid number of inputs: {inputs}. Maximum allowed is {max_limit} ({width} - 1).")]
    InvalidNumberOfInputs {
        inputs: usize,
        max_limit: usize,
        width: usize,
    },
    #[error("Input is an empty slice.")]
    EmptyInput,
    #[error("Invalid length of the input: {len}. The length matching the modulus of the prime field is: {modulus_bytes_len}.")]
    InvalidInputLength {
        len: usize,
        modulus_bytes_len: usize,
    },
    #[error("Failed to convert bytes {bytes:?} into a prime field element")]
    BytesToPrimeFieldElement { bytes: Vec<u8> },
    #[error("Input is larger than the modulus of the prime field.")]
    InputLargerThanModulus,
    #[error("Failed to convert a vector of bytes into an array.")]
    VecToArray,
    #[error("Failed to convert the number of inputs from u64 to u8.")]
    U64Tou8,
    #[error("Failed to convert bytes to BigInt")]
    BytesToBigInt,
    #[error("Invalid width: {width}. Choose a width between 2 and 16 for 1 to 15 inputs.")]
    InvalidWidthCircom { width: usize, max_limit: usize },
    #[error(
        "Inconsistent parameter dimensions: expected {expected_ark} round constants and \
         {expected_mds} MDS entries, got {actual_ark} and {actual_mds}."
    )]
    InvalidParameterDimensions {
        expected_ark: usize,
        actual_ark: usize,
        expected_mds: usize,
        actual_mds: usize,
    },
    #[error("Invalid width: {width}. Must be between 2 and {max_limit}.")]
    InvalidWidth { width: usize, max_limit: usize },
}

/// Parameters for the Poseidon hash algorithm.
///
/// Both `ark` and `mds` borrow `'static` data, so constructing a hasher performs
/// no allocation and no field conversion. The bundled parameter sets in
/// [`parameters`] are `static` arrays built at compile time.
///
/// Callers supplying their own parameters need `'static` data as well; a set
/// computed at run time can be promoted with [`Box::leak`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoseidonParameters<F: PrimeField> {
    /// Round constants, in round-major order: `width` constants per round, for
    /// `full_rounds + partial_rounds` rounds.
    pub ark: &'static [F],
    /// MDS matrix, flattened row-major: `width * width` elements, where the
    /// entry at row `i` column `j` lives at index `i * width + j`.
    pub mds: &'static [F],
    /// Number of full rounds (where S-box is applied to all elements of the
    /// state).
    pub full_rounds: usize,
    /// Number of partial rounds (where S-box is applied only to the first
    /// element of the state).
    pub partial_rounds: usize,
    /// Number of prime fields in the state.
    pub width: usize,
    /// Exponential used in S-box to power elements of the state.
    pub alpha: u64,
}

impl<F: PrimeField> PoseidonParameters<F> {
    /// Builds a parameter set without checking that the dimensions agree.
    ///
    /// This is what the bundled Circom parameter sets use: their dimensions are
    /// fixed when [`parameters`] is generated, so re-checking them on every
    /// hasher construction would be wasted work on the syscall hot path.
    ///
    /// # Correctness
    ///
    /// The caller guarantees that `mds` holds exactly `width * width` elements
    /// and `ark` exactly `width * (full_rounds + partial_rounds)`. Passing
    /// shorter slices does not invoke undefined behaviour -- hashing returns
    /// [`PoseidonError::InvalidParameterDimensions`] rather than computing with
    /// missing terms -- but the error surfaces at hash time instead of here.
    /// Prefer [`PoseidonParameters::new`] for parameters from any other source.
    pub fn new_unchecked(
        ark: &'static [F],
        mds: &'static [F],
        full_rounds: usize,
        partial_rounds: usize,
        width: usize,
        alpha: u64,
    ) -> Self {
        Self {
            ark,
            mds,
            full_rounds,
            partial_rounds,
            width,
            alpha,
        }
    }

    /// Builds a parameter set, validating that the dimensions are consistent.
    ///
    /// Returns [`PoseidonError::InvalidParameterDimensions`] unless `mds` holds
    /// exactly `width * width` elements and `ark` exactly
    /// `width * (full_rounds + partial_rounds)`. Without this check a truncated
    /// matrix would silently hash with missing terms rather than being rejected.
    pub fn new(
        ark: &'static [F],
        mds: &'static [F],
        full_rounds: usize,
        partial_rounds: usize,
        width: usize,
        alpha: u64,
    ) -> Result<Self, PoseidonError> {
        let expected_mds = width
            .checked_mul(width)
            .ok_or(PoseidonError::InvalidParameterDimensions {
                expected_ark: 0,
                actual_ark: ark.len(),
                expected_mds: 0,
                actual_mds: mds.len(),
            })?;
        let expected_ark = full_rounds
            .checked_add(partial_rounds)
            .and_then(|rounds| rounds.checked_mul(width))
            .ok_or(PoseidonError::InvalidParameterDimensions {
                expected_ark: 0,
                actual_ark: ark.len(),
                expected_mds,
                actual_mds: mds.len(),
            })?;

        if mds.len() != expected_mds || ark.len() != expected_ark {
            return Err(PoseidonError::InvalidParameterDimensions {
                expected_ark,
                actual_ark: ark.len(),
                expected_mds,
                actual_mds: mds.len(),
            });
        }

        Ok(Self {
            ark,
            mds,
            full_rounds,
            partial_rounds,
            width,
            alpha,
        })
    }
}

pub trait PoseidonHasher<F: PrimeField> {
    /// Calculates a Poseidon hash for the given input of prime fields and
    /// returns the result as a prime field.
    ///
    /// # Examples
    ///
    /// Example with two simple big-endian byte inputs (converted to prime
    /// fields) and BN254-based parameters provided by the library.
    ///
    /// ```rust
    /// use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};
    /// use ark_bn254::Fr;
    /// use ark_ff::{BigInteger, PrimeField};
    ///
    /// let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    ///
    /// let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
    /// let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);
    ///
    /// let hash = poseidon.hash(&[input1, input2]).unwrap();
    ///
    /// // Do something with `hash`.
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError>;
}

pub trait PoseidonBytesHasher {
    /// Calculates a Poseidon hash for the given input of big-endian byte slices
    /// and returns the result as a byte array.
    ///
    /// # Examples
    ///
    /// Example with two simple big-endian byte inputs and BN254-based
    /// parameters provided by the library.
    ///
    /// ```rust
    /// use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5};
    /// use ark_bn254::Fr;
    /// use ark_ff::{BigInteger, PrimeField};
    ///
    /// let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    ///
    /// let hash = poseidon.hash_bytes_be(&[&[1u8; 32], &[2u8; 32]]).unwrap();
    ///
    /// println!("{:?}", hash);
    /// // Should print:
    /// // [
    /// //     13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
    /// //     254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
    /// // ]
    /// ```
    ///
    /// # Safety
    ///   
    /// Unlike the
    /// [`PrimeField::from_be_bytes_mod_order`](ark_ff::PrimeField::from_be_bytes_mod_order)
    /// and [`Field::from_random_bytes`](ark_ff::Field::from_random_bytes)
    /// methods, this function ensures that the input byte slice's length exactly matches
    /// the modulus size of the prime field. If the size doesn't match, an error is returned.
    ///
    /// This strict check is designed to prevent unexpected behaviors and collisions
    /// that might occur when using `from_be_bytes_mod_order` or `from_random_bytes`,
    /// which simply take a subslice of the input if it's too large, potentially
    /// leading to collisions.
    fn hash_bytes_be(&mut self, inputs: &[&[u8]]) -> Result<[u8; HASH_LEN], PoseidonError>;
    /// Calculates a Poseidon hash for the given input of little-endian byte
    /// slices and returns the result as a byte array.
    ///
    /// # Examples
    ///
    /// Example with two simple little-endian byte inputs and BN254-based
    /// parameters provided by the library.
    ///
    /// ```rust
    /// use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5};
    /// use ark_bn254::Fr;
    /// use ark_ff::{BigInteger, PrimeField};
    ///
    /// let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    ///
    /// let hash = poseidon.hash_bytes_le(&[&[1u8; 32], &[2u8; 32]]).unwrap();
    ///
    /// println!("{:?}", hash);
    /// // Should print:
    /// // [
    /// //     144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99, 242,
    /// //     85, 3, 94, 235, 125, 28, 140, 138, 143, 147, 225, 84, 13
    /// // ]
    /// ```
    ///
    /// # Safety
    ///
    /// Unlike the
    /// [`PrimeField::from_le_bytes_mod_order`](ark_ff::PrimeField::from_le_bytes_mod_order)
    /// and [`Field::from_random_bytes`](ark_ff::Field::from_random_bytes)
    /// methods, this function ensures that the input byte slice's length exactly matches
    /// the modulus size of the prime field. If the size doesn't match, an error is returned.
    ///
    /// This strict check is designed to prevent unexpected behaviors and collisions
    /// that might occur when using `from_be_bytes_mod_order` or `from_random_bytes`,
    /// which simply take a subslice of the input if it's too large, potentially
    /// leading to collisions.
    fn hash_bytes_le(&mut self, inputs: &[&[u8]]) -> Result<[u8; HASH_LEN], PoseidonError>;
}

/// A stateful sponge performing Poseidon hash computation.
///
/// The permutation state lives on the stack for the duration of a hash, so a
/// hasher holds only its parameters and domain tag, and hashing performs no
/// heap allocation.
#[derive(Clone, Copy, Debug)]
pub struct Poseidon<F: PrimeField> {
    params: PoseidonParameters<F>,
    domain_tag: F,
}

impl<F: PrimeField> Poseidon<F> {
    /// Returns a new Poseidon hasher based on the given parameters, with a zero
    /// domain tag.
    ///
    /// Returns [`PoseidonError::InvalidWidth`] for a width outside
    /// `2..=MAX_X5_LEN`. That bound is what lets the permutation keep its state
    /// in a fixed-size stack array; rejecting here means no later operation can
    /// overrun it.
    pub fn new(params: PoseidonParameters<F>) -> Result<Self, PoseidonError> {
        Self::with_domain_tag(params, F::zero())
    }

    fn with_domain_tag(
        params: PoseidonParameters<F>,
        domain_tag: F,
    ) -> Result<Self, PoseidonError> {
        if params.width < 2 || params.width > MAX_X5_LEN {
            return Err(PoseidonError::InvalidWidth {
                width: params.width,
                max_limit: MAX_X5_LEN,
            });
        }
        Ok(Self { domain_tag, params })
    }

    /// Raises `a` to the S-box exponent. `Field::pow` is a generic binary
    /// exponentiation (3 squarings + 2 multiplications for x^5), so the
    /// common exponents get explicit, shorter squaring/multiplication chains.
    #[inline(always)]
    fn sbox(a: F, alpha: u64) -> F {
        match alpha {
            5 => {
                let x2 = a.square();
                let x4 = x2.square();
                x4 * a
            }
            4 => a.square().square(),
            _ => a.pow([alpha]),
        }
    }

    /// Seeds `state` with the domain tag, leaving `state[1..]` for the caller
    /// to fill with inputs.
    ///
    /// Returns the live slice, whose length is exactly `width`.
    #[inline(always)]
    fn init_state<'a>(&self, state: &'a mut [F; MAX_X5_LEN]) -> Result<&'a mut [F], PoseidonError> {
        let width = self.params.width;
        let live = state
            .get_mut(..width)
            .ok_or(PoseidonError::InvalidWidth {
                width,
                max_limit: MAX_X5_LEN,
            })?;
        if let Some(first) = live.first_mut() {
            *first = self.domain_tag;
        }
        Ok(live)
    }

    /// Checks that the caller supplied exactly `width - 1` inputs.
    #[inline(always)]
    fn check_input_count(&self, inputs: usize) -> Result<(), PoseidonError> {
        // `width >= 2` is guaranteed by the constructor, so this cannot wrap.
        let max_limit = self.params.width - 1;
        if inputs != max_limit {
            return Err(PoseidonError::InvalidNumberOfInputs {
                inputs,
                max_limit,
                width: self.params.width,
            });
        }
        Ok(())
    }

    /// Applies the full Poseidon permutation to `state` and returns lane zero.
    ///
    /// `state` must hold exactly `width` elements. All scratch space is on the
    /// stack, so this allocates nothing regardless of width.
    fn permute(&self, state: &mut [F]) -> Result<F, PoseidonError> {
        let PoseidonParameters {
            ark,
            mds,
            full_rounds,
            partial_rounds,
            width,
            alpha,
        } = self.params;

        // The constructor and `PoseidonParameters` validation make these
        // unreachable; they exist so no path can panic on malformed input.
        let dimension_error = || PoseidonError::InvalidParameterDimensions {
            expected_ark: width.saturating_mul(full_rounds.saturating_add(partial_rounds)),
            actual_ark: ark.len(),
            expected_mds: width.saturating_mul(width),
            actual_mds: mds.len(),
        };

        if state.len() != width {
            return Err(dimension_error());
        }

        let mut scratch = [F::zero(); MAX_X5_LEN];
        let mut round_constants = ark.chunks_exact(width);
        let half_rounds = full_rounds / 2;
        let all_rounds = full_rounds.saturating_add(partial_rounds);

        for round in 0..all_rounds {
            let constants = round_constants.next().ok_or_else(dimension_error)?;
            for (lane, constant) in state.iter_mut().zip(constants) {
                *lane += *constant;
            }

            // Full rounds bracket the partial rounds on both sides.
            if round < half_rounds || round >= half_rounds + partial_rounds {
                for lane in state.iter_mut() {
                    *lane = Self::sbox(*lane, alpha);
                }
            } else if let Some(first) = state.first_mut() {
                *first = Self::sbox(*first, alpha);
            }

            let next = scratch.get_mut(..width).ok_or_else(dimension_error)?;
            for (i, out) in next.iter_mut().enumerate() {
                let start = i.saturating_mul(width);
                let row = mds
                    .get(start..start.saturating_add(width))
                    .ok_or_else(dimension_error)?;
                *out = state
                    .iter()
                    .zip(row)
                    .fold(F::zero(), |acc, (lane, m)| acc + *lane * *m);
            }
            state.copy_from_slice(next);
        }

        state.first().copied().ok_or_else(dimension_error)
    }
}

impl<F: PrimeField> PoseidonHasher<F> for Poseidon<F> {
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError> {
        self.check_input_count(inputs.len())?;

        let mut state = [F::zero(); MAX_X5_LEN];
        let live = self.init_state(&mut state)?;
        for (lane, input) in live.iter_mut().skip(1).zip(inputs) {
            *lane = *input;
        }

        self.permute(live)
    }
}

/// Writes a canonical integer into a fixed-size byte array, most significant
/// limb first, without allocating.
fn bigint_to_hash_bytes_be<F: PrimeField>(
    value: F::BigInt,
) -> Result<[u8; HASH_LEN], PoseidonError> {
    let limbs: &[u64] = value.as_ref();
    if limbs.len().saturating_mul(8) != HASH_LEN {
        return Err(PoseidonError::VecToArray);
    }
    let mut out = [0u8; HASH_LEN];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs.iter().rev()) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    Ok(out)
}

/// Writes a canonical integer into a fixed-size byte array, least significant
/// limb first, without allocating.
fn bigint_to_hash_bytes_le<F: PrimeField>(
    value: F::BigInt,
) -> Result<[u8; HASH_LEN], PoseidonError> {
    let limbs: &[u64] = value.as_ref();
    if limbs.len().saturating_mul(8) != HASH_LEN {
        return Err(PoseidonError::VecToArray);
    }
    let mut out = [0u8; HASH_LEN];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs.iter()) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    Ok(out)
}

macro_rules! impl_hash_bytes {
    ($fn_name:ident, $bytes_to_prime_field_element_fn:ident, $to_bytes_fn:ident) => {
        fn $fn_name(&mut self, inputs: &[&[u8]]) -> Result<[u8; HASH_LEN], PoseidonError> {
            // Error precedence is load-bearing and matches the historical
            // behaviour: every length is validated first, then every value is
            // converted, and only then is the input count checked.
            for input in inputs {
                validate_bytes_length::<F>(input)?;
            }

            // Inputs are converted straight into the permutation state, so
            // there is no intermediate buffer to size or overflow. Excess
            // inputs are still converted, so a conversion error in one of them
            // surfaces ahead of the count error, as it did before.
            let mut state = [F::zero(); MAX_X5_LEN];
            let live = self.init_state(&mut state)?;
            {
                let mut lanes = live.iter_mut().skip(1);
                for input in inputs {
                    let value = $bytes_to_prime_field_element_fn(input)?;
                    if let Some(lane) = lanes.next() {
                        *lane = value;
                    }
                }
            }
            self.check_input_count(inputs.len())?;

            let hash = self.permute(live)?;
            $to_bytes_fn::<F>(hash.into_bigint())
        }
    };
}

impl<F: PrimeField> PoseidonBytesHasher for Poseidon<F> {
    impl_hash_bytes!(
        hash_bytes_le,
        bytes_to_prime_field_element_le,
        bigint_to_hash_bytes_le
    );
    impl_hash_bytes!(
        hash_bytes_be,
        bytes_to_prime_field_element_be,
        bigint_to_hash_bytes_be
    );
}

/// Checks whether a slice of bytes is not empty or its length does not exceed
/// the modulus size od the prime field. If it does, an error is returned.
///
/// # Safety
///
/// [`PrimeField::from_be_bytes_mod_order`](ark_ff::PrimeField::from_be_bytes_mod_order)
/// just takes a subslice of the input if it's too large, potentially leading
/// to collisions. The purpose of this function is to prevent them by returning
/// and error. It should be always used before converting byte slices to
/// prime field elements.
pub fn validate_bytes_length<F>(input: &[u8]) -> Result<&[u8], PoseidonError>
where
    F: PrimeField,
{
    let modulus_bytes_len = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;
    if input.is_empty() {
        return Err(PoseidonError::EmptyInput);
    }
    if input.len() != modulus_bytes_len {
        return Err(PoseidonError::InvalidInputLength {
            len: input.len(),
            modulus_bytes_len,
        });
    }
    Ok(input)
}

macro_rules! impl_bytes_to_prime_field_element {
    ($name:ident, $endianess:expr, $is_be:expr) => {
        #[doc = "Converts a slice of "]
        #[doc = $endianess]
        #[doc = "-endian bytes into a prime field element, \
                 represented by the [`ark_ff::PrimeField`](ark_ff::PrimeField) trait."]
        ///
        /// The value is assembled directly into the field's limb array, which is
        /// a fixed-size stack type, so no heap allocation takes place.
        pub fn $name<F>(input: &[u8]) -> Result<F, PoseidonError>
        where
            F: PrimeField,
        {
            // Zero padding at the most significant end is accepted, matching the
            // previous `BigUint`-based behaviour.
            let trimmed = if $is_be {
                let start = input.iter().position(|byte| *byte != 0).unwrap_or(input.len());
                input.get(start..).ok_or(PoseidonError::BytesToBigInt)?
            } else {
                let end = input
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map(|i| i + 1)
                    .unwrap_or(0);
                input.get(..end).ok_or(PoseidonError::BytesToBigInt)?
            };

            let mut repr = F::BigInt::default();
            {
                let limbs: &mut [u64] = repr.as_mut();
                let mut remaining = trimmed;
                for limb in limbs.iter_mut() {
                    if remaining.is_empty() {
                        break;
                    }
                    let take = remaining.len().min(8);
                    let mut bytes = [0u8; 8];
                    if $is_be {
                        // The least significant group sits at the end.
                        let (head, tail) = remaining.split_at(remaining.len() - take);
                        bytes
                            .get_mut(8 - take..)
                            .ok_or(PoseidonError::BytesToBigInt)?
                            .copy_from_slice(tail);
                        *limb = u64::from_be_bytes(bytes);
                        remaining = head;
                    } else {
                        let (head, tail) = remaining.split_at(take);
                        bytes
                            .get_mut(..take)
                            .ok_or(PoseidonError::BytesToBigInt)?
                            .copy_from_slice(head);
                        *limb = u64::from_le_bytes(bytes);
                        remaining = tail;
                    }
                }
                // Anything left over does not fit in the field's limb array.
                if !remaining.is_empty() {
                    return Err(PoseidonError::BytesToBigInt);
                }
            }

            // `F::from_bigint` is documented to reject values at or above the
            // modulus, but this crate has been bitten by relying on that before
            // (commit 9746e79, "this time for real"), so the check stays explicit.
            if repr >= F::MODULUS {
                return Err(PoseidonError::InputLargerThanModulus);
            }
            F::from_bigint(repr).ok_or(PoseidonError::InputLargerThanModulus)
        }
    };
}

impl_bytes_to_prime_field_element!(bytes_to_prime_field_element_le, "little", false);
impl_bytes_to_prime_field_element!(bytes_to_prime_field_element_be, "big", true);

impl<F: PrimeField> Poseidon<F> {
    pub fn new_circom(nr_inputs: usize) -> Result<Poseidon<Fr>, PoseidonError> {
        Self::with_domain_tag_circom(nr_inputs, Fr::zero())
    }

    pub fn with_domain_tag_circom(
        nr_inputs: usize,
        domain_tag: Fr,
    ) -> Result<Poseidon<Fr>, PoseidonError> {
        let width = nr_inputs + 1;
        if width > MAX_X5_LEN {
            return Err(PoseidonError::InvalidWidthCircom {
                width,
                max_limit: MAX_X5_LEN,
            });
        }

        let params = crate::parameters::bn254_x5::get_poseidon_parameters(
            (width).try_into().map_err(|_| PoseidonError::U64Tou8)?,
        )?;
        Poseidon::<Fr>::with_domain_tag(params, domain_tag)
    }
}
