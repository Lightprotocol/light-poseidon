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
//! * x^5 S-boxes
//! * t = 2 - 17 (for 1 to 15 inputs)
//! * 8 full rounds and partial rounds depending on t [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64]
//! The parameters can be generated with:
//! ```$ cargo xtask generate-poseidon-parameters``
//! # Output type
//!
//! [`Poseidon`](crate::Poseidon) type implements two traits which serve the purpose
//! of returning the calculated hash in different representations:
//!
//! * [`PoseidonBytesHasher`](crate::PoseidonBytesHasher) with the
//!   [`hash_bytes`](crate::PoseidonBytesHasher::hash_bytes) method which
//!   returns a byte array.
//! * [`PoseidonHasher`](crate::PoseidonHasher) with the
//!   [`hash`](crate::PoseidonHasher::hash) method which returns
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
//! let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();
//!
//! println!("{:?}", hash);
//! // Should print:
//! // [
//! //     13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
//! //     254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
//! // ]
//! ```
//!
//! With [`PoseidonHasher`][crate::PoseidonHasher] trait and
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
//! ## Performance
//!
//! This repository contains a benchmark measuring the performance of this
//! Poseidon implementation for given 1 - 15 random 32 bytes inputs.
//!
//! To run them, simply use:
//!
//! ```bash
//! cargo bench
//! ```
//!
//! This is the result from a host with the following hardware:
//!
//! * 12th Gen Intel® Core™ i7-1260P × 16
//!
//! ```norust
//! poseidon_bn254_x5_1     time:   [14.656 µs 14.740 µs 14.848 µs]
//! Found 8 outliers among 100 measurements (8.00%)
//!   4 (4.00%) high mild
//!   4 (4.00%) high severe
//!
//! poseidon_bn254_x5_2     time:   [23.013 µs 24.307 µs 25.752 µs]
//! Found 5 outliers among 100 measurements (5.00%)
//!   2 (2.00%) high mild
//!   3 (3.00%) high severe
//!
//! poseidon_bn254_x5_3     time:   [29.276 µs 29.325 µs 29.377 µs]
//! Found 4 outliers among 100 measurements (4.00%)
//!   4 (4.00%) high mild
//!
//! poseidon_bn254_x5_4     time:   [41.699 µs 41.856 µs 42.039 µs]
//! Found 7 outliers among 100 measurements (7.00%)
//!   6 (6.00%) high mild
//!   1 (1.00%) high severe
//!
//! poseidon_bn254_x5_5     time:   [55.947 µs 57.883 µs 60.190 µs]
//! Found 14 outliers among 100 measurements (14.00%)
//!   1 (1.00%) high mild
//!   13 (13.00%) high severe
//!
//! poseidon_bn254_x5_6     time:   [70.992 µs 71.327 µs 71.737 µs]
//! Found 10 outliers among 100 measurements (10.00%)
//!   4 (4.00%) high mild
//!   6 (6.00%) high severe
//!
//! poseidon_bn254_x5_7     time:   [87.824 µs 88.174 µs 88.587 µs]
//! Found 12 outliers among 100 measurements (12.00%)
//!   5 (5.00%) high mild
//!   7 (7.00%) high severe
//!
//! poseidon_bn254_x5_8     time:   [110.07 µs 111.22 µs 112.77 µs]
//!
//! poseidon_bn254_x5_9     time:   [131.48 µs 131.82 µs 132.24 µs]
//! Found 9 outliers among 100 measurements (9.00%)
//!   1 (1.00%) high mild
//!   8 (8.00%) high severe
//!
//! poseidon_bn254_x5_10    time:   [176.36 µs 177.01 µs 177.80 µs]
//! Found 8 outliers among 100 measurements (8.00%)
//!   1 (1.00%) low mild
//!   6 (6.00%) high mild
//!   1 (1.00%) high severe
//!
//! poseidon_bn254_x5_11    time:   [191.53 µs 192.26 µs 193.20 µs]
//! Found 14 outliers among 100 measurements (14.00%)
//!   8 (8.00%) high mild
//!   6 (6.00%) high severe
//!
//! poseidon_bn254_x5_12    time:   [259.56 µs 273.31 µs 287.16 µs]
//! Found 15 outliers among 100 measurements (15.00%)
//!   15 (15.00%) high severe
//!
//! poseidon_bn254_x5_13    time:   [307.41 µs 307.88 µs 308.38 µs]
//! Found 5 outliers among 100 measurements (5.00%)
//!   2 (2.00%) high mild
//!   3 (3.00%) high severe
//!
//! poseidon_bn254_x5_14    time:   [309.65 µs 311.24 µs 313.54 µs]
//! Found 4 outliers among 100 measurements (4.00%)
//!   2 (2.00%) high mild
//!   2 (2.00%) high severe
//!
//! poseidon_bn254_x5_15    time:   [383.48 µs 385.41 µs 387.49 µs]
//! Found 2 outliers among 100 measurements (2.00%)
//!   2 (2.00%) high mild
//! ```
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use thiserror::Error;

pub mod parameters;

pub const HASH_LEN: usize = 32;
pub const MAX_X5_LEN: usize = 16;

#[derive(Error, Debug, PartialEq)]
pub enum PoseidonError {
    #[error("Invalid number of inputs: {inputs}, the maximum limit is {max_limit} ({width} - 1)")]
    InvalidNumberOfInputs {
        inputs: usize,
        max_limit: usize,
        width: usize,
    },
    #[error("Failed to convert a vector of bytes into an array")]
    VecToArray,
    #[error("Failed to convert a the number of inputs to a u8")]
    U64Tou8,
    #[error("Selected width is invalid, select a width between 2 and 16, for 1 to 15 inputs.")]
    InvalidWidthCircom { width: usize, max_limit: usize },
}

/// Parameters for the Poseidon hash algorithm.
pub struct PoseidonParameters<F: PrimeField> {
    /// Round constants.
    pub ark: Vec<F>,
    /// MDS matrix.
    pub mds: Vec<Vec<F>>,
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
    pub fn new(
        ark: Vec<F>,
        mds: Vec<Vec<F>>,
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
}

pub trait PoseidonHasher<F: PrimeField> {
    /// Calculates a Poseidon hash for the given input of prime fields and
    /// returns the result as a prime field.
    ///
    /// Poseidon prepends a zero prime field at the beginning of the state,
    /// appends the given `input` and then, if the length of the state is
    /// still smaller than the width of the state, it appends zero prime
    /// fields at the end of the state until they are equal.
    ///
    /// Therefore `inputs` argument cannot be larger than the number of prime
    /// fields in the state - 1. To be precise, the undesirable condition is
    /// `inputs.len() > self.params.width - 1`. Providing such `input` will
    /// result in an error.
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
    /// ```
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError>;
}

pub trait PoseidonBytesHasher {
    /// Calculates a Poseidon hash for the given input of byte slices and
    /// returns the result as a byte array.
    ///
    /// Poseidon prepends a zero prime field at the beginning of the state,
    /// appends the given `input` and then, if the length of the state is
    /// still smaller than the width of the state, it appends zero prime
    /// fields at the end of the state until they are equal.
    ///
    /// Therefore `inputs` argument cannot be larger than the number of prime
    /// fields in the state - 1. To be precise, the undesirable condition is
    /// `inputs.len() > self.params.width - 1`. Providing such `input` will
    /// result in an error.
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
    /// let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();
    ///
    /// println!("{:?}", hash);
    /// // Should print:
    /// // [
    /// //     13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
    /// //     254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
    /// // ]
    /// ```
    fn hash_bytes(&mut self, inputs: &[&[u8]]) -> Result<[u8; HASH_LEN], PoseidonError>;
}

/// A stateful sponge performing Poseidon hash computation.
pub struct Poseidon<F: PrimeField> {
    params: PoseidonParameters<F>,
    state: Vec<F>,
}

impl<F: PrimeField> Poseidon<F> {
    /// Returns a new Poseidon hasher based on the given parameters.
    pub fn new(params: PoseidonParameters<F>) -> Self {
        let width = params.width;
        Self {
            params,
            state: Vec::with_capacity(width),
        }
    }

    #[inline(always)]
    fn apply_ark(&mut self, round: usize) {
        self.state.iter_mut().enumerate().for_each(|(i, a)| {
            let c = self.params.ark[round * self.params.width + i];
            *a += c;
        });
    }

    #[inline(always)]
    fn apply_sbox_full(&mut self) {
        self.state.iter_mut().for_each(|a| {
            *a = a.pow([self.params.alpha]);
        });
    }

    #[inline(always)]
    fn apply_sbox_partial(&mut self) {
        self.state[0] = self.state[0].pow([self.params.alpha]);
    }

    #[inline(always)]
    fn apply_mds(&mut self) {
        self.state = self
            .state
            .iter()
            .enumerate()
            .map(|(i, _)| {
                self.state
                    .iter()
                    .enumerate()
                    .fold(F::zero(), |acc, (j, a)| acc + *a * self.params.mds[i][j])
            })
            .collect();
    }
}

impl<F: PrimeField> PoseidonHasher<F> for Poseidon<F> {
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError> {
        if inputs.len() > self.params.width - 1 {
            return Err(PoseidonError::InvalidNumberOfInputs {
                inputs: inputs.len(),
                max_limit: self.params.width - 1,
                width: self.params.width,
            });
        }

        self.state.push(F::zero());

        for input in inputs {
            self.state.push(*input);
        }
        while self.state.len() < self.params.width {
            self.state.push(F::zero());
        }

        let all_rounds = self.params.full_rounds + self.params.partial_rounds;
        let half_rounds = self.params.full_rounds / 2;

        // full rounds + partial rounds
        for round in 0..half_rounds {
            self.apply_ark(round);
            self.apply_sbox_full();
            self.apply_mds();
        }

        for round in half_rounds..half_rounds + self.params.partial_rounds {
            self.apply_ark(round);
            self.apply_sbox_partial();
            self.apply_mds();
        }

        for round in half_rounds + self.params.partial_rounds..all_rounds {
            self.apply_ark(round);
            self.apply_sbox_full();
            self.apply_mds();
        }

        let result = self.state[0];
        self.state.clear();
        Ok(result)
    }
}

impl<F: PrimeField> PoseidonBytesHasher for Poseidon<F> {
    fn hash_bytes(&mut self, inputs: &[&[u8]]) -> Result<[u8; HASH_LEN], PoseidonError> {
        let inputs: Vec<F> = inputs
            .iter()
            .map(|bytes| F::from_be_bytes_mod_order(bytes))
            .collect();
        let hash = self.hash(&inputs)?;

        hash.into_bigint()
            .to_bytes_be()
            .try_into()
            .map_err(|_| PoseidonError::VecToArray)
    }
}

impl<F: PrimeField> Poseidon<F> {
    pub fn new_circom(nr_inputs: usize) -> Result<Poseidon<Fr>, PoseidonError> {
        let width = nr_inputs + 1;
        if width > MAX_X5_LEN {
            return Err(PoseidonError::InvalidWidthCircom {
                width,
                max_limit: MAX_X5_LEN,
            });
        }

        let params = crate::parameters::bn254_x5::get_poseidon_parameters::<Fr>(
            (width).try_into().map_err(|_| PoseidonError::U64Tou8)?,
        )?;
        Ok(Poseidon::<Fr>::new(params))
    }
}
