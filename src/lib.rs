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
//! * 3 prime fields (one zero prime field and two inputs from the caller)
//! * 8 full rounds and 57 partial rounds
//!
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
//! Example with two simple big-endian byte inputs (converted to prime fields)
//! and BN254-based parameters provided by the library, with
//! [`PoseidonBytesHasher`](crate::PoseidonHasher) trait and a byte array
//! result:
//!
//! ```rust
//! use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5_3::poseidon_parameters};
//! use ark_bn254::Fq;
//! use ark_ff::{BigInteger, PrimeField};
//!
//! let params = poseidon_parameters();
//! let mut poseidon = Poseidon::new(params);
//!
//! let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();
//!
//! println!("{:?}", hash);
//! // Should print:
//! // [
//! //     40, 7, 251, 60, 51, 30, 115, 141, 251, 200, 13, 46, 134, 91, 113, 170, 131, 90, 53,
//! //     175, 9, 61, 242, 164, 127, 33, 249, 65, 253, 131, 35, 116
//! // ]
//! ```
//!
//! With [`PoseidonHasher`][crate::PoseidonHasher] trait and
//! [`ark_ff::PrimeField`](ark_ff::PrimeField) result:
//!
//! ```rust
//! use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5_3::poseidon_parameters};
//! use ark_bn254::Fq;
//! use ark_ff::{BigInteger, PrimeField};
//!
//! let params = poseidon_parameters();
//! let mut poseidon = Poseidon::new(params);
//!
//! let input1 = Fq::from_be_bytes_mod_order(&[1u8; 32]);
//! let input2 = Fq::from_be_bytes_mod_order(&[2u8; 32]);
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
//! Poseidon implementation for given two random 32 bytes inputs.
//!
//! To run them, simply use:
//!
//! ```bash
//! cargo bench
//! ```
//!
//! This is the result from a host with the following hardware:
//!
//! * AMD Ryzen 9 5950x (base clock: 3.4 GHz, up to: 4.9 GHz)
//! * 4 x Corsair Vengeance DDR4 32GB 3600 MHz
//!
//! ```norust
//! poseidon_bn254_x5_3     time:   [21.980 µs 21.997 µs 22.017 µs]
//! Found 9 outliers among 100 measurements (9.00%)
//!   4 (4.00%) high mild
//!   5 (5.00%) high severe
//! ```

use ark_ff::{BigInteger, PrimeField};
use thiserror::Error;

pub mod parameters;

pub const HASH_LEN: usize = 32;

#[derive(Error, Debug)]
pub enum PoseidonError {
    #[error("Invalid number of inputs: {inputs}, the maximum limit is {max_limit} ({width} - 1)")]
    InvalidNumberOfInputs {
        inputs: usize,
        max_limit: usize,
        width: usize,
    },
    #[error("Failed to convert a vector of bytes into an array")]
    VecToArray,
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
    /// use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5_3::poseidon_parameters};
    /// use ark_bn254::Fq;
    /// use ark_ff::{BigInteger, PrimeField};
    ///
    /// let params = poseidon_parameters();
    /// let mut poseidon = Poseidon::new(params);
    ///
    /// let input1 = Fq::from_be_bytes_mod_order(&[1u8; 32]);
    /// let input2 = Fq::from_be_bytes_mod_order(&[2u8; 32]);
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
    /// use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5_3::poseidon_parameters};
    /// use ark_bn254::Fq;
    /// use ark_ff::{BigInteger, PrimeField};
    ///
    /// let params = poseidon_parameters();
    /// let mut poseidon = Poseidon::new(params);
    ///
    /// let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();
    ///
    /// println!("{:?}", hash);
    /// // Should print:
    /// // [
    /// //     40, 7, 251, 60, 51, 30, 115, 141, 251, 200, 13, 46, 134, 91, 113, 170, 131, 90, 53,
    /// //     175, 9, 61, 242, 164, 127, 33, 249, 65, 253, 131, 35, 116
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

        Ok(hash
            .into_repr()
            .to_bytes_be()
            .try_into()
            .map_err(|_| PoseidonError::VecToArray)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_bn254::Fq;
    use ark_ff::BigInteger;

    use parameters::bn254_x5_3;

    #[test]
    fn test_poseidon_bn254_x5_3_input_ones_twos() {
        let params = bn254_x5_3::poseidon_parameters();
        let mut poseidon = Poseidon::new(params);

        let input1 = Fq::from_be_bytes_mod_order(&[1u8; 32]);
        let input2 = Fq::from_be_bytes_mod_order(&[2u8; 32]);

        let hash = poseidon.hash(&[input1, input2]).unwrap();
        assert_eq!(
            hash.into_repr().to_bytes_be(),
            [
                40, 7, 251, 60, 51, 30, 115, 141, 251, 200, 13, 46, 134, 91, 113, 170, 131, 90, 53,
                175, 9, 61, 242, 164, 127, 33, 249, 65, 253, 131, 35, 116
            ]
        );
    }

    #[test]
    fn test_poseidon_bn254_x5_3_input_one_two() {
        let params = bn254_x5_3::poseidon_parameters();
        let mut poseidon = Poseidon::new(params);

        let input1 = Fq::from_be_bytes_mod_order(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let input2 = Fq::from_be_bytes_mod_order(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]);

        let hash = poseidon.hash(&[input1, input2]).unwrap();
        assert_eq!(
            hash.into_repr().to_bytes_be(),
            [
                25, 11, 182, 121, 54, 48, 205, 9, 39, 164, 111, 44, 108, 203, 20, 95, 112, 101, 97,
                130, 151, 54, 169, 215, 37, 104, 12, 83, 176, 236, 253, 54
            ]
        );
    }

    #[test]
    fn test_poseidon_bn254_x5_3_input_random() {
        let params = bn254_x5_3::poseidon_parameters();
        let mut poseidon = Poseidon::new(params);

        let input1 = Fq::from_be_bytes_mod_order(&[
            0x06, 0x9c, 0x63, 0x81, 0xac, 0x0b, 0x96, 0x8e, 0x88, 0x1c, 0x91, 0x3c, 0x17, 0xd8,
            0x36, 0x06, 0x7f, 0xd1, 0x5f, 0x2c, 0xc7, 0x9f, 0x90, 0x2c, 0x80, 0x70, 0xb3, 0x6d,
            0x28, 0x66, 0x17, 0xdd,
        ]);
        let input2 = Fq::from_be_bytes_mod_order(&[
            0xc3, 0x3b, 0x60, 0x04, 0x2f, 0x76, 0xc7, 0xfb, 0xd0, 0x5d, 0xb7, 0x76, 0x23, 0xcb,
            0x17, 0xb8, 0x1d, 0x49, 0x41, 0x4b, 0x82, 0xe5, 0x6a, 0x2e, 0xc0, 0x18, 0xf7, 0xa5,
            0x5c, 0x3f, 0x30, 0x0b,
        ]);

        let hash = poseidon.hash(&[input1, input2]).unwrap();
        assert_eq!(
            hash.into_repr().to_bytes_be(),
            [
                43, 94, 133, 6, 86, 161, 42, 237, 224, 252, 105, 131, 134, 176, 141, 84, 159, 162,
                172, 12, 155, 131, 123, 94, 218, 217, 178, 239, 100, 87, 4, 238
            ]
        )
    }

    #[test]
    fn test_poseidon_bn254_x5_3_input_invalid() {
        let params = bn254_x5_3::poseidon_parameters();
        let mut poseidon = Poseidon::new(params);

        let input1 = Fq::from_be_bytes_mod_order(&[1u8; 32]);
        let input2 = Fq::from_be_bytes_mod_order(&[2u8; 32]);
        let input3 = Fq::from_be_bytes_mod_order(&[3u8; 32]);

        assert!(poseidon.hash(&[input1, input2, input3]).is_err());

        let input4 = Fq::from_be_bytes_mod_order(&[4u8; 32]);

        assert!(poseidon.hash(&[input1, input2, input3, input4]).is_err());
    }

    #[test]
    fn test_poseidon_bn254_x5_4_hash_bytes() {
        let params = bn254_x5_3::poseidon_parameters();
        let mut poseidon = Poseidon::new(params);

        let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();

        assert_eq!(
            hash,
            [
                40, 7, 251, 60, 51, 30, 115, 141, 251, 200, 13, 46, 134, 91, 113, 170, 131, 90, 53,
                175, 9, 61, 242, 164, 127, 33, 249, 65, 253, 131, 35, 116
            ]
        );
    }
}
