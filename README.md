[![Crates.io](https://img.shields.io/crates/v/light-poseidon.svg)](https://crates.io/crates/light-poseidon)
[![Workflow Status](https://github.com/Lightprotocol/light-poseidon/workflows/main/badge.svg)](https://github.com/Lightprotocol/light-poseidon/actions?query=workflow)

# light-poseidon

**light-poseidon** is a [Poseidon](https://eprint.iacr.org/2019/458) hash
implementation in Rust created for [Light Protocol](https://www.lightprotocol.com/).

## Parameters

The library provides pre-generated parameters over the BN254 curve, however
it can work with any parameters provided as long as developers take care
of generating the round constants.

Parameters provided by the library are:

* x^5 S-boxes
* t = 2 - 17 (for 1 to 15 inputs)
* 8 full rounds and partial rounds depending on t [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64]
The parameters can be generated with:
```$ cargo xtask generate-poseidon-parameters``
## Output type

[`Poseidon`](crate::Poseidon) type implements two traits which serve the purpose
of returning the calculated hash in different representations:

* [`PoseidonBytesHasher`](crate::PoseidonBytesHasher) with the
  [`hash_bytes`](crate::PoseidonBytesHasher::hash_bytes) method which
  returns a byte array.
* [`PoseidonHasher`](crate::PoseidonHasher) with the
  [`hash`](crate::PoseidonHasher::hash) method which returns
  [`ark_ff::PrimeField`](ark_ff::PrimeField). Might be useful if you want
  to immediately process the result with an another library which works with
  [`ark_ff::PrimeField`](ark_ff::PrimeField) types.

## Examples

Example with two simple big-endian byte inputs (converted to field elements)
and BN254-based parameters provided by the library, with
[`PoseidonBytesHasher`](crate::PoseidonHasher) trait and a byte array
result:

```rust
use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();

println!("{:?}", hash);
// Should print:
// [
//     13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
//     254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
// ]
```

With [`PoseidonHasher`][crate::PoseidonHasher] trait and
[`ark_ff::PrimeField`](ark_ff::PrimeField) result:

```rust
use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);

let hash = poseidon.hash(&[input1, input2]).unwrap();

// Do something with `hash`.
```

## Implementation

The implementation is compatible with the
[original SageMath implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master/),
but it was also inspired by the following ones:

* [circomlibjs](https://github.com/iden3/circomlibjs)
* [zero-knowledge-gadgets](https://github.com/webb-tools/zero-knowledge-gadgets)

### Performance

This repository contains a benchmark measuring the performance of this
Poseidon implementation for given 1 - 15 random 32 bytes inputs.

To run them, simply use:

```bash
cargo bench
```

This is the result from a host with the following hardware:

* 12th Gen Intel® Core™ i7-1260P × 16

```norust
poseidon_bn254_x5_1     time:   [14.656 µs 14.740 µs 14.848 µs]
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) high mild
  4 (4.00%) high severe

poseidon_bn254_x5_2     time:   [23.013 µs 24.307 µs 25.752 µs]
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) high mild
  3 (3.00%) high severe

poseidon_bn254_x5_3     time:   [29.276 µs 29.325 µs 29.377 µs]
Found 4 outliers among 100 measurements (4.00%)
  4 (4.00%) high mild

poseidon_bn254_x5_4     time:   [41.699 µs 41.856 µs 42.039 µs]
Found 7 outliers among 100 measurements (7.00%)
  6 (6.00%) high mild
  1 (1.00%) high severe

poseidon_bn254_x5_5     time:   [55.947 µs 57.883 µs 60.190 µs]
Found 14 outliers among 100 measurements (14.00%)
  1 (1.00%) high mild
  13 (13.00%) high severe

poseidon_bn254_x5_6     time:   [70.992 µs 71.327 µs 71.737 µs]
Found 10 outliers among 100 measurements (10.00%)
  4 (4.00%) high mild
  6 (6.00%) high severe

poseidon_bn254_x5_7     time:   [87.824 µs 88.174 µs 88.587 µs]
Found 12 outliers among 100 measurements (12.00%)
  5 (5.00%) high mild
  7 (7.00%) high severe

poseidon_bn254_x5_8     time:   [110.07 µs 111.22 µs 112.77 µs]

poseidon_bn254_x5_9     time:   [131.48 µs 131.82 µs 132.24 µs]
Found 9 outliers among 100 measurements (9.00%)
  1 (1.00%) high mild
  8 (8.00%) high severe

poseidon_bn254_x5_10    time:   [176.36 µs 177.01 µs 177.80 µs]
Found 8 outliers among 100 measurements (8.00%)
  1 (1.00%) low mild
  6 (6.00%) high mild
  1 (1.00%) high severe

poseidon_bn254_x5_11    time:   [191.53 µs 192.26 µs 193.20 µs]
Found 14 outliers among 100 measurements (14.00%)
  8 (8.00%) high mild
  6 (6.00%) high severe

poseidon_bn254_x5_12    time:   [259.56 µs 273.31 µs 287.16 µs]
Found 15 outliers among 100 measurements (15.00%)
  15 (15.00%) high severe

poseidon_bn254_x5_13    time:   [307.41 µs 307.88 µs 308.38 µs]
Found 5 outliers among 100 measurements (5.00%)
  2 (2.00%) high mild
  3 (3.00%) high severe

poseidon_bn254_x5_14    time:   [309.65 µs 311.24 µs 313.54 µs]
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe

poseidon_bn254_x5_15    time:   [383.48 µs 385.41 µs 387.49 µs]
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high mild
```

## License

Licensed under [Apache License, Version 2.0](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.