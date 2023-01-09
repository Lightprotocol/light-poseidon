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
* 3 prime fields (one zero prime field and two inputs from the caller)
* 8 full rounds and 57 partial rounds

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

Example with two simple big-endian byte inputs (converted to prime fields)
and BN254-based parameters provided by the library, with
[`PoseidonBytesHasher`](crate::PoseidonHasher) trait and a byte array
result:

```rust
use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5_3::poseidon_parameters};
use ark_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};

let params = poseidon_parameters();
let mut poseidon = Poseidon::new(params);

let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();

println!("{:?}", hash);
// Should print:
// [
//     40, 7, 251, 60, 51, 30, 115, 141, 251, 200, 13, 46, 134, 91, 113, 170, 131, 90, 53,
//     175, 9, 61, 242, 164, 127, 33, 249, 65, 253, 131, 35, 116
// ]
```

With [`PoseidonHasher`][crate::PoseidonHasher] trait and
[`ark_ff::PrimeField`](ark_ff::PrimeField) result:

```rust
use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5_3::poseidon_parameters};
use ark_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};

let params = poseidon_parameters();
let mut poseidon = Poseidon::new(params);

let input1 = Fq::from_be_bytes_mod_order(&[1u8; 32]);
let input2 = Fq::from_be_bytes_mod_order(&[2u8; 32]);

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
Poseidon implementation for given two random 32 bytes inputs.

To run them, simply use:

```bash
cargo bench
```

This is the result from a host with the following hardware:

* AMD Ryzen 9 5950x (base clock: 3.4 GHz, up to: 4.9 GHz)
* 4 x Corsair Vengeance DDR4 32GB 3600 MHz

```norust
poseidon_bn254_x5_3     time:   [21.980 µs 21.997 µs 22.017 µs]
Found 9 outliers among 100 measurements (9.00%)
  4 (4.00%) high mild
  5 (5.00%) high severe
```

## License

Licensed under [Apache License, Version 2.0](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
