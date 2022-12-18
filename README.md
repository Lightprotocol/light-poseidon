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

## Examples

Example with two simple big-endian byte inputs (converted to prime fields)
and BN254-based parameters provided by the library:

```rust
use light_poseidon::{PoseidonHasher, parameters::bn254_x5_3::poseidon_parameters};
use ark_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};

let params = poseidon_parameters();
let mut poseidon = PoseidonHasher::new(params);

let input1 = Fq::from_be_bytes_mod_order(&[1u8; 32]);
let input2 = Fq::from_be_bytes_mod_order(&[2u8; 32]);

let hash = poseidon.hash(&[input1, input2]).unwrap();

// Do something with `hash`.
println!("{:?}", hash.into_repr().to_bytes_be());
// Should print:
// [
//     40, 7, 251, 60, 51, 30, 115, 141, 251, 200, 13, 46, 134, 91, 113, 170, 131, 90, 53,
//     175, 9, 61, 242, 164, 127, 33, 249, 65, 253, 131, 35, 116
// ]
```

## Implementation

The implementation is compatible with the
[original SageMath implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master/),
but it was also inspired by the following ones:

* [circomlibjs](https://github.com/iden3/circomlibjs)
* [zero-knowledge-gadgets](https://github.com/webb-tools/zero-knowledge-gadgets)

## License

Licensed under [Apache License, Version 2.0](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
