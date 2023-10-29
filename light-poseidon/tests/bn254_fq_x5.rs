use ark_bn254::Fr;
use ark_ff::{BigInteger, BigInteger256, One, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonError};
use light_poseidon::{PoseidonBytesHasher, PoseidonHasher};
use rand::Rng;

#[test]
fn test_poseidon_one() {
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();

    let expected = [
        0, 122, 243, 70, 226, 211, 4, 39, 158, 121, 224, 169, 243, 2, 63, 119, 18, 148, 167, 138,
        203, 112, 231, 63, 144, 175, 226, 124, 173, 64, 30, 129,
    ];

    let input = Fr::from_be_bytes_mod_order(&[1u8]);
    let hash = hasher.hash(&[input, input]).unwrap();

    assert_eq!(hash.into_bigint().to_bytes_be(), expected,);

    let input = Fr::from_be_bytes_mod_order(&[0u8, 1u8]);
    let hash = hasher.hash(&[input, input]).unwrap();

    assert_eq!(hash.into_bigint().to_bytes_be(), expected);

    let input = Fr::from_be_bytes_mod_order(&[0u8, 0u8, 1u8]);
    let hash = hasher.hash(&[input, input]).unwrap();

    assert_eq!(hash.into_bigint().to_bytes_be(), expected);
}

#[test]
fn test_poseidon_bn254_x5_fq_input_ones_twos() {
    let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
    let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();

    assert_eq!(
        hash.into_bigint().to_bytes_be(),
        [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ]
    );
}

#[test]
fn test_poseidon_bn254_x5_fq_with_domain_tag() {
    let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
    let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);
    let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(2, Fr::zero()).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();

    let expected_tag_zero = [
        13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132, 254,
        156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144,
    ];

    assert_eq!(hash.into_bigint().to_bytes_be(), expected_tag_zero);

    let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(2, Fr::one()).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();

    assert_ne!(hash.into_bigint().to_bytes_be(), expected_tag_zero);
}

#[test]
fn test_poseidon_bn254_x5_fq_input_one_two() {
    let input1 = Fr::from_be_bytes_mod_order(&[1]);
    let input2 = Fr::from_be_bytes_mod_order(&[2]);

    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();

    assert_eq!(
        hash.into_bigint().to_bytes_le(),
        [
            154, 24, 23, 68, 122, 96, 25, 158, 81, 69, 50, 116, 242, 23, 54, 42, 207, 233, 98, 150,
            107, 76, 246, 61, 65, 144, 214, 231, 245, 192, 92, 17
        ]
    );
}

#[test]
fn test_poseidon_bn254_x5_fq_input_random() {
    let input1 = Fr::from_be_bytes_mod_order(&[
        0x06, 0x9c, 0x63, 0x81, 0xac, 0x0b, 0x96, 0x8e, 0x88, 0x1c, 0x91, 0x3c, 0x17, 0xd8, 0x36,
        0x06, 0x7f, 0xd1, 0x5f, 0x2c, 0xc7, 0x9f, 0x90, 0x2c, 0x80, 0x70, 0xb3, 0x6d, 0x28, 0x66,
        0x17, 0xdd,
    ]);
    let input2 = Fr::from_be_bytes_mod_order(&[
        0xc3, 0x3b, 0x60, 0x04, 0x2f, 0x76, 0xc7, 0xfb, 0xd0, 0x5d, 0xb7, 0x76, 0x23, 0xcb, 0x17,
        0xb8, 0x1d, 0x49, 0x41, 0x4b, 0x82, 0xe5, 0x6a, 0x2e, 0xc0, 0x18, 0xf7, 0xa5, 0x5c, 0x3f,
        0x30, 0x0b,
    ]);

    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();
    assert_eq!(
        hash.into_bigint().to_bytes_le(),
        [
            75, 85, 249, 42, 66, 238, 230, 151, 158, 90, 250, 51, 131, 212, 131, 18, 151, 235, 96,
            103, 135, 243, 186, 61, 173, 135, 52, 77, 132, 173, 19, 10
        ]
    )
}

#[test]
fn test_poseidon_bn254_x5_fq_input_invalid() {
    let mut vec = Vec::new();
    for _ in 0..17 {
        vec.push(Fr::from_be_bytes_mod_order(&[1u8; 32]));
    }
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();

    assert!(hasher.hash(&vec).is_err());

    vec.push(Fr::from_be_bytes_mod_order(&[4u8; 32]));

    assert!(hasher.hash(&vec).is_err());
}

#[test]
fn test_poseidon_bn254_x5_fq_hash_bytes_be() {
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash = hasher.hash_bytes_be(&[&[1u8; 32], &[2u8; 32]]).unwrap();

    assert_eq!(
        hash,
        [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ]
    );
}

#[test]
fn test_poseidon_bn254_x5_fq_hash_bytes_le() {
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash = hasher.hash_bytes_le(&[&[1u8; 32], &[2u8; 32]]).unwrap();

    assert_eq!(
        hash,
        [
            144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99, 242,
            85, 3, 94, 235, 125, 28, 140, 138, 143, 147, 225, 84, 13
        ]
    );
}

macro_rules! test_random_input_same_results {
    ($name:ident, $method:ident) => {
        #[test]
        fn $name() {
            let input = [1u8; 32];

            for nr_inputs in 1..12 {
                let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

                let mut inputs = Vec::with_capacity(nr_inputs);
                for _ in 0..nr_inputs {
                    inputs.push(input.as_slice());
                }

                let hash1 = hasher.$method(inputs.as_slice()).unwrap();
                let hash2 = hasher.$method(inputs.as_slice()).unwrap();

                assert_eq!(hash1, hash2);
            }
        }
    };
}

test_random_input_same_results!(
    test_poseidon_bn254_x5_fq_hash_bytes_be_random_input_same_results,
    hash_bytes_be
);

test_random_input_same_results!(
    test_poseidon_bn254_x5_fq_hash_bytes_le_random_input_same_results,
    hash_bytes_le
);

macro_rules! test_invalid_input_length {
    ($name:ident, $method:ident) => {
        #[test]
        fn $name() {
            let mut rng = rand::thread_rng();

            for _ in 0..100 {
                let len = rng.gen_range(33..524_288_000); // Maximum 500 MB.
                let input = vec![1u8; len];

                for nr_inputs in 1..12 {
                    let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

                    let mut inputs = Vec::with_capacity(nr_inputs);
                    for _ in 0..nr_inputs {
                        inputs.push(input.as_slice());
                    }

                    let hash = hasher.$method(inputs.as_slice());
                    assert_eq!(
                        hash,
                        Err(PoseidonError::InvalidInputLength {
                            len,
                            modulus_bytes_len: 32,
                        })
                    );
                }
            }
        }
    };
}

test_invalid_input_length!(
    test_poseidon_bn254_x5_fq_hash_bytes_be_invalid_input_length,
    hash_bytes_be
);

test_invalid_input_length!(
    test_poseidon_bn254_x5_fq_hash_bytes_le_invalid_input_length,
    hash_bytes_le
);

macro_rules! test_fuzz_input_gt_field_size {
    ($name:ident, $method:ident, $to_bytes_method:ident) => {
        #[test]
        fn $name() {
            let mut greater_than_field_size = Fr::MODULUS;
            let mut rng = rand::thread_rng();
            let random_number = rng.gen_range(1u64..1_000_000u64);
            greater_than_field_size.add_with_carry(&BigInteger256::from(random_number));
            let greater_than_field_size = greater_than_field_size.$to_bytes_method();

            assert_eq!(greater_than_field_size.len(), 32);

            for nr_inputs in 1..12 {
                let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

                let mut inputs = Vec::with_capacity(nr_inputs);
                for _ in 0..nr_inputs {
                    inputs.push(&greater_than_field_size[..]);
                }

                let hash = hasher.$method(inputs.as_slice());
                assert_eq!(hash, Err(PoseidonError::InputLargerThanModulus));
            }
        }
    };
}

test_fuzz_input_gt_field_size!(
    test_fuzz_poseidon_bn254_fq_hash_bytes_be_input_gt_field_size,
    hash_bytes_be,
    to_bytes_be
);

test_fuzz_input_gt_field_size!(
    test_fuzz_poseidon_bn254_fq_hash_bytes_le_input_gt_field_size,
    hash_bytes_le,
    to_bytes_le
);

macro_rules! test_input_gt_field_size {
    ($name:ident, $method:ident, $greater_than_field_size:expr) => {
        #[test]
        fn $name() {
            for nr_inputs in 1..12 {
                let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

                let mut inputs = Vec::with_capacity(nr_inputs);
                for _ in 0..nr_inputs {
                    inputs.push(&$greater_than_field_size[..]);
                }

                let hash = hasher.$method(inputs.as_slice());
                assert_eq!(hash, Err(PoseidonError::InputLargerThanModulus));
            }
        }
    };
}

test_input_gt_field_size!(
    test_poseidon_bn254_fq_hash_bytes_be_input_gt_field_size,
    hash_bytes_be,
    [
        48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72,
        121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 2
    ]
);

test_input_gt_field_size!(
    test_poseidon_bn254_fq_hash_bytes_le_input_gt_field_size,
    hash_bytes_le,
    [
        2, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129,
        182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48
    ]
);

#[test]
fn test_endianness() {
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let le_input: &[u8] = &[0, 0, 0, 1];
    let be_input: &[u8] = &[1, 0, 0, 0];

    let hash1 = hasher.hash_bytes_le(&[le_input, le_input]).unwrap();
    let mut hash2 = hasher.hash_bytes_be(&[be_input, be_input]).unwrap();

    assert_ne!(hash1, hash2);

    // Make it little-endian.
    hash2.reverse();

    assert_eq!(hash1, hash2);

    let le_input: &[u8] = &[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let be_input: &[u8] = &[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    let hash3 = hasher.hash_bytes_le(&[le_input, le_input]).unwrap();
    let mut hash4 = hasher.hash_bytes_be(&[be_input, be_input]).unwrap();

    assert_ne!(hash3, hash4);

    // Make it little-endian.
    hash4.reverse();

    // Compare the latest hashes.
    assert_eq!(hash3, hash4);

    let one = 1u64;
    let le_input = one.to_le_bytes();
    let be_input = one.to_be_bytes();

    let hash5 = hasher.hash_bytes_le(&[&le_input, &le_input]).unwrap();
    let mut hash6 = hasher.hash_bytes_be(&[&be_input, &be_input]).unwrap();

    assert_ne!(hash5, hash6);

    // Make it little-endian,
    hash6.reverse();

    // Compare the latest hashes.
    assert_eq!(hash5, hash6);
}

#[test]
fn test_empty_input() {
    let empty: &[u8] = &[];
    let non_empty = &[1u8; 32];

    // All inputs empty.
    for nr_inputs in 1..12 {
        let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

        let mut inputs = Vec::with_capacity(nr_inputs);
        for _ in 0..nr_inputs {
            inputs.push(empty);
        }

        let hash = hasher.hash_bytes_be(inputs.as_slice());
        assert_eq!(hash, Err(PoseidonError::EmptyInput));

        let hash = hasher.hash_bytes_le(inputs.as_slice());
        assert_eq!(hash, Err(PoseidonError::EmptyInput));
    }

    // One empty input.
    for nr_inputs in 1..12 {
        let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

        let mut inputs = Vec::with_capacity(nr_inputs);
        for _ in 0..(nr_inputs - 1) {
            inputs.push(non_empty.as_slice());
        }
        inputs.push(empty);

        let hash = hasher.hash_bytes_be(inputs.as_slice());
        assert_eq!(hash, Err(PoseidonError::EmptyInput));

        let hash = hasher.hash_bytes_le(inputs.as_slice());
        assert_eq!(hash, Err(PoseidonError::EmptyInput));
    }
}

// test cases were created with circomlibjs poseidon([1, ...]) for 1 to 16 inputs
const TEST_CASES: [[u8; 32]; 12] = [
    [
        41, 23, 97, 0, 234, 169, 98, 189, 193, 254, 108, 101, 77, 106, 60, 19, 14, 150, 164, 209,
        22, 139, 51, 132, 139, 137, 125, 197, 2, 130, 1, 51,
    ],
    [
        0, 122, 243, 70, 226, 211, 4, 39, 158, 121, 224, 169, 243, 2, 63, 119, 18, 148, 167, 138,
        203, 112, 231, 63, 144, 175, 226, 124, 173, 64, 30, 129,
    ],
    [
        2, 192, 6, 110, 16, 167, 42, 189, 43, 51, 195, 178, 20, 203, 62, 129, 188, 177, 182, 227,
        9, 97, 205, 35, 194, 2, 177, 134, 115, 191, 37, 67,
    ],
    [
        8, 44, 156, 55, 10, 13, 36, 244, 65, 111, 188, 65, 74, 55, 104, 31, 120, 68, 45, 39, 216,
        99, 133, 153, 28, 23, 214, 252, 12, 75, 125, 113,
    ],
    [
        16, 56, 150, 5, 174, 104, 141, 79, 20, 219, 133, 49, 34, 196, 125, 102, 168, 3, 199, 43,
        65, 88, 156, 177, 191, 134, 135, 65, 178, 6, 185, 187,
    ],
    [
        42, 115, 246, 121, 50, 140, 62, 171, 114, 74, 163, 229, 189, 191, 80, 179, 144, 53, 215,
        114, 159, 19, 91, 151, 9, 137, 15, 133, 197, 220, 94, 118,
    ],
    [
        34, 118, 49, 10, 167, 243, 52, 58, 40, 66, 20, 19, 157, 157, 169, 89, 190, 42, 49, 178,
        199, 8, 165, 248, 25, 84, 178, 101, 229, 58, 48, 184,
    ],
    [
        23, 126, 20, 83, 196, 70, 225, 176, 125, 43, 66, 51, 66, 81, 71, 9, 92, 79, 202, 187, 35,
        61, 35, 11, 109, 70, 162, 20, 217, 91, 40, 132,
    ],
    [
        14, 143, 238, 47, 228, 157, 163, 15, 222, 235, 72, 196, 46, 187, 68, 204, 110, 231, 5, 95,
        97, 251, 202, 94, 49, 59, 138, 95, 202, 131, 76, 71,
    ],
    [
        46, 196, 198, 94, 99, 120, 171, 140, 115, 48, 133, 79, 74, 112, 119, 193, 255, 146, 96,
        228, 72, 133, 196, 184, 29, 209, 49, 173, 58, 134, 205, 150,
    ],
    [
        0, 113, 61, 65, 236, 166, 53, 241, 23, 212, 236, 188, 235, 95, 58, 102, 220, 65, 66, 235,
        112, 181, 103, 101, 188, 53, 143, 27, 236, 64, 187, 155,
    ],
    [
        20, 57, 11, 224, 186, 239, 36, 155, 212, 124, 101, 221, 172, 101, 194, 229, 46, 133, 19,
        192, 129, 193, 205, 114, 201, 128, 6, 9, 142, 154, 143, 190,
    ],
];

#[test]
fn test_circom_1_to_12_inputs() {
    let mut inputs = Vec::new();
    let value = [vec![0u8; 31], vec![1u8]].concat();
    for i in 1..13 {
        inputs.push(value.as_slice());
        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
        let hash = hasher.hash_bytes_be(&inputs[..]).unwrap();
        assert_eq!(hash, TEST_CASES[i - 1]);
    }
    let mut inputs = Vec::new();
    let value = [vec![0u8; 31], vec![2u8]].concat();
    for i in 1..13 {
        inputs.push(value.as_slice());
        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
        let hash = hasher.hash_bytes_be(&inputs[..]).unwrap();
        assert!(hash != TEST_CASES[i - 1]);
    }
}

#[test]
fn test_circom_solana_t_gt_12_fails() {
    use light_poseidon::PoseidonError;

    let mut inputs = Vec::new();
    let value = [vec![0u8; 31], vec![1u8]].concat();
    for i in 13..16 {
        inputs.push(value.as_slice());
        let hasher = Poseidon::<Fr>::new_circom(i);
        unsafe {
            assert_eq!(
                hasher.unwrap_err_unchecked(),
                PoseidonError::InvalidWidthCircom {
                    width: i + 1,
                    max_limit: 13
                }
            );
        }
    }
}

#[test]
fn test_circom_t_0_fails() {
    use light_poseidon::PoseidonError;
    let hasher = Poseidon::<Fr>::new_circom(0);
    unsafe {
        assert_eq!(
            hasher.unwrap_err_unchecked(),
            PoseidonError::InvalidWidthCircom {
                width: 1,
                max_limit: 13
            }
        );
    }
}
