use ark_ff::{BigInteger, PrimeField};

use light_poseidon::{parameters::bn254_x5_3, Poseidon, PoseidonBytesHasher, PoseidonHasher};

#[test]
fn test_poseidon_bn254_x5_3_fq_input_ones_twos() {
    let params = bn254_x5_3::poseidon_parameters!(Fr);
    let mut poseidon = Poseidon::new(params);

    let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
    let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);

    let hash = poseidon.hash(&[input1, input2]).unwrap();
    assert_eq!(
        hash.into_repr().to_bytes_be(),
        [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ]
    );
}
use ark_bn254::Fr;
#[test]
fn test_poseidon_bn254_x5_3_fq_input_one_two() {
    let params = bn254_x5_3::poseidon_parameters!(Fr);
    let mut poseidon = Poseidon::new(params);

    let input1 = Fr::from_be_bytes_mod_order(&[1]);
    let input2 = Fr::from_be_bytes_mod_order(&[2]);

    let hash = poseidon.hash(&[input1, input2]).unwrap();

    assert_eq!(
        hash.into_repr().to_bytes_le(),
        [
            154, 24, 23, 68, 122, 96, 25, 158, 81, 69, 50, 116, 242, 23, 54, 42, 207, 233, 98, 150,
            107, 76, 246, 61, 65, 144, 214, 231, 245, 192, 92, 17
        ]
    );
}

#[test]
fn test_poseidon_bn254_x5_3_fq_input_random() {
    let params = bn254_x5_3::poseidon_parameters!(Fr);
    let mut poseidon = Poseidon::new(params);

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

    let hash = poseidon.hash(&[input1, input2]).unwrap();
    assert_eq!(
        hash.into_repr().to_bytes_le(),
        [
            75, 85, 249, 42, 66, 238, 230, 151, 158, 90, 250, 51, 131, 212, 131, 18, 151, 235, 96,
            103, 135, 243, 186, 61, 173, 135, 52, 77, 132, 173, 19, 10
        ]
    )
}

#[test]
fn test_poseidon_bn254_x5_3_fq_input_invalid() {
    let params = bn254_x5_3::poseidon_parameters!(Fr);
    let mut poseidon = Poseidon::new(params);

    let input1 = Fr::from_be_bytes_mod_order(&[1u8; 32]);
    let input2 = Fr::from_be_bytes_mod_order(&[2u8; 32]);
    let input3 = Fr::from_be_bytes_mod_order(&[3u8; 32]);

    assert!(poseidon.hash(&[input1, input2, input3]).is_err());

    let input4 = Fr::from_be_bytes_mod_order(&[4u8; 32]);

    assert!(poseidon.hash(&[input1, input2, input3, input4]).is_err());
}

#[test]
fn test_poseidon_bn254_x5_3_fq_hash_bytes() {
    let params = bn254_x5_3::poseidon_parameters!(Fr);
    let mut poseidon = Poseidon::new(params);

    let hash = poseidon.hash_bytes(&[&[1u8; 32], &[2u8; 32]]).unwrap();

    assert_eq!(
        hash,
        [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ]
    );
}
