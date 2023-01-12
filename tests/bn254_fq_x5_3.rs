use ark_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};

use light_poseidon::{parameters::bn254_x5_3, Poseidon, PoseidonBytesHasher, PoseidonHasher};

#[test]
fn test_poseidon_bn254_x5_3_fq_input_ones_twos() {
    let params = bn254_x5_3::poseidon_parameters!(Fq);
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
fn test_poseidon_bn254_x5_3_fq_input_one_two() {
    let params = bn254_x5_3::poseidon_parameters!(Fq);
    let mut poseidon = Poseidon::new(params);

    let input1 = Fq::from_be_bytes_mod_order(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);
    let input2 = Fq::from_be_bytes_mod_order(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
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
fn test_poseidon_bn254_x5_3_fq_input_random() {
    let params = bn254_x5_3::poseidon_parameters!(Fq);
    let mut poseidon = Poseidon::new(params);

    let input1 = Fq::from_be_bytes_mod_order(&[
        0x06, 0x9c, 0x63, 0x81, 0xac, 0x0b, 0x96, 0x8e, 0x88, 0x1c, 0x91, 0x3c, 0x17, 0xd8, 0x36,
        0x06, 0x7f, 0xd1, 0x5f, 0x2c, 0xc7, 0x9f, 0x90, 0x2c, 0x80, 0x70, 0xb3, 0x6d, 0x28, 0x66,
        0x17, 0xdd,
    ]);
    let input2 = Fq::from_be_bytes_mod_order(&[
        0xc3, 0x3b, 0x60, 0x04, 0x2f, 0x76, 0xc7, 0xfb, 0xd0, 0x5d, 0xb7, 0x76, 0x23, 0xcb, 0x17,
        0xb8, 0x1d, 0x49, 0x41, 0x4b, 0x82, 0xe5, 0x6a, 0x2e, 0xc0, 0x18, 0xf7, 0xa5, 0x5c, 0x3f,
        0x30, 0x0b,
    ]);

    let hash = poseidon.hash(&[input1, input2]).unwrap();
    assert_eq!(
        hash.into_repr().to_bytes_be(),
        [
            43, 94, 133, 6, 86, 161, 42, 237, 224, 252, 105, 131, 134, 176, 141, 84, 159, 162, 172,
            12, 155, 131, 123, 94, 218, 217, 178, 239, 100, 87, 4, 238
        ]
    )
}

#[test]
fn test_poseidon_bn254_x5_3_fq_input_invalid() {
    let params = bn254_x5_3::poseidon_parameters!(Fq);
    let mut poseidon = Poseidon::new(params);

    let input1 = Fq::from_be_bytes_mod_order(&[1u8; 32]);
    let input2 = Fq::from_be_bytes_mod_order(&[2u8; 32]);
    let input3 = Fq::from_be_bytes_mod_order(&[3u8; 32]);

    assert!(poseidon.hash(&[input1, input2, input3]).is_err());

    let input4 = Fq::from_be_bytes_mod_order(&[4u8; 32]);

    assert!(poseidon.hash(&[input1, input2, input3, input4]).is_err());
}

#[test]
fn test_poseidon_bn254_x5_3_fq_hash_bytes() {
    let params = bn254_x5_3::poseidon_parameters!(Fq);
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
