use ark_bn254::Fr;
use ark_ff::PrimeField;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;

use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher};

/// Hashing field elements with a hasher that is built once and reused.
pub fn bench_poseidon_bn254_x5(c: &mut Criterion) {
    let mut inputs = Vec::new();
    for i in 1..13 {
        let name = [String::from("poseidon_bn254_x5_"), i.to_string()].concat();
        let random_bytes1 = Fr::from_be_bytes_mod_order(&rand::thread_rng().gen::<[u8; 32]>());
        inputs.push(random_bytes1);
        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();

        c.bench_function(&name, |b| b.iter(|| hasher.hash(&inputs[..])));
    }
}

/// Produces a random 32-byte value that is below the BN254 modulus when read as
/// either big-endian or little-endian.
///
/// Zeroing only one end is a trap: the byte that is most significant depends on
/// the endianness, and the modulus starts at 0x30, so a random most significant
/// byte is above it roughly 81% of the time. Zeroing both ends makes the value
/// valid whichever way it is read.
fn random_input() -> [u8; 32] {
    let mut bytes = rand::thread_rng().gen::<[u8; 32]>();
    if let Some(byte) = bytes.first_mut() {
        *byte = 0;
    }
    if let Some(byte) = bytes.last_mut() {
        *byte = 0;
    }
    bytes
}

/// Hashing byte inputs with a hasher that is built once and reused.
///
/// The byte path has its own parser and serializer, neither of which the field
/// benchmark above exercises.
///
/// Every result is unwrapped. A benchmark that discards the `Result` will
/// happily report the timing of an early error return as if it were a hash.
pub fn bench_poseidon_bn254_x5_bytes(c: &mut Criterion) {
    let mut storage: Vec<[u8; 32]> = Vec::new();
    for i in 1..13 {
        storage.push(random_input());
        let inputs: Vec<&[u8]> = storage.iter().map(|b| b.as_slice()).collect();

        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
        let name = [String::from("poseidon_bn254_x5_bytes_be_"), i.to_string()].concat();
        c.bench_function(&name, |b| b.iter(|| hasher.hash_bytes_be(&inputs).unwrap()));

        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
        let name = [String::from("poseidon_bn254_x5_bytes_le_"), i.to_string()].concat();
        c.bench_function(&name, |b| b.iter(|| hasher.hash_bytes_le(&inputs).unwrap()));
    }
}

/// The shape `solana_poseidon::hashv` actually uses: a hasher is constructed on
/// every call, so parameter construction is timed alongside the permutation.
pub fn bench_poseidon_bn254_x5_syscall_shape(c: &mut Criterion) {
    let mut storage: Vec<[u8; 32]> = Vec::new();
    for i in 1..13 {
        storage.push(random_input());
        let inputs: Vec<&[u8]> = storage.iter().map(|b| b.as_slice()).collect();

        let name = [String::from("poseidon_bn254_x5_syscall_"), i.to_string()].concat();
        c.bench_function(&name, |b| {
            b.iter(|| {
                let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
                hasher.hash_bytes_be(&inputs).unwrap()
            })
        });
    }
}

criterion_group!(
    benches,
    bench_poseidon_bn254_x5,
    bench_poseidon_bn254_x5_bytes,
    bench_poseidon_bn254_x5_syscall_shape
);
criterion_main!(benches);
