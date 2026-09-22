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

/// Hashing byte inputs with a hasher that is built once and reused.
///
/// The byte path has its own parser and serializer, neither of which the field
/// benchmark above exercises.
pub fn bench_poseidon_bn254_x5_bytes(c: &mut Criterion) {
    let mut storage: Vec<[u8; 32]> = Vec::new();
    for i in 1..13 {
        storage.push(rand::thread_rng().gen::<[u8; 32]>());
        // Clear the top byte so the value is always below the modulus.
        if let Some(last) = storage.last_mut() {
            if let Some(first_byte) = last.first_mut() {
                *first_byte = 0;
            }
        }
        let inputs: Vec<&[u8]> = storage.iter().map(|b| b.as_slice()).collect();

        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
        let name = [String::from("poseidon_bn254_x5_bytes_be_"), i.to_string()].concat();
        c.bench_function(&name, |b| b.iter(|| hasher.hash_bytes_be(&inputs)));

        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
        let name = [String::from("poseidon_bn254_x5_bytes_le_"), i.to_string()].concat();
        c.bench_function(&name, |b| b.iter(|| hasher.hash_bytes_le(&inputs)));
    }
}

/// The shape `solana_poseidon::hashv` actually uses: a hasher is constructed on
/// every call, so parameter construction is timed alongside the permutation.
pub fn bench_poseidon_bn254_x5_syscall_shape(c: &mut Criterion) {
    let mut storage: Vec<[u8; 32]> = Vec::new();
    for i in 1..13 {
        storage.push(rand::thread_rng().gen::<[u8; 32]>());
        if let Some(last) = storage.last_mut() {
            if let Some(first_byte) = last.first_mut() {
                *first_byte = 0;
            }
        }
        let inputs: Vec<&[u8]> = storage.iter().map(|b| b.as_slice()).collect();

        let name = [String::from("poseidon_bn254_x5_syscall_"), i.to_string()].concat();
        c.bench_function(&name, |b| {
            b.iter(|| {
                let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();
                hasher.hash_bytes_be(&inputs)
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
