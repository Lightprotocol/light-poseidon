use ark_bn254::Fq;
use ark_ff::PrimeField;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;

use light_poseidon::{parameters::bn254_x5_3, PoseidonHasher};

pub fn bench_poseidon_bn254_x5_3(c: &mut Criterion) {
    let params = bn254_x5_3::poseidon_parameters();
    let mut poseidon = PoseidonHasher::new(params);

    let random_bytes1 = rand::thread_rng().gen::<[u8; 32]>();
    let random_bytes2 = rand::thread_rng().gen::<[u8; 32]>();
    let input1 = Fq::from_be_bytes_mod_order(&random_bytes1);
    let input2 = Fq::from_be_bytes_mod_order(&random_bytes2);

    c.bench_function("poseidon_bn254_x5_3", |b| {
        b.iter(|| poseidon.hash(&[input1, input2]))
    });
}

criterion_group!(benches, bench_poseidon_bn254_x5_3);
criterion_main!(benches);
