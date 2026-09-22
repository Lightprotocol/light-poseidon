//! Measures the sparse partial rounds against the unoptimized ones.
//!
//! Both hashers run in the same process on the same inputs, so the comparison
//! does not depend on machine state between runs.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use light_poseidon::{
    parameters::{bn254_x5, bn254_x5_sparse},
    Poseidon, PoseidonHasher,
};
use rand::{rngs::StdRng, SeedableRng};

fn bench_sparse_mds(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x5041_5253_4530_0004);
    let mut group = c.benchmark_group("partial_rounds");

    for t in 2u8..=13 {
        let width = usize::from(t);
        let inputs: Vec<Fr> = (0..width - 1).map(|_| Fr::rand(&mut rng)).collect();

        let reference_params = bn254_x5::get_poseidon_parameters(t).unwrap();
        let sparse_params = bn254_x5::get_poseidon_parameters(t)
            .unwrap()
            .with_sparse_mds(bn254_x5_sparse::get_sparse_mds_parameters(t).unwrap())
            .unwrap();

        let mut reference = Poseidon::new(reference_params).unwrap();
        let mut sparse = Poseidon::new(sparse_params).unwrap();

        group.bench_with_input(BenchmarkId::new("full_mds", t), &t, |b, _| {
            b.iter(|| reference.hash(&inputs).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("sparse_mds", t), &t, |b, _| {
            b.iter(|| sparse.hash(&inputs).unwrap())
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sparse_mds);
criterion_main!(benches);
