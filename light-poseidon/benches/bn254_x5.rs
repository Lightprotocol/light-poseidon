use ark_bn254::Fr;
use ark_ff::PrimeField;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;

use light_poseidon::{parameters::bn254_x5, Poseidon, PoseidonHasher};

pub fn bench_poseidon_bn254_x5(c: &mut Criterion) {


    // let random_bytes2 = rand::thread_rng().gen::<[u8; 32]>();
    // let input1 = Fr::from_be_bytes_mod_order(&random_bytes1);
    // let input2 = Fr::from_be_bytes_mod_order(&random_bytes2);
    let mut inputs = Vec::new();
    for i in 2..18 {
        let params = bn254_x5::get_poseidon_parameters(i);
        let mut poseidon = Poseidon::new(params);
        let name = [String::from("poseidon_bn254_x5_"), i.to_string()].concat();
        let random_bytes1 = Fr::from_be_bytes_mod_order(&rand::thread_rng().gen::<[u8; 32]>());
        inputs.push(random_bytes1);
        c.bench_function(&name, |b| {
            b.iter(|| poseidon.hash(&inputs[..]))
        });
    }

}

criterion_group!(benches, bench_poseidon_bn254_x5);
criterion_main!(benches);
