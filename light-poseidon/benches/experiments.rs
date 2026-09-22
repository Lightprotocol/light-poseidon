//! Width-3 optimization experiments, all compared in one process.
//!
//! Every variant is checked against the library's own output before being
//! benchmarked, so a variant that is fast and wrong cannot be reported.

use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use criterion::{criterion_group, criterion_main, Criterion};
use light_poseidon::{
    parameters::{bn254_x5, bn254_x5_sparse},
    Poseidon, PoseidonHasher,
};

const W: usize = 3;

#[inline(always)]
fn sbox(a: Fr) -> Fr {
    let x2 = a.square();
    let x4 = x2.square();
    x4 * a
}

fn arr3(s: &[Fr]) -> [Fr; 3] {
    let mut out = [Fr::zero(); 3];
    for (o, v) in out.iter_mut().zip(s) {
        *o = *v;
    }
    out
}

fn arr2(s: &[Fr]) -> [Fr; 2] {
    let mut out = [Fr::zero(); 2];
    for (o, v) in out.iter_mut().zip(s) {
        *o = *v;
    }
    out
}

/// Parameters pre-shaped into fixed-size arrays, as a const-generic
/// implementation would have them.
struct Prepared {
    ark: Vec<[Fr; W]>,
    mds: [[Fr; W]; W],
    pre: [[Fr; W]; W],
    sp_ark: Vec<Fr>,
    sp_row: Vec<[Fr; W]>,
    sp_col: Vec<[Fr; 2]>,
    post: [Fr; W],
    full_rounds: usize,
    partial_rounds: usize,
}

fn prepare() -> Prepared {
    let base = bn254_x5::get_poseidon_parameters(W as u8).expect("params");
    let sparse = bn254_x5_sparse::get_sparse_mds_parameters(W as u8).expect("sparse");

    let mds_rows: Vec<[Fr; W]> = base.mds.chunks_exact(W).map(arr3).collect();
    let pre_rows: Vec<[Fr; W]> = sparse.pre.chunks_exact(W).map(arr3).collect();

    let mut mds = [[Fr::zero(); W]; W];
    let mut pre = [[Fr::zero(); W]; W];
    for (dst, src) in mds.iter_mut().zip(&mds_rows) {
        *dst = *src;
    }
    for (dst, src) in pre.iter_mut().zip(&pre_rows) {
        *dst = *src;
    }

    let entries = 2 * W - 1;
    let sp_row: Vec<[Fr; W]> = sparse
        .matrices
        .chunks_exact(entries)
        .map(|m| arr3(m.get(..W).expect("row")))
        .collect();
    let sp_col: Vec<[Fr; 2]> = sparse
        .matrices
        .chunks_exact(entries)
        .map(|m| arr2(m.get(W..).expect("col")))
        .collect();

    Prepared {
        ark: base.ark.chunks_exact(W).map(arr3).collect(),
        mds,
        pre,
        sp_ark: sparse.ark.to_vec(),
        sp_row,
        sp_col,
        post: arr3(sparse.post),
        full_rounds: base.full_rounds,
        partial_rounds: base.partial_rounds,
    }
}

// ---------------------------------------------------------------- V1
// Fixed-size arrays + sum_of_products for the full-round MDS only.

#[inline(always)]
fn mds_sop(s: &[Fr; W], m: &[[Fr; W]; W]) -> [Fr; W] {
    let mut out = [Fr::zero(); W];
    for (o, row) in out.iter_mut().zip(m.iter()) {
        *o = Fr::sum_of_products::<W>(s, row);
    }
    out
}

#[inline(always)]
fn mds_plain(s: &[Fr; W], m: &[[Fr; W]; W]) -> [Fr; W] {
    let mut out = [Fr::zero(); W];
    for (o, row) in out.iter_mut().zip(m.iter()) {
        *o = s
            .iter()
            .zip(row.iter())
            .fold(Fr::zero(), |acc, (a, b)| acc + *a * *b);
    }
    out
}

#[inline(always)]
fn partial_block(p: &Prepared, s: &mut [Fr; W], sop_row: bool) {
    for ((c, row), col) in p.sp_ark.iter().zip(&p.sp_row).zip(&p.sp_col) {
        let head = sbox(s[0] + *c);
        s[0] = head;
        let mixed = if sop_row {
            Fr::sum_of_products::<W>(s, row)
        } else {
            s.iter()
                .zip(row.iter())
                .fold(Fr::zero(), |acc, (a, b)| acc + *a * *b)
        };
        s[1] += head * col[0];
        s[2] += head * col[1];
        s[0] = mixed;
    }
    for (l, c) in s.iter_mut().zip(p.post.iter()) {
        *l += *c;
    }
}

fn run(p: &Prepared, inputs: [Fr; 2], sop_full: bool, sop_row: bool, trim_last: bool) -> Fr {
    let mut s = [Fr::zero(), inputs[0], inputs[1]];
    let half = p.full_rounds / 2;
    let all = p.full_rounds + p.partial_rounds;

    for round in 0..half {
        let c = p.ark.get(round).expect("ark row");
        for (l, cc) in s.iter_mut().zip(c.iter()) {
            *l += *cc;
        }
        for l in s.iter_mut() {
            *l = sbox(*l);
        }
        let m = if round + 1 == half { &p.pre } else { &p.mds };
        s = if sop_full {
            mds_sop(&s, m)
        } else {
            mds_plain(&s, m)
        };
    }

    partial_block(p, &mut s, sop_row);

    let second_half_start = half + p.partial_rounds;
    for round in second_half_start..all {
        let c = p.ark.get(round).expect("ark row");
        for (l, cc) in s.iter_mut().zip(c.iter()) {
            *l += *cc;
        }
        for l in s.iter_mut() {
            *l = sbox(*l);
        }
        if trim_last && round + 1 == all {
            // Only lane 0 is returned, so the final round needs row 0 alone.
            let row = p.mds.first().expect("row 0");
            return Fr::sum_of_products::<W>(&s, row);
        }
        s = if sop_full {
            mds_sop(&s, &p.mds)
        } else {
            mds_plain(&s, &p.mds)
        };
    }

    s[0]
}

// ---------------------------------------------------------------- V4/V5
// Fully unrolled width-3, no loops over lanes.

#[inline(always)]
fn sop3(s: &[Fr; 3], row: &[Fr; 3]) -> Fr {
    Fr::sum_of_products::<3>(s, row)
}

fn run_unrolled(p: &Prepared, inputs: [Fr; 2], sop_row: bool) -> Fr {
    let mut a = Fr::zero();
    let mut b = inputs[0];
    let mut c = inputs[1];
    let half = p.full_rounds / 2;
    let all = p.full_rounds + p.partial_rounds;

    for round in 0..half {
        let k = p.ark.get(round).expect("ark row");
        a = sbox(a + k[0]);
        b = sbox(b + k[1]);
        c = sbox(c + k[2]);
        let m = if round + 1 == half { &p.pre } else { &p.mds };
        let s = [a, b, c];
        a = sop3(&s, &m[0]);
        b = sop3(&s, &m[1]);
        c = sop3(&s, &m[2]);
    }

    for ((k, row), col) in p.sp_ark.iter().zip(&p.sp_row).zip(&p.sp_col) {
        let head = sbox(a + *k);
        a = head;
        let s = [a, b, c];
        let mixed = if sop_row {
            sop3(&s, row)
        } else {
            a * row[0] + b * row[1] + c * row[2]
        };
        b += head * col[0];
        c += head * col[1];
        a = mixed;
    }
    a += p.post[0];
    b += p.post[1];
    c += p.post[2];

    let second_half_start = half + p.partial_rounds;
    for round in second_half_start..all {
        let k = p.ark.get(round).expect("ark row");
        a = sbox(a + k[0]);
        b = sbox(b + k[1]);
        c = sbox(c + k[2]);
        let s = [a, b, c];
        if round + 1 == all {
            return sop3(&s, &p.mds[0]);
        }
        a = sop3(&s, &p.mds[0]);
        b = sop3(&s, &p.mds[1]);
        c = sop3(&s, &p.mds[2]);
    }

    a
}

fn bench(c: &mut Criterion) {
    let p = prepare();
    let inputs = [Fr::from(1u64), Fr::from(2u64)];

    let mut lib = Poseidon::<Fr>::new_circom(2).expect("hasher");
    let expected = lib.hash(&inputs).expect("hash");

    // Every variant must reproduce the library's output.
    let checks: [(&str, Fr); 6] = [
        ("v1", run(&p, inputs, true, false, false)),
        ("v2", run(&p, inputs, true, true, false)),
        ("v3", run(&p, inputs, true, true, true)),
        ("v4", run_unrolled(&p, inputs, true)),
        ("v5", run_unrolled(&p, inputs, false)),
        ("v0_shape", run(&p, inputs, false, false, false)),
    ];
    for (name, got) in checks {
        assert_eq!(got, expected, "{name} diverged from the library");
    }

    let mut g = c.benchmark_group("w3");
    g.bench_function("v0_library", |bn| bn.iter(|| lib.hash(&inputs)));
    g.bench_function("v0_shape_no_sop", |bn| {
        bn.iter(|| run(&p, inputs, false, false, false))
    });
    g.bench_function("v1_sop_full_mds", |bn| {
        bn.iter(|| run(&p, inputs, true, false, false))
    });
    g.bench_function("v2_sop_full_and_sparse", |bn| {
        bn.iter(|| run(&p, inputs, true, true, false))
    });
    g.bench_function("v3_trim_last_round", |bn| {
        bn.iter(|| run(&p, inputs, true, true, true))
    });
    g.bench_function("v4_unrolled_sop_row", |bn| {
        bn.iter(|| run_unrolled(&p, inputs, true))
    });
    g.bench_function("v5_unrolled_plain_row", |bn| {
        bn.iter(|| run_unrolled(&p, inputs, false))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
