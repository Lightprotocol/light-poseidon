//! A BN254-`Fr` copy of the permutation core, reached through [`TypeId`].
//!
//! Why this module exists: rustc's MIR inliner runs before monomorphization,
//! so it can inline `Fr::square` and the other field primitives into
//! *concrete* callers. A call through a type parameter --
//! `<F as Field>::square` -- is not inlinable there, and LLVM's cost model
//! then keeps the wide Montgomery bodies as outline calls, with the state
//! round-tripping through memory between them. Measured at width 3 on arm64,
//! the generic path costs ~12% more per hash (5.6 us against 4.9 us).
//!
//! The crate's bundled parameters are all BN254, so the concrete copy serves
//! every caller that uses them; the generic path in `lib.rs` remains for any
//! other field. Both paths are the same algorithm, statement for statement;
//! `tests` runs every bundled width through each and requires agreement.

use core::any::TypeId;

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};

use crate::{PoseidonError, PoseidonParameters, SparseMdsParameters, MAX_X5_LEN};

/// Casts the parameters and state to BN254 when `F` is `Fr`, selecting the
/// concretely-compiled permutation this module exists to provide (see the
/// module docs). Returns `None` for any other field, sending the caller down
/// the generic path.
pub fn downcast<'a, F: PrimeField>(
    params: &'a PoseidonParameters<F>,
    state: &'a mut [F],
) -> Option<(&'a PoseidonParameters<Fr>, &'a mut [Fr])> {
    if TypeId::of::<F>() != TypeId::of::<Fr>() {
        return None;
    }
    // SAFETY: `TypeId` equality means `F` and `Fr` are the same type, so the
    // reinterprets change nothing: same layout, same lifetime, same aliasing.
    let params =
        unsafe { &*(params as *const PoseidonParameters<F> as *const PoseidonParameters<Fr>) };
    let state = unsafe { &mut *(state as *mut [F] as *mut [Fr]) };
    Some((params, state))
}

/// Casts a hash output back to `F`; the counterpart of [`downcast`]. Only
/// reached when `downcast` returned `Some`, so `F` is `Fr`.
pub fn upcast<F: PrimeField>(x: Fr) -> F {
    debug_assert_eq!(TypeId::of::<F>(), TypeId::of::<Fr>());
    // SAFETY: `F` is `Fr` here, so this changes nothing; `Fr` is `Copy`, so
    // no ownership is duplicated either.
    unsafe { core::mem::transmute_copy::<Fr, F>(&x) }
}

/// Raises `a` to the S-box exponent; see the generic `sbox` in `lib.rs`.
#[inline(always)]
fn sbox(a: Fr, alpha: u64) -> Fr {
    match alpha {
        5 => {
            let x2 = a.square();
            let x4 = x2.square();
            x4 * a
        }
        4 => a.square().square(),
        _ => sbox_pow(a, alpha),
    }
}

/// The S-box for exponents without a hardcoded chain; see `sbox_pow` in
/// `lib.rs`.
#[cold]
#[inline(never)]
fn sbox_pow(a: Fr, alpha: u64) -> Fr {
    a.pow([alpha])
}

/// One full round; see `full_round_w` in `lib.rs`.
#[inline(always)]
fn full_round_w<const W: usize>(
    state: &mut [Fr; W],
    constants: &[Fr; W],
    matrix: &[[Fr; W]; W],
    alpha: u64,
) {
    for (lane, constant) in state.iter_mut().zip(constants) {
        *lane += *constant;
    }
    for lane in state.iter_mut() {
        *lane = sbox(*lane, alpha);
    }
    let mut next = [Fr::zero(); W];
    for (out, row) in next.iter_mut().zip(matrix.iter()) {
        *out = Fr::sum_of_products(state, row);
    }
    *state = next;
}

/// Every partial round through the sparse factorization; see
/// `partial_rounds_sparse_w` in `lib.rs`.
#[inline(always)]
fn partial_rounds_sparse_w<const W: usize>(
    state: &mut [Fr; W],
    sparse: &SparseMdsParameters<Fr>,
    alpha: u64,
) {
    let entries_per_matrix = 2 * W - 1;

    for (constant, matrix) in sparse
        .ark
        .iter()
        .zip(sparse.matrices.chunks_exact(entries_per_matrix))
    {
        state[0] = sbox(state[0] + *constant, alpha);

        if let Some(row) = matrix
            .get(..W)
            .and_then(|row| <&[Fr; W]>::try_from(row).ok())
        {
            let column = matrix.get(W..).unwrap_or(&[]);
            let head = state[0];
            let mixed = Fr::sum_of_products(state, row);
            for (lane, coefficient) in state.iter_mut().skip(1).zip(column) {
                *lane += head * *coefficient;
            }
            state[0] = mixed;
        }
    }

    for (lane, constant) in state.iter_mut().zip(sparse.post.iter()) {
        *lane += *constant;
    }
}

/// The permutation core; see `permute_w` in `lib.rs`. Dimensions were checked
/// by the caller, [`permute`], so the conversions below cannot fail.
///
/// Deliberately *not* inlined into `permute`: with twelve widths inlined
/// there, the dispatcher becomes one enormous function and the individual
/// permutation bodies optimize measurably worse.
#[inline(never)]
fn permute_w<const W: usize>(
    params: &PoseidonParameters<Fr>,
    state: &mut [Fr],
) -> Result<Fr, PoseidonError> {
    let PoseidonParameters {
        ark,
        mds,
        full_rounds,
        partial_rounds,
        width,
        alpha,
        sparse,
    } = *params;

    let dimension_error = || PoseidonError::InvalidWidthCircom {
        width,
        max_limit: MAX_X5_LEN,
    };

    let state: &mut [Fr; W] = <&mut [Fr; W]>::try_from(state).map_err(|_| dimension_error())?;

    let half_rounds = full_rounds / 2;

    let ark_rounds = ark.as_chunks::<W>().0;
    let mds_rows: &[[Fr; W]; W] =
        <&[[Fr; W]; W]>::try_from(mds.as_chunks::<W>().0).map_err(|_| dimension_error())?;
    let pre_rows = match sparse {
        Some(sparse) => Some(
            <&[[Fr; W]; W]>::try_from(sparse.pre.as_chunks::<W>().0)
                .map_err(|_| dimension_error())?,
        ),
        None => None,
    };

    // First half of the full rounds. The last of them mixes with the
    // pre-sparse matrix when a factorization is attached; it carries the
    // linear factor the factorization pushes out of the partial block.
    let first_half = ark_rounds.get(..half_rounds).ok_or_else(dimension_error)?;
    for (round, constants) in first_half.iter().enumerate() {
        let matrix = match pre_rows {
            Some(pre_rows) if round + 1 == half_rounds => pre_rows,
            _ => mds_rows,
        };
        full_round_w(state, constants, matrix, alpha);
    }

    // The partial block. With a factorization attached it runs through the
    // sparse form; without one, each round applies the S-box to lane zero
    // alone but still multiplies by the full MDS matrix.
    match sparse {
        Some(sparse) => partial_rounds_sparse_w(state, &sparse, alpha),
        None => {
            let partial_ark = ark_rounds
                .get(half_rounds..half_rounds.saturating_add(partial_rounds))
                .ok_or_else(dimension_error)?;
            for constants in partial_ark {
                for (lane, constant) in state.iter_mut().zip(constants) {
                    *lane += *constant;
                }
                if let Some(first) = state.first_mut() {
                    *first = sbox(*first, alpha);
                }
                let mut next = [Fr::zero(); W];
                for (out, row) in next.iter_mut().zip(mds_rows.iter()) {
                    *out = Fr::sum_of_products(state, row);
                }
                *state = next;
            }
        }
    }

    // Second half of the full rounds. Only lane zero of the final round is
    // read, so its MDS application collapses to a single dot product.
    let second_half = ark_rounds
        .get(half_rounds.saturating_add(partial_rounds)..)
        .ok_or_else(dimension_error)?;
    if let Some((last_constants, earlier)) = second_half.split_last() {
        for constants in earlier {
            full_round_w(state, constants, mds_rows, alpha);
        }
        for (lane, constant) in state.iter_mut().zip(last_constants) {
            *lane += *constant;
        }
        for lane in state.iter_mut() {
            *lane = sbox(*lane, alpha);
        }
        let row = mds_rows.first().ok_or_else(dimension_error)?;
        return Ok(Fr::sum_of_products(state, row));
    }

    // Reaching here means the parameters declared no second-half full rounds;
    // the up-front `ark` length check passes for such parameters (all rounds
    // partial), and the output is lane zero as it was before.
    state.first().copied().ok_or_else(dimension_error)
}

/// Dispatches to the permutation monomorphized for the state width.
///
/// Called from [`Poseidon::permute`](crate::Poseidon), which has already
/// checked the parameter dimensions, so every conversion in `permute_w` is
/// guaranteed by the time it runs.
pub fn permute(params: &PoseidonParameters<Fr>, state: &mut [Fr]) -> Result<Fr, PoseidonError> {
    let width = params.width;
    let dimension_error = || PoseidonError::InvalidWidthCircom {
        width,
        max_limit: MAX_X5_LEN,
    };

    macro_rules! dispatch {
        ($($w:literal),+ $(,)?) => {
            match width {
                $($w => permute_w::<$w>(params, state),)+
                _ => Err(dimension_error()),
            }
        };
    }
    dispatch!(2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parameters, Poseidon, PoseidonHasher};

    /// The generic and concrete permutation cores are two copies of the same
    /// algorithm. Run every bundled width through both, with and without the
    /// sparse factorization, and require identical outputs.
    #[test]
    fn generic_and_concrete_paths_agree() {
        for inputs in 1usize..MAX_X5_LEN {
            let input: Vec<Fr> = (0..inputs).map(|i| Fr::from(i as u64 + 7)).collect();

            // `new_circom` attaches the sparse factorization; the plain
            // parameter set exercises the reference partial rounds.
            let mut sparse_hasher = Poseidon::<Fr>::new_circom(inputs).expect("params");
            let plain_params =
                parameters::bn254_x5::get_poseidon_parameters((inputs + 1) as u8).expect("params");
            let mut plain_hasher = Poseidon::<Fr>::new(plain_params).expect("hasher");

            for hasher in [&mut sparse_hasher, &mut plain_hasher] {
                let fast = hasher.hash(&input).expect("hash");

                // The generic core, driven directly: it is a private method,
                // so the fast path in `permute` is not involved.
                let width = hasher.parameters().width;
                let mut state = [Fr::zero(); MAX_X5_LEN];
                state[1..=inputs].copy_from_slice(&input);
                let generic = match width {
                    2 => hasher.permute_w::<2>(&mut state[..width]),
                    3 => hasher.permute_w::<3>(&mut state[..width]),
                    4 => hasher.permute_w::<4>(&mut state[..width]),
                    5 => hasher.permute_w::<5>(&mut state[..width]),
                    6 => hasher.permute_w::<6>(&mut state[..width]),
                    7 => hasher.permute_w::<7>(&mut state[..width]),
                    8 => hasher.permute_w::<8>(&mut state[..width]),
                    9 => hasher.permute_w::<9>(&mut state[..width]),
                    10 => hasher.permute_w::<10>(&mut state[..width]),
                    11 => hasher.permute_w::<11>(&mut state[..width]),
                    12 => hasher.permute_w::<12>(&mut state[..width]),
                    13 => hasher.permute_w::<13>(&mut state[..width]),
                    other => panic!("unexpected width {other}"),
                }
                .expect("generic permute");

                assert_eq!(fast, generic, "width {width}: fast path diverged");
            }
        }
    }
}
