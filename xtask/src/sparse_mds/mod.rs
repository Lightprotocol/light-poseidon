//! Derivation of the sparse-MDS constants for the partial rounds.
//!
//! # What this computes
//!
//! A Poseidon partial round applies the S-box to `state[0]` only, but still
//! multiplies by the full `width x width` MDS matrix, so each partial round
//! costs `O(width^2)` field multiplications. The standard optimization, as
//! implemented by Filecoin's `neptune` and circomlib's `poseidon_opt`, rewrites
//! the whole partial-round block into an equivalent one whose per-round matrix
//! is *sparse*: the identity outside
//! its first row and first column. Applying such a matrix costs `2 * width - 1`
//! multiplications instead of `width^2`.
//!
//! Write the MDS matrix in block form, with `m00` a scalar, `w` and `v` vectors
//! of length `width - 1` and `m_hat` the `(width - 1) x (width - 1)` minor:
//!
//! ```text
//! M = | m00  w^T   |
//!     | v    m_hat |
//! ```
//!
//! Every matrix `M'` of the form `diag(1, N)` leaves coordinate 0 untouched, so
//! it commutes with the partial-round S-box `Sb`:
//!
//! ```text
//! Sb(M' x) = M' Sb(x)
//! ```
//!
//! and every `M` factors as `M = M_sparse * M'` with
//!
//! ```text
//! M_sparse = | m00               w^T m_hat^-1 |      M' = | 1  0     |
//!            | v                 I            |           | 0  m_hat |
//! ```
//!
//! Repeatedly factoring and commuting `M'` to the right turns the block
//!
//! ```text
//! M Sb M Sb ... M Sb M          (partial_rounds copies of "M Sb", then the
//!                                MDS of the preceding full round)
//! ```
//!
//! into
//!
//! ```text
//! M''_1 Sb M''_2 Sb ... M''_p Sb P
//! ```
//!
//! reading right to left, where `M_k = M'_{k-1} M` (with `M'_0 = I`) factors as
//! `M_k = M''_k M'_k`, and `P = M'_p M`. In application order the sparse
//! matrices therefore run *backwards*: `M''_p` is used by the first partial
//! round and `M''_1` by the last.
//!
//! # Round constants
//!
//! The reference implementation adds a full-width constant vector before every
//! partial round, but only coordinate 0 feeds the S-box. The other coordinates
//! commute through it, so they can be pushed forward through the linear layer
//! and accumulated. Writing `c_r` for round `r`'s constant vector, `s_r` for its
//! coordinate 0 and `rest_r` for the same vector with coordinate 0 zeroed:
//!
//! ```text
//! d = 0
//! for r in 0..partial_rounds:
//!     u          = d + c_r
//!     folded[r]  = u[0]
//!     d          = M * (u with coordinate 0 zeroed)
//! post = d
//! ```
//!
//! Each partial round then adds the single scalar `folded[r]` to `state[0]`,
//! and `post` is added to the state once after the last partial round.
//!
//! Both rewrites are exact identities over the field, so the permutation and
//! every hash output are unchanged. [`verify`] checks that claim directly
//! rather than trusting the derivation.

pub mod generate;
mod matrix;

use anyhow::anyhow;
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};

use matrix::solve;
pub use matrix::Matrix;

/// The parameters of one width, in the shape the derivation needs.
pub struct RoundParameters {
    pub width: usize,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub alpha: u64,
    /// Round constants, round-major: round `r` occupies `r * width..`.
    pub ark: Vec<Fr>,
    pub mds: Matrix,
}

impl RoundParameters {
    /// Loads the bundled BN254 parameters for width `t`.
    pub fn load(t: u8) -> Result<Self, anyhow::Error> {
        let params = light_poseidon::parameters::bn254_x5::get_poseidon_parameters(t)
            .map_err(|e| anyhow!("failed to load parameters for width {t}: {e}"))?;
        let mds = Matrix::from_flat(params.mds, params.width)?;
        if mds.order() != params.width {
            return Err(anyhow!(
                "MDS order {} does not match width {}",
                mds.order(),
                params.width
            ));
        }
        let expected_ark = params.width * (params.full_rounds + params.partial_rounds);
        if params.ark.len() != expected_ark {
            return Err(anyhow!(
                "ark has {} entries, expected {expected_ark}",
                params.ark.len()
            ));
        }
        Ok(Self {
            width: params.width,
            full_rounds: params.full_rounds,
            partial_rounds: params.partial_rounds,
            alpha: params.alpha,
            ark: params.ark.to_vec(),
            mds,
        })
    }

    fn ark_round(&self, round: usize) -> Result<&[Fr], anyhow::Error> {
        self.ark
            .get(round * self.width..(round + 1) * self.width)
            .ok_or_else(|| anyhow!("no ark constants for round {round}"))
    }
}

/// A matrix that is the identity outside its first row and first column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMatrix {
    /// The full first row, `width` entries.
    pub row: Vec<Fr>,
    /// The first column below the diagonal, `width - 1` entries.
    pub column: Vec<Fr>,
}

impl SparseMatrix {
    /// Expands back to a dense matrix, for verification.
    pub fn to_dense(&self) -> Result<Matrix, anyhow::Error> {
        let order = self.row.len();
        if self.column.len() + 1 != order {
            return Err(anyhow!(
                "sparse matrix has a {}-entry row and a {}-entry column",
                self.row.len(),
                self.column.len()
            ));
        }
        let mut dense = Matrix::identity(order)?;
        for (j, value) in self.row.iter().enumerate() {
            dense.set(0, j, *value)?;
        }
        for (i, value) in self.column.iter().enumerate() {
            dense.set(i + 1, 0, *value)?;
        }
        Ok(dense)
    }

    /// Applies the matrix to `state` in place.
    fn apply(&self, state: &mut [Fr]) -> Result<(), anyhow::Error> {
        if state.len() != self.row.len() {
            return Err(anyhow!(
                "state of length {} does not match a width-{} sparse matrix",
                state.len(),
                self.row.len()
            ));
        }
        let mut first = Fr::zero();
        for (value, coefficient) in state.iter().zip(self.row.iter()) {
            first += *value * *coefficient;
        }
        let head = *state
            .first()
            .ok_or_else(|| anyhow!("sparse matrix applied to an empty state"))?;
        for (value, coefficient) in state.iter_mut().skip(1).zip(self.column.iter()) {
            *value += head * *coefficient;
        }
        let head_slot = state
            .first_mut()
            .ok_or_else(|| anyhow!("sparse matrix applied to an empty state"))?;
        *head_slot = first;
        Ok(())
    }
}

/// Splits `matrix` into `(sparse, prime)` with `matrix == sparse * prime`.
///
/// `prime` is `diag(1, minor)` and so commutes with the partial-round S-box;
/// `sparse` is the identity outside its first row and column.
fn factorize(matrix: &Matrix) -> Result<(SparseMatrix, Matrix), anyhow::Error> {
    let order = matrix.order();
    if order < 2 {
        return Err(anyhow!("cannot factorize a matrix of order {order}"));
    }

    let minor = matrix.minor_00()?;

    // `w` is the first row without its leading entry, `v` the first column
    // without it.
    let mut w = Vec::with_capacity(order - 1);
    let mut v = Vec::with_capacity(order - 1);
    for i in 1..order {
        w.push(matrix.get(0, i)?);
        v.push(matrix.get(i, 0)?);
    }

    // The sparse factor's first row is `w^T minor^-1`, i.e. the solution of
    // `minor^T x = w`.
    let w_hat = solve(&minor.transpose()?, &w)?;

    let mut row = Vec::with_capacity(order);
    row.push(matrix.get(0, 0)?);
    row.extend_from_slice(&w_hat);

    let sparse = SparseMatrix { row, column: v };
    let prime = Matrix::from_minor_00(&minor)?;
    Ok((sparse, prime))
}

/// The derived constants for one width.
pub struct Optimized {
    /// Replaces the MDS matrix in the last full round before the partial
    /// rounds. Flat, row-major, `width * width`.
    pub pre: Matrix,
    /// One sparse matrix per partial round, in application order.
    pub matrices: Vec<SparseMatrix>,
    /// One folded constant per partial round, added to `state[0]` before the
    /// S-box.
    pub ark: Vec<Fr>,
    /// Added to the state once after the last partial round.
    pub post: Vec<Fr>,
}

/// Derives the sparse-MDS constants for one width.
pub fn derive(params: &RoundParameters) -> Result<Optimized, anyhow::Error> {
    let width = params.width;
    let partial_rounds = params.partial_rounds;

    // Sparse factorization. `prime` starts as the identity (`M'_0`); each step
    // factors `M'_{k-1} * M` and keeps the new `M'_k`.
    let mut prime = Matrix::identity(width)?;
    let mut matrices = Vec::with_capacity(partial_rounds);
    for _ in 0..partial_rounds {
        let product = prime.mul(&params.mds)?;
        let (sparse, next_prime) = factorize(&product)?;
        matrices.push(sparse);
        prime = next_prime;
    }
    let pre = prime.mul(&params.mds)?;
    // Generated as `M''_1 .. M''_p`, but applied in the opposite order.
    matrices.reverse();

    // Constant folding across the partial rounds.
    let half_rounds = params.full_rounds / 2;
    let mut carry = vec![Fr::zero(); width];
    let mut ark = Vec::with_capacity(partial_rounds);
    for round in half_rounds..half_rounds + partial_rounds {
        let round_ark = params.ark_round(round)?;
        let mut combined: Vec<Fr> = carry
            .iter()
            .zip(round_ark.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        let head = combined
            .first_mut()
            .ok_or_else(|| anyhow!("empty round constant vector"))?;
        ark.push(*head);
        *head = Fr::zero();
        carry = params.mds.mul_vec(&combined)?;
    }

    Ok(Optimized {
        pre,
        matrices,
        ark,
        post: carry,
    })
}

/// One partial round of the rescaled constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScaledRound {
    /// The first row without its leading entry, rescaled: `row[1..] /
    /// lambda_{i+1}`. `width - 1` entries.
    pub rest: Vec<Fr>,
    /// The first column below the diagonal, rescaled: `column * lambda_i^alpha`.
    /// `width - 1` entries.
    pub column: Vec<Fr>,
}

/// The rescaled constants for one width.
///
/// Lane 0 is carried through the partial rounds scaled by `1 / lambda_i`,
/// exploiting `S(x / lambda) = S(x) / lambda^alpha` for the S-box exponent.
/// Choosing `lambda_{i+1} = row_i[0] * lambda_i^alpha` makes the S-box
/// output's coefficient in the next scaled lane 0 exactly 1, so the round's
/// dot product runs over lanes 1.. only -- and does not depend on the S-box.
/// The scale factors move into the round constants, the remaining row
/// entries and the column; [`lambda_end`](Self::lambda_end) undoes the
/// accumulated scaling after the last partial round.
pub struct ScaledOptimized {
    /// Rescaled folded constants: `ark[i] / lambda_i`, one per partial round.
    pub ark: Vec<Fr>,
    /// One scaled round per partial round, in application order.
    pub rounds: Vec<ScaledRound>,
    /// `lambda` after the last partial round; multiplied into lane 0 once to
    /// restore its true value.
    pub lambda_end: Fr,
}

/// Rescales the derived constants, as documented on [`ScaledOptimized`].
///
/// Fails when a leading row entry is zero, which would make the rescaling
/// singular; no bundled width has one.
pub fn derive_scaled(
    params: &RoundParameters,
    optimized: &Optimized,
) -> Result<ScaledOptimized, anyhow::Error> {
    let alpha = params.alpha;
    let mut lambda = Fr::from(1u64);
    let mut ark = Vec::with_capacity(optimized.ark.len());
    let mut rounds = Vec::with_capacity(optimized.matrices.len());
    for (constant, matrix) in optimized.ark.iter().zip(optimized.matrices.iter()) {
        let row0 = matrix
            .row
            .first()
            .ok_or_else(|| anyhow!("width {}: sparse matrix has an empty row", params.width))?;
        let lambda_alpha = lambda.pow([alpha]);
        let next = *row0 * lambda_alpha;
        if next.is_zero() {
            return Err(anyhow!(
                "width {}: sparse matrix has a zero leading row entry, cannot rescale",
                params.width
            ));
        }
        let lambda_inv = lambda
            .inverse()
            .ok_or_else(|| anyhow!("zero accumulated scale factor"))?;
        let next_inv = next
            .inverse()
            .ok_or_else(|| anyhow!("zero next scale factor"))?;
        ark.push(*constant * lambda_inv);
        let rest = matrix.row[1..].iter().map(|r| *r * next_inv).collect();
        let column = matrix.column.iter().map(|c| *c * lambda_alpha).collect();
        rounds.push(ScaledRound { rest, column });
        lambda = next;
    }
    Ok(ScaledOptimized {
        ark,
        rounds,
        lambda_end: lambda,
    })
}

/// Raises `a` to the S-box exponent.
fn sbox(a: Fr, alpha: u64) -> Fr {
    match alpha {
        5 => {
            let x2 = a.square();
            let x4 = x2.square();
            x4 * a
        }
        4 => a.square().square(),
        _ => a.pow([alpha]),
    }
}

/// The unoptimized permutation, mirroring `light_poseidon`'s round loop.
pub fn permute_reference(params: &RoundParameters, state: &mut [Fr]) -> Result<(), anyhow::Error> {
    if state.len() != params.width {
        return Err(anyhow!(
            "state of length {} does not match width {}",
            state.len(),
            params.width
        ));
    }
    let all_rounds = params.full_rounds + params.partial_rounds;
    let half_rounds = params.full_rounds / 2;

    for round in 0..all_rounds {
        let round_ark = params.ark_round(round)?;
        for (value, constant) in state.iter_mut().zip(round_ark.iter()) {
            *value += *constant;
        }
        if round < half_rounds || round >= half_rounds + params.partial_rounds {
            for value in state.iter_mut() {
                *value = sbox(*value, params.alpha);
            }
        } else {
            let head = state
                .first_mut()
                .ok_or_else(|| anyhow!("empty state in a partial round"))?;
            *head = sbox(*head, params.alpha);
        }
        let mixed = params.mds.mul_vec(state)?;
        state.copy_from_slice(&mixed);
    }
    Ok(())
}

/// The optimized permutation, using the derived sparse constants.
pub fn permute_optimized(
    params: &RoundParameters,
    optimized: &Optimized,
    state: &mut [Fr],
) -> Result<(), anyhow::Error> {
    if state.len() != params.width {
        return Err(anyhow!(
            "state of length {} does not match width {}",
            state.len(),
            params.width
        ));
    }
    let all_rounds = params.full_rounds + params.partial_rounds;
    let half_rounds = params.full_rounds / 2;

    // First half of the full rounds. The last one mixes with `pre` instead of
    // the MDS matrix.
    for round in 0..half_rounds {
        let round_ark = params.ark_round(round)?;
        for (value, constant) in state.iter_mut().zip(round_ark.iter()) {
            *value += *constant;
        }
        for value in state.iter_mut() {
            *value = sbox(*value, params.alpha);
        }
        let matrix = if round + 1 == half_rounds {
            &optimized.pre
        } else {
            &params.mds
        };
        let mixed = matrix.mul_vec(state)?;
        state.copy_from_slice(&mixed);
    }

    // Partial rounds: one scalar constant, one S-box, one sparse matrix.
    for (constant, matrix) in optimized.ark.iter().zip(optimized.matrices.iter()) {
        let head = state
            .first_mut()
            .ok_or_else(|| anyhow!("empty state in a partial round"))?;
        *head = sbox(*head + *constant, params.alpha);
        matrix.apply(state)?;
    }
    for (value, constant) in state.iter_mut().zip(optimized.post.iter()) {
        *value += *constant;
    }

    // Second half of the full rounds, unchanged.
    for round in half_rounds + params.partial_rounds..all_rounds {
        let round_ark = params.ark_round(round)?;
        for (value, constant) in state.iter_mut().zip(round_ark.iter()) {
            *value += *constant;
        }
        for value in state.iter_mut() {
            *value = sbox(*value, params.alpha);
        }
        let mixed = params.mds.mul_vec(state)?;
        state.copy_from_slice(&mixed);
    }
    Ok(())
}

/// The scaled permutation: `permute_optimized` with the rescaled partial
/// block. Shares the full-round halves with it.
pub fn permute_scaled(
    params: &RoundParameters,
    optimized: &Optimized,
    scaled: &ScaledOptimized,
    state: &mut [Fr],
) -> Result<(), anyhow::Error> {
    if state.len() != params.width {
        return Err(anyhow!(
            "state of length {} does not match width {}",
            state.len(),
            params.width
        ));
    }
    let all_rounds = params.full_rounds + params.partial_rounds;
    let half_rounds = params.full_rounds / 2;

    // First half of the full rounds, identical to `permute_optimized`.
    for round in 0..half_rounds {
        let round_ark = params.ark_round(round)?;
        for (value, constant) in state.iter_mut().zip(round_ark.iter()) {
            *value += *constant;
        }
        for value in state.iter_mut() {
            *value = sbox(*value, params.alpha);
        }
        let matrix = if round + 1 == half_rounds {
            &optimized.pre
        } else {
            &params.mds
        };
        let mixed = matrix.mul_vec(state)?;
        state.copy_from_slice(&mixed);
    }

    // Partial rounds: the lanes-1.. dot product does not depend on the
    // S-box; the leading row entry is 1 after rescaling.
    for (constant, round) in scaled.ark.iter().zip(scaled.rounds.iter()) {
        let mut rest_dot = Fr::zero();
        for (value, coefficient) in state.iter().skip(1).zip(round.rest.iter()) {
            rest_dot += *value * *coefficient;
        }
        let head = state
            .first_mut()
            .ok_or_else(|| anyhow!("empty state in a partial round"))?;
        *head = sbox(*head + *constant, params.alpha);
        let head = *head;
        for (value, coefficient) in state.iter_mut().skip(1).zip(round.column.iter()) {
            *value += head * *coefficient;
        }
        let slot = state
            .first_mut()
            .ok_or_else(|| anyhow!("empty state in a partial round"))?;
        *slot = head + rest_dot;
    }
    let slot = state
        .first_mut()
        .ok_or_else(|| anyhow!("empty state after the partial rounds"))?;
    *slot *= scaled.lambda_end;
    for (value, constant) in state.iter_mut().zip(optimized.post.iter()) {
        *value += *constant;
    }

    // Second half of the full rounds, unchanged.
    for round in half_rounds + params.partial_rounds..all_rounds {
        let round_ark = params.ark_round(round)?;
        for (value, constant) in state.iter_mut().zip(round_ark.iter()) {
            *value += *constant;
        }
        for value in state.iter_mut() {
            *value = sbox(*value, params.alpha);
        }
        let mixed = params.mds.mul_vec(state)?;
        state.copy_from_slice(&mixed);
    }
    Ok(())
}

/// A deterministic byte source, so verification failures are reproducible.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn next_field(&mut self) -> Fr {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        Fr::from_le_bytes_mod_order(&bytes)
    }
}

/// Checks the derived constants against the reference implementation.
///
/// Two independent checks: the matrix identities the derivation is built on,
/// and end-to-end equality of the two permutations on pseudo-random states.
pub fn verify(
    params: &RoundParameters,
    optimized: &Optimized,
    rounds: usize,
) -> Result<(), anyhow::Error> {
    let width = params.width;

    if optimized.matrices.len() != params.partial_rounds {
        return Err(anyhow!(
            "width {width}: derived {} sparse matrices, expected {}",
            optimized.matrices.len(),
            params.partial_rounds
        ));
    }
    if optimized.ark.len() != params.partial_rounds {
        return Err(anyhow!(
            "width {width}: derived {} folded constants, expected {}",
            optimized.ark.len(),
            params.partial_rounds
        ));
    }
    if optimized.post.len() != width {
        return Err(anyhow!(
            "width {width}: post vector has {} entries, expected {width}",
            optimized.post.len()
        ));
    }

    // Replay the factorization chain and check every step, plus `pre`. The
    // matrices are stored in application order, so walk them backwards.
    let mut prime = Matrix::identity(width)?;
    for (step, sparse) in optimized.matrices.iter().rev().enumerate() {
        let expected = prime.mul(&params.mds)?;
        let dense = sparse.to_dense()?;
        let next_prime = {
            // Recover `M'_k` from the identity `M_k = M''_k M'_k`, using the
            // minor of `M_k` directly, then confirm the product.
            let minor = expected.minor_00()?;
            Matrix::from_minor_00(&minor)?
        };
        if dense.mul(&next_prime)? != expected {
            return Err(anyhow!(
                "width {width}: sparse factorization does not reconstruct the product at step {step}"
            ));
        }
        prime = next_prime;
    }
    if prime.mul(&params.mds)? != optimized.pre {
        return Err(anyhow!(
            "width {width}: pre-sparse matrix does not match the factorization chain"
        ));
    }

    // End-to-end equality on pseudo-random states.
    let mut rng = Rng(0x0123_4567_89ab_cdef ^ (width as u64));
    for round in 0..rounds {
        let input: Vec<Fr> = (0..width).map(|_| rng.next_field()).collect();
        let mut reference = input.clone();
        let mut candidate = input.clone();
        permute_reference(params, &mut reference)?;
        permute_optimized(params, optimized, &mut candidate)?;
        if reference != candidate {
            return Err(anyhow!(
                "width {width}: optimized permutation differs from the reference on sample {round}"
            ));
        }
    }

    // Boundary states the random sampler will not reach.
    for state in [vec![Fr::zero(); width], vec![Fr::from(1u64); width]] {
        let mut reference = state.clone();
        let mut candidate = state;
        permute_reference(params, &mut reference)?;
        permute_optimized(params, optimized, &mut candidate)?;
        if reference != candidate {
            return Err(anyhow!(
                "width {width}: optimized permutation differs from the reference on a boundary state"
            ));
        }
    }

    Ok(())
}

/// Checks the rescaled constants against the derived ones and against the
/// reference permutation.
///
/// The algebraic identities are checked in inverse-free form: with `lambda`
/// replayed from the unscaled rows, `scaled.ark[i] * lambda_i == ark[i]`,
/// `scaled.rest[i][j] * lambda_{i+1} == row_i[j + 1]` and
/// `scaled.column[i][j] == column_i[j] * lambda_i^alpha`. End-to-end
/// equality with the reference permutation is checked on the same samples
/// as [`verify`].
pub fn verify_scaled(
    params: &RoundParameters,
    optimized: &Optimized,
    scaled: &ScaledOptimized,
    rounds: usize,
) -> Result<(), anyhow::Error> {
    let width = params.width;

    if scaled.rounds.len() != params.partial_rounds || scaled.ark.len() != params.partial_rounds {
        return Err(anyhow!(
            "width {width}: scaled constants cover {} rounds with {} constants, expected {}",
            scaled.rounds.len(),
            scaled.ark.len(),
            params.partial_rounds
        ));
    }

    let mut lambda = Fr::from(1u64);
    for (i, (matrix, round)) in optimized
        .matrices
        .iter()
        .zip(scaled.rounds.iter())
        .enumerate()
    {
        if round.rest.len() + 1 != width || round.column.len() + 1 != width {
            return Err(anyhow!(
                "width {width}: scaled round {i} has wrong dimensions"
            ));
        }
        if scaled.ark[i] * lambda != optimized.ark[i] {
            return Err(anyhow!(
                "width {width}: scaled round constant {i} does not match the derivation"
            ));
        }
        let lambda_alpha = lambda.pow([params.alpha]);
        let next = *matrix
            .row
            .first()
            .ok_or_else(|| anyhow!("width {width}: sparse matrix {i} has an empty row"))?
            * lambda_alpha;
        for (j, (rest, row)) in round.rest.iter().zip(matrix.row[1..].iter()).enumerate() {
            if *rest * next != *row {
                return Err(anyhow!(
                    "width {width}: scaled rest entry ({i}, {j}) does not match the derivation"
                ));
            }
        }
        for (j, (column, expected)) in round.column.iter().zip(matrix.column.iter()).enumerate() {
            if *column != *expected * lambda_alpha {
                return Err(anyhow!(
                    "width {width}: scaled column entry ({i}, {j}) does not match the derivation"
                ));
            }
        }
        lambda = next;
    }
    if scaled.lambda_end != lambda {
        return Err(anyhow!(
            "width {width}: lambda_end does not match the replayed scale factor"
        ));
    }

    // End-to-end equality on pseudo-random and boundary states.
    let mut rng = Rng(0x0123_4567_89ab_cdef ^ (width as u64));
    for round in 0..rounds {
        let input: Vec<Fr> = (0..width).map(|_| rng.next_field()).collect();
        let mut reference = input.clone();
        let mut candidate = input.clone();
        permute_reference(params, &mut reference)?;
        permute_scaled(params, optimized, scaled, &mut candidate)?;
        if reference != candidate {
            return Err(anyhow!(
                "width {width}: scaled permutation differs from the reference on sample {round}"
            ));
        }
    }
    for state in [vec![Fr::zero(); width], vec![Fr::from(1u64); width]] {
        let mut reference = state.clone();
        let mut candidate = state;
        permute_reference(params, &mut reference)?;
        permute_scaled(params, optimized, scaled, &mut candidate)?;
        if reference != candidate {
            return Err(anyhow!(
                "width {width}: scaled permutation differs from the reference on a boundary state"
            ));
        }
    }

    Ok(())
}

/// Formats one field element as the expression `Fr::new(BigInteger256::new([..]))`.
pub fn field_element_expr(element: &Fr) -> String {
    let limbs = element.into_bigint().0;
    let rendered: Vec<String> = limbs.iter().map(|limb| limb.to_string()).collect();
    format!("Fr::new(BigInteger256::new([{}]))", rendered.join(", "))
}

/// Formats one field element as a single-line `Fr::new(BigInteger256::new([..]))`.
pub fn format_field_element(element: &Fr) -> String {
    format!("    {},\n", field_element_expr(element))
}
