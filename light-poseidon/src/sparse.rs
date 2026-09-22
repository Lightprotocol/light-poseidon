//! Sparse factorization of the partial rounds, with lane 0 rescaled so the
//! S-box output enters the next lane 0 with coefficient 1.
//!
//! A partial round applies the S-box to `state[0]` only, but the reference
//! round still multiplies the state by the full MDS matrix, costing `width^2`
//! field multiplications. The standard optimization rewrites the partial-round
//! block into an equivalent one whose per-round matrix is the identity outside
//! its first row and first column, so a partial round costs `2 * width - 1`
//! multiplications instead.
//!
//! The construction and its round numbers are from
//! [Poseidon](https://eprint.iacr.org/2019/458) (Grassi, Khovratovich,
//! Rechberger, Roy and Schofnegger). The sparse factorization used here is the
//! one implemented by Filecoin's `neptune` and by circomlib's `poseidon_opt`.
//!
//! # Lane-0 rescaling
//!
//! One multiplication per round remains on the serial path: the first row
//! entry, `row[0]`, multiplies the S-box output. The constants here eliminate
//! it. Because `S(x / lambda) = S(x) / lambda^alpha` for the S-box exponent,
//! lane 0 can be carried scaled by `1 / lambda_i`, choosing
//! `lambda_{i+1} = row_i[0] * lambda_i^alpha` so that each round's scaled
//! lane 0 is exactly `head + rest`, where `rest` is the dot product of the
//! other lanes -- which does not depend on the S-box and is computed
//! alongside it. The scale factors move into the round constants, the
//! remaining row entries and the column; a single multiplication by
//! [`lambda_end`](SparseMdsParameters::lambda_end) after the last partial
//! round restores the true lane 0.
//!
//! Both rewrites are exact identities over the field, so hash outputs are
//! unchanged. The constants are derived and checked by
//! `cargo xtask generate-sparse-mds-parameters`, which compares the scaled
//! permutation against the unoptimized one for every bundled width.

use ark_ff::PrimeField;

/// Precomputed scaled-sparse factorization of a parameter set's partial
/// rounds.
///
/// All slices are `'static` for the same reason
/// [`PoseidonParameters`](crate::PoseidonParameters) holds borrowed data: the
/// bundled constants live in the binary, so constructing a hasher copies
/// pointers rather than allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseMdsParameters<F: PrimeField> {
    /// Replaces the MDS matrix in the last full round before the partial
    /// rounds. Flat row-major, `width * width` entries; entry `(i, j)` is at
    /// `i * width + j`.
    pub pre: &'static [F],
    /// One scaled sparse matrix per partial round, in application order.
    ///
    /// Each matrix occupies `2 * width - 2` consecutive entries: its first
    /// row without the leading entry (`width - 1` entries, rescaled as
    /// described in the module documentation), followed by its first column
    /// below the diagonal (`width - 1` entries, rescaled). The leading entry
    /// is not stored: after rescaling it is 1. Every other entry is the
    /// identity, so it is not stored either.
    pub matrices: &'static [F],
    /// One rescaled folded constant per partial round, added to `state[0]`
    /// before the S-box. Replaces the full-width round-constant rows of the
    /// partial rounds, whose remaining coordinates are accumulated into
    /// [`post`].
    ///
    /// [`post`]: Self::post
    pub ark: &'static [F],
    /// Added to the state once, after the last partial round. `width` entries.
    pub post: &'static [F],
    /// Undoes the accumulated lane-0 rescaling: multiplied into `state[0]`
    /// once, after the last partial round. See the module documentation.
    pub lambda_end: &'static F,
}

impl<F: PrimeField> SparseMdsParameters<F> {
    /// Assembles the parameters without checking their dimensions.
    ///
    /// Used by the generated constant tables, whose dimensions are checked
    /// when they are derived.
    pub const fn new_unchecked(
        pre: &'static [F],
        matrices: &'static [F],
        ark: &'static [F],
        post: &'static [F],
        lambda_end: &'static F,
    ) -> Self {
        Self {
            pre,
            matrices,
            ark,
            post,
            lambda_end,
        }
    }

    /// Returns whether this factorization can drive `permute` for the given
    /// round structure.
    ///
    /// Checked once, up front, so the partial-round path can be total.
    ///
    /// `full_rounds` must be at least 2: the pre-sparse matrix is absorbed by
    /// the last full round before the partial ones, so there has to be one.
    ///
    /// This returns a `bool` rather than a `Result` so the caller picks the
    /// error. [`PoseidonError`](crate::PoseidonError) cannot grow a variant:
    /// `solana-poseidon` matches it exhaustively in
    /// `From<PoseidonError> for PoseidonSyscallError`, so a new one breaks
    /// Agave's compilation even with every signature unchanged.
    pub fn fits(&self, width: usize, full_rounds: usize, partial_rounds: usize) -> bool {
        // Saturating rather than checked: a width large enough to overflow
        // cannot match any real slice length, so it falls out as an ordinary
        // mismatch.
        let entries_per_matrix = width.saturating_mul(2).saturating_sub(2);

        full_rounds >= 2
            && width != 0
            && self.pre.len() == width.saturating_mul(width)
            && self.matrices.len() == partial_rounds.saturating_mul(entries_per_matrix)
            && self.ark.len() == partial_rounds
            && self.post.len() == width
    }
}
