//! Sparse factorization of the partial rounds.
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
//! The rewrite is an exact identity over the field, so hash outputs are
//! unchanged. The constants are derived and checked by
//! `cargo xtask generate-sparse-mds-parameters`, which compares the optimized
//! permutation against the unoptimized one for every bundled width.

use ark_ff::PrimeField;

/// Precomputed sparse factorization of a parameter set's partial rounds.
///
/// All four slices are `'static` for the same reason
/// [`PoseidonParameters`](crate::PoseidonParameters) holds borrowed data: the
/// bundled constants live in the binary, so constructing a hasher copies four
/// pointers rather than allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseMdsParameters<F: PrimeField> {
    /// Replaces the MDS matrix in the last full round before the partial
    /// rounds. Flat row-major, `width * width` entries; entry `(i, j)` is at
    /// `i * width + j`.
    pub pre: &'static [F],
    /// One sparse matrix per partial round, in application order.
    ///
    /// Each matrix occupies `2 * width - 1` consecutive entries: its first row
    /// (`width` entries), followed by its first column below the diagonal
    /// (`width - 1` entries). Every other entry is the identity, so it is not
    /// stored.
    pub matrices: &'static [F],
    /// One folded constant per partial round, added to `state[0]` before the
    /// S-box. Replaces the full-width round-constant rows of the partial
    /// rounds, whose remaining coordinates are accumulated into [`post`].
    ///
    /// [`post`]: Self::post
    pub ark: &'static [F],
    /// Added to the state once, after the last partial round. `width` entries.
    pub post: &'static [F],
}

impl<F: PrimeField> SparseMdsParameters<F> {
    /// Assembles the parameters without checking their dimensions.
    ///
    /// Used by the generated constant tables, whose dimensions are checked when
    /// they are derived. Prefer [`new`](Self::new) for anything else.
    pub const fn new_unchecked(
        pre: &'static [F],
        matrices: &'static [F],
        ark: &'static [F],
        post: &'static [F],
    ) -> Self {
        Self {
            pre,
            matrices,
            ark,
            post,
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
        let entries_per_matrix = width.saturating_mul(2).saturating_sub(1);

        full_rounds >= 2
            && width != 0
            && self.pre.len() == width.saturating_mul(width)
            && self.matrices.len() == partial_rounds.saturating_mul(entries_per_matrix)
            && self.ark.len() == partial_rounds
            && self.post.len() == width
    }
}
