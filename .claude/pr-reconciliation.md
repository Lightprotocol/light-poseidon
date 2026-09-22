# Reconciliation of PRs #60, #61 and #54 (commit 1c9b2b6)

Recorded 2026-09-22. **Decisions only — nothing has been posted to GitHub and no
PR has been closed.**

These are the three open performance PRs that overlap the two branches now in
flight:

- **PR #64**, `perf/zero-alloc-poseidon`. `PoseidonParameters` holding
  `&'static [F]` with a flat row-major MDS, constants emitted as `static` arrays
  through the `const fn` `Fp::new`, stack state, fallible `Poseidon::new`,
  allocation-free byte path. Zero allocations per syscall.
- **`worktree-poseidon-perf-followups`**, local only, not pushed. Sparse
  factorization of the partial rounds, stacked on #64. Width 13 goes from
  123.76 us to 34.64 us.

Every decision below is contingent on #64 landing first.

---

## PR #60 — "Zip MDS rows in the inner `apply_mds` loop" (vadorovsky)

**Decision: close as superseded.**

The change replaces `self.params.mds[i][j]` with a zip over the row slice, worth
1-3% by its own measurements. #64 flattens `mds` to a single `&'static [F]`,
which removes the row-pointer chase the zip was working around, and removes the
per-row allocations as well. Landing #60 first would only create a conflict in a
method that #64 deletes.

### On the open disagreement

The review comment was that `zip` stops at the shorter iterator, so a malformed
short MDS row would silently drop terms instead of panicking — an empty first row
would make `hash` return `Ok(0)`. Michal's reply: generated parameters always
have `width`-long rows, the existing indexing would panic anyway, and a check on
the syscall hot path costs more than it is worth; he would accept it in xtask
instead.

That disagreement dissolves rather than needing a winner, and the thread should
say so. #64 gives `PoseidonParameters` two constructors:

- `new_unchecked`, used by the generated tables, which validates nothing.
- `new`, used for caller-supplied parameters, which rejects
  `mds.len() != width * width`.

Generated constants pay nothing, which is Michal's requirement. Untrusted input
is rejected at construction instead of silently mis-hashing, which is the
review's requirement. His objection was reasonable and is being honored, not
overruled — worth saying explicitly, since his reply was left unanswered.

## PR #61 — "Avoid heap allocations in state, input buffers and byte hash path" (vadorovsky)

**Decision: close as superseded.**

Right direction; #64 goes further in the same one. Three concrete differences:

1. **It does not touch the largest allocation source.** `PoseidonParameters`
   holding `Vec<F>` + `Vec<Vec<F>>` costs 5 allocations per call at width 2 and
   16 at width 13, on every `sol_poseidon` syscall, because
   `solana_poseidon::hashv` constructs a hasher per call
   (`solana-poseidon-5.0.0/src/lib.rs:253`). #61 leaves that untouched.
2. **Two reachable panics**, both raised in review and unaddressed. The
   `hash_bytes_*` macro fills `ArrayVec<F, MAX_INPUTS>` before `hash` validates
   the count, so 13 valid 32-byte inputs hit `CapacityError` instead of
   `InvalidNumberOfInputs`; and `state: ArrayVec<F, MAX_X5_LEN>` makes the Circom
   x5 bound the capacity for every hasher, so custom parameters with `width = 14`
   pass the input check and panic on the last push. #64 dissolves both — it
   validates width at construction and converts bytes straight into the state —
   rather than guarding them.
3. **It relaxes the modulus check.** #61 rewrites
   `bytes_to_prime_field_element_*` to drop the explicit `element >= F::MODULUS`
   comparison and rely on `from_bigint` returning `None`, and adds leading-zero
   trimming so over-long inputs are accepted. That comparison was added
   deliberately in `9746e79` ("Ensure that input doesn't exceed the modulus, this
   time for real", fixing #36) precisely because that path had been judged
   unreliable. Relaxing it is a security-relevant behaviour change bundled into a
   performance PR and is not mentioned in the description. #64 keeps the explicit
   comparison.

Point 3 is worth raising on the thread even though the PR is being closed,
because the same idea can come back in a later PR.

## PR #54 / commit 1c9b2b6 — "speed up poseidon with scratch reuse and pow5 fast-path"

**Decision: close as superseded. Half of it is already merged.**

- The `pow5` fast path landed as `Poseidon::sbox` in #59 and is on `main`.
- Scratch reuse (`mem::swap` between `state` and a persistent `scratch` `Vec`)
  removes the per-round `collect` allocation but keeps two heap buffers per
  hasher. #64 uses a stack array and keeps none.
- The width caching is subsumed by the same rewrite.

Nothing in it survives that is not already done or done better. Worth crediting
on the thread that #59 came from the same observation.

---

## Status of the other two follow-ups

**Sparse MDS — done**, on `worktree-poseidon-perf-followups`, local only, two
commits on top of #64. Verified by: the 144 frozen pre-rewrite vectors in
`tests/differential.rs`; a direct comparison of the sparse and unoptimized paths
for every width in `tests/sparse_mds.rs` (512 random inputs each, boundary
values, both endiannesses, hasher reuse); `tests/allocations.rs` still reporting
zero allocations; and `solana-poseidon` 5.0.0 compiled unmodified against the
branch, returning the bytes from light-poseidon's own doc example.

**Drop `num-bigint` — done on #64** (`8e74b5f`), since its byte-path rewrite is
what orphaned the dependency. One finding worth keeping: removing it from
`light-poseidon/Cargo.toml` does **not** remove it from the build.
`cargo tree -i num-bigint` shows `ark-ff`, `ark-ec`, `ark-poly`, `ark-serialize`
and `ark-ff-macros` all pulling it in. The win is that light-poseidon stops using
it directly, not a smaller dependency tree.

## Two constraints worth remembering beyond this work

1. **`PoseidonError` cannot grow a variant.** `solana-poseidon` matches it
   exhaustively in `From<PoseidonError> for PoseidonSyscallError`
   (`solana-poseidon-5.0.0/src/lib.rs:229-246`), so a new variant breaks Agave's
   compilation even when every function signature is unchanged. Both branches hit
   this and backed it out; new failure modes reuse `InvalidWidthCircom`.
2. **The sparse factorization's attribution.** It is commonly credited to
   "appendix B of the Poseidon paper". That could not be verified against the
   ePrint PDF, and circomlibjs attributes the concrete S/P formulation to
   Filecoin's `neptune`, citing 2019/458 only for round numbers. The source
   comments credit `neptune` and circomlib's `poseidon_opt`.

## Sequencing, if these are ever acted on

1. #64 merges.
2. Comment and close #60, #61, #54 with the above.
3. `worktree-poseidon-perf-followups` retargets to `main` and opens as its own PR.
