<!-- Draft PR for leanEthereum/leanVM, option A of #529. Open it only after the maintainers answer the #529 comment. Cut the branch from upstream main and cherry-pick the implementation commit; .contrib/ stays out. -->

# Fiat-Shamir: the transcript's security argument, and a test pinning what it rests on

Closes the `main` half of #529, if the maintainers agree it is the target there.

## What

`main`'s transcript, the overwrite-mode duplex over Keccak-f[1600] from #636, had a description in §8 (`sec:e2e-fiat-shamir`) but no security argument. This adds one, and no code: the transcript already is the duplex-sponge Fiat-Shamir transformation (DSFS) of Chiesa and Orrù (TCC 2025, ePrint 2025/536), so their Theorem 6.1 applies.

- **Spec**, §8: a "Security" paragraph. The instance is (IV, public input, announced sizes); the seed and the size absorptions are CO25's start with `h = p`; each challenge ends a round; the codec is the tagged lanes zero-padded to whole rates, and the first three lanes of a squeezed rate, unbiased on GF(2^192). Theorem 6.1 then bounds the soundness error by the protocol's state-restoration error plus `25 N²/2^576` for `N` queries to Keccak-f. Round-by-round soundness (Annex B) implies state-restoration soundness, so the existing per-round errors carry over unchanged.
- **Test**, `only_the_sizes_shape_the_transcript` in `leanvm_core/tests/verifiers`: the argument needs every absorb and squeeze count to follow from the bytecode and the announced sizes alone. The test changes every scalar after the sizes, and so every challenge, and checks that `replay_unchecked` still reads the stream and the openings exactly to their end, with the Keccak reduction's scalars where they were.
- **AGENTS.md**: the invariant joins the Fiat-Shamir convention.
- **refs.bib**, **macros.tex**: CO25, CY24, and `\fsq` for the query count.

## Why no framing

The duplex has one non-injectivity: a permutation forced by a fifth absorbed scalar equals one drawn for a challenge with four waiting. SAFE closes that shape with an IO-pattern tag. CO25 shows no tag is needed when the instance fixes the round structure ("DSFS does not hash lengths/labels … our results guarantee this is secure"), and here it does. #552 needed framing for a different reason: BLAKE2s compression is not a permutation, so its argument goes through a hashing-mode theorem (DMV18) instead.

## Checks

- `cargo test --release -p leanvm_core --test verifiers`: all pass, the Python verifier's included.
- The test fails, and only it, under a mutation of `crates/verifier` that reads one extra scalar in a replay depending on a bit of the commitment root (a value-dependent schedule the honest proof does not trigger).
- `latexmk -pdf main.tex`: builds, no undefined references, no new overfull boxes.
- `cargo fmt --all -- --check`, `cargo clippy --release -p leanvm_core --all-targets -- -D warnings`: clean.

## Not covered

- The test pins reads, not challenge counts: an extra squeeze changes no read, and nothing in the verifier's output counts permutations. Every squeeze count in `crates/verifier` is a layout constant today.
- Grinding is credited nothing, and Merkle openings rest on PCS binding, as in #552.
- Knowledge soundness (Theorem 6.2, rewinding) is not discussed; recursion's needs there are a separate question.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01F3hLCY1dFojeQS4eK38eiM
