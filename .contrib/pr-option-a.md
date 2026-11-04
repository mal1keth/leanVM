<!-- Draft PR for leanEthereum/leanVM, option A of #529. Open it only after the maintainers answer the #529 comment. Cut the branch from upstream main and squash the implementation commits (3aa2f33 and its correction) into one, with this file's first section as the message; .contrib/ stays out. -->

# Fiat-Shamir: what the transcript's security rests on, and a test pinning it

For #529, if the maintainers agree `main` is the target there.

## What

`main`'s transcript, the overwrite-mode duplex over Keccak-f[1600] from #636, had a description in §8 (`sec:e2e-fiat-shamir`) and no security argument. This adds what can be said now, and no code.

- **Spec**, §8, a "Security" paragraph. For a fixed bytecode and fixed announced sizes, the transcript is the duplex-sponge Fiat-Shamir transformation (DSFS) of Chiesa and Orrù (TCC 2025, ePrint 2025/536): the seed and the size absorptions are the start CO25 says, informally, it covers with `h = p`; each challenge ends a round; the codec is the tagged lanes zero-padded to a multiple of sixteen and the first three lanes of a squeezed block, unbiased on GF(2^192). It then names the two steps CO25 does not contain (a prover choosing the sizes, or the program; Merkle and IV hashing on the same Keccak-f, taken as an independent oracle), the resulting bound (CO25 §2.6, Corollary 1, informal) and knowledge soundness's (Theorem 6.2, rewinding), and the scope: state-restoration soundness is established only for the opening, grinding is not credited (each query message counts for 111 bits without it), and the argument is classical, in the ideal-permutation model, for one proof, a heuristic for computations that evaluate Keccak-f themselves (KRS25), as the aggregation guest does. The Merkle line above it no longer says "apart from the sponge".
- **Test**, `only_the_sizes_shape_the_transcript` in `leanvm_core/tests/verifiers`: the mapping needs every absorb and squeeze count to follow from the bytecode and the announced sizes alone. The test changes every scalar after the sizes, and so every challenge, and checks that `replay_unchecked` still reads the stream and the openings exactly to their end, with the Keccak reduction's scalars where they were.
- **AGENTS.md**: the invariant joins the Fiat-Shamir convention.
- **refs.bib**, **macros.tex**: CO25, CY24, KRS25, and `\fsq` for the query count.

## Why no framing

The duplex has one non-injectivity: a permutation forced by a fifth absorbed scalar equals one drawn for a challenge with four waiting. For a fixed shape CO25 needs no framing ("DSFS does not hash lengths/labels … our results guarantee this is secure"). Framing that binds the schedule into the sponge (SAFE's IO-pattern tag, #552's per-node framing) would close the first gap through another theorem, and domain separation between transcript and Merkle inputs would close the second, both at the cost of a protocol change in all four implementations. If the extension for prover-chosen sizes holds, the first is unnecessary.

## Checks

- `cargo test --release -p leanvm_core --test verifiers`: all pass, the Python verifier's included.
- The new test fails, and only it, under a mutation of `crates/verifier` that reads one extra scalar in a replay depending on a bit of the commitment root (a value-dependent schedule the honest proof does not trigger).
- A literal implementation of CO25's Construction 3.3 under the codec above reproduces the permutation inputs and challenges of the Python verifier and of mirrors of the Rust prover and verifier on 6,000 random schedules.
- `latexmk -pdf main.tex`: builds, no undefined references, no new overfull boxes.
- `cargo fmt --all -- --check`, `cargo clippy --release -p leanvm_core --all-targets -- -D warnings`: clean.

## Not covered

- The extension of CO25's reduction to a prover-chosen shape is stated, not proved. For the deployed guest the bytecode is fixed and only the sizes vary.
- The test pins reads, not challenge counts: an extra squeeze changes no read, and nothing in the verifier's output counts permutations. Every squeeze count in `crates/verifier` is a layout constant today.
- The recursion's batching transcript has the same shape but is not part of the mapping.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01F3hLCY1dFojeQS4eK38eiM
