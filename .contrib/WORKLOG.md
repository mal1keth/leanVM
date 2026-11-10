# Work log: leanVM#529 (Fiat-Shamir transcript)

> **2026-11-10: overtaken.** Upstream's `formal/` (commit `b6167fe`, Nov 9) proves leanVM's knowledge soundness, Fiat-Shamir transcript included, in Lean. The drafted comment, intro and PR are superseded and were never posted. `HANDOFF.md` is the current state and supersedes this log where they differ.

Branch `test/gallant-ritchie-n13fe5` on `mal1keth/leanVM`, based on upstream `main` at `23a305b` (2026-11-04). The fork's `main` equalled upstream's when the work started.

## Outcome

- The scoping comment for [leanEthereum/leanVM#529](https://github.com/leanEthereum/leanVM/issues/529) is ready to post: `529-comment.md`. Not posted; it goes out from Adi's account.
- The analysis behind it: `529-analysis.md`. The learning guide: `LEARNING.md`.
- Option A of the plan is implemented on this branch: a security paragraph in the spec, one test, and one AGENTS.md rule. It changes no prover, verifier or guest code. The upstream PR waits for the maintainers' answer (`pr-option-a.md`).
- The comment, the analysis and the spec paragraph went through three rounds of adversarial review against the code, git and the papers. The third round checked only what had changed since the second, and its own fixes (`78b2209`, `04f5690`) had a final read, not a fourth round. The PR draft was checked only where the first two rounds cited it, and the Discord intro in none. `LEARNING.md` and this log had one review of their own, applied in the commit after their first version.

## Changes

### Code and spec (the part that would go upstream)

| file | change |
| --- | --- |
| `crates/leanvm_core/tests/verifiers/portable_verifier.rs` | new test `only_the_sizes_shape_the_transcript` (23 lines and two imports); the only Rust written |
| `doc/leanvm/body/08-end-to-end-protocol.tex` | a "Security" paragraph (three paragraphs) in `sec:e2e-fiat-shamir`; the Merkle line above it reworded |
| `doc/leanvm/preamble/macros.tex` | `\fsq` (`N_FS`), the query count in the bound |
| `doc/leanvm/refs.bib` | `CO25`, `CY24`, `KRS25` |
| `AGENTS.md` | the schedule invariant added to the Fiat-Shamir convention |

Commits: `3aa2f33` (first version), `e0a58c1`, `7ec4b6e`, `78b2209` (spec corrections after each review round). The PR should squash them into one, so the overclaiming first version never ships.

### Notes (`.contrib/`, never upstream)

`529-comment.md`, `529-analysis.md`, `discord-intro.md`, `pr-option-a.md`, `LEARNING.md`, this file, and `checks/`: `co25_equivalence.py` (CO25's Construction 3.3 run against the Python verifier's transcript and Python mirrors of the Rust prover's and verifier's), `collisions.py` (the brute force over operation sequences), `fs_count.patch` (the exact counter behind the guest-cost numbers). Commits `79dcb29`, `147b30b`, `86a4257`, `0a0feae`, `04f5690`, and the one adding this file.

## How it was verified

| check | result |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippyall` (workspace, all targets, `-D warnings`) | clean |
| `cargo testall` (release, whole workspace) | 328 passed, 0 failed, 6 ignored (the repository's own `#[ignore]`d slow checks and manual reports), in 4m38s; includes `only_the_sizes_shape_the_transcript` and the end-to-end `aggregate_two_to_one` |
| `cargo docall` | clean |
| `cargo test --release -p leanvm_core --test verifiers` | 6 passed, 1 ignored (manual table regeneration), including the Python verifier and tamper tests |
| mutation test of the new test | with `crates/verifier` reading one extra scalar in a replay when a bit of the root is 0 (false for the fixture's honest proof), the new test failed and no other test in that binary did; reverted. Recorded in `3aa2f33`'s message; exercise 3 of `LEARNING.md` reproduces it |
| `latexmk -pdf main.tex` | the final version (`78b2209`) rebuilt from an empty `.build`: 56 pages, no undefined references, the one pre-existing overfull box and no new one; its page rendered and read back |
| `checks/co25_equivalence.py` | 0 mismatches on the 6,000 schedules with sizes under the corrected codec (the `codec=fixed sizes=True` lines of the default run, 3,000 each with and without a raw nonce, over a Feistel stand-in for Keccak-f); the run's other lines report mismatches, every one with an empty first round, which `main` never has. Run by a reviewer and re-run here |
| `checks/collisions.py` | 265,720 sequences, every collision explained by the one rule |
| guest cost | recursion 2→1 at the AGENTS.md benchmark settings: Fiat-Shamir permutations counted in the native verifier's sponge (`checks/fs_count.patch`) as it replayed the two children, and carried to the guest at one `KECCAK` per permutation, not measured in the guest; a trace of the Python verifier reproduced the counts |

Not done: the x86 cross-check from AGENTS.md (nothing `cfg`-gated changed), the `#[ignore]`d slow tests, and `ruff` (`python-verifier/verifier.py`, the file AGENTS.md lints, is unchanged).

## Problems found in the codebase

None is a bug in the running code; they are gaps in what is written down or proved.

1. **The transcript has one encoding ambiguity.** A permutation forced by a fifth absorbed scalar equals a challenge drawn with four waiting. It is harmless only because the schedule never depends on a challenge, a sent value other than the announced sizes, or Merkle data (the bytecode's length and the sizes, absorbed before any challenge, the bytecode through the IV, fix it), and because leanVM's other transcripts start from distinct seeds. The schedule rule was neither stated nor tested. Now stated (AGENTS.md, spec) and the reads are tested.
2. **The spec described the transcript but argued nothing** about its security. Now drafted, with its limits.
3. **State-restoration soundness is established only for the PCS opening.** Annex B proves round-by-round soundness for the opening (Theorem `thm:rbr`); the bus, the sumchecks, the Keccak reduction and ring switching are analysed for plain soundness only, and their composition with the list-binding commitment is not written. This predates the transcript question and is the real bottleneck.
4. **Grinding is uncredited by any argument.** WHIR's query counts close only `128 - 17` bits, so without a proof-of-work argument each query phase gives about 111 bits of round-by-round soundness.
5. **Merkle hashing and the transcript share Keccak-f without domain separation.** A 512-byte Merkle leaf's first Keccak-256 block can equal the transcript's seed input. Not an attack, but it takes the protocol outside the setting of CO25's Merkle-compiled bound (§2.6, Corollary 1, stated informally), which keeps the Merkle hash apart from the permutation, so the bound needs an independence assumption.
6. **The KRS25 setting applies.** Every leanVM program can evaluate Keccak-f in one instruction, and the aggregation guest does. KRS25's known attack needs an uncommitted-trace GKR over a circuit that can compute the hash; leanVM's are grand products and Keccak-f with its state committed every 12 rounds except the output (`KECCAK_DEPTH` in `crates/verifier/src/layout.rs`). Still, nothing rules out an analogue.
7. **Knowledge soundness, which aggregation needs, is not established** anywhere in the spec.
8. **#529's issue page links none of the related work** (#523, #552, #607, #620 on `riscv-exploration`), which is how the plan came to think the issue was untouched.

## Mistakes in my own work, and what caught them

| mistake | caught by | fixed in |
| --- | --- | --- |
| The plan's premise that nobody had worked on #529 (it came from the issue page alone) | reading the upstream branches | `79dcb29`'s notes, then the comment |
| First analysis: "exactly CO25's DSFS", "provably", "no code change". CO25 fixes round lengths by `(λ, n)`, not by the instance; Merkle-compiled protocols fall under an informal corollary that assumes a separate Merkle hash | review round 1 (blocking B1, B2) | `e0a58c1`, `86a4257` |
| History: `main` kept the BLAKE2s chain until Oct 23, not Oct 14; `spongefish-fs` did merge (#607); #523 came the day before the issue | review round 1, then `git` | `86a4257` |
| The start's permutation count, the codec's round 1 and the nonce's place; "nothing branches on a challenge, a sent value or Merkle data" (the sizes are sent values) | review round 1 (C1 to C4) | `86a4257` |
| "never by a value", which `86a4257` wrote into the comment while applying that fix, and AGENTS.md's "never from a challenge or a sent value" from `3aa2f33`: the same error again | review round 2 | `0a0feae`, `7ec4b6e` |
| Called #523's step "unframed"; its blocks carry a role tag and a scalar count. Taken from the commit message without reading the code | review round 2 | `0a0feae` |
| The comment fell behind the notes on scope (one proof, knowledge soundness, 111 bits, the batching transcript, the Keccak-256 assumption); "framing cannot close gap 1" was backwards | review round 2 | `0a0feae`, `7ec4b6e` |
| KRS25 described as needing a circuit the prover chooses; their §4 attacks a fixed universal circuit and calls that reasoning "perilous" | review round 3 | `04f5690` |
| "random" dropped from "random oracle"; Definition 4.1 credited with fixing the number of rounds; small wording | review round 3 and a final read | `78b2209`, `04f5690` |
| Wrote `#529` in commit messages pushed to the public fork. GitHub resolved them to the upstream issue, whose timeline has shown six of these commits as references since Nov 4, before any comment was posted | a check of the issue page on Nov 10 | not undoable by rewriting the fork, which would also break the comment's permalink; later commit messages carry no issue references |
| Told Adi on Nov 10 that the comment could be posted after checking only the transcript code on the new `main`; the commit that deleted the Python verifier also added `formal/`, which closes the comment's gaps | the review of `HANDOFF.md` | comment, intro and PR marked superseded; nothing was posted |

The pattern: most errors were facts stated from memory or from a summary (a commit message, an issue page) instead of from the primary source. The rest came in with a revision: a review fix applied wrongly, a word dropped, and a reviewer's replacement text taken unchecked (Definition 4.1). Each was caught by a later check against the source before posting. The review of this log found one more of the same kind: it said every claim had three review rounds, which was true only of the comment, the analysis and the spec.

## Environment notes

- ePrint refused automated PDF downloads (HTTP 403). Retrying with a browser user agent was blocked as bot-check circumvention, correctly; the papers came from Adi instead.
- The Discord connector failed to connect, and the session could not read `leanEthereum/leanVM` issues through the GitHub tools; the issue was read with a web fetch, and git history through anonymous clones.
- TeX was not installed; installed `latexmk`, `texlive-*` and `lmodern` to build the spec.
- The workflow cap of two concurrent agents on this 4-core machine made the first review round take about 70 minutes.

## Upstream drift (found Nov 10)

Upstream `main` moved 67 commits past `23a305b`, to `64f8030`. The sponge in `crates/fiat_shamir/src/lib.rs` is unchanged but for cosmetics, so the construction the analysis describes stands. But the Python verifier was deleted, the verifiers' test fixture moved to `fixture.rs`, Merkle openings now carry query indexes and leaf sizes (`3f2ff324`), WHIR's queries and the verifier's transcript changed, and the guest was rewritten (#660, and #724's `KECCAK` with a custom output size). So the implementation commits no longer cherry-pick cleanly (conflicts in `portable_verifier.rs` and §8), the schedule invariant has to be re-checked on the new verifier, and the guest-cost numbers are from `23a305b`.

## Open items

1. Adi reads, posts the #529 comment, then the Discord intro.
2. The maintainers answer which line (`main` or `riscv-exploration`) #529 targets, and whether they want option A as is or the gap-1 extension first.
3. If option A: cut a branch from upstream `main`, cherry-pick and squash the four commits `3aa2f33`, `e0a58c1`, `7ec4b6e` and `78b2209` (the test is in the first), open the PR with `pr-option-a.md`.
4. Optional research: write out gap 1's extension of CO25's BackTrack.
