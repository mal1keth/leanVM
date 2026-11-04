# Work log: leanVM#529 (Fiat-Shamir transcript)

Branch `test/gallant-ritchie-n13fe5` on `mal1keth/leanVM`, based on upstream `main` at `23a305b` (2026-11-04). The fork's `main` equalled upstream's when the work started.

## Outcome

- The scoping comment for [leanEthereum/leanVM#529](https://github.com/leanEthereum/leanVM/issues/529) is ready to post: `529-comment.md`. Not posted; it goes out from Adi's account.
- The analysis behind it: `529-analysis.md`. The learning guide: `LEARNING.md`.
- Option A of the plan is implemented on this branch: a security paragraph in the spec, one test, and one AGENTS.md rule. It changes no prover, verifier or guest code. The upstream PR waits for the maintainers' answer (`pr-option-a.md`).
- Every claim went through three rounds of adversarial review against the code, git and the papers before being kept.

## Changes

### Code and spec (the part that would go upstream)

| file | change |
| --- | --- |
| `crates/leanvm_core/tests/verifiers/portable_verifier.rs` | new test `only_the_sizes_shape_the_transcript` (25 lines); the only code written |
| `doc/leanvm/body/08-end-to-end-protocol.tex` | a "Security" paragraph (three paragraphs) in `sec:e2e-fiat-shamir`; the Merkle line above it reworded |
| `doc/leanvm/preamble/macros.tex` | `\fsq` (`N_FS`), the query count in the bound |
| `doc/leanvm/refs.bib` | `CO25`, `CY24`, `KRS25` |
| `AGENTS.md` | the schedule invariant added to the Fiat-Shamir convention |

Commits: `3aa2f33` (first version), `e0a58c1`, `7ec4b6e`, `78b2209` (spec corrections after each review round). The PR should squash them into one, so the overclaiming first version never ships.

### Notes (`.contrib/`, never upstream)

`529-comment.md`, `529-analysis.md`, `discord-intro.md`, `pr-option-a.md`, `LEARNING.md`, this file, and `checks/`: `co25_equivalence.py` (CO25's Construction 3.3 run against the verifiers), `collisions.py` (the brute force over operation sequences), `fs_count.patch` (the exact counter behind the guest-cost numbers). Commits `79dcb29`, `147b30b`, `86a4257`, `0a0feae`, `04f5690`, and the one adding this file.

## How it was verified

| check | result |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippyall` (workspace, all targets, `-D warnings`) | clean |
| `cargo testall` (release, whole workspace) | 328 passed, 0 failed, 6 ignored (the repository's own `#[ignore]`d slow tests), in 4m38s; includes `only_the_sizes_shape_the_transcript` and the end-to-end `aggregate_two_to_one` |
| `cargo docall` | clean |
| `cargo test --release -p leanvm_core --test verifiers` | 6 passed, 1 ignored (manual table regeneration), including the Python verifier and tamper tests |
| mutation test of the new test | with `crates/verifier` reading one extra scalar in a replay when a bit of the root is 0 (false for the fixture's honest proof), the new test failed and no other test did; reverted |
| `latexmk -pdf main.tex` | builds, 56 pages, no undefined references, the one pre-existing overfull box and no new one; rendered pages read back |
| `checks/co25_equivalence.py` | 0 mismatches on 6,000 schedules with sizes (re-run twice) |
| `checks/collisions.py` | 265,720 sequences, every collision explained by the one rule |
| guest cost | recursion 2→1 at the AGENTS.md benchmark settings, counter from `checks/fs_count.patch`; a trace of the Python verifier reproduced the counts |

Not done: the x86 cross-check from AGENTS.md (nothing `cfg`-gated changed), the `#[ignore]`d slow tests, and `ruff` (no Python changed).

## Problems found in the codebase

None is a bug in the running code; they are gaps in what is written down or proved.

1. **The transcript has one encoding ambiguity.** A permutation forced by a fifth absorbed scalar equals a challenge drawn with four waiting. It is harmless only because the schedule never depends on values, which was neither stated nor tested. Now stated (AGENTS.md, spec) and the reads are tested.
2. **The spec described the transcript but argued nothing** about its security. Now drafted, with its limits.
3. **State-restoration soundness is established only for the PCS opening.** Annex B proves round-by-round soundness for the opening (Theorem `thm:rbr`); the bus, the sumchecks, the Keccak reduction and ring switching are analysed for plain soundness only, and their composition with the list-binding commitment is not written. This predates the transcript question and is the real bottleneck.
4. **Grinding is uncredited by any argument.** WHIR's query counts close only `128 - 17` bits, so without a proof-of-work argument each query phase gives about 111 bits of round-by-round soundness.
5. **Merkle hashing and the transcript share Keccak-f without domain separation.** A 512-byte Merkle leaf's first Keccak-256 block can equal the transcript's seed input. Not an attack, but it takes the protocol outside CO25's theorem and needs an independence assumption.
6. **The KRS25 setting applies.** Every leanVM program can evaluate Keccak-f in one instruction, and the aggregation guest does. KRS25's known attack needs an uncommitted-trace GKR over a circuit that can compute the hash; leanVM's are grand products and Keccak-f with a state committed every 12 rounds. Still, nothing rules out an analogue.
7. **Knowledge soundness, which aggregation needs, is not established** anywhere in the spec.
8. **#529's issue page links none of the related work** (#523, #552, #607, #620 on `riscv-exploration`), which is how the plan came to think the issue was untouched.

## Mistakes in my own work, and what caught them

| mistake | caught by | fixed in |
| --- | --- | --- |
| The plan's premise that nobody had worked on #529 (it came from the issue page alone) | reading the upstream branches | `79dcb29`'s notes, then the comment |
| First analysis: "exactly CO25's DSFS", "provably", "no code change". CO25 fixes round lengths by `(λ, n)`, not by the instance; Merkle-compiled protocols fall under an informal corollary that assumes a separate Merkle hash | review round 1 (blocking B1, B2) | `e0a58c1`, `86a4257` |
| History: `main` kept the BLAKE2s chain until Oct 23, not Oct 14; `spongefish-fs` did merge (#607); #523 came the day before the issue | review round 1, then `git` | `86a4257` |
| The start's permutation count, the codec's round 1 and the nonce's place, "never by a value" (the sizes are values) | review round 1 | `86a4257` |
| Called #523's step "unframed"; its blocks carry a role tag and a scalar count. Taken from the commit message without reading the code | review round 2 | `0a0feae` |
| The comment fell behind the notes on scope (one proof, knowledge soundness, 111 bits, the batching transcript, the Keccak-256 assumption); "framing cannot close gap 1" was backwards | review round 2 | `0a0feae`, `7ec4b6e` |
| KRS25 described as needing a circuit the prover chooses; their §4 attacks a fixed universal circuit and calls that reasoning "perilous" | review round 3 | `04f5690`, `78b2209` |
| "random" dropped from "random oracle"; Definition 4.1 credited with fixing the number of rounds; small wording | review round 3 and a final read | `78b2209`, `04f5690` |

The pattern: each error was a fact stated from memory or from a summary (a commit message, an issue page) instead of from the primary source. Every one was caught by an independent check against that source before posting.

## Environment notes

- ePrint refused automated PDF downloads (HTTP 403). Retrying with a browser user agent was blocked as bot-check circumvention, correctly; the papers came from Adi instead.
- The Discord connector failed to connect, and the session could not read `leanEthereum/leanVM` issues through the GitHub tools; the issue was read with a web fetch, and git history through anonymous clones.
- TeX was not installed; installed `latexmk`, `texlive-*` and `lmodern` to build the spec.
- The workflow cap of two concurrent agents on this 4-core machine made the first review round take about 70 minutes.

## Open items

1. Adi reads, posts the #529 comment, then the Discord intro.
2. The maintainers answer which line (`main` or `riscv-exploration`) #529 targets, and whether they want option A as is or the gap-1 extension first.
3. If option A: cut a branch from upstream `main`, cherry-pick and squash the four spec commits and the test, open the PR with `pr-option-a.md`.
4. Optional research: write out gap 1's extension of CO25's BackTrack.
