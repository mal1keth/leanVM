# Handoff: leanVM Fiat-Shamir transcript work

For an agent picking this up. Written 2026-11-10. Read this first, then `AGENTS.md` (the repository's rules), then `.contrib/WORKLOG.md`.

## The person and the goal

Adi (cryptography researcher, GitHub fork `mal1keth/leanVM`) wants to contribute to [leanEthereum/leanVM issue 529](https://github.com/leanEthereum/leanVM/issues/529), "Review Fiat-Shamir construction", opened by kevaundray on 2026-10-07: "@khovratovich noted that the duplex construction looks insecure", plus a relayed ask for a duplex with 128 bits provable in the CO25 or SAFE paradigm. Adi's plan had three steps: post a scoping comment on the issue, write an analysis, then one PR in the direction the maintainers pick (A: prove the current mode; B: add framing; C: squeeze several challenges per permutation). A Discord intro in #lean-consensus was also planned. Adi prefers direct, honest feedback, including being told when they are wrong.

## Where things are

| item | state |
| --- | --- |
| Scoping comment, `.contrib/529-comment.md` | final; not posted. Adi posts it from their own account |
| Analysis, `.contrib/529-analysis.md` | final for `main` at `23a305b`; linked from the comment by permalink at fork commit `1798ed7` (verified publicly reachable) |
| Discord intro, `.contrib/discord-intro.md` | final; to post after the comment, with the comment's URL. Which server hosts #lean-consensus is unknown; the Discord connector fails to connect here |
| Option A implementation | on branch `test/gallant-ritchie-n13fe5`, commits `3aa2f33`, `e0a58c1`, `7ec4b6e`, `78b2209`: a "Security" paragraph in `doc/leanvm/body/08-end-to-end-protocol.tex`, the test `only_the_sizes_shape_the_transcript` in `crates/leanvm_core/tests/verifiers/portable_verifier.rs`, `\fsq` in `macros.tex`, CO25/CY24/KRS25 in `refs.bib`, one sentence in `AGENTS.md`. Full gates passed on `23a305b`: testall 328 passed, 0 failed |
| PR description, `.contrib/pr-option-a.md` | draft; open nothing until the maintainers answer the comment |
| Learning guide, `.contrib/LEARNING.md` | for Adi; reviewed |
| Evidence, `.contrib/checks/` | `co25_equivalence.py`, `collisions.py`, `fs_count.patch` (see the analysis §6 and LEARNING §7) |

Waiting on Adi: read and post the comment (decide on mentioning kevaundray), then the Discord intro, then bring back the maintainers' reply.

## What was established

All checked against the code, git or the papers; details and sources in `529-analysis.md`.

- **History.** On 2026-10-07 `main` had a BLAKE2s hash chain, not a duplex. The day before, #523 put a two-scalar BLAKE2s step on `riscv-exploration`, its blocks tagged with role and count. #552 (kevaundray, Oct 10) replaced it with a framed BLAKE2s duplex with a written argument (DMV18), and #607 and #620 (Thomas Coratger) followed, all on `riscv-exploration`. `main` got its current duplex from #636 (merged Oct 23, after Plonky3's challenger). The issue page links none of this.
- **The construction.** Keccak-f[1600] duplex in overwrite mode, rate lanes 0..16, capacity 16..25 (576 bits); each scalar of GF(2^192) absorbed as `(c0, c1, c2, tag)`, tag 1 or 4 (grinding nonce); four scalars per permutation; one challenge per permutation (lanes 0..3); the rate is zeroed after every permutation; seed = permute(IV ‖ public input) with IV = Keccak-256("leanvm-v1" ‖ bytecode).
- **One ambiguity:** a permutation forced by a fifth absorbed scalar equals a challenge drawn with four waiting. Brute force over all 265,720 operation sequences of length at most 11 finds no other.
- **Why harmless:** every count and order of absorbs and squeezes follows from the bytecode's length and the eight announced sizes, absorbed right after the seed. Never from a challenge, another sent value or Merkle data.
- **CO25 (Chiesa and Orrù, ePrint 2025/536):** for a fixed bytecode and sizes, `main` is exactly their DSFS with an injective, unbiased codec (`co25_equivalence.py`: 0 mismatches on 6,000 schedules). Two gaps to a theorem: (1) CO25's codec fixes round lengths by `(λ, n)`, so a prover choosing the sizes needs an extension of their BackTrack reduction (plausible: it recovers the instance before computing offsets); (2) Merkle hashing (Keccak-256) shares Keccak-f with the transcript, outside CO25 §2.6's informal Corollary 1, so Keccak-256 must be assumed an independent random oracle. Not the transcript's fault but open: state-restoration soundness beyond the PCS opening, grinding credit (query phases give 111 bits without it), knowledge soundness, KRS25 exposure (the guest evaluates Keccak-f).
- **Options:** A recommended. B (framing) would close the gaps through another theorem at the cost of a protocol change. C saves about 2% of the guest's `KECCAK`s (measured at `23a305b`).

## Upstream drift (found 2026-11-10)

Upstream `main` is at `64f8030`, 67 commits past `23a305b`. Checked: all 62 transcript call sites in `crates/verifier/src` are textually identical to `23a305b`'s except `merkle()`, which dropped a parameter and never touches the sponge, and the control-flow changes in `lib.rs` and `keccak.rs` are in claim evaluation, not around transcript calls; the sponge in `crates/fiat_shamir/src/lib.rs` and `crates/verifier/src/transcript.rs` is unchanged but for cosmetics, `sample_queries` is unchanged, `KECCAK_DEPTH` is still 12 and the Keccak outputs are still virtual, so the comment's argument holds. Changed:

- The Python verifier was deleted. The verifiers' test fixture moved to `crates/leanvm_core/tests/verifiers/fixture.rs`.
- Merkle openings are now `Vec<Vec<MerklePath>>` carrying their query positions; `Transcript::merkle` requires, in replay too, that each path's position equals the sampled query and its shape matches.
- The guest was reworked (#660, and #724's `KECCAK` with a custom output size), so the comment's cost figures are dated in the comment as measured at `23a305b`.
- The four implementation commits no longer cherry-pick cleanly (conflicts in `portable_verifier.rs` and §8).

**The test must be redesigned for the PR.** It changes every scalar after the sizes and expects the replay to walk the whole proof; on today's `main` the changed challenges move the queries and the replay refuses the honest openings (`MerkleOpeningPosition`). A design that survives: prove the fixture program twice with different values but the same shape (same sizes), and check that both replays read the same number of scalars and the same `keccak_scalars` range. Re-run the mutation check (a value-dependent extra read in `walk`) on whatever design is chosen.

## Rules learned the hard way

- **No issue or PR numbers in commit messages pushed to the fork.** `#529` in six commit messages put cross-references on the upstream issue's timeline. Write "issue 529" without `#`, or nothing.
- **Never post to GitHub or Discord for Adi.** Adi posts. Do not open the upstream PR until the maintainers answer and Adi agrees. Push only to `test/gallant-ritchie-n13fe5`.
- **Check every claim against the primary source before it goes in front of Adi or the maintainers**, including a reviewer's suggested replacement text. Three review rounds each caught errors, several introduced by the previous fix (see the work log's mistakes table). An independent adversarial review before any security claim under Adi's name is worth its cost.
- **The upstream PR is built from upstream `main`**, with the implementation squashed into one commit. `.contrib/` never goes upstream and stays committed on the fork (the comment links into it, and the container is ephemeral).
- **Repository style** (from AGENTS.md): no em or en dashes in prose, no hard-wrapped Markdown or LaTeX paragraphs, measurements only in commit messages, one symbol one meaning in the spec (`preamble/macros.tex`), doc labels are an API.

## Environment notes

- Upstream is reachable for git reads: `git remote add upstream https://github.com/leanEthereum/leanvm`, then `GIT_LFS_SKIP_SMUDGE=1 git fetch upstream main riscv-exploration`. The session's GitHub tools cannot read upstream issues; a web fetch of the issue's HTML page works (the API returned 403).
- ePrint refuses automated PDF downloads; do not work around it. Adi supplied CO25, SAFE and KRS25 as uploads in the first session; a new session will not have them, so ask Adi to re-upload if a citation needs checking.
- TeX for `latexmk` in a fresh container: `apt-get install -y --no-install-recommends latexmk texlive-latex-recommended texlive-latex-extra texlive-science texlive-fonts-recommended texlive-pictures texlive-bibtex-extra biber lmodern`.
- On a 4-core machine workflows run two agents at a time; the nine-reviewer round took about 70 minutes. `cargo testall` takes under 5 minutes with a warm cache.
- Commit messages end with the attribution lines the session's system prompt gives.

## Next steps, by the maintainers' answer

1. **`main` is the target, option A welcome:** branch from upstream `main`, port the four commits (redesign the test as above; merge the Security paragraph into the current §8, re-checking every sentence against today's verifier), run the full gates and the mutation check, have the result reviewed, show Adi, then open the PR with `pr-option-a.md` adapted.
2. **They want gap 1 worked out first:** extend CO25's BackTrack (§5.2, Definition 5.3) so round offsets come from the parsed sizes; write it for Adi to review. This is research, not code.
3. **`riscv-exploration` is the target:** nothing on `main`; re-scope with Adi.
4. **Anyone asks for current guest numbers:** apply `checks/fs_count.patch` (adapting it to today's verifier), run `cargo leanvm recursion --n 2 --xmss-per-leaf 900 --log-inv-rate 2`, and sum the `FSCOUNT replay` lines in pairs.
