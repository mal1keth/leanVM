# Handoff: leanVM Fiat-Shamir transcript work

For an agent picking this up. Written 2026-11-10, updated 2026-11-11 with a local session's findings. Read this first; where `WORKLOG.md` or other notes differ, this file is newer. Then read `AGENTS.md` (the repository's rules) and upstream's `formal/statement.tex` (below).

## Stop first: the plan was overtaken on 2026-11-09

Upstream commit `b6167fe` (Tom Wambsgans, Nov 9) vendored `formal/`: Lean 4 developments from Verified-zkEVM/leanerVM, pinned to leanVM at `40f877dc` (on `main`), with a plain-language summary in `formal/statement.tex`. It states, "proved using only Lean's three axioms … no `sorry`":

- **Knowledge soundness of leanVM's verifier** in the random-permutation model: Keccak-f[1600] is a uniformly random permutation, and Keccak-256 is the sponge over that same permutation. The adversary outputs the program, the public input and the proof; the extractor is straight-line; the error is at most `(Q+2^14)·2^-128 + 5(Q+2^14)²·2^-256` for `Q ≤ 2^128` queries.
- Completeness, the guest program's soundness as an aggregation step, the signature schemes' strong unforgeability, LeanDA's binding.
- An explicit list of what is not proved (its last section): soundness across recursion levels; quantum adversaries; programs that evaluate their own proof's duplex (the KRS25 setting), excluded by the model; the Rust verifier, prover and guests themselves (differential-tested against the Lean specification, not proved); LeanDA's link to the in-circuit check; witness generation.

That proof covers everything the drafted #529 comment called open, by another route than the analysis's CO25 mapping: the duplex's security; gap 1, since the adversary outputs the program and the sizes; gap 2, through a two-oracle transfer (`formal/common/Common/Transfer2.lean`) under a duplex discipline (`DuplexOK`, `Common/Indiff2/Defs.lean`): every direct permutation call absorbs a non-final block into the initial state or an earlier answer. For Keccak that is `keccakNF` and `keccakNF_blockTo` (`Common/Keccak.lean`): byte 135 is kept, so the duplex never writes lane 16. leanVM's transcript is shown to follow it in `formal/lean_vm/LeanVM/Protocol/Rpm/Duplex.lean`: `AdmissibleVm` (every query keeps lanes 16..24 of the zero state or of an earlier answer) and `theorem duplexVm_verifier` (line 362). Its header also names `duplexVm_honest` for the honest prover, but no definition under that name was found in `formal/lean_vm` (completeness side; not checked further, and the Lean was not built here). No Lean lemma matching the analysis's schedule rule was found, and the formal route does not need one: its Fiat-Shamir theorem (`formal/lean_vm/LeanVM/Protocol/Compile/Rom/Sound.lean`, a round-by-round certificate per `Compile/Prog.lean`) decodes each permutation from the verifier program's position (`Compile/Rom/Decode.lean`), which handles the fifth-absorption ambiguity explicitly, and `LeanVMSound.lean` credits grinding per challenge group (each group, discounted by the proof of work before it, escapes with probability at most `2^-128`), so the 111-bit caveat does not apply to the Lean bound. More broadly, since it proves soundness of the Lean transcription itself and ties the Rust verifier to it by testing (`formal/check-all.sh`: the Rust-vs-Lean verifier differential `fuzz-verifier.py` over fixtures and their mutations, a wire differential and a prover differential). **Adi posted `.contrib/529-comment-short.md` on 2026-11-11 at 05:28 UTC**: https://github.com/leanEthereum/leanVM/issues/529#issuecomment-6787918509 (no handle mentions; the notes link points at the analysis at `7f70002`). **Next step in every branch of the plan: wait for a maintainer's answer. No PR and no further comment until then.** Do not send Option A's Security paragraph upstream as it is. The Discord intro and `pr-option-a.md` carry a superseded banner. Nothing was posted: the issue page on Nov 10 still showed only kevaundray's Oct 7 comment (plus the commit references below).

## The person and the goal

Adi (cryptography researcher, public fork `mal1keth/leanVM`) wanted to contribute to [leanEthereum/leanVM issue 529](https://github.com/leanEthereum/leanVM/issues/529), "Review Fiat-Shamir construction", opened by kevaundray on 2026-10-07 ("@khovratovich noted that the duplex construction looks insecure"), with a same-day comment relaying Dmitry's asks: a duplex over BLAKE2s/2b compression, long absorb-squeeze patterns, fewest compression calls, 128 bits provable in the CO25 or SAFE paradigm. Adi's plan: a scoping comment, an analysis, then one PR (A: prove the current mode; B: add framing; C: squeeze several challenges per permutation), and a Discord intro in #lean-consensus (server unknown; the Discord connector fails to connect here). Adi prefers direct, honest feedback, including being told when they are wrong.

**Awaiting Adi's decision on re-scoping** (see "Options now").

## What exists, and its status

| item | status |
| --- | --- |
| `.contrib/529-comment-short.md` | **posted** 2026-11-11 05:28 UTC, [comment 6787918509](https://github.com/leanEthereum/leanVM/issues/529#issuecomment-6787918509), as recorded in `20703ef` (Adi reworded the first sentence); unanswered so far; asks whether `formal/` closes the issue for `main`, notes the one non-injectivity and the KRS25/recursion gap, links the analysis at `7f70002` |
| `.contrib/529-comment.md` | the longer revised comment, kept; not the one to post |
| `.contrib/529-analysis.md` | revised after the Lean proof (local session, `7f70002`, one independent review); permalink target `7f70002`. The old target `1798ed7` is the stale version |
| who edits what | the local session wrote these three files on `contrib/formal-revision` (`7f70002`, `27dfa8d`, merged as `d4ad9b4`); coordinate with Adi before editing them |
| `.contrib/discord-intro.md`, `.contrib/pr-option-a.md` | superseded |
| Option A commits on `test/gallant-ritchie-n13fe5` (`3aa2f33`, `e0a58c1`, `7ec4b6e`, `78b2209`) | a §8 "Security" paragraph, the test `only_the_sizes_shape_the_transcript`, `\fsq`, CO25/CY24/KRS25 in `refs.bib`, an AGENTS.md sentence; all gates passed at `23a305b`; no longer cherry-pick onto `main` and now largely redundant with `formal/` |
| `.contrib/LEARNING.md` | still a valid guide to the transcript as it was at `23a305b`; the sponge is unchanged on `main` |
| `.contrib/WORKLOG.md` | full history, verification, and the mistakes table |
| `.contrib/checks/` | `co25_equivalence.py`, `collisions.py` (both run against `23a305b`'s files), `fs_count.patch` (applies to `23a305b`'s verifier, not to `main`'s) |

## What was established (still true, still useful as background)

- **History.** On 2026-10-07 `main` had a BLAKE2s hash chain. The day before, #523 put a two-scalar BLAKE2s step on `riscv-exploration`, each block tagged with its role and scalar count. #552 (kevaundray, Oct 10) replaced it with a framed BLAKE2s duplex and a DMV18 argument; #607 and #620 (Thomas Coratger) followed, all on `riscv-exploration`. `main` got its Keccak-f duplex from #636 (merged Oct 23, after Plonky3's challenger).
- **The construction** (unchanged on `main` but for cosmetics): Keccak-f[1600] duplex in overwrite mode, rate lanes 0..16, capacity 16..25; each GF(2^192) scalar absorbed as `(c0, c1, c2, tag)`, tag 1, or 4 for the grinding nonce; four scalars per permutation; one challenge per permutation; the rate zeroed after every permutation; seed = permute(IV ‖ public input), IV = Keccak-256("leanvm-v1" ‖ bytecode).
- **One encoding ambiguity**, harmless because the schedule follows from the bytecode's length and the announced sizes: a permutation forced by a fifth absorbed scalar equals a challenge drawn with four waiting (brute force over 265,720 sequences of length at most 11).
- **Guest cost** (at `23a305b`, counted in the native verifier and carried to the guest at one `KECCAK` per permutation): about 921 Fiat-Shamir permutations per child verified, about 15% of the root's `KECCAK`s; option C would save about 2% of them. Any transcript change now also means updating the Lean proof, which makes C less attractive still.

## Upstream drift since `23a305b` (to `64f8030`, 67 commits)

- `b6167fe`: `formal/` (above); the Python verifier deleted; the Lean transcription `formal/Statement/LeanVmVerifier.lean` became the second of AGENTS.md's three verifiers; the verifiers' fixture moved to `crates/leanvm_core/tests/verifiers/fixture.rs` (its `chain()` is also called by `formal/lean_vm/scripts/export-rust.sh`).
- `3f2ff324`: Merkle openings are `Vec<Vec<MerklePath>>` carrying their positions; `Transcript::merkle` refuses, in replay too, a path of the wrong shape or at a position other than the sampled query; `Summary` lost `merkle_paths`; `finish()` returns `()`.
- `40f877dc` (#724): `KECCAK` writes one, two or all thirteen output cells; the KECCAK table gained two columns (a layout constant, so the schedule invariant still holds).
- The guest was reworked (#660, #724), so the cost figures above are from `23a305b`.
- Checked: every `transcript.<method>(...)` call in `crates/verifier/src` is textually identical to `23a305b`'s except `merkle()` (dropped `row_words`) and `finish()`; the sponge, `sample_queries`, the WHIR query counts and `KECCAK_DEPTH = 12` are unchanged.
- If anything of option A is ever ported, the test needs a new design: tampering every scalar now moves the queries and the replay refuses the honest openings (`MerkleOpeningPosition`), and the old helpers (`Proof::load`, `encode`, `python_verifier`) are gone. Two honest proofs with the same shape and different values would work, but the fixture cannot give them as it stands (`chain(loop_steps)` changes the row counts, the public input is the program's own output, the prover is deterministic): add a second placeholder that changes values but no size, for example the Keccak message `[5, 7, 5, 7, 5, 7, 5, 7, 5, 7]`, keeping `chain()`'s signature.

## The test, if Option A is ever revived

Redesigning `only_the_sizes_shape_the_transcript` for today's `main` is probably not worth it. What it pins (the Rust verifier's reads depend only on the shape) is now covered from the other side: the Lean transcription carries the proof, and `formal/check-all.sh`'s verifier differential checks the Rust verifier against it on fixtures and their mutations. The test would remain a cheap, targeted regression for the Rust side only; keep it out unless a maintainer asks.

## Options now (for Adi to choose)

1. **Close the loop on the issue, briefly or not at all.** The maintainers wrote `formal/`, so they know. If Adi wants to engage, a short comment asking whether the issue is resolved for `main` by `formal/` (and whether anything remains for `riscv-exploration`) is the most it needs. Nothing is needed otherwise.
2. **Contribute where `formal/statement.tex` says "not proved".** The closest to Adi's expertise and to the issue's origin: the KRS25 setting the model excludes by construction. The recursion guest verifies proofs of its own bytecode and evaluates Keccak-f with one instruction, so whether a self-referential program could exploit its own proof's duplex is a real, open question. Others: soundness across recursion levels; a quantum (QRPM) analysis; the Rust verifier's equivalence to the Lean transcription (differential fuzzing exists; a review of its coverage could help).
3. **Review `formal/statement.tex` itself** against the Rust code and the papers, as a reader of a security claim: a modest, useful first contribution that also builds familiarity.

## Rules learned the hard way

- **Check what a commit adds, not only what it removes.** The `formal/` commit was first noticed only as "the Python verifier was deleted", and Adi was told the comment could be posted. A review of this file caught it.
- **A drift check covers what upstream added outside the files we touch.** The Nov 10 check compared transcript call sites only. Run at least `git diff --stat <base>..upstream/main -- formal doc AGENTS.md` (and skim `git log --stat`) before calling any claim about `main` current.
- **Coordinate file ownership across sessions.** A local session owns `529-comment.md` and `529-analysis.md` until its branch is merged; this session's banner on them had to be reverted to keep that merge clean.
- **No issue or PR numbers in commit messages pushed to the fork.** `#529` in seven commit messages (`79dcb29`, `147b30b`, `86a4257`, `0a0feae`, `04f5690`, `1798ed7`, `0075601`) put six of them on the upstream issue's timeline since Nov 4; four also name #523, #552, #607, #620 or #636.
- **Never post to GitHub or Discord for Adi.** Adi posts. Push only to `test/gallant-ritchie-n13fe5`.
- **Check every claim against the primary source** before it reaches Adi or the maintainers, including a reviewer's suggested replacement text. Every review round in this work found errors, several introduced by the previous fix (see the work log's mistakes table).
- **`.contrib/` never goes upstream** and stays committed on the fork (the container is ephemeral, and `1798ed7` is a permalink target).
- **Repository style** (AGENTS.md): no em or en dashes in prose, no hard-wrapped Markdown or LaTeX paragraphs, measurements only in commit messages, one symbol one meaning in the spec, doc labels are an API.

## Environment notes

- Git reads of upstream work anonymously: `git remote add upstream https://github.com/leanEthereum/leanvm`, then `GIT_LFS_SKIP_SMUDGE=1 git fetch upstream main riscv-exploration`. The session's GitHub tools cannot read upstream issues; a web fetch of the issue's HTML page works (its API returned 403).
- ePrint refuses automated PDF downloads; do not work around it. Adi supplied CO25, SAFE and KRS25 as uploads in the first session; a new session will not have them.
- TeX for `latexmk` in a fresh container: `apt-get update && apt-get install -y --no-install-recommends latexmk texlive-latex-recommended texlive-latex-extra texlive-science texlive-fonts-recommended texlive-pictures texlive-bibtex-extra biber lmodern texlive-fonts-extra`. The last package (about 630 MB) is needed only on upstream `main`, whose preamble loads `dsfont`.
- Lean for `formal/`: `lake exe cache get` once, then `lake build` (per AGENTS.md); not tried in this work.
- On a 4-core machine workflows run two agents at a time. `cargo testall` takes under 5 minutes with a warm cache.
- Commit messages end with the attribution lines the session's system prompt gives.
