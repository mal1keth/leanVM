# Learning guide: leanVM's Fiat-Shamir transcript

A guide to the part of leanVM this work touched: how a proof's challenges are derived, where that happens in each of the four implementations, why the construction is (mostly) sound, and where the known gaps are. Line numbers are against this branch's head, which is identical to upstream `main` at `23a305b` outside the files listed in `WORKLOG.md`.

Suggested pace: §1 and §2 in one sitting, §3 with the code open beside it, then the exercises in §7.

## 1. The big picture

A leanVM proof is an interactive protocol made non-interactive. In the interactive version, the prover sends messages (commitments, sumcheck round polynomials, evaluations) and the verifier answers with random challenges. **Fiat-Shamir** replaces the verifier's randomness with a hash of everything said so far: both sides run the same hash, called the **transcript**, so the prover can compute the challenges itself and the proof becomes one string.

In leanVM the transcript is a **duplex sponge** over **Keccak-f[1600]**, the 1600-bit permutation inside Keccak-256. The prover's messages are field elements of `E = GF(2^192)`, called scalars. Everything rests on one discipline, stated at the top of `crates/fiat_shamir/src/transcript.rs`: **sending a scalar and binding it into the transcript are one act**. Nothing on the scalar stream reaches the verifier without being hashed into every later challenge; Merkle openings travel beside the stream and are bound only through their roots, which were (§3.2).

The same protocol is implemented four times, and they must agree bit for bit:

| implementation | where | role |
| --- | --- | --- |
| prover | `crates/fiat_shamir` (state), callers in `pcs`, `leanvm_core`, `keccak_gkr` | produces the proof |
| native verifier | `crates/verifier` | what `EthereumProof::verify` runs; no dependencies, no `unsafe` |
| Python verifier | `python-verifier/verifier.py` | the readable reference |
| recursion guest | `crates/rec_aggregation/guests/lean_ethereum.py` | zkDSL; proving its execution proves a child proof was valid |

The guest is why the design looks the way it does: every transcript operation the native verifier performs, the guest performs inside the VM, where a permutation is one `KECCAK` instruction and everything around it costs cycles.

## 2. Concepts you need

**Fields.** `K = GF(2^64)` (one 64-bit word) and `E = GF(2^192) = K[y]/(y³+y+1)`, three `K` limbs `c0, c1, c2`. A scalar therefore fits in three 64-bit Keccak lanes, and three uniformly random lanes are exactly a uniformly random element of `E`. That is why leanVM's challenges have no bias, unlike prime-field systems that must reduce hash output modulo `p`.

**Sponge.** A permutation `p` on a state split into a **rate** (the part inputs and outputs touch) and a **capacity** (never touched directly). Here the state is 25 lanes: rate lanes `0..16` (1024 bits), capacity lanes `16..25` (576 bits). Security of sponge-based constructions scales with the capacity: the generic attack costs about `2^(c/2)`, here `2^288`.

**Duplex, overwrite mode.** A *duplex* interleaves absorbing and squeezing on one running state. In *overwrite* mode, input replaces the rate lanes instead of being XORed into them. leanVM additionally zeroes the rate lanes past the last input before each permutation.

**Domain tags.** leanVM writes each absorbed scalar as four lanes `(c0, c1, c2, tag)`: tag `1` for a sent scalar, `4` for a proof-of-work nonce. The tags are nonzero, so "k scalars" and "k scalars followed by a zero scalar" never look alike after zero padding.

**Soundness notions.** *Soundness*: no prover convinces the verifier of a false statement except with small probability. *Round-by-round (RBR) soundness*: each verifier challenge has a small chance of rescuing a prover who was already losing. *State-restoration (SR) soundness*: soundness against a prover who may rewind to any earlier point and retry, which is exactly what a Fiat-Shamir prover can do by rehashing. RBR implies SR, and SR is what Fiat-Shamir needs. *Knowledge soundness*: from any convincing prover, a witness can be extracted. For signature aggregation this, not plain soundness, is the property that matters: for an honestly generated key a valid signature exists for every message, so "a signature exists" proves nothing.

**CO25.** Chiesa and Orrù, *A Fiat-Shamir Transformation From Duplex Sponges* (TCC 2025). They prove that Fiat-Shamir over an overwrite-mode duplex with an ideal permutation (their DSFS, Construction 4.3) has soundness error at most the protocol's SR error (at `t` moves) plus `25t²/|Σ|^c` plus the codec's bias terms `t·max ε_cdc,i + Σ ε_cdc,i`, for `t` permutation queries (Theorem 6.1). For leanVM the bias terms are zero, since three uniform lanes are a uniform element of `E`. A **codec** (Definition 4.1) says how prover messages become sponge input (injective) and how sponge output becomes challenges (low bias). DSFS hashes no framing at all; what replaces framing is that every round's length is fixed in advance.

**SAFE.** Aumasson, Khovratovich, Mennink and Quine's sponge API. It handles the same problem differently: the whole sequence of absorb and squeeze lengths (the *IO pattern*) is hashed into a tag placed in the capacity at the start.

**BCS and Merkle.** leanVM's protocol is an IOP compiled with Merkle commitments (the BCS transformation). The prover commits to big vectors by sending Merkle roots and later opens positions the verifier picks. CO25 covers this in §2.6 (Corollary 1, stated informally), adding a Merkle extraction term `κ_MT` and assuming the Merkle hash is separate from the transcript's permutation.

**Grinding.** Before WHIR's query positions are sampled, the prover searches for a nonce such that the next challenge's low 17 bits are zero. This makes every attempt to re-roll the queries cost about `2^17` work. WHIR's query counts are sized assuming that credit (`crates/pcs/src/whir_config.rs:56-60`).

**KRS25.** Khovratovich, Rothblum and Soukhanov, *How to Prove False Statements*. They break Fiat-Shamir for GKR-based proofs of computations that evaluate the Fiat-Shamir hash itself, even with a fixed universal circuit (their §4, Theorem 9). A random-oracle or ideal-permutation proof cannot see this class of attack, because the model assumes the computation cannot evaluate the hash.

## 3. Code walkthrough

### 3.1 The prover's state: `crates/fiat_shamir/src/lib.rs`

Read the module comment at the top first; it is the specification in eight lines.

- `FiatShamirState` (line 52) holds the 25-lane `state` and `n_pending`, the number of scalars waiting in the rate.
- `new` (65): writes the IV into lanes `0..4` and the public input into lanes `4..8` of a zero state, then permutes. The IV is `Keccak-256("leanvm-v1" ‖ bytecode table)` (`crates/verifier/src/bytecode.rs:46`, `TAG` at `crates/verifier/src/layout.rs:68`). So the program and the statement are bound before any challenge.
- `from_label` (79): the same seed shape for protocols with no public input, `(H(label), 0)`.
- `duplex` (84): one permutation; returns lanes `0..3` as the challenge; zeroes the rate; resets `n_pending`.
- `absorb` (92): if four scalars already wait, permute first; then write the scalar as `(c0, c1, c2, tag)` into lanes `4k..4k+4`.
- `observe` (116) is `absorb` with tag 1. `sample` (124) is just `duplex`: **every challenge costs its own permutation**, even two in a row.
- `pow_bits_ok` (137) and `grind_pow` (154): the proof of work. The nonce is absorbed with tag 4, a challenge is drawn, and its low `bits` bits must be zero. For grinds of 13 bits or more (production uses 17) the search is batched and parallel, smaller ones scan sequentially, and either way it returns the smallest valid nonce.
- Tests at the bottom; `fs_binds_length` (236) is the one that pins the tags' purpose.

### 3.2 The prover's transport: `crates/fiat_shamir/src/transcript.rs`

- `add_scalar` (64): pushes the scalar onto the proof stream **and** observes it. There is no way to send without binding.
- `add_root` (78): a Merkle root as two scalars.
- `add_round_poly` (92): a sumcheck round polynomial minus the one coefficient the verifier can derive from the running claim. The derived coefficient is neither sent nor bound, since it is a function of things already bound.
- `grind` (108): grinds and pushes the nonce onto the stream (it was already bound by the grind).
- `hint_merkle` (57): Merkle openings go to a side channel and are **never absorbed**. Their binding is the root, which was.

Where a proof starts: `crates/leanvm_core/src/cpu/mod.rs:451` creates the `ProverState` from the IV and the public input, then announces the sizes and commits.

### 3.3 The native verifier's transcript: `crates/verifier/src/transcript.rs`

The same sponge, written independently:

- `Sponge` (41), `duplex` (63), `sample` (86): identical behaviour to the prover's state, with the waiting scalars held in a small array.
- `Transcript` (92) wraps the sponge, the proof stream and the Merkle openings, plus a `checked` flag.
- `next_scalar` (141): read one scalar from the stream and observe it. The verifier's mirror of `add_scalar`.
- `grind_check` (153): read the nonce, absorb it with tag 4, sample, and (if checked) require the low bits to be zero.
- `merkle` (181): read and authenticate openings; note that nothing here touches the sponge.
- `sumcheck_round_poly` (231): reads the sent coefficients and rebuilds the missing one from the claim.
- `finish` (249): fails unless the stream and the openings were read exactly to the end.

**`checked`.** The same walk serves `verify_execution` (checks everything) and `replay_unchecked` (checks nothing, but still reads every scalar and draws every challenge; `crates/verifier/src/lib.rs:169-178`). Aggregation replays children to build the guest's witness, and the guest's in-VM verification does the checking. AGENTS.md: every check sits behind `checked`, and nothing else may depend on it.

### 3.4 The protocol walk: `crates/verifier/src/lib.rs`, `walk` (229)

Read it top to bottom and note every transcript call. The first few:

1. `next_scalars(2 + N_TABLES)` (234): the eight **announced sizes** (memory log-size, six table row counts, log-inverse-rate), absorbed right after the seed and before any challenge. They decide the layout, and so every later count.
2. `next_scalars(2)` (250): the commitment root.
3. `verify_bus_balance` (254): the first challenges, `alphas` (`crates/verifier/src/bus.rs:112`), then the bus GKR.
4. `xi` (258), the table sumcheck (263), the public-input challenge (284), the Keccak reduction (301), ring switching (318) and the stacked WHIR opening (328), which contains the query grinding (`crates/verifier/src/whir.rs:184`), `sample_queries` (`whir.rs:70`) and the batching challenge `lam` (`whir.rs:189`).

Every count in these calls is a constant or comes from the layout, never from a challenge or a sent value other than the sizes. That is the invariant §5 depends on.

### 3.5 The Python verifier: `python-verifier/verifier.py`

`DS_OBSERVE` (354), `class Transcript` (378), `_duplex` (386), `grind_check` (420). It is the shortest of the four and the best one to read first if Rust slows you down. `crates/leanvm_core/tests/verifiers/python_verifier.rs` runs it against real proofs.

### 3.6 The recursion guest: `crates/rec_aggregation/guests/lean_ethereum.py`

The Fiat-Shamir section starts at line 527 with a comment worth reading. The guest holds the sponge as the 13-cell output of its last `KECCAK`. A VM cell carries two lanes (`crates/leanvm_core/src/keccak.rs:64`, `cell_lanes`), so a scalar's four lanes are two cells.

- `fs_pack` (538): writes a scalar as two rate cells, hinting its limbs and checking them.
- `fs_perm` (550): one `KECCAK` with `k` waiting scalars, `k` a compile-time constant (`k: Const`) at every call site; where the count is not constant, the guest calls `fs_perm4` instead.
- `fs_perm4` (569): the exception, called at every layer of the bus GKR, where up to two scalars wait across a loop boundary: the two roots at the first layer, none (zeroed cells) at later ones.
- `fs_next` (617): read the next stream word and absorb it, in one step. As the comment says, this is the soundness invariant of the whole guest.
- `squeeze` (628) and `challenge_from_state` (515): a challenge is lanes 0, 1, 2, assembled from cell 0 and the low half of cell 1.

## 4. The one ambiguity

Write `B` for four waiting scalars and `y` for one more.

- Sequence 1, `observe B, observe y, sample`: the fifth scalar forces a permutation of `B`; then the sample permutes `y`.
- Sequence 2, `observe B, sample, observe y, sample`: the first sample permutes `B` and its output is a challenge; then the second sample permutes `y`.

The permutation inputs are identical. The sponge records a sequence of rate blocks, not a sequence of operations, so a full block does not say whether a challenge was drawn from its output. A brute force over every sequence of up to 11 operations (`checks/collisions.py`) finds no other ambiguity. Tags rule out the rest.

The ambiguity is harmless if no two transcripts that agree so far can differ in whether the next step absorbs or squeezes. On `main` they can't, because of the invariant at the end of §3.4: the schedule is fixed by data that was itself absorbed first (the sizes) or hashed into the seed (the bytecode).

## 5. How far the theory goes

**Update (2026-11-10).** Upstream `main` now carries `formal/` (commit `b6167fe`), a Lean proof of the verifier's straight-line knowledge soundness in the random-permutation model, with the adversary choosing program, input and proof, and Keccak-256 and the duplex over the same permutation (`formal/statement.tex`, `LeanVM.knowledgeSoundness_holds`). It closes the two gaps below by another route: the adversary outputs the sizes (gap 1), and a two-oracle transfer under a duplex discipline handles the shared permutation (gap 2; `formal/common/Common/Transfer2.lean`, `formal/lean_vm/LeanVM/Protocol/Rpm/Duplex.lean`, where the duplex never writes lane 16). Read what follows as the CO25 view of the same construction, useful for understanding, not as the state of the art for `main`. What the Lean does not prove is in `statement.tex`'s last section: the KRS25 setting, recursion across levels, quantum adversaries, the Rust code itself.

The CO25 argument is in `529-analysis.md` §4. In short:

- **For a fixed bytecode and fixed sizes**, `main`'s transcript is CO25's DSFS. The start is CO25's informally covered `h = p` case (the instance absorbed from a fixed state), with the bytecode entering through its digest, the IV, which Keccak-256 computes on the same permutation, so this step also rests on gap 2's assumption and pays an IV collision. The codec writes each scalar as its tagged lanes, zero-padded per round to a multiple of 16 lanes, with an empty round after a challenge encoded as 16 zero lanes. A challenge is the first three lanes of a 16-lane squeeze. `checks/co25_equivalence.py` runs CO25's Construction 3.3 literally against the real Python verifier and matches it on thousands of random schedules.
- **Gap 1.** CO25 fixes the number of rounds and their lengths in advance (the latter by its codec, Definition 4.1); here both depend on the bytecode's length and the sizes, which the prover may choose (the sizes always, the bytecode unless the program is fixed, and the bytecode reaches the sponge only through the IV). CO25's reduction (BackTrack, Definition 5.3) already recovers each chain's instance before computing round offsets, so the offsets could come from the parsed sizes. That extension is plausible and unwritten.
- **Gap 2.** Merkle hashing (Keccak-256) runs on the same Keccak-f as the transcript, with no domain separation, while CO25's Merkle corollary assumes a separate hash. The bound needs Keccak-256 to be treated as an independent random oracle.
- **Not the transcript's fault, but open.** SR soundness of the whole protocol (Annex B proves RBR soundness only for the PCS opening). Grinding is uncredited, so each query phase gives about 111 bits. The KRS25 setting applies, since the guest evaluates Keccak-f; its uncommitted-trace GKRs are grand products and Keccak-f with a state committed every 12 rounds (`KECCAK_DEPTH`, `crates/verifier/src/layout.rs:83`).
- **The sponge's own term** is `25t²/2^576`, negligible. The real hash loss is birthday-scale in 256 bits (Merkle trees, IV).

## 6. The test this branch adds

`only_the_sizes_shape_the_transcript` (`crates/leanvm_core/tests/verifiers/portable_verifier.rs:66`) pins the invariant of §3.4 from the outside:

1. Take the shared fixture proof (`python_verifier.rs:143`, a small zkDSL program proven once).
2. Add one to the low limb of every scalar after the eight sizes. This changes every root, coefficient and nonce, and therefore every challenge.
3. Encode it in the raw opening form, where each query's opening has a fixed length regardless of which position it opens.
4. `replay_unchecked` must still succeed: `finish` passes only if the stream and the openings were read exactly to the end. The Keccak reduction's scalars must sit at the same stream positions.
5. Sanity check: `bytecode_point` (challenge-derived) must differ, so the challenges really did change.

If a read count depended on a value this change alters, the walk would almost certainly fall out of step and fail. That was checked by mutation: a temporary change to `crates/verifier` reading one extra scalar when a bit of the root is 0 (false for the fixture's honest proof, so the verifiers binary's other tests, which walk only that proof, still pass) made this test fail and no other test in that binary. The test pins **reads**, not challenge counts: an extra `sample()` reads nothing, and nothing in the verifier's output counts permutations.

Run it:

```bash
cargo test --release -p leanvm_core --test verifiers only_the_sizes
```

## 7. Exercises

1. **See the ambiguity.** Run `python3 .contrib/checks/collisions.py` and read the example group it prints. Then disable the permutation a fifth scalar forces (for example, change `if len(pend) == 4:` to `if False:`, letting the rate grow without bound) and watch the collisions disappear.
2. **See the mapping.** Run `python3 .contrib/checks/co25_equivalence.py 200`. Find `phi` and `co25_run`, and explain to yourself why, with sizes absorbed (as on `main`), the `stated` codec fails exactly when round 1 is empty, and why without sizes it is the `fixed` codec that fails there instead (hint: whether the start leaves a full rate waiting).
3. **Break the invariant.** In `crates/verifier/src/lib.rs`, after the root is read (line 250), add `if !transcript.checked() && halves[0].c0 & 1 == 0 { transcript.next_scalar()?; }`. Run the verifiers test binary and confirm that only `only_the_sizes_shape_the_transcript` fails. Then revert.
4. **Count permutations.** `git apply .contrib/checks/fs_count.patch`, rebuild, and run `cargo leanvm recursion --n 2 --xmss-per-leaf 50 --log-inv-rate 2`. Sum the `FSCOUNT replay` lines in pairs, since the counters are process-wide. Revert with `git checkout crates/verifier`.
5. **Trace one WHIR level** in `crates/verifier/src/whir.rs` from line 150: list each absorb and sample in order, and mark where a run of challenges happens back to back (these are the only places packing challenges would save permutations).
6. **Compute the bounds.** Evaluate `25t²/2^576` at `t = 2^128`, and compare it with a 256-bit birthday bound `t²/2^256` at the same `t`. Which term dominates, and why does that make the sponge's capacity irrelevant to the overall number?
7. **Read the guest's view.** In `lean_ethereum.py`, find every call to `fs_perm4` and explain why the number of waiting scalars there is not a compile-time constant, but is still not chosen by the prover.

## 8. Reading list

- CO25 (ePrint 2025/536): §2.2 and Remark 2.1 (the start), §2.6 (BCS, Corollary 1), Construction 3.3, Definitions 3.12 and 4.1, Construction 4.3, Theorems 6.1 and 6.2, Definition 5.3 and BackTrack (§5.2) if you want to attempt gap 1.
- SAFE (ePrint 2023/522): §1's misuse list, §3.3 (IO patterns to tags).
- KRS25 (ePrint 2025/118): §1.1, §4 (the universal-circuit attack), Remark 3, §5 (countermeasures).
- Chiesa and Yogev, *Building Cryptographic Proofs from Hash Functions* (snargsbook.org): state-restoration and round-by-round soundness.
- In the repository: `doc/leanvm/body/08-end-to-end-protocol.tex` §8.4 (`sec:e2e-fiat-shamir`), Annex B §B.1.2 and Theorem `thm:rbr`; and, on `upstream/riscv-exploration`, the same section after #552, for the framed alternative.

## 9. Glossary

| term | meaning here |
| --- | --- |
| scalar | an element of `E = GF(2^192)`, three 64-bit limbs |
| lane | one 64-bit word of the 25-lane Keccak state |
| rate / capacity | lanes `0..16` / lanes `16..25` |
| IV | `Keccak-256("leanvm-v1" ‖ bytecode table)`, binding the program |
| announced sizes | the eight scalars after the seed that fix the layout |
| shape | bytecode length plus sizes: everything that fixes the transcript's schedule |
| codec | CO25's maps from messages to sponge lanes and from lanes to challenges |
| replay | `replay_unchecked`: the walk with every check skipped |
| grinding | proof of work before WHIR's queries: 17 low zero bits |
| BackTrack | the step in CO25's proof that reconstructs a transcript from permutation queries |
