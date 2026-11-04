# Fiat-Shamir on `main`: the transcript is CO25's duplex-sponge Fiat-Shamir

Draft for [leanEthereum/leanVM#529](https://github.com/leanEthereum/leanVM/issues/529), against upstream `main` at `23a305b` (2026-11-04). Not yet reviewed by the maintainers.

Code links below are permalinks to that commit. `P` abbreviates `https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4`.

## Summary

- #529 (Oct 7) was opened while `main`'s transcript was a BLAKE2s hash chain, not a duplex. On `riscv-exploration`, #552 (Oct 10) rebuilt that line's transcript as a framed BLAKE2s duplex with a written argument (DMV18), and the unmerged `spongefish-fs` put spongefish's interface on top. `main` went another way: #636 (merged Oct 23) replaced the chain with an unframed duplex over Keccak-f[1600], after Plonky3's challenger. Nothing in the spec argues its security.
- `main`'s duplex has exactly one non-injectivity: a permutation forced by a fifth absorbed scalar is the same permutation as a challenge drawn with four scalars waiting. SAFE lists this shape as a misuse and closes it with an IO-pattern tag. CO25 closes it differently, with no tag, by requiring the round structure to be fixed by the instance.
- `main` already meets CO25's conditions. Every count the verifier absorbs or samples is a function of the bytecode (hashed into the IV) and the announced sizes (absorbed right after the seed). Taking the instance to be (IV, public input, sizes), `main`'s transcript is DSFS (CO25, Construction 4.3) over Keccak-f with an injective, unbiased codec, and Theorem 6.1 gives `ε_NARG ≤ ε_sr_IP + 25t²/2^576`. This needs no code change. What is missing is the written argument and a test pinning its one load-bearing invariant.
- #552 says CO25 and SAFE do not apply. That is right for BLAKE2s compression, which is not a permutation. On `main` the primitive is a permutation, so CO25 applies directly, and the argument survives replacing Keccak by any other permutation.
- Measured in the recursion guest (2→1, leaves of 900 leanXMSS, log-inv-rate 2): about 922 Fiat-Shamir permutations per child verified, about 15% of the root's `KECCAK` instructions. Squeezing five challenges per permutation would save about 12% of them, about 2% of the root's `KECCAK`s.

## 1. History

| when | where | transcript |
| --- | --- | --- |
| until Oct 14 | `main` | BLAKE2s chain: `cv ← BLAKE2s(cv ‖ x ‖ tag)`, one compression per absorbed scalar and per challenge; a challenge is three of the four words of the new `cv` |
| Oct 7 | #529 opened | "the duplex construction looks insecure" (attributed to Khovratovich). Relayed ask: a duplex over Blake2s/2b supporting long absorb-squeeze patterns, fewest compression calls, 128 bits provable in the CO25 or SAFE paradigm |
| Oct 10 | `riscv-exploration`, #552 (kevaundray) | framed BLAKE2s duplex with "conditional mode security": DMV18 Theorem 1 for the mode, a round-by-round adapter via CCHLRR18; a section "Why not directly CO25 or SAFE" (BLAKE2s compression is not a permutation) |
| Oct 10 to 11 | `spongefish-fs` (Thomas Coratger), unmerged | spongefish v0.8 / draft-irtf-cfrg-fiat-shamir-03 interface over that duplex |
| Oct 14, merged Oct 23 | `main`, `b92ca6ba` in #636 | duplex sponge over Keccak-f[1600] in overwrite mode, "after Plonky3's duplex challenger". #636's description in full: "Keccak is still still a placeholder, for now." Neither mentions #529 |

On Oct 7 `main` had no duplex, so whatever was reviewed, `main`'s transcript today is newer than the review.

## 2. The construction on `main`

The state is 25 lanes of 64 bits: the rate is lanes `0..16` (`r = 16`), the capacity lanes `16..25` (`c = 9`, 576 bits). The alphabet is a lane, `Σ = {0,1}^64`.

- **Seed.** From the zero state, lanes `0..4` take the IV, `Keccak-256("leanvm-v1" ‖ bytecode table)`, and lanes `4..8` the 256-bit public input; one permutation; the rate is zeroed.
- **Absorb.** A sent scalar of `E = GF(2^192)` waits; the `k`-th waiting scalar is written as `(c0, c1, c2, tag)` over lanes `4k..4k+4`, tag `1` for a sent scalar and `4` for a grinding nonce. A fifth scalar first permutes the four waiting.
- **Sample.** Permute with whatever waits, the rate past it zeroed; the challenge is lanes `0..3` of the output; the rate is zeroed. Every challenge is a permutation of its own.
- **Grinding.** Absorb the nonce (tag 4) and sample; that challenge's low `b` bits must be zero, `b = 17` before WHIR's queries; with `b = 0` the nonce must be zero.
- **Not absorbed:** Merkle openings. Their roots are absorbed, as two scalars each.

Four implementations agree: the prover's [`FiatShamirState`](P/crates/fiat_shamir/src/lib.rs#L51-L194), the native verifier's [`Sponge`](P/crates/verifier/src/transcript.rs#L32-L90), the [Python verifier](P/python-verifier/verifier.py#L354-L424), and the [guest](P/crates/rec_aggregation/guests/lean_ethereum.py#L515-L633), which replays each permutation as one `KECCAK` instruction with the number of waiting scalars a compile-time constant at every site. The spec's description is [§8, `sec:e2e-fiat-shamir`](P/doc/leanvm/body/08-end-to-end-protocol.tex#L63-L75); it describes the construction and argues nothing about it.

Other transcripts share the seed shape `(H(x), y)`: the aggregation statement, `from_label("leanvm/recursion-aggregation/v1")`, and LeanDA's challenge, `(H("leanDA/rs-membership/v1"), root)`. These preimages and `"leanvm-v1" ‖ bytecode` differ within their first seven bytes and `TAG` has a fixed length, so no two seeds coincide.

## 3. The collision

Let `B` be four waiting scalars. Then `observe B, observe y, sample` and `observe B, sample, observe y, sample` feed the permutation the same inputs and end on the same challenge: the first discards a permutation output that the second calls a challenge. The sponge sees a sequence of rate blocks, not a sequence of operations, and a full block does not record whether a challenge was drawn from its output. The tags rule out every other ambiguity, such as `k` scalars against `k` scalars and a zero (`fs_binds_length`), so this is the only one.

Exploiting it needs a verifier that, at the same point of the same transcript, could either draw a challenge or read another scalar. SAFE's misuse list names the shape: "When the input data fills the full rate, no padding or any other length-dependent separator is applied." The rest of this note shows `main`'s verifier never faces that choice, and that this is exactly CO25's hypothesis.

## 4. Why it is harmless: `main` is an instance of DSFS

CO25 (Chiesa and Orrù, *A Fiat-Shamir Transformation From Duplex Sponges*, TCC 2025, ePrint 2025/536) analyses DSFS (Construction 4.3) over the overwrite-mode duplex of Construction 3.3, with an ideal permutation. Its hypotheses: a public-coin IP of `k` rounds, each a prover message then a verifier message; a codec (Definition 4.1) fixing per-round lengths `ℓP(i)`, `ℓV(i)` from `(λ, n)`, with injective encodings `φi` and decodings `ψi` of bias `ε_cdc,i`; and a start state depending only on the instance. It deliberately hashes no framing: "DSFS does not hash lengths/labels of the prover and verifier messages (our results guarantee this is secure)" (§2.2), and it "avoids the use of padding or IO patterns" (§1).

Map `main` onto it with `Σ = {0,1}^64`, `r = 16`, `c = 9`, `p = Keccak-f[1600]`, and salt `δ = 0` (proofs are not zero knowledge).

### 4.1 Instance and start

Take the instance `x' = (IV, pi, a)`, where `a` is the eight announced sizes: the memory log-size, the six row counts and the log-inverse-rate, each with zero high limbs (the verifier rejects otherwise, `AnnouncedHighLimb`). Let `Start(x') = Absorb(st*, φ0(x'))` from the zero state `st*`, with

`φ0(x') = IV ‖ pi ‖ 0^8 ‖ (a_j, 0, 0, 1) for j = 0..8`,

48 lanes. Absorbing them in Construction 3.3 performs exactly `main`'s seed permutation followed by the two permutations its absorbed sizes trigger: each block overwrites the whole rate, so `main`'s zeroing of the rate is invisible. CO25 covers a start by absorption from a fixed state "as a special case (with h = p)" (§2.2, after Remark 2.1).

The sizes come from the proof, so the prover chooses `x'`. CO25's soundness is adaptive in the instance (the state-restoration prover outputs `x`, Definition 3.12), and a false statement `(bytecode, pi)` stays false under every `a`, so this costs nothing.

### 4.2 Rounds and codec

Number the challenges `main` draws `σ_1, …, σ_k`, grinding challenges included. Round `i`'s prover message is the `m_i ≥ 0` scalars absorbed between `σ_{i−1}` and `σ_i` (between the start and `σ_1` for `i = 1`), and its verifier message is `σ_i`.

**The load-bearing fact: `k` and every `m_i` depend on `x'` alone.** Every count the native verifier reads or samples is a constant or comes from the layout that [`build_layout(bytecode, log_memory, table_rows)`](P/crates/verifier/src/lib.rs#L229-L247) and the log-inverse-rate determine: the bus GKR's `1 << step` and `samples(step)`, `samples(BUS_BITS)`, each table's `width()`, the Keccak reduction's `segments()`, `PRODUCT_BITS`, `LANE_BITS` and `K_BITS`, the ring switch's shifts, and WHIR's fold counts, `message_log`, residual size and query count. `sample_queries` draws `⌈count / ⌊192/depth⌋⌉` challenges with `depth` from the layout. No count depends on a challenge, on a sent scalar's value other than `a`, or on Merkle data, which feeds only arithmetic. The guest says the same thing structurally: the number of waiting scalars is a compile-time constant at every Fiat-Shamir site.

The codec:

- `φ_i`: each scalar as its tagged lanes `(c0, c1, c2, 1)`, then zero lanes up to a multiple of 16; for `m_i = 0`, sixteen zero lanes. Injective, since `ℓP(i)` is fixed.
- `ψ_i`: read 16 lanes and keep lanes `0..3` as an element of `E`. Three 64-bit lanes are a bijection onto `GF(2^192)`, so the bias is zero.

Checked against Construction 3.3, step by step:

- A message of `m_i ≥ 1` scalars ends on a block boundary, so its last block overwrites the whole rate, and the squeeze then permutes. That is `main`'s sample with the rate past the waiting scalars zeroed.
- When a fifth element arrives with `i_A = r`, Absorb permutes, then writes. That is `main`'s fifth scalar.
- An empty message writes sixteen zeros over the previous output, and the squeeze permutes `(0^16, capacity)`. That is `main`'s sample with nothing waiting.
- Squeezing 16 lanes leaves `i_S = r`, so a later squeeze permutes first, and Squeeze sets `i_A = 0`, so a later absorb starts at lane 0. Both match `main`.

Splitting a run of consecutive challenges into rounds with empty prover messages loses nothing. In CO25's state-restoration game a verifier message is `ρ_i := f_i(x, τ, α_1, …, α_i)`, a function of the prover-message prefix (Definition 3.12), and an empty message has a single value, so a state-restoration prover against the split IP is one against the batched IP with no more moves.

### 4.3 Outside the IP

- **Merkle openings** are not absorbed. They are bound by their roots, which are, and the PCS binding argument covers them; #552 treats them the same way.
- **Grinding.** The nonce is a round's prover message (tag 4) and the proof-of-work challenge is its verifier message. The check only adds a reason to reject, so the bound below holds without crediting grinding at all. Crediting it needs a separate proof-of-work argument, which #552 also leaves out.

### 4.4 The bound

CO25 Theorem 6.1: `ε_NARG(λ, t, n) ≤ ε_sr_IP(δ*, t, n) + 25t²/|Σ|^c + t · max_i ε_cdc,i + Σ_i ε_cdc,i`, for `t` queries to `p` and `p⁻¹`. Here `|Σ|^c = 2^576` and both bias terms are zero, so the transcript adds `25t²/2^576`, below `2^-315` at `t = 2^128`. Theorem 6.2 gives the same additive term for rewinding knowledge soundness.

So the transcript is not where soundness is decided. It is decided by the IP's state-restoration soundness, which is where the per-round errors of §8 and Annex B belong, round by round.

### 4.5 What has to stay true

1. Every count the verifier reads or samples is a function of the bytecode and the announced sizes. A count depending on a challenge or a message value would make the round structure prefix-dependent, outside Definition 4.1, and is exactly where the collision of §3 could bite.
2. The sizes are absorbed before anything they size.
3. The codec stays injective per round: nonzero tags, or any other fixed-length encoding.
4. Distinct transcripts keep distinct seeds (`TAG` fixed-length and first, labels distinct).
5. The primitive stays a permutation modelled as ideal. Replacing Keccak by another permutation keeps the argument; replacing it by a compression function does not, which is #552's case.

None of these is written down or tested today.

## 5. Comparison

| | `main` | CO25 DSFS (spongefish) | SAFE | #552 (`riscv-exploration`) |
| --- | --- | --- | --- | --- |
| primitive | Keccak-f, `r = 16`, `c = 9` lanes | ideal permutation | permutation over a field | BLAKE2s compression, not a permutation |
| absorb | overwrite, rate past the block zeroed | overwrite | add | framed compression nodes |
| framing | a tag lane per scalar, none between absorb and squeeze | none | IO-pattern tag `T = H(pattern ‖ D)` in the capacity | role, length and consumed-output counter per node |
| what fixes the schedule | bytecode in the IV, sizes absorbed first | the IP's round structure, via the codec | the declared IO pattern | the counter |
| squeeze | one challenge per permutation | the whole rate | the whole rate | 32-byte output blocks, unused bytes kept |
| argument | none written; CO25 Theorem 6.1 applies (§4) | Theorems 6.1, 6.2 | Theorem 1, details in a separate report (KMM23) | DMV18 Theorem 1 with a CCHLRR18 adapter |
| transcript loss | `25t²/2^576` | `25t²/|Σ|^c` | `c log₂|F|` bits claimed | `C(Q, 2)/2^256` |

spongefish's own duplex (cited there as "[CO25], Construction 3.3, with minor changes") has the same absorb/squeeze ambiguity as `main` and documents it: "The session identifier MUST account for the absorb/squeeze pattern." `main` meets that obligation with the bytecode in the IV and the sizes absorbed at the start.

## 6. Cost in the recursion guest

Measured on `main` at `23a305b`, `cargo leanvm recursion --n 2 --xmss-per-leaf 900 --log-inv-rate 2`, with a counter in `crates/verifier`'s sponge (not committed), on a 4-core cloud VM:

| | per child proof verified |
| --- | --- |
| scalars absorbed | 2,532 |
| challenges | 699 (569 after absorbed scalars, 130 after another challenge) |
| permutations after the seed | 921 (222 forced by a fifth scalar, 699 for challenges) |
| longest run of consecutive challenges | 21 |
| Merkle query paths | 222, with 4,878 sibling compressions plus leaf hashes |
| permutations with up to 5 challenges each | 808 (12% fewer) |
| permutations with up to 4 challenges each | 814 |

The root runs 537,703 cycles, with `KECCAK` at 2^13.63 (about 12,700 instructions, 2.4% of cycles) and the Keccak table padded to 2^14. Fiat-Shamir is about 1,844 of those `KECCAK`s (15%), and the rest is mostly Merkle hashing. Five challenges per permutation would remove about 226 `KECCAK`s at the root (about 2%), without moving the table off 2^14. Cycles spent around each permutation (packing scalars, reading challenges) were not attributed.

If challenges are ever packed, five per permutation is the cheaper layout in the guest as well as natively. [`challenge_from_state`](P/crates/rec_aggregation/guests/lean_ethereum.py#L515-L524) already splits the cell holding lanes 2 and 3, hinting one limb and deriving the other, and discards lane 3. With challenges at lanes `3j..3j+3`, consecutive pairs share that split, one hint per two challenges, where four-lane-aligned challenges need one per challenge.

## 7. The options, re-scored

- **A. Prove the current mode.** §4 as a lemma in §8 (`sec:e2e-fiat-shamir`), citing CO25 Theorem 6.1, plus a test pinning invariant 1 of §4.5. No change to the prover, the verifiers or the guest, and none to `TAG` or the labels. Recommended.
- **B. Add framing.** Not needed on `main`: CO25 shows framing is unnecessary when the instance fixes the round structure, and here it does. #552 needs framing because its theorem (DMV18) is about hashing modes of a compression function. Framing would add guest work to every permutation without improving the bound.
- **C. Squeeze up to five challenges per permutation.** About 2% of the root's `KECCAK`s, no change to the padded table at this size, and it touches all four implementations. Worth doing only bundled with another transcript change.

## 8. Open questions for the maintainers

1. Is `main` now the target of #529, or is `riscv-exploration`'s transcript (#552, `spongefish-fs`) the one that matters?
2. Which construction did the original concern refer to: `main`'s old BLAKE2s chain, the `riscv-exploration` duplex, or Plonky3-style duplex challengers in general? `main` is now the last kind.
3. Would a PR adding §4 to the spec, and a test pinning the schedule invariant, be welcome?

## References

- CO25: A. Chiesa, M. Orrù. *A Fiat-Shamir Transformation From Duplex Sponges.* TCC 2025, ePrint 2025/536 (revision of 2026-03-27). Construction 3.3, Definitions 3.12 and 4.1, Construction 4.3, Theorems 6.1 and 6.2, §2.2.
- SAFE: J.-P. Aumasson, D. Khovratovich, B. Mennink, P. Quine. *SAFE: Sponge API for Field Elements.* ePrint 2023/522. §1 (misuse patterns), §3.2 Theorem 1, §3.3.
- spongefish: `arkworks-rs/spongefish` at `2880323`, `spongefish/src/duplex_sponge.rs`.
- #552 and `spongefish-fs`: `upstream/riscv-exploration` (`f11f84f5`), `upstream/spongefish-fs` (`8ba3da3c`), and `doc/leanvm/body/08-end-to-end-protocol.tex` there.
