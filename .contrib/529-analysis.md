# Fiat-Shamir on `main`: how far CO25's duplex-sponge Fiat-Shamir covers the transcript

> **Overtaken on 2026-11-09** by upstream's `formal/` (commit `b6167fe`), which proves leanVM's knowledge soundness in the random-permutation model with the transcript, a prover-chosen program and sizes, and Keccak-256 over the same permutation all covered: the two gaps of §4.4 and §4.5, and the open knowledge soundness of §4.7, are closed there. This analysis stays as a record of `main` at `23a305b` and of the reasoning; see `HANDOFF.md`.

Notes for [leanEthereum/leanVM#529](https://github.com/leanEthereum/leanVM/issues/529), against upstream `main` at `23a305b` (2026-11-04). Revised after an adversarial review that found the first version overclaimed (§9). Not yet reviewed by the maintainers.

Code links are permalinks to upstream `main` at that commit.

## Summary

- **History.** #529 (Oct 7) was opened the day after #523 put a two-scalar BLAKE2s transcript step on `riscv-exploration`, each block tagged with its role and scalar count. #552 (Oct 10) replaced that step with a framed BLAKE2s duplex and a written argument, and #607 and #620 followed. `main` kept a BLAKE2s hash chain until #636 (merged Oct 23) replaced it with a duplex over Keccak-f[1600] that tags each scalar but frames nothing between absorbing and squeezing (after Plonky3's challenger). Nothing in the spec argues that duplex's security.
- **One ambiguity.** `main`'s duplex has exactly one non-injectivity: a permutation forced by a fifth absorbed scalar is the same permutation as a challenge drawn with four scalars waiting. A brute force over all 265,720 operation sequences of length at most 11 finds no other.
- **Why it does not bite.** Every count of absorbed scalars and squeezed challenges, and their order, is fixed by the bytecode (hashed into the IV) and the eight announced sizes (absorbed right after the seed, before any challenge). Values never change it.
- **What CO25 gives.** For each fixed bytecode length and fixed sizes (a "shape"), `main`'s transcript is CO25's DSFS (Construction 4.3) with an injective, unbiased codec, its start the informally covered `h = p` case with the bytecode entering through the IV (§4.1); a literal implementation of Construction 3.3 reproduces `main`'s permutation inputs on 6,000 random schedules.
- **Two gaps to a theorem for `main` as deployed.** (1) In CO25 the protocol's number of rounds is fixed and the codec fixes their lengths by the security parameter and the instance-size bound (Definition 4.1), so a prover who chooses the sizes needs an extension of its reduction. Its reduction already recovers each chain's instance before computing round offsets, and the sizes sit in the clear in the first blocks, which makes this plausible; it is not written down. (2) The Merkle openings bring in CO25's BCS form (§2.6, Corollary 1, stated informally), which adds a Merkle term and keeps the Merkle hash separate from the permutation; on `main` both run on Keccak-f, so the bound needs Keccak-256 to be a random oracle independent of the permutation, an extra assumption.
- **What the transcript is not responsible for.** End-to-end state-restoration soundness is not established in the spec (Annex B proves round-by-round errors for the opening only), and WHIR's query counts assume 17 bits of grinding, which no Fiat-Shamir argument here credits.
- **Scope.** All of this is classical, in the ideal-permutation model, for one proof. It does not address KRS25-style attacks (every leanVM program can evaluate Keccak-f in one instruction, and the deployed guest does), quantum adversaries, or recursion's need for knowledge soundness, beyond noting CO25's Theorem 6.2.
- **Cost.** In the recursion guest (2→1, leaves of 900 leanXMSS, log-inv-rate 2), Fiat-Shamir is 921 permutations per child verified after the seed, about 1,840 of the root's roughly 12,700 `KECCAK` instructions. Squeezing five challenges per permutation would save 12% of those, about 2% of the root's `KECCAK`s.

## 1. History

| when | where | transcript |
| --- | --- | --- |
| until Oct 23 | `main` | BLAKE2s chain: `cv ← BLAKE2s(cv ‖ x ‖ tag)`, one compression per absorbed scalar and per challenge; a challenge is three of the four words of the new `cv` |
| Oct 6 | `riscv-exploration`, #523 (kevaundray) | "The Fiat-Shamir step is one compression keyed by the state, absorbing up to two scalars; a squeeze absorbs the waiting ones in its own step." Each 64-byte block holds the scalars, their count and a role tag (`step_block`: observe, squeeze, proof-of-work base, nonce), so a squeeze never reads as a continued absorb |
| Oct 7 | #529 opened | "the duplex construction looks insecure" (attributed to Khovratovich). Relayed ask: a duplex over Blake2s/2b supporting long absorb-squeeze patterns, fewest compression calls, 128 bits provable in the CO25 or SAFE paradigm |
| Oct 10 | `riscv-exploration`, #552 (kevaundray) | framed BLAKE2s duplex with "conditional mode security": DMV18 Theorem 1 for the mode, a round-by-round adapter via CCHLRR18, and a section "Why not directly CO25 or SAFE" (BLAKE2s compression is not a permutation) |
| Oct 11, Oct 13 | `riscv-exploration`, #607, #620 (Thomas Coratger) | a spongefish-style transcript over that duplex; then "messages sent under a one-time pad" |
| merged Oct 23 | `main`, #636 | duplex sponge over Keccak-f[1600] in overwrite mode, "after Plonky3's duplex challenger" (`b92ca6ba` on the PR branch, Oct 14, first over the VM's SHA3 step, plain Keccak-f from `e471f70d`, Oct 21). #636's description calls Keccak a placeholder for now. Neither mentions #529 |

The issue does not say which construction it means or what looked insecure. The closest in time is #523's step, which was framed, so if the concern was about it, it was not the ambiguity of §3 (a concern about duplex challengers in general could be). #552 is its author's own rework on `riscv-exploration`. `main`'s transcript is newer than all of it.

## 2. The construction on `main`

The state is 25 lanes of 64 bits: the rate is lanes `0..16`, the capacity lanes `16..25` (576 bits).

- **Seed.** From the zero state, lanes `0..4` take the IV, `Keccak-256("leanvm-v1" ‖ bytecode table)`, and lanes `4..8` the 256-bit public input; one permutation; the rate is zeroed.
- **Absorb.** A sent scalar of `E = GF(2^192)` waits; the `k`-th waiting scalar is written as `(c0, c1, c2, tag)` over lanes `4k..4k+4`, tag `1` for a sent scalar and `4` for a grinding nonce. A fifth scalar first permutes the four waiting.
- **Sample.** Permute with whatever waits, the rate past it zeroed; the challenge is lanes 0, 1, 2 of the output; the rate is zeroed.
- **Grinding.** Absorb the nonce (tag 4) and sample; that challenge's low `b` bits must be zero (`b = 17` before WHIR's queries); with `b = 0` the nonce must be zero. The nonce is always the last scalar before its challenge.
- **Not absorbed:** Merkle openings. Their roots are absorbed, as two scalars each.

Four implementations agree: the prover's [`FiatShamirState`](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/crates/fiat_shamir/src/lib.rs#L51-L194), the native verifier's [`Sponge`](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/crates/verifier/src/transcript.rs#L32-L90) and [`grind_check`](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/crates/verifier/src/transcript.rs#L151-L167), the [Python verifier](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/python-verifier/verifier.py#L354-L424), and the [guest](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/crates/rec_aggregation/guests/lean_ethereum.py#L515-L633), which replays each permutation as one `KECCAK` instruction. The spec describes the construction in [§8, `sec:e2e-fiat-shamir`](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/doc/leanvm/body/08-end-to-end-protocol.tex#L63-L75) and argues nothing about it.

Other transcripts share the seed shape `(H(x), y)`: the recursion's deferred-claim batching, `from_label("leanvm/recursion-aggregation/v1")`, and LeanDA's challenge, `(H("leanDA/rs-membership/v1"), root)`; `verify_keccak_batch` (bench and tests) takes a caller's IV. The labels differ from `TAG` within their first seven bytes and `TAG` has a fixed length, so no two production seeds coincide.

## 3. The ambiguity

Let `B` be four waiting scalars. Then `observe B, observe y, sample` and `observe B, sample, observe y, sample` feed the permutation the same inputs and end on the same challenge: the first discards a permutation output that the second calls a challenge. The sponge sees a sequence of rate blocks, not of operations, and a full block does not record whether a challenge was drawn from its output. The tags rule out everything else (`k` scalars against `k` scalars and a zero: `fs_binds_length`); [`checks/collisions.py`](checks/collisions.py) confirms symbolically, over every sequence of observes, nonces and samples of length at most 11, that this rule explains every collision.

Exploiting it needs two transcripts that agree on every permutation input so far and differ in whether the next step squeezes or absorbs: of one proof, of two instances, or of two protocols on the same permutation. SAFE's list of misuses names the shape: "When the input data fills the full rate, no padding or any other length-dependent separator is applied." The question is whether `main` ever admits two such transcripts. Distinct seeds (§2) rule out two of leanVM's Fiat-Shamir transcripts, and §4.3 rules out two runs of the execution proof's. Keccak-256, whose evaluations on the same permutation can start from the seed's input, is left to the assumption of §4.5.

## 4. How far CO25 goes

CO25 (Chiesa and Orrù, *A Fiat-Shamir Transformation From Duplex Sponges*, TCC 2025, ePrint 2025/536 revised 2026-03-27) analyses DSFS (Construction 4.3) over the overwrite-mode duplex of Construction 3.3, with an ideal permutation. It hashes no framing: "DSFS does not hash lengths/labels of the prover and verifier messages (our results guarantee this is secure)" (§2.2), and it "avoids the use of padding or IO patterns" (§1). What it needs instead is a codec (Definition 4.1), "a function cdc that maps every security parameter λ ∈ N and instance size bound n ∈ N to a tuple cdc(λ, n) = (ℓP, ℓV, φ, ψ)": the length of every round is fixed in advance.

Map `main` onto it with an alphabet of 64-bit lanes, rate 16, capacity 9, `p` = Keccak-f[1600], and no salt (proofs are not zero knowledge).

### 4.1 Instance and start

The instance is `x = (bytecode, public input, a)`, with `a` the eight announced sizes: the memory log-size, the six row counts and the log-inverse-rate, each with zero high limbs (the verifier rejects otherwise). The bytecode enters the sponge through its digest, the IV, so the argument also pays for an IV collision, about `t²/2^256`. Take `Start(x) = Absorb(st*, φ0(x))` from the zero state, with

`φ0(x) = IV ‖ pi ‖ 0^8 ‖ (a_j, 0, 0, 1) for j = 0..8`,

48 lanes. In Construction 3.3, absorbing them performs two permutations: `main`'s seed permutation, and the one the fifth size forces. The last four sizes wait in the rate, exactly as on `main`, where the commitment root's first half permutes them; in CO25 the same happens when round 1's first lane arrives. CO25 states informally that its analysis "covers, as a special case, the particular choice where DS.Start^h(x) = DS.Absorb^p(st*, φ0(x)) (with h = p)" (§2.2, after Remark 2.1). Here `φ0` is not oracle-free: the IV is Keccak-256 of the bytecode, computed on the same permutation in another mode. So this is that special case for the instance with the bytecode replaced by its digest, which rests on the assumption of §4.5 and costs an IV collision.

### 4.2 Rounds and codec, for a fixed shape

Number the challenges `main` draws `σ_1, …, σ_k`, the proof-of-work challenges included. Round `i`'s prover message is the `m_i` scalars absorbed between `σ_{i−1}` and `σ_i` (between the start and `σ_1` for `i = 1`), and its verifier message is `σ_i`.

- `φ_i`: each scalar as `(c0, c1, c2, tag)`, tag 1 for a sent scalar and 4 for the grinding nonce, which is always the last scalar of its round; then zero lanes up to a multiple of 16. An empty message of a round `i ≥ 2` is sixteen zero lanes. Round 1 is never empty on `main`: it opens with the commitment root.
- `ψ_i`: squeeze 16 lanes and keep lanes 0, 1, 2. Three 64-bit lanes are a bijection onto `GF(2^192)` and the projection has equal fibres, so the decoding has no bias.

Against Construction 3.3, step by step: a nonempty round ends on a block boundary, so its last block overwrites the whole rate and the squeeze permutes, which is `main`'s sample with the rate past the waiting scalars zeroed; when the 17th lane of a round arrives, Absorb permutes first, which is `main`'s fifth scalar; an empty round writes sixteen zeros over the previous challenge's output and the squeeze permutes `(0^16, capacity)`, which is `main`'s sample with nothing waiting; every Absorb sets `i_S = r` and every Squeeze sets `i_A = 0`, so the next operation behaves as on `main`.

[`checks/co25_equivalence.py`](checks/co25_equivalence.py) runs Construction 3.3 literally under this codec, against the Python verifier's `Transcript` and line-by-line mirrors of the Rust prover and verifier, with a stand-in permutation and with real Keccak-f. Permutation inputs and challenges match on all 6,000 random schedules with sizes (3,000 of them with raw nonces). With an empty round 1 encoded as sixteen zeros instead, every mismatch has an empty round 1, the case `main` never reaches.

Splitting a run of consecutive challenges into rounds with empty prover messages loses nothing: in CO25's state-restoration game a verifier message is `ρ_i := f_i(x, τ, α_1, …, α_i)`, a function of the prover-message prefix (Definition 3.12), and an empty message has a single value.

### 4.3 The schedule

The mapping needs `k` and every `m_i` to be fixed once the shape is. On `main` they are: no count or order of absorbed scalars and squeezed challenges depends on a challenge, on a sent value other than the sizes, or on Merkle data. In `walk()`, which `verify_execution` and `replay_unchecked` share, every count is a constant or comes from the layout that [`build_layout(bytecode, log_memory, table_rows)`](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/crates/verifier/src/lib.rs#L229-L247) and the log-inverse-rate determine: for example the bus GKR's `1 << step`, each table's `width()`, the table sumcheck's rounds, and WHIR's fold counts, residual size and query count; `sample_queries` draws `⌈count / ⌊192/depth⌋⌉` challenges with `depth` from the layout and does no rejection or deduplication. Values feed checks, and a failed check only ends the walk; Merkle data never enters the sponge (the pruned form deduplicates positions, but only to expand the openings).

Three independent confirmations: a trace of the Python verifier with its checks disabled gives the same operation sequence for a zero stream and for random streams, and a different `log_memory` changes it; the guest's runtime loops and branches around Fiat-Shamir sites are bounded by values pinned to the absorbed sizes (the bus GKR's first layer takes the two waiting roots from record cells that later layers zero); and `only_the_sizes_shape_the_transcript` (on this branch) changes every scalar after the sizes and checks that the replay still reads the stream and the openings exactly to their end. That test fails, alone, under a mutation that makes one read depend on a bit of the commitment root. It pins reads, not squeeze counts.

### 4.4 Gap 1: a prover who chooses the shape

The protocol has a fixed round complexity `k`, and Definition 4.1's codec fixes `ℓP(i)` and `ℓV(i)` by `(λ, n)`; CO25's message spaces "may be functions of, e.g., the instance size" (§3). On `main` they vary with the bytecode's length and the sizes at a fixed `n`. So §4.2 shows that `main` is DSFS for each fixed shape, and CO25's adaptivity (the prover outputs the instance, Definitions 3.5 and 3.12) does not let the codec depend on the instance. A union bound over shapes would cost soundness bits, and `ε_sr` would have to hold uniformly over every admitted shape (log-inverse-rate 1 to 4, each stack size with its own WHIR query count).

The natural extension of CO25's §5 reduction: BackTrack already recovers a chain's instance (Definition 5.3, the chain's start) before its step 4 computes the round offsets `L_ptr(i)` from the fixed lengths, so the offsets can come from the recovered instance instead. For a fixed program, as deployed (`crates/leanvm` exposes only aggregation, whose guest is fixed, so the IV is a constant), the part of the instance that sets the shape is the sizes, in the clear in the 48-lane prefix, readable from each chain's first three blocks. A prover-chosen program also changes the shape through the bytecode's length, which the prefix holds only as its Keccak-256 digest; there the reduction must find the IV's preimage among the adversary's queries, which needs §4.5's assumption, so in general gap 1 is not independent of gap 2. Chains that agree on their first three blocks agree on `(IV, pi, sizes)`, and a capacity collision is already in the `25t²` term. #552's round-by-round adapter rebuilds the schedule the same way ("The verifier's deterministic schedule, reconstructed from its statement and parsed announcement/message prefix"), though its per-node framing makes the mode's own parsing schedule-free. This extension is plausible and not written anywhere.

### 4.5 Gap 2: Merkle openings on the same permutation

Theorem 6.1 covers interactive proofs without oracles. leanVM is a Merkle-compiled IOP, which CO25 covers in §2.6: "BCS[IOP] = DSFS[iBCS[IOP], cdc]", "(The compression function for the Merkle commitment remains.)", with Corollary 1 (informal): `ε_NARG(t) ≤ ε_sr_IOP(t) + κ_MT(t, l, (t+1)·k, k) + 25t²/|Σ|^c + t·max_i ε_cdc,i + Σ_i ε_cdc,i`.

The roots are absorbed before the challenges that choose the queries on them, and the openings are never absorbed, as in #552, so they fit as an unabsorbed final round entering through `κ_MT` (the PCS is list-binding, so extractability, not binding, is the property). But `main`'s Merkle trees hash with Keccak-256, on the same Keccak-f as the duplex, and nothing separates the two: a prover-chosen leaf can make a Merkle hash evaluate the transcript's own permutation inputs. That is not an attack (the adversary can query the permutation anyway), but the composition is outside CO25, whose corollary assumes a separate hash. Treating Keccak-256 as a random oracle independent of the permutation is an extra assumption here, not a consequence of the ideal-permutation model, since the two are not domain-separated: a level-0 WHIR leaf is 512 bytes, so its first Keccak-256 block is 17 prover-chosen lanes over a zero capacity, which can equal the seed's input. #552 avoids the assumption by keeping transcript and Merkle nodes in disjoint frames, and a domain-separation constant in either input would too.

### 4.6 The resulting bound, if the extension holds

`ε_NARG(t) ≤ ε_sr_IOP(t) + κ_MT + (IV collision) + 25t²/2^576`, for `t` queries to Keccak-f in either direction (proof-of-work evaluations included) and to Keccak-256, taken as the separate oracle of §4.5 (Merkle and IV evaluations). The sponge's own term is below `2^-315` at `t = 2^128`; the Merkle and IV terms are birthday-scale in 256 bits and dominate the hash loss. Theorem 6.2 gives the analogous bound for rewinding knowledge soundness, with the failure probability shifted by the same additive term, and a straightline extractor only if the protocol's own state-restoration extractor is straightline.

### 4.7 What this does not cover

- **State-restoration soundness of the protocol.** CO25 notes that round-by-round soundness implies it [CY24]. Annex B proves round-by-round errors for the PCS opening only; the bus, the sumchecks, the Keccak GKR and the ring switch carry plain soundness errors, with no union over the list-binding commitment's list. Composing them into `ε_sr_IOP` is open work, independent of the transcript.
- **Grinding.** The bound credits none. WHIR's query counts are sized so that "the query count only needs to close the remaining `SECURITY_BITS - 17` bits" (`crates/pcs/src/whir_config.rs`), where `SECURITY_BITS` is a round-by-round target per verifier message; without a proof-of-work argument each query message counts for about 111 bits, before state restoration multiplies it by up to `t`.
- **KRS25.** The ideal-permutation model treats Keccak-f as an oracle the proven computation cannot evaluate, while every leanVM program can, with one `KECCAK` instruction, and the deployed guest does: for its signatures, its Merkle paths and its children's transcripts, the children being proofs of its own bytecode. KRS25's attack also runs GKR, whose trace is not committed (their §5), over a circuit that can compute the hash: one the prover picks, or a fixed universal one (their §4, which warns that keeping the hash out of the circuit is not enough). Remark 3 says canonical grand products seem out of reach. leanVM's uncommitted-trace GKRs are the bus's grand products and the Keccak-f circuit, which commits a state every 12 rounds (`KECCAK_DEPTH`), so no single GKR spans a whole permutation: the depth limit their §5 names as a natural countermeasure ("reducing the depth of the circuit in question (possibly by committing to some of the intermediate values)"). The rest of the execution trace is committed; the Keccak rows' outputs are the one part left to the GKR. None of this proves an analogue impossible, which KRS25 itself warns against; for such computations the bound is a heuristic.
- **Scope.** Classical, ideal permutation, one proof; not quantum adversaries (CO25 §1.3: "Establishing the security of DSFS against superposition queries to the permutation function remains a challenging open question"). For signature aggregation, plain soundness says little (for an honestly generated key, a valid signature exists for every message); knowledge soundness is what matters, and recursion needs it to compose. The extracted signatures then rest on the schemes' proofs (`formal/`), which model Keccak-256 as a random oracle while this argument models Keccak-f as an ideal permutation; composing the two is a further step.
- **The recursion's batching transcript** (`from_label(RECURSION_AGG_LABEL)`) has the same shape (child count absorbed first, every child padded to whole rates) but is not part of this mapping.

### 4.8 What has to stay true

1. Every count and the order of absorbed scalars and squeezed challenges follow from the bytecode and the announced sizes.
2. The sizes, and then the commitment root, are absorbed before any challenge.
3. The codec stays injective per round: nonzero tags, or any other fixed-length encoding.
4. No seed preimage other than the VM's begins with `TAG`.
5. The primitive stays a permutation modelled as ideal.
6. Keccak-256 (Merkle trees, the IV) can be treated as an oracle independent of the duplex's permutation. This one is an assumption, not a property of the code (§4.5).

(1) and (2), the two properties of the code the argument newly rests on, were neither written down nor tested; this branch adds the AGENTS.md rule and the test. (3) and part of (4) are already stated in §8, and (3) is tested by `fs_binds_length`.

## 5. Comparison

| | `main` | CO25 DSFS | spongefish | SAFE | #552 (`riscv-exploration`) |
| --- | --- | --- | --- | --- | --- |
| primitive | Keccak-f, rate 16, capacity 9 lanes | ideal permutation | any permutation | permutation over a field | BLAKE2s compression, not a permutation |
| absorb | overwrite, rate past the block zeroed | overwrite | overwrite | add | framed compression nodes |
| framing | a tag lane per scalar; none between absorb and squeeze | none | through the session id | IO-pattern tag `T = H(pattern ‖ D)` in the capacity | role, length and consumed-output counter per node |
| what fixes the schedule | bytecode in the IV and sizes absorbed first | the codec, by `(λ, n)` | the session id, which "MUST account for the absorb/squeeze pattern" | the declared IO pattern | statement and announcement, as on `main`; the counter records each node's operation |
| squeeze | one challenge per permutation | the whole rate | the whole rate | the whole rate | 32-byte output blocks, unused bytes kept |
| argument | none written (§4: per shape, with two gaps) | Theorems 6.1, 6.2; BCS: Corollary 1, informal | CO25 | Theorem 1, proof in a separate report | DMV18 Theorem 1 with a CCHLRR18 adapter |

spongefish's duplex (cited there as "[CO25], Construction 3.3, with minor changes") has the same absorb/squeeze ambiguity as `main`. `main` meets its session-id obligation in substance, not literally: the pattern is fixed by the IV together with the sizes absorbed first, which are not in the IV.

## 6. Cost in the recursion guest

Measured on `main` at `23a305b`, `cargo leanvm recursion --n 2 --xmss-per-leaf 900 --log-inv-rate 2`, with the counter of [`checks/fs_count.patch`](checks/fs_count.patch) in `crates/verifier`'s sponge (never committed to the code), on a 4-core cloud VM. The two children are replayed concurrently and the patch's counters are process-wide, so each `FSCOUNT replay` line holds whatever both had counted since the previous report; only the sum of a pair is meaningful. A trace of the Python verifier reproduces the per-child and root counts exactly. These are counts in the native verifier; the guest replays each permutation as one `KECCAK`.

| | per child proof verified |
| --- | --- |
| scalars absorbed | 2,532 |
| challenges | 699 (569 after absorbed scalars, 130 after another challenge) |
| permutations after the seed | 921 (222 forced by a fifth scalar, 699 for challenges) |
| longest run of consecutive challenges | 21 |
| Merkle (native verifier counts) | 222 query paths, 4,878 sibling compressions plus leaf hashes |
| permutations with up to 5 challenges each | 808 (12% fewer) |
| permutations with up to 4 challenges each | 814 |

The root runs 537,703 cycles, with `KECCAK` at 2^13.63 (about 12,680 instructions, 2.4% of cycles) and the Keccak table padded to 2^14. Fiat-Shamir for the two children is about 1,844 of those (15%), not counting the root's own batching transcript; the rest was not attributed. Five challenges per permutation would remove about 226 at the root (about 2%) and leave the table at 2^14. The cycles spent around each permutation were not attributed.

If challenges are ever packed, five per permutation is also the cheaper layout in the guest. [`challenge_from_state`](https://github.com/leanEthereum/leanVM/blob/23a305b017a5c553c2a62ecdbd6fc49e06849df4/crates/rec_aggregation/guests/lean_ethereum.py#L515-L524) splits the cell holding lanes 2 and 3, hinting one limb and deriving the other, and discards lane 3. With five challenges at lanes `3j..3j+3`, pairs share the split cells: three hints for five challenges, against one per challenge when challenges are aligned to four lanes.

## 7. The options, re-scored

- **A. Write the argument down.** The per-shape mapping (§4.1 to §4.3), the extension for a prover-chosen shape (§4.4), the Merkle assumption (§4.5) and the scope (§4.7), in §8, with the test pinning the read schedule and the rule in AGENTS.md. No change to the prover, the verifiers or the guest. The extension is the one piece of real proof work, and the most useful thing to have checked by someone who knows CO25's §5.
- **B. Add framing.** For a fixed shape CO25 needs none. Framing that binds the schedule into the sponge would close gap 1 too, through another theorem: SAFE's IO-pattern tag fixes it at the start, and #552's per-node framing makes the mode's own parsing schedule-free. Domain separation between transcript and Merkle inputs, framing or a constant, would close gap 2. If the extension of §4.4 is not accepted, that is what would make a published argument apply, at the cost of a protocol change in all four implementations.
- **C. Squeeze up to five challenges per permutation.** About 2% of the root's `KECCAK`s, no change to the padded table at this size, and it touches all four implementations. Only worth it bundled with another transcript change.

## 8. Open questions for the maintainers

1. Is `main` now the target of #529, or is `riscv-exploration`'s transcript the one that matters?
2. Which construction, and what about it, did the concern refer to: #523's step (merged the day before #529, and framed), `main`'s BLAKE2s chain, or duplex challengers in general? `main` is now the last kind.
3. Would a PR writing §7's option A into §8 be useful as is, or would you rather see the extension of §4.4 worked out first?

## 9. Review

The first version of these notes said `main`'s transcript "is exactly CO25's DSFS", "provably" harmless, with "no code change" needed. An adversarial review (nine independent reviewers, one lens each, against the paper, the code and git) found that this overclaimed: gaps 1 and 2 above, the history of §1 (`main`'s chain lasted until Oct 23; #607 merged; #523 preceded the issue), the start's permutation count, the codec's round 1 and nonce, the scope and the grinding caveat. Every correction was checked against its source before being applied. A second round (three reviewers: the comment sentence by sentence, the spec paragraph, and a cold read as a SAFE and KRS25 author would read it) found that the revision had called #523's step "unframed", which it was not, and had left the comment behind the notes on scope (one proof, knowledge soundness, the 111-bit consequence, the batching transcript, the Keccak-256 assumption); it also sharpened §4.4 (BackTrack, the deployed guest's fixed bytecode), §4.5 (the assumption is not standard here) and option B. A third, on that revision alone, found its KRS25 sentence wrong (the attack does not need a prover-chosen circuit: a fixed universal one suffices, their §4) and tightened the knowledge-soundness, seed and wording points.

## References

- CO25: A. Chiesa, M. Orrù. *A Fiat-Shamir Transformation From Duplex Sponges.* TCC 2025; ePrint 2025/536, revised 2026-03-27. §1, §1.3, §2.2, §2.6 (Corollary 1), §3, Construction 3.3, Definitions 3.12 and 4.1, Construction 4.3, Theorems 6.1 and 6.2.
- SAFE: J.-P. Aumasson, D. Khovratovich, B. Mennink, P. Quine. *SAFE: Sponge API for Field Elements.* ePrint 2023/522. §1 (misuse patterns), §3.2, §3.3.
- KRS25: D. Khovratovich, R. Rothblum, L. Soukhanov. *How to Prove False Statements: Practical Attacks on Fiat-Shamir.* ePrint 2025/118.
- CY24: A. Chiesa, E. Yogev. *Building Cryptographic Proofs from Hash Functions.* 2024.
- spongefish: `arkworks-rs/spongefish` at `2880323`, `spongefish/src/duplex_sponge.rs`.
- `riscv-exploration`: #523 `c0a6aab3`, #552 `f11f84f5`, #607 `d3c7f9d9`, #620 `f14c2300`; `doc/leanvm/body/08-end-to-end-protocol.tex` there.
