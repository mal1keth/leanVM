<!-- Draft reply for https://github.com/leanEthereum/leanVM/issues/529, posted from Adi's own account. Everything between the two rules below is the comment. -->

---

I'd like to pick this up for `main`, and want to check scope first.

**Where things stand, as far as I can tell.** When this issue was opened, `main`'s transcript was a BLAKE2s hash chain, not a duplex. On `riscv-exploration`, #552 then rebuilt it as a framed BLAKE2s duplex with a written mode argument (DMV18), and `spongefish-fs` put spongefish's interface on top. `main` went another way: #636 replaced the chain with an unframed duplex over Keccak-f[1600], after Plonky3's challenger, and nothing in the spec argues its security.

**The question for `main`.** Its duplex has one non-injectivity: a permutation forced by a fifth absorbed scalar is the same permutation as a challenge drawn with four scalars waiting, so the sponge alone does not record whether a challenge was drawn. That is the "full rate, no separator" shape SAFE warns about. I think it is harmless here, and provably so. Every count the verifier absorbs or samples is fixed by the bytecode (in the IV) and the announced sizes (absorbed right after the seed). With those as the instance, `main`'s transcript is exactly CO25's DSFS (Construction 4.3) with an injective, unbiased codec, and Theorem 6.1 gives `ε ≤ ε_sr(IP) + 25t²/2^576` with no code change. #552's point that CO25 does not apply holds for BLAKE2s compression, but `main` now runs on a permutation.

<details>
<summary>The mapping onto CO25</summary>

`Σ` = 64-bit lanes, `r = 16`, `c = 9`, `p` = Keccak-f[1600], no salt (proofs are not zero knowledge).

- **Instance and start.** `x' = (IV, public input, announced sizes)`. `main`'s seed permutation plus the two permutations its absorbed sizes trigger are `Absorb(st*, φ0(x'))` from the zero state, which CO25 covers "as a special case (with h = p)" (§2.2, after Remark 2.1). Soundness is adaptive in the instance (Definition 3.12), so the prover choosing the sizes is the prover choosing `x'`.
- **Rounds.** Round `i` is the `m_i ≥ 0` scalars absorbed before the `i`-th challenge, then that challenge (grinding challenges included). `k` and every `m_i` depend on `x'` alone: every count in `crates/verifier` is a constant or comes from `build_layout` and the log-inverse-rate, and nothing branches on a challenge, a sent value or Merkle data.
- **Codec.** `φ_i`: tagged lanes `(c0, c1, c2, 1)` per scalar, zero-padded to a multiple of 16 lanes, and sixteen zero lanes for `m_i = 0`; injective since lengths are fixed. `ψ_i`: squeeze 16 lanes, keep lanes 0..2, a bijection onto `GF(2^192)`, so the bias is zero. Step by step this reproduces `main`'s permutation inputs under Construction 3.3, including the zeroed rate and back-to-back challenges.
- **Batches of challenges** become rounds with empty prover messages. That loses nothing: in the state-restoration game `ρ_i = f_i(x, τ, α_1..α_i)` is a function of the message prefix.
- **Outside the IP.** Merkle openings are covered by PCS binding, as in #552. Grinding only adds a rejection condition, so the bound holds without crediting it.

What has to stay true for this to hold: (1) every count is a function of the bytecode and the sizes; (2) the sizes are absorbed before anything they size; (3) the codec stays injective; (4) distinct transcripts keep distinct seeds; (5) the primitive stays a permutation. None of these is written down or tested today.

</details>

**What the sponge costs in the guest** (recursion 2→1, leaves of 900 leanXMSS, log-inv-rate 2, measured with a counter in `crates/verifier`'s sponge): about 920 Fiat-Shamir permutations per child verified, about 15% of the root's `KECCAK` instructions. Squeezing five challenges per permutation would save about 12% of those (about 2% of the root's `KECCAK`s) and leave the Keccak table at 2^14, so I don't think it justifies a protocol change on its own.

**Questions:**

1. Is `main` the target for this issue now, or is the `riscv-exploration` transcript (#552, `spongefish-fs`) the one that matters?
2. Which construction did Dmitry's concern refer to: `main`'s old BLAKE2s chain, the `riscv-exploration` duplex, or Plonky3-style duplex challengers in general? `main`'s transcript is now the last kind, so I want to be sure the argument answers what he actually saw.
3. If the mapping holds up, would you take a PR that writes it into §8 (`sec:e2e-fiat-shamir`) with a test pinning invariant (1)? It would change no prover, verifier or guest code, and leave `TAG` and the labels at `v1`.

---
