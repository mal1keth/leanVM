<!-- Draft reply for https://github.com/leanEthereum/leanVM/issues/529, posted from Adi's own account. Everything between the two rules below is the comment. Replace [notes] with a link to .contrib/529-analysis.md on a public branch, or drop that line. -->

---

I'd like to help with this on `main`, and want to check scope first.

**History, as far as I can tell from git.** The day before this issue, #523 put an unframed duplex-style step on `riscv-exploration` (one compression keyed by the state, absorbing up to two scalars, a squeeze absorbing the waiting ones in its own step). #552 then replaced it with a framed BLAKE2s duplex and a written argument (DMV18 with a round-by-round adapter), and #607 and #620 followed. `main` kept a BLAKE2s hash chain until #636 replaced it with an unframed duplex over Keccak-f[1600], after Plonky3's challenger. Nothing in the spec argues that duplex's security.

**`main`'s duplex.** It has one non-injectivity: a permutation forced by a fifth absorbed scalar is the same permutation as a challenge drawn with four scalars waiting. A brute force over all operation sequences up to length 11 finds no other. It only matters if the verifier could, at one point of one transcript, either squeeze or absorb, and `main`'s can't: every count of absorbed scalars and squeezed challenges is fixed by the bytecode (hashed into the IV) and the announced sizes (absorbed right after the seed, before any challenge), never by a value.

How far CO25 goes from there:

- For a fixed bytecode length and fixed sizes, `main`'s transcript is CO25's DSFS (Construction 4.3) with an injective, unbiased codec: a literal implementation of Construction 3.3 reproduces its permutation inputs on random schedules.
- A prover who chooses the sizes is not covered as stated, since CO25 fixes round lengths by the security parameter and the instance-size bound (Definition 4.1). The sizes are a fixed-length prefix absorbed before any round, so I expect the reduction to extend, much as #552's adapter reconstructs the schedule from the parsed announcement, but I haven't written that out.
- The Merkle openings bring in CO25's BCS form (§2.6, Corollary 1, stated informally), which adds the Merkle term and keeps the Merkle hash separate from the permutation. On `main` both run on Keccak-f.

So my current view: the collision is harmless for a reason that can be stated precisely, and the sponge's own term would be about `25t²/2^576`, with the Merkle and IV terms (birthday-scale in 256 bits) dominating the hash loss. But there are two gaps between that and a theorem. All of it is classical and in the ideal-permutation model: it says nothing about KRS25-style attacks (the recursion guest evaluates Keccak-f itself) or quantum adversaries, it credits no grinding (WHIR's query counts assume 17 bits of it), and it takes the protocol's state-restoration soundness as given, which the spec establishes only for the opening.

**Cost in the guest** (recursion 2→1, leaves of 900 leanXMSS, log-inv-rate 2): about 920 Fiat-Shamir permutations per child verified, roughly 1,840 of the root's ~12,700 `KECCAK` instructions. Squeezing five challenges per permutation would save about 12% of those, about 2% of the root's `KECCAK`s, so I don't think that's worth a protocol change on its own.

**Questions:**

1. Is `main` the target for this issue now, or is `riscv-exploration`'s transcript the one that matters?
2. Was the concern about #523's step, `main`'s BLAKE2s chain, or duplex challengers in general? `main` is now the last kind, so I'd like the argument to answer what was actually seen.
3. Would a PR that writes the per-shape mapping, the two gaps and the scope into §8, with a test pinning the read schedule, be useful? It changes no prover, verifier or guest code. Or would you rather see the extension for prover-chosen sizes worked out first?

Notes, with the mapping, the checks and the measurements: [notes]

---
