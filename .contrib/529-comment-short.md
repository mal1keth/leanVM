<!-- Short alternative to 529-comment.md, for https://github.com/leanEthereum/leanVM/issues/529, posted from Adi's own account. Everything between the two rules below is the comment. Written 2026-11-11, revised after one independent review, then given a humanizer pass. DO NOT POST YET: the notes link at the bottom is a placeholder (REPIN_AFTER_PUSH) and must become a permalink to the commit on the public fork that holds the revised analysis. No one is mentioned by handle; Adi decides whether to add mentions. -->

---

I'd like to help with this on `main`, but first I want to check what is left to do.

As far as I can tell from git, the issue is older than `main`'s current transcript. #552, #607 and #620 reworked the BLAKE2s one on `riscv-exploration`, and `main` got its Keccak-f[1600] duplex later, in #636. Since Nov 9 there is also `formal/`. As I read `formal/statement.tex`, it proves knowledge soundness of a Lean transcription of the verifier in the random-permutation model, duplex included (`LeanVM.knowledgeSoundness_holds`), and the Rust is tied to that transcription by differential tests. Does that close this issue for `main`? Or is it about `riscv-exploration`'s transcript?

Two notes from reading the transcript:

- The duplex has one non-injectivity. A permutation forced by a fifth absorbed scalar is the same permutation as a challenge drawn with four scalars waiting. I brute-forced all operation sequences up to length 11 and found no other. The Lean handles it by decoding each permutation from the verifier program's position (`formal/lean_vm/LeanVM/Protocol/Compile/Rom/Decode.lean`), but the spec's §8 doesn't mention it. Would a sentence there be welcome?
- `formal/statement.tex` lists programs that evaluate their own proof's Fiat-Shamir duplex (the KRS25 setting) and soundness across recursion levels as not proved. The deployed guest does evaluate Keccak-f, including to recompute its children's challenges. KRS25's attack runs GKR, with no committed trace, over a circuit general enough to compute the hash. leanVM's uncommitted-trace GKRs are the bus's grand products, which their Remark 3 sets aside, and the Keccak-f circuit, which commits a state every 12 rounds. If it would help, I can write up how far their attack is from that.

Last, which construction was the original concern about: #523's step on `riscv-exploration`, `main`'s BLAKE2s chain at the time, or duplex challengers in general?

Notes, with the brute force and the measurements: [mal1keth/leanVM `.contrib/529-analysis.md`](https://github.com/mal1keth/leanVM/blob/REPIN_AFTER_PUSH/.contrib/529-analysis.md)

---
