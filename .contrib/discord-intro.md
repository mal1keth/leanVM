> **SUPERSEDED, do not post (2026-11-10).** Upstream commit `b6167fe` (Nov 9) vendored `formal/`, a machine-checked proof (Lean 4, no `sorry`) of leanVM's straight-line knowledge soundness in the random-permutation model, covering the Fiat-Shamir duplex, a prover-chosen program, public input and proof, and Keccak-256 as the sponge over the same permutation (`formal/statement.tex`, section "The zkVM"). This text's central claims (no argument for the duplex, two gaps to a theorem, knowledge soundness not established) are therefore out of date. See `HANDOFF.md`.

<!-- For #lean-consensus. Post AFTER the #529 comment is up, and replace [link] with that comment's URL. -->

Hey all, I'm Adi, a cryptography researcher. I've been looking at leanVM's Fiat-Shamir transcript for #529 and just posted a scoping comment there: [link]

Short version: `main`'s Keccak duplex comes close to Chiesa and Orrù's duplex-sponge Fiat-Shamir, with two gaps I've tried to pin down, so it may need a written argument more than a redesign. If anyone remembers what Dmitry flagged back in October (#523's two-scalar step had landed on `riscv-exploration` the day before), I'd love the context.
