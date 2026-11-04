<!-- For #lean-consensus. Post AFTER the #529 comment is up, and replace [link] with that comment's URL. -->

Hey all, I'm Adi, a cryptography researcher. I've been looking at leanVM's Fiat-Shamir transcript for #529 and just posted a scoping comment there: [link]

Short version: `main`'s Keccak duplex looks like an exact instance of Chiesa and Orrù's duplex-sponge Fiat-Shamir, so it may need a written argument rather than a redesign. If anyone remembers what Dmitry flagged back in October, I'd love the context.
