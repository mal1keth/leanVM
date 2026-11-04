<!-- For #lean-consensus. Post AFTER the #529 comment is up, and replace [link] with that comment's URL. -->

Hey all, I'm Adi, a cryptography researcher. I've been looking at leanVM's Fiat-Shamir transcript for #529 and just posted a scoping comment there: [link]

Short version: `main`'s Keccak duplex comes close to Chiesa and Orrù's duplex-sponge Fiat-Shamir, with two gaps I've tried to pin down, so it may need a written argument more than a redesign. If anyone remembers what Dmitry flagged back in October (I suspect the two-scalar step from #523), I'd love the context.
