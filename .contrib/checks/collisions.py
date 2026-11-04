# Symbolic check of the analysis's section 3: over all op sequences of length <= L on {obs, nonce, sample}, with the
# j-th absorbed value the symbol j, which pairs of distinct sequences give the same permutation-input sequence
# (rates, symbolically) and the same final pending list? Expect exactly: a sample with four waiting that is
# immediately followed by an absorb is invisible.
import itertools
def run(ops):
    pend, perms, v = [], [], 0
    for op in ops:
        if op in ("obs", "nonce"):
            if len(pend) == 4:
                perms.append(tuple(pend)); pend = []
            pend.append((v, 1 if op == "obs" else 4)); v += 1
        else:
            perms.append(tuple(pend)); pend = []
    return tuple(perms), tuple(pend)
L = 11
seen = {}
for n in range(L + 1):
    for ops in itertools.product(("obs", "nonce", "sample"), repeat=n):
        seen.setdefault(run(ops), []).append(ops)
def explained(a, b):
    # b equals a with some samples (each at four waiting and directly followed by an absorb) removed, or vice versa
    def strip(ops):
        out, pend = [], 0
        for i, op in enumerate(ops):
            if op == "sample" and pend == 4 and i + 1 < len(ops) and ops[i + 1] != "sample":
                pend = 0; continue
            if op == "sample": pend = 0
            else: pend = 1 if pend == 4 else pend + 1
            out.append(op)
        return tuple(out)
    return strip(a) == strip(b)
groups = [g for g in seen.values() if len(g) > 1]
bad = [g for g in groups if not all(explained(g[0], x) for x in g[1:])]
print(f"sequences up to length {L}: {sum(len(g) for g in seen.values())}, colliding groups: {len(groups)}, unexplained: {len(bad)}")
print("example group:", groups[0] if groups else None)
