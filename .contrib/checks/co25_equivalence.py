"""Executable check of the analysis's section 4.2: CO25 Construction 3.3 (overwrite duplex, literal) driven as
DSFS (Construction 4.3) with the stated codec, against leanVM's sponge in three forms:
  - the Python verifier's Transcript (imported from python-verifier/verifier.py; written against 23a305b),
  - a line-by-line mirror of crates/fiat_shamir/src/lib.rs (FiatShamirState, incl. grind_pow's batched path),
  - a line-by-line mirror of crates/verifier/src/transcript.rs (Sponge + Transcript::grind_check).
Compares the full sequence of permutation INPUTS and every challenge."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pyverifier", os.path.join(HERE, "..", "..", "python-verifier", "verifier.py"))
pv = importlib.util.module_from_spec(spec)
sys.modules["pyverifier"] = pv
spec.loader.exec_module(pv)
REAL_KECCAK = pv.keccak_f

M64 = (1 << 64) - 1
R, C = 16, 9
W = R + C


# --- stand-in permutation: a 25-lane type-1 generalized Feistel with a keyed BLAKE2b round function (a bijection) ---
def feistel(state):
    s = list(state)
    for rnd in range(30):
        h = hashlib.blake2b(struct.pack("<25Q", *s[1:], rnd), digest_size=8, key=b"stand-in").digest()
        s = s[1:] + [s[0] ^ int.from_bytes(h, "little")]
    return s


def feistel_inv(state):
    s = list(state)
    for rnd in reversed(range(30)):
        last = s[-1]
        rest = s[:-1]
        h = hashlib.blake2b(struct.pack("<25Q", *rest, rnd), digest_size=8, key=b"stand-in").digest()
        s = [last ^ int.from_bytes(h, "little")] + rest
    return s


PERM = feistel


class Recorder:
    def __init__(self):
        self.inputs = []

    def __call__(self, state):
        assert len(state) == W
        self.inputs.append(tuple(state))
        return list(PERM(list(state)))


def silent(state):
    return list(PERM(list(state)))


# --- model 1: CO25 Construction 3.3, literal (recursive, as written) ---
class CO25:
    def __init__(self, p):
        self.p = p

    def absorb(self, st, chi):
        s, iA, iS = st
        iS2 = R  # 1. Set i'_S := r
        if len(chi) == 0:  # 2.
            return (s, iA, iS2)
        if 0 <= iA < R:  # 3(a)
            x, rest = chi[0], chi[1:]
            s2 = list(s)
            s2[iA] = x
            return self.absorb((s2, iA + 1, iS2), rest)
        assert iA == R  # 3(b)
        s2 = self.p(s)
        return self.absorb((s2, 0, iS2), chi)

    def squeeze(self, st, ell):
        s, iA, iS = st
        if ell == 0:  # 1.
            return [], st
        iA2 = 0  # 2(a)
        if 0 <= iS < R:  # 2(b)
            rho2, st2 = self.squeeze((s, iA2, iS + 1), ell - 1)
            return [s[iS]] + rho2, st2
        assert iS == R  # 2(c)
        s2 = self.p(s)
        return self.squeeze((s2, iA2, 0), ell)


def lanes_of(x, tag):
    return [x[0], x[1], x[2], tag]


def phi(msg, round_index, codec):
    """msg: list of (E, tag). codec 'stated': pad to a multiple of 16, empty -> 16 zeros (every round).
    codec 'fixed': same, but round 1's empty message is the empty string."""
    out = [lane for x, tag in msg for lane in lanes_of(x, tag)]
    if not msg:
        if codec == "fixed" and round_index == 1:
            return []
        return [0] * R
    out += [0] * ((-len(out)) % R)
    return out


def co25_run(iv, pi, sizes, rounds, trailing, codec, ellV=16):
    rec = Recorder()
    ds = CO25(rec)
    st_star = ([0] * W, 0, R)
    phi0 = list(iv) + list(pi) + [0] * 8
    for a in sizes:
        phi0 += [a, 0, 0, 1]
    st = ds.absorb(st_star, phi0)  # Start(x') = Absorb(st*, phi0(x'))
    start_perms = len(rec.inputs)
    start_state = st
    st = ds.absorb(st, [])  # salt, delta = 0
    challenges = []
    for i, msg in enumerate(rounds, start=1):
        st = ds.absorb(st, phi(msg, i, codec))
        rho_hat, st = ds.squeeze(st, ellV)
        challenges.append(tuple(rho_hat[:3]))  # psi_i: keep lanes 0..2
    if trailing:  # a last prover message with no verifier message (ell_V = 0)
        st = ds.absorb(st, phi(trailing, len(rounds) + 1, codec))
        _, st = ds.squeeze(st, 0)
    return rec.inputs, challenges, start_perms, start_state


# --- model 2: mirror of crates/fiat_shamir/src/lib.rs ---
class RustProverFS:
    RATE_SCALARS = 4
    RATE_LANES = 16

    def __init__(self, iv, pi, perm, _clone=False):
        self.perm = perm
        if _clone:
            return
        self.state = [0] * W
        self.n_pending = 0
        for k, word in enumerate(list(iv) + list(pi)):
            self.state[k] = word
        self.duplex()

    def clone(self, perm=silent):
        c = RustProverFS(None, None, perm, _clone=True)
        c.state = list(self.state)
        c.n_pending = self.n_pending
        return c

    def duplex(self):
        self.state = list(self.perm(self.state))
        out = (self.state[0], self.state[1], self.state[2])
        for k in range(self.RATE_LANES):
            self.state[k] = 0
        self.n_pending = 0
        return out

    def absorb(self, x, tag):
        if self.n_pending == self.RATE_SCALARS:
            self.duplex()
        i = 4 * self.n_pending
        self.state[i : i + 4] = [x[0], x[1], x[2], tag]
        self.n_pending += 1

    def observe(self, x):
        self.absorb(x, 1)

    def sample(self):
        return self.duplex()

    def pow_bits_ok(self, nonce, bits):
        assert bits < 64
        probe = self.clone()
        probe.absorb(nonce, 4)
        return probe.sample()[0] & ((1 << bits) - 1) == 0

    def absorb_nonce(self, nonce):
        self.absorb(nonce, 4)
        self.sample()

    def grind_pow(self, bits, parallel_grind_min=1 << 13, BATCH=16):
        assert bits < 64
        if bits == 0:
            nonce = 0
        elif (1 << bits) < parallel_grind_min:
            n = 0
            while not self.pow_bits_ok((n, 0, 0), bits):
                n += 1
            nonce = n
        else:
            base = self.clone()
            base.absorb((0, 0, 0), 4)
            lane = 4 * (base.n_pending - 1)

            def batch(first):
                states = []
                for i in range(BATCH):
                    s = list(base.state)
                    s[lane] = first + i
                    states.append(silent(s))
                for i, s in enumerate(states):
                    if s[0] & ((1 << bits) - 1) == 0:
                        return i
                return None

            block = 1 << (min(bits, 24) + 1)
            start = 0
            while True:
                hit = next((i for i in range(block // BATCH) if batch(start + i * BATCH) is not None), None)
                if hit is not None:
                    first = start + hit * BATCH
                    nonce = first + batch(first)
                    break
                start += block
        self.absorb_nonce((nonce, 0, 0))
        return nonce


# --- model 3: mirror of crates/verifier/src/transcript.rs ---
class RustVerifierSponge:
    def __init__(self, iv, pi, perm):
        self.perm = perm
        state = [0] * W
        state[0:4] = list(iv)
        state[4:8] = list(pi)
        self.state = list(perm(state))
        self.pending = [((0, 0, 0), 0)] * 4
        self.n_pending = 0

    def duplex(self):
        inp = list(self.state)
        for k in range(16):
            inp[k] = 0
        for i, (value, tag) in enumerate(self.pending[: self.n_pending]):
            inp[4 * i : 4 * i + 4] = [value[0], value[1], value[2], tag]
        self.state = list(self.perm(inp))
        self.n_pending = 0

    def absorb(self, value, tag):
        if self.n_pending == 4:
            self.duplex()
        self.pending[self.n_pending] = (value, tag)
        self.n_pending += 1

    def observe(self, value):
        self.absorb(value, 1)

    def sample(self):
        self.duplex()
        return (self.state[0], self.state[1], self.state[2])


class RustVerifierTranscript:
    def __init__(self, stream, iv, pi, perm):
        self.stream = stream
        self.off = 0
        self.sponge = RustVerifierSponge(iv, pi, perm)

    def next(self):
        v = self.stream[self.off]
        self.off += 1
        return v

    def next_scalar(self):
        v = self.next()
        self.sponge.observe(v)
        return v

    def sample(self):
        return self.sponge.sample()

    def grind_check(self, bits):
        nonce = self.next()
        self.sponge.absorb(nonce, 4)
        challenge = self.sample()
        mask = ((1 << bits) - 1) if bits < 64 else M64
        valid = (nonce == (0, 0, 0)) if bits == 0 else (challenge[0] & mask == 0)
        return challenge, valid


# --- schedules ---
def rand_e(rng):
    k = rng.random()
    if k < 0.1:
        return (0, 0, 0)
    if k < 0.2:
        return (rng.randrange(8), 0, 0)
    return (rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64))


RUN_LENGTHS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 4, 8, 4, 8, 12, 16, 17, 33]


def gen_schedule(rng, with_sizes=True, allow_raw_nonce=False):
    iv = [rng.getrandbits(64) for _ in range(4)]
    pi = [rng.getrandbits(64) for _ in range(4)] if rng.random() < 0.8 else [0, 0, 0, 0]
    sizes = [rng.choice([rng.randrange(40), rng.getrandbits(64)]) for _ in range(8)] if with_sizes else []
    ops = []
    for _ in range(rng.randrange(1, 14)):
        kind = rng.random()
        if kind < 0.45:  # a run of observes then a run of samples
            ops += [("obs", rand_e(rng)) for _ in range(rng.choice(RUN_LENGTHS))]
            ops += [("sample",)] * rng.choice([1, 1, 1, 2, 3, 5])
        elif kind < 0.6:  # consecutive samples
            ops += [("sample",)] * rng.randrange(1, 7)
        elif kind < 0.85:  # observes, then a grind (nonce + its challenge), as WHIR does
            ops += [("obs", rand_e(rng)) for _ in range(rng.choice(RUN_LENGTHS))]
            ops += [("grind", rng.choice([0, 0, 1, 2, 3, 4, 5]))]
        elif allow_raw_nonce:  # a nonce-tagged scalar not followed by a challenge (not reachable via the APIs)
            ops += [("nonce", rand_e(rng))]
        else:
            ops += [("obs", rand_e(rng)) for _ in range(rng.choice(RUN_LENGTHS))]
    if rng.random() < 0.3:  # trailing absorbs, no challenge after
        ops += [("obs", rand_e(rng)) for _ in range(rng.choice(RUN_LENGTHS))]
    return iv, pi, sizes, ops


def digest(words):
    return pv.Digest(struct.pack("<4Q", *words))


def run_all(iv, pi, sizes, ops, codec, batched_grind):
    # Rust prover mirror: produce the transcript (nonces) and its permutation inputs
    prec = Recorder()
    prover = RustProverFS(iv, pi, prec)
    p_ch = []
    stream = []
    for a in sizes:
        prover.observe((a, 0, 0))
        stream.append((a, 0, 0))
    resolved = []
    for op in ops:
        if op[0] == "obs":
            prover.observe(op[1])
            stream.append(op[1])
            resolved.append(op)
        elif op[0] == "sample":
            p_ch.append(prover.sample())
            resolved.append(op)
        elif op[0] == "nonce":
            prover.absorb(op[1], 4)
            stream.append(op[1])
            resolved.append(op)
        elif op[0] == "grind":
            bits = op[1]
            before = prover.clone()
            # capture the challenge the nonce is checked against
            nonce = prover.grind_pow(bits, parallel_grind_min=(1 << 4) if batched_grind else (1 << 13))
            # recompute via a probe to compare: the state after absorb_nonce has its sample taken; the challenge is
            # the last permutation output's lanes 0..2, which the prover zeroed; recover it from the recorder
            p_ch.append(tuple(PERM(list(prec.inputs[-1]))[:3]))
            stream.append((nonce, 0, 0))
            resolved.append(("grind", bits, (nonce, 0, 0)))
            # smallest nonce check
            if bits > 0:
                assert nonce == next(n for n in range(nonce + 1) if before.pow_bits_ok((n, 0, 0), bits)), "not smallest"
                assert before.pow_bits_ok((nonce, 0, 0), bits)
            else:
                assert nonce == 0

    # Python verifier (real code, keccak_f swapped for the recorder)
    vrec = Recorder()
    pv.keccak_f = vrec
    proof = pv.Proof(tuple(pv.E(*x) for x in stream), b"")
    t = pv.Transcript(proof, digest(iv), digest(pi))
    py_ch = []
    for _ in sizes:
        t.next_scalar()
    for op in resolved:
        if op[0] == "obs":
            t.next_scalar()
        elif op[0] == "sample":
            c = t.sample()
            py_ch.append((c.c0.value, c.c1.value, c.c2.value))
        elif op[0] == "nonce":
            t._absorb(t._next(), pv.DS_POW_NONCE)
        elif op[0] == "grind":
            t.grind_check(op[1])  # raises VerificationError on a bad nonce
            py_ch.append(tuple(PERM(list(vrec.inputs[-1]))[:3]))
    t.finish()
    pv.keccak_f = REAL_KECCAK

    # Rust verifier mirror
    rrec = Recorder()
    rt = RustVerifierTranscript(stream, iv, pi, rrec)
    r_ch = []
    for _ in sizes:
        rt.next_scalar()
    for op in resolved:
        if op[0] == "obs":
            rt.next_scalar()
        elif op[0] == "sample":
            r_ch.append(rt.sample())
        elif op[0] == "nonce":
            rt.sponge.absorb(rt.next(), 4)
        elif op[0] == "grind":
            ch, ok = rt.grind_check(op[1])
            assert ok, "rust verifier mirror rejects the prover's nonce"
            r_ch.append(ch)
    assert rt.off == len(stream)

    # CO25: split into rounds at every challenge
    rounds, cur = [], []
    for op in resolved:
        if op[0] == "obs":
            cur.append((op[1], 1))
        elif op[0] == "nonce":
            cur.append((op[1], 4))
        elif op[0] == "grind":
            cur.append((op[2], 4))
            rounds.append(cur)
            cur = []
        elif op[0] == "sample":
            rounds.append(cur)
            cur = []
    co_in, co_ch, start_perms, start_state = co25_run(iv, pi, sizes, rounds, cur, codec)
    return dict(prover=(prec.inputs, p_ch), py=(vrec.inputs, py_ch), rustv=(rrec.inputs, r_ch), co25=(co_in, co_ch)), rounds, start_perms, start_state


def first_diff(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b)) if len(a) != len(b) else None


def check(iv, pi, sizes, ops, codec, batched_grind=False):
    res, rounds, start_perms, start_state = run_all(iv, pi, sizes, ops, codec, batched_grind)
    ref_in, ref_ch = res["prover"]
    problems = []
    for name in ("py", "rustv", "co25"):
        ins, chs = res[name]
        if ins != ref_in:
            problems.append((name, "perm inputs", first_diff(ins, ref_in), len(ins), len(ref_in)))
        if chs != ref_ch:
            problems.append((name, "challenges", first_diff(chs, ref_ch), len(chs), len(ref_ch)))
    return problems, rounds, start_perms, start_state


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    stats = {}
    for codec in ("stated", "fixed"):
        for with_sizes in (True, False):
            for raw in (False, True):
                rng = random.Random(f"{codec}-{with_sizes}-{raw}")
                fails = []
                n_perm_inputs = 0
                for trial in range(n):
                    iv, pi, sizes, ops = gen_schedule(rng, with_sizes, raw)
                    probs, rounds, sp, ss = check(iv, pi, sizes, ops, codec, batched_grind=(trial % 2 == 1))
                    if probs:
                        fails.append((trial, probs, ops[:3], len(rounds[0]) if rounds else None))
                stats[(codec, with_sizes, raw)] = fails
                first_round_empty = sum(1 for f in fails if f[3] == 0)
                print(f"codec={codec:6s} sizes={with_sizes!s:5s} raw_nonce={raw!s:5s}: {n} schedules, {len(fails)} mismatches"
                      f" (of which round-1 message empty: {first_round_empty})")
                if fails:
                    print("   e.g.", fails[0][1], "first ops:", fails[0][2])
    return stats


if __name__ == "__main__":
    main()
