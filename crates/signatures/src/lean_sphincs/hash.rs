//! The address and the hash functions of FIPS 205, on Keccak-256.
//!
//! `F`, `H`, `T_l` and `PRF` are one function here, [`th`], since FIPS 205's
//! SHAKE instances lay all four out as `PK.seed | ADRS | M`, truncated to `n`
//! bytes.

use primitives::hash::Hasher;

use crate::lean_sphincs::*;

pub type PkSeed = [u8; N];

/// FIPS 205's address: 32 bytes, eight big-endian words.
pub const ADRS_LEN: usize = 32;
/// The bytes before a payload: `PK.seed | ADRS`.
pub const PREFIX_LEN: usize = N + ADRS_LEN;

// Address types (FIPS 205 §4.2), and WOTS+C's encoding, which FIPS 205 has none of.
pub const WOTS_HASH: u32 = 0;
pub const WOTS_PK: u32 = 1;
pub const TREE: u32 = 2;
pub const FORS_TREE: u32 = 3;
pub const FORS_ROOTS: u32 = 4;
pub const WOTS_PRF: u32 = 5;
pub const FORS_PRF: u32 = 6;
pub const WOTS_ENC: u32 = 7;

/// `ADRS`: the layer address (bytes 0..4), the tree address (4..16), the type
/// (16..20), then three words whose meaning the type gives: the key pair
/// address, the chain address or tree height, and the hash address or tree
/// index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Adrs([u8; ADRS_LEN]);

impl Adrs {
    /// The address of tree `tree` of hypertree layer `layer`, type `WOTS_HASH`.
    pub fn new(layer: u32, tree: u64) -> Self {
        let mut out = [0; ADRS_LEN];
        out[..4].copy_from_slice(&layer.to_be_bytes());
        out[8..16].copy_from_slice(&tree.to_be_bytes());
        Self(out)
    }

    fn word(mut self, at: usize, value: u32) -> Self {
        self.0[at..at + 4].copy_from_slice(&value.to_be_bytes());
        self
    }

    /// `setTypeAndClear`: type `t`, the last three words zero.
    pub fn with_type(mut self, t: u32) -> Self {
        self.0[20..].fill(0);
        self.word(16, t)
    }

    pub fn with_key_pair(self, i: u32) -> Self {
        self.word(20, i)
    }

    pub fn with_chain(self, i: u32) -> Self {
        self.word(24, i)
    }

    pub fn with_tree_height(self, z: u32) -> Self {
        self.word(24, z)
    }

    pub fn with_hash(self, j: u32) -> Self {
        self.word(28, j)
    }

    pub fn with_tree_index(self, j: u32) -> Self {
        self.word(28, j)
    }

    pub fn as_bytes(&self) -> &[u8; ADRS_LEN] {
        &self.0
    }
}

fn truncate(output: [u8; 32]) -> Digest {
    output[..N].try_into().unwrap()
}

/// A hasher that has absorbed `PK.seed | ADRS`.
pub fn hasher(pk_seed: &PkSeed, adrs: &Adrs) -> Hasher {
    let mut hasher = Hasher::new();
    hasher.update(pk_seed).update(adrs.as_bytes());
    hasher
}

/// `F`, `H` and `T_l`: `Trunc_n(H(PK.seed | ADRS | M))`.
pub fn th(pk_seed: &PkSeed, adrs: &Adrs, m: &[u8]) -> Digest {
    truncate(hasher(pk_seed, adrs).update(m).finalize())
}

/// [`th`] over a concatenation of values: a node, a one-time key or a FORS key.
pub fn th_digests(pk_seed: &PkSeed, adrs: &Adrs, values: &[Digest]) -> Digest {
    th(pk_seed, adrs, values.as_flattened())
}

/// `PRF(PK.seed, SK.seed, ADRS)`.
pub fn prf(pk_seed: &PkSeed, sk_seed: &Seed, adrs: &Adrs) -> Digest {
    th(pk_seed, adrs, sk_seed)
}

/// `PRF_msg(SK.prf, opt_rand, M) = Trunc_n(H(SK.prf | opt_rand | M))`.
pub fn prf_msg(sk_prf: &Digest, opt_rand: &[u8; N], m: &Message) -> Digest {
    truncate(Hasher::new().update(sk_prf).update(opt_rand).update(m).finalize())
}

/// `H_msg(R, PK.seed, PK.root, M)` in counter mode: the calls
/// `H(R | PK.seed | PK.root | M | BE_32(i))`, one block each, whole, of which the
/// first [`DIGEST_BYTES`] are `H_msg`.
pub fn h_msg(r: &Digest, pk_seed: &PkSeed, pk_root: &Digest, m: &Message) -> [u8; 32 * DIGEST_CALLS] {
    let mut prefix = Hasher::new();
    prefix.update(r).update(pk_seed).update(pk_root).update(m);
    let mut out = [0; 32 * DIGEST_CALLS];
    for (i, call) in out.as_chunks_mut::<32>().0.iter_mut().enumerate() {
        *call = prefix.clone().update(&(i as u32).to_be_bytes()).finalize();
    }
    out
}

/// FIPS 205's three key seeds, which `slh_keygen_internal` takes. Here `SK.seed` is
/// 32 bytes, the whole secret key, and the other two derive from it.
#[derive(Clone, Copy)]
pub struct KeySeeds {
    pub sk_seed: Seed,
    pub sk_prf: Digest,
    pub pk_seed: PkSeed,
}

/// The key seeds of `SK.seed`: `PK.seed | SK.prf = H(tag | SK.seed)`.
pub fn key_seeds(sk_seed: &Seed) -> KeySeeds {
    let out = Hasher::new().update(SEED_TAG).update(sk_seed).finalize();
    KeySeeds {
        sk_seed: *sk_seed,
        sk_prf: out[N..].try_into().unwrap(),
        pk_seed: out[..N].try_into().unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_layout() {
        let adrs = Adrs::new(2, 0x0102_0304_0506)
            .with_type(FORS_TREE)
            .with_key_pair(0x0708_090a)
            .with_tree_height(0x0b0c_0d0e)
            .with_tree_index(0x0f10_1112);
        let bytes: Vec<u8> = [
            [0, 0, 0, 2],
            [0, 0, 0, 0],
            [0, 0, 1, 2],
            [3, 4, 5, 6],
            [0, 0, 0, 3],
            [7, 8, 9, 10],
            [11, 12, 13, 14],
            [15, 16, 17, 18],
        ]
        .concat();
        assert_eq!(adrs.as_bytes()[..], bytes[..]);
        assert_eq!(adrs.with_type(WOTS_PK).as_bytes()[20..], [0; 12]);
    }
}
