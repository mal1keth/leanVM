//! The hypertree, the message digest, and the three algorithms.
//!
//! The message digest picks a bottom leaf `idx`, and so a FORS instance and the
//! one-time key on every layer above it. Nothing is reserved and nothing is
//! spent, which is what makes the scheme stateless. The bottom key signs the
//! FORS public key, the middle key the bottom tree's root, the top key the middle
//! tree's root, and the top tree's root is `PK.root`.

use serde::{Deserialize, Serialize};

use crate::lean_sphincs::*;

/// Ordered lexicographically on [`Self::to_bytes`], which is what an aggregate's
/// signer list is sorted and deduplicated by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LeanSphincsPublicKey {
    pub(crate) pk_seed: PkSeed,
    pub(crate) root: Digest,
}

impl LeanSphincsPublicKey {
    pub fn pk_seed(&self) -> &PkSeed {
        &self.pk_seed
    }

    pub fn root(&self) -> &Digest {
        &self.root
    }

    /// `PK.seed | PK.root`.
    pub fn to_bytes(&self) -> [u8; PUB_KEY_SIZE] {
        let mut out = [0; PUB_KEY_SIZE];
        out[..N].copy_from_slice(&self.pk_seed);
        out[N..].copy_from_slice(&self.root);
        out
    }

    pub fn from_bytes(bytes: &[u8; PUB_KEY_SIZE]) -> Self {
        Self {
            pk_seed: bytes[..N].try_into().unwrap(),
            root: bytes[N..].try_into().unwrap(),
        }
    }
}

/// `SK.seed`, all of the key: [`key_seeds`] derives the rest.
#[derive(Clone)]
pub struct LeanSphincsSecretKey {
    seed: Seed,
}

impl std::fmt::Debug for LeanSphincsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeanSphincsSecretKey").finish_non_exhaustive()
    }
}

impl LeanSphincsSecretKey {
    /// The public key, rebuilt as key generation builds it: the whole top tree.
    pub fn public_key(&self) -> LeanSphincsPublicKey {
        keygen(&key_seeds(&self.seed)).0
    }

    /// SECRET KEY MATERIAL: the seed, all of the key.
    pub fn to_bytes(&self) -> Seed {
        self.seed
    }

    pub fn from_bytes(bytes: &Seed) -> Self {
        Self { seed: *bytes }
    }
}

/// What a signature carries for one layer: the one-time signature of what the
/// layer below gives. Its key's path is [`LeanSphincsSignature::path`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerSignature {
    pub(crate) counter: u32,
    pub(crate) wots: [Digest; V],
}

impl LayerSignature {
    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn wots(&self) -> &[Digest; V] {
        &self.wots
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeanSphincsSignature {
    pub(crate) randomizer: Digest,
    pub(crate) fors: ForsOpening,
    /// Bottom first.
    pub(crate) layers: [LayerSignature; LAYERS],
    /// The layers' paths one after the other, bottom first ([`Self::path`]).
    pub(crate) paths: [Digest; H],
}

impl LeanSphincsSignature {
    /// `R`.
    pub fn randomizer(&self) -> &Digest {
        &self.randomizer
    }

    pub fn fors(&self) -> &ForsOpening {
        &self.fors
    }

    /// Bottom first.
    pub fn layers(&self) -> &[LayerSignature; LAYERS] {
        &self.layers
    }

    /// Layer `layer`'s path in its tree, from the leaf up.
    pub fn path(&self, layer: usize) -> &[Digest] {
        let start: usize = LAYER_HEIGHTS[..layer].iter().sum();
        &self.paths[start..start + LAYER_HEIGHTS[layer]]
    }

    /// The specification's serialization, exactly [`SIG_SIZE`] bytes: the
    /// randomizer, the FORS openings, then each layer from the bottom up, its
    /// counter (big endian), chain values and path.
    pub fn to_bytes(&self) -> [u8; SIG_SIZE] {
        let mut out = [0; SIG_SIZE];
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&self.randomizer);
        for tree in &self.fors {
            put(&tree.secret);
            put(tree.path.as_flattened());
        }
        for (layer, signed) in self.layers.iter().enumerate() {
            put(&signed.counter.to_be_bytes());
            put(signed.wots.as_flattened());
            put(self.path(layer).as_flattened());
        }
        debug_assert_eq!(at, SIG_SIZE);
        out
    }

    pub fn from_bytes(bytes: &[u8; SIG_SIZE]) -> Self {
        let mut at = 0;
        let mut take = |len: usize| {
            at += len;
            &bytes[at - len..at]
        };
        let randomizer = take(N).try_into().unwrap();
        let fors = std::array::from_fn(|_| ForsTreeOpening {
            secret: take(N).try_into().unwrap(),
            path: std::array::from_fn(|_| take(N).try_into().unwrap()),
        });
        let mut paths = Vec::with_capacity(H);
        let layers = std::array::from_fn(|layer| {
            let signed = LayerSignature {
                counter: u32::from_be_bytes(take(COUNTER_LEN).try_into().unwrap()),
                wots: std::array::from_fn(|_| take(N).try_into().unwrap()),
            };
            paths.extend((0..LAYER_HEIGHTS[layer]).map(|_| Digest::try_from(take(N)).unwrap()));
            signed
        });
        debug_assert_eq!(at, SIG_SIZE);
        Self {
            randomizer,
            fors,
            layers,
            paths: paths.try_into().unwrap(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LeanSphincsSignError {
    /// `C_max` counters in a row failed to encode.
    NoAdmissibleEncoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LeanSphincsVerifyError {
    /// A counter does not encode what its layer signs.
    InadmissibleEncoding,
    RootMismatch,
}

impl std::fmt::Display for LeanSphincsSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAdmissibleEncoding => write!(f, "no admissible encoding within C_max attempts"),
        }
    }
}

impl std::error::Error for LeanSphincsSignError {}

impl std::fmt::Display for LeanSphincsVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InadmissibleEncoding => write!(f, "a counter does not encode what its layer signs"),
            Self::RootMismatch => write!(f, "the walk does not reach the key's root"),
        }
    }
}

impl std::error::Error for LeanSphincsVerifyError {}

/// The index and the FORS leaves a digest spells (FIPS 205 Algorithm 19): the
/// first [`MD_BYTES`] give each tree's leaf, `a` bits a tree most significant
/// first (`base_2^a`), the next [`TREE_INDEX_BYTES`] the tree, and the last
/// [`LEAF_INDEX_BYTES`] its leaf, each a big-endian integer cut to its bits.
/// The index is the tree then the leaf.
pub fn digest_fields(digest: &[u8; 32 * DIGEST_CALLS]) -> (u64, [usize; FORS_TREES]) {
    let bit = |p: usize| usize::from(digest[p / 8] >> (7 - p % 8) & 1);
    let leaves = std::array::from_fn(|c| (0..FORS_HEIGHT).fold(0, |v, j| v << 1 | bit(FORS_HEIGHT * c + j)));
    let int = |bytes: &[u8], bits: usize| bytes.iter().fold(0u64, |v, &b| v << 8 | u64::from(b)) & ((1 << bits) - 1);
    let tree = int(&digest[MD_BYTES..MD_BYTES + TREE_INDEX_BYTES], H - LAYER_HEIGHTS[0]);
    let leaf = int(&digest[MD_BYTES + TREE_INDEX_BYTES..DIGEST_BYTES], LAYER_HEIGHTS[0]);
    (tree << LAYER_HEIGHTS[0] | leaf, leaves)
}

/// The message digest read as the index and the FORS leaves.
fn message_digest(pk: &LeanSphincsPublicKey, r: &Digest, m: &Message) -> (u64, [usize; FORS_TREES]) {
    digest_fields(&h_msg(r, &pk.pk_seed, &pk.root, m))
}

/// The levels of a tree `height` levels over `leaves`, the leaves first,
/// `node(level, j, children)` hashing node `j` on `level`.
pub(crate) fn merkle_levels(
    leaves: Vec<Digest>,
    height: usize,
    node: impl Fn(usize, usize, &[Digest; 2]) -> Digest,
) -> Vec<Vec<Digest>> {
    let mut levels = vec![leaves];
    for level in 1..=height {
        let (pairs, _) = levels[level - 1].as_chunks::<2>();
        let up = pairs.iter().enumerate().map(|(j, pair)| node(level, j, pair)).collect();
        levels.push(up);
    }
    levels
}

/// A node and its sibling in index order: `bit` says the node is the right one.
pub(crate) fn ordered(bit: usize, node: Digest, sibling: Digest) -> [Digest; 2] {
    if bit & 1 == 0 { [node, sibling] } else { [sibling, node] }
}

/// Node `j` at height `z` of the tree holding `key`, from its two children.
fn node(pk_seed: &PkSeed, key: &OtsKey, z: usize, j: usize, children: &[Digest; 2]) -> Digest {
    let adrs = key
        .tree_adrs()
        .with_type(TREE)
        .with_tree_height(z as u32)
        .with_tree_index(j as u32);
    th_digests(pk_seed, &adrs, children)
}

/// The levels of the tree holding `key`, its leaves first and its root last.
fn tree_levels(seeds: &KeySeeds, key: &OtsKey) -> Vec<Vec<Digest>> {
    let height = LAYER_HEIGHTS[key.layer];
    let leaves = parallel::map_collect(1 << height, |leaf| {
        wots_public_leaf(
            seeds,
            &OtsKey {
                leaf: leaf as u32,
                ..*key
            },
        )
    });
    merkle_levels(leaves, height, |z, j, pair| node(&seeds.pk_seed, key, z, j, pair))
}

/// `Gen`, deterministic: the seed's [`key_seeds`], and the top tree gives the root.
pub fn key_gen_from_seed(seed: Seed) -> (LeanSphincsSecretKey, LeanSphincsPublicKey) {
    (LeanSphincsSecretKey { seed }, keygen(&key_seeds(&seed)).0)
}

/// `slh_keygen_internal`: the public key, `PK.seed` and the top tree's root, with
/// the top tree's levels, which signing reuses.
fn keygen(seeds: &KeySeeds) -> (LeanSphincsPublicKey, Vec<Vec<Digest>>) {
    let top = tree_levels(seeds, &OtsKey::of_index(LAYERS - 1, 0));
    let pk = LeanSphincsPublicKey {
        pk_seed: seeds.pk_seed,
        root: top[LAYER_HEIGHTS[LAYERS - 1]][0],
    };
    (pk, top)
}

/// `Gen`, on a fresh seed from the operating system's randomness.
pub fn key_gen() -> (LeanSphincsSecretKey, LeanSphincsPublicKey) {
    key_gen_from_seed(rand::random())
}

/// `Sign`. Deterministic and stateless: the digest picks the FORS instance,
/// which opens the message, and each layer signs what the layer below gives. A
/// key signs at most `2^30` messages (`doc/lean_sphincs`). It builds its trees on
/// `parallel`, so never sign from inside a `parallel` task.
pub fn sign(sk: &LeanSphincsSecretKey, message: &Message) -> Result<LeanSphincsSignature, LeanSphincsSignError> {
    sign_with(&key_seeds(&sk.seed), message)
}

/// `slh_sign_internal`, deterministic (`opt_rand = PK.seed`). It builds the top
/// tree for `PK.root` and the top path, then the FORS instance and the two trees
/// below.
fn sign_with(seeds: &KeySeeds, message: &Message) -> Result<LeanSphincsSignature, LeanSphincsSignError> {
    let (pk, mut top) = keygen(seeds);
    let r = prf_msg(&seeds.sk_prf, &seeds.pk_seed, message);
    let (idx, leaves) = message_digest(&pk, &r, message);
    let (mut signed, fors) = fors_open(seeds, idx, &leaves);
    let (mut layers, mut paths) = (Vec::with_capacity(LAYERS), Vec::with_capacity(H));
    for layer in 0..LAYERS {
        let key = OtsKey::of_index(layer, idx);
        let (counter, wots) = wots_sign(seeds, &key, &signed).ok_or(LeanSphincsSignError::NoAdmissibleEncoding)?;
        let levels = if layer == LAYERS - 1 {
            std::mem::take(&mut top)
        } else {
            tree_levels(seeds, &key)
        };
        let height = LAYER_HEIGHTS[layer];
        paths.extend((0..height).map(|z| levels[z][(key.leaf as usize >> z) ^ 1]));
        layers.push(LayerSignature { counter, wots });
        signed = levels[height][0];
    }
    Ok(LeanSphincsSignature {
        randomizer: r,
        fors,
        layers: layers.try_into().unwrap(),
        paths: paths.try_into().unwrap(),
    })
}

/// `Tree.fold`: the root a key's leaf and its path reach, showing `visit` the two
/// children of every node on the way up.
pub fn tree_fold(
    pk_seed: &PkSeed,
    key: &OtsKey,
    leaf: Digest,
    path: &[Digest],
    mut visit: impl FnMut(&[Digest; 2]),
) -> Digest {
    let e = key.leaf as usize;
    path.iter().enumerate().fold(leaf, |current, (level, sibling)| {
        let children = ordered(e >> level, current, *sibling);
        visit(&children);
        node(pk_seed, key, level + 1, e >> (level + 1), &children)
    })
}

/// `Ver`.
pub fn verify(
    pk: &LeanSphincsPublicKey,
    message: &Message,
    signature: &LeanSphincsSignature,
) -> Result<(), LeanSphincsVerifyError> {
    let pk_seed = &pk.pk_seed;
    let (idx, leaves) = message_digest(pk, &signature.randomizer, message);
    let mut signed = fors_recover(pk_seed, idx, &leaves, &signature.fors, |_| ());
    for (layer, layer_sig) in signature.layers.iter().enumerate() {
        let key = OtsKey::of_index(layer, idx);
        let (_, leaf) = wots_leaf(pk_seed, &key, &signed, layer_sig.counter, &layer_sig.wots)
            .ok_or(LeanSphincsVerifyError::InadmissibleEncoding)?;
        signed = tree_fold(pk_seed, &key, leaf, signature.path(layer), |_| ());
    }
    if signed == pk.root {
        Ok(())
    } else {
        Err(LeanSphincsVerifyError::RootMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known answer, byte for byte: the key whose `SK.seed` is `S[i] = 37 i + 11`
    /// and its signature of `m[i] = 7 i + 3`.
    #[test]
    fn known_answer() {
        let mut lines = include_str!("known_answer.hex").lines();
        let mut unhex = || {
            let s = lines.next().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let (pk_bytes, sig_bytes) = (unhex(), unhex());
        let seeds = key_seeds(&std::array::from_fn(|i| (37 * i + 11) as u8));
        let pk = keygen(&seeds).0;
        let message: Message = std::array::from_fn(|i| (7 * i + 3) as u8);
        assert_eq!(pk.to_bytes()[..], pk_bytes[..]);
        let signature = sign_with(&seeds, &message).unwrap();
        assert_eq!(signature.to_bytes()[..], sig_bytes[..]);
        assert_eq!(verify(&pk, &message, &signature), Ok(()));
    }
}
