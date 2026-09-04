//! LUD-25 seed-recoverable note secrets: the specified scheme.
//!
//! LUD-25's "Seed-recoverable note secrets" section, in full:
//!
//! ```text
//! cashHashingKey   = derive(masterKey, m/139'/0)
//! domainMaterial   = hmacSha256(cashHashingKey, full SERVICE domain)
//! (d1, d2, d3, d4) = first 16 bytes of domainMaterial as 4 uint32
//! secret_i         = derive(masterKey, m/139'/d1/d2/d3/d4/i')
//! ```
//!
//! "exactly as LUD-05", says the draft of the middle two lines, and that
//! reference is what settles the one thing the path shape leaves open.
//! `d1..d4` are raw uint32 drawn from a hash, and BIP-32 already reads any
//! index >= 2^31 as hardened, so roughly half of any given mint's four levels
//! are hardened by magnitude alone. They are used exactly as they fall:
//! nothing is masked, and nothing is forced hardened. That is what LUD-05's
//! own corpus does with the same four longs, and what the reference wallet
//! does. Only `i` is deliberately hardened, by the spec's own `i'`.
//!
//! An implementation that masks the top bit, or hardens all four, derives a
//! different tree from every conforming wallet - and a restore against it
//! finds nothing, silently, and only once the money is gone.
//!
//! This is NOT the scheme in [`crate::secrets`]. That one (HMAC-SHA256 under
//! `lnurlcash-note-v1`) predates this section and is now the legacy scheme:
//! still derived, still scanned on restore forever, so nothing already minted
//! goes missing, but no longer what a new wallet should mint under.

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Sha256, Sha512};

use crate::errors::{Error, Result};

type HmacSha512 = Hmac<Sha512>;
type HmacSha256 = Hmac<Sha256>;

const HARDENED: u32 = 0x8000_0000;
const CASH_PURPOSE: u32 = 139;

/// A BIP-32 extended private key, reduced to the two things deriving a child
/// actually needs.
///
/// Bearer material for every note derived beneath it. A domain node is the
/// unit a hardware signer is provisioned with (see [`cash_node_to_hex`]), so
/// this deliberately serialises as plain bytes rather than as an xprv.
#[derive(Clone)]
pub struct CashNode {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
}

// Redacted rather than derived. A node is bearer material for every note
// beneath it, and the surest way to leak one is a struct that prints itself
// into a log line somebody added while debugging something else.
impl std::fmt::Debug for CashNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CashNode(redacted)")
    }
}

impl Drop for CashNode {
    fn drop(&mut self) {
        self.private_key.fill(0);
        self.chain_code.fill(0);
    }
}

fn hmac512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    bytes
}

/// One BIP-32 CKDpriv step. Hardened when `index >= 2^31`, by the index's own
/// magnitude and nothing else, which is the whole of the convention question
/// above: the caller passes the raw uint32 and this decides.
///
/// Public so a consumer can check this crate against BIP-32's own published
/// test vectors rather than taking the derivation on trust, and so a host
/// provisioning a hardware signer can walk the intermediate levels.
pub fn derive_cash_child(node: &CashNode, index: u32) -> Result<CashNode> {
    let secp = Secp256k1::signing_only();
    let parent = SecretKey::from_slice(&node.private_key)
        .map_err(|_| Error::Protocol("cash node holds an invalid private key".into()))?;

    let mut data = [0u8; 37];
    if index >= HARDENED {
        // 0x00 || ser256(kpar): the leading zero pads the 32-byte scalar out
        // to the 33 bytes a serialised point occupies, so the two legs hash
        // over the same length and can never collide.
        data[1..33].copy_from_slice(&node.private_key);
    } else {
        data[..33].copy_from_slice(&PublicKey::from_secret_key(&secp, &parent).serialize());
    }
    data[33..].copy_from_slice(&index.to_be_bytes());

    let material = hmac512(&node.chain_code, &data);
    let mut left = [0u8; 32];
    left.copy_from_slice(&material[..32]);

    // Both BIP-32 failure cases come free from the curve library: a tweak at
    // or above the group order is refused by Scalar, and a zero child key by
    // add_tweak. Both are ~2^-127 events, and a silently wrong answer here is
    // a note nobody can spend, so neither is assumed away.
    let tweak = Scalar::from_be_bytes(left)
        .map_err(|_| Error::Protocol(format!("BIP-32 derivation at {index} is out of range")))?;
    let child = parent
        .add_tweak(&tweak)
        .map_err(|_| Error::Protocol(format!("BIP-32 derivation at {index} is out of range")))?;

    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&material[32..]);
    Ok(CashNode {
        private_key: child.secret_bytes(),
        chain_code,
    })
}

fn master_from(seed: &[u8]) -> Result<CashNode> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(Error::Protocol(format!(
            "a BIP-32 seed must be 16 to 64 bytes, not {}",
            seed.len()
        )));
    }
    let material = hmac512(b"Bitcoin seed", seed);
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&material[..32]);
    SecretKey::from_slice(&private_key)
        .map_err(|_| Error::Protocol("this seed does not produce a valid BIP-32 master key".into()))?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&material[32..]);
    Ok(CashNode {
        private_key,
        chain_code,
    })
}

/// `m/139'` - the wallet's own root for note secrets, under its own purpose so
/// it never shares key material with LUD-05's `m/138'` linking-key branch.
///
/// `seed` is raw bytes. A 64-byte BIP39 seed is the interop case, and what the
/// reference wallet feeds in, but nothing here depends on BIP39 - which is
/// also what keeps a mnemonic wordlist out of every consumer's binary.
pub fn derive_cash_root(seed: &[u8]) -> Result<CashNode> {
    derive_cash_child(&master_from(seed)?, CASH_PURPOSE + HARDENED)
}

/// The four raw uint32 levels this mint's subtree hangs off.
///
/// Public because they are the whole of what a conformance vector has to pin,
/// and because a wallet debugging a restore that finds nothing wants to see
/// them.
pub fn cash_domain_indices(root: &CashNode, host: &str) -> Result<[u32; 4]> {
    let hashing = derive_cash_child(root, 0)?;
    let mut mac =
        HmacSha256::new_from_slice(&hashing.private_key).expect("HMAC takes a key of any length");
    mac.update(host.as_bytes());
    let material = mac.finalize().into_bytes();
    let mut out = [0u32; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = i * 4;
        *slot = u32::from_be_bytes([
            material[at],
            material[at + 1],
            material[at + 2],
            material[at + 3],
        ]);
    }
    Ok(out)
}

/// `m/139'/d1/d2/d3/d4` for one mint: everything above a note's own index.
///
/// Worth having as its own step, and not only to derive it once for a run of
/// secrets. Every unhardened level in the path is at or above this node, so a
/// signer given THIS rather than the seed needs no elliptic curve at all -
/// each `i'` beneath it is HMAC-SHA512 plus one modular addition. That is the
/// difference between a hardware wallet that can do LUD-25 recovery and one
/// that would need secp256k1 added to its firmware for it.
///
/// The cost is that whoever derives it can derive every note secret the wallet
/// will ever hold AT THIS MINT, so it is provisioning material rather than
/// something to hand out: one mint's subtree, not the wallet.
///
/// `host` is the mint host exactly as the wallet stores it - lowercase, port
/// included where there is one - which is what the reference wallet passes, so
/// the two derive the same tree.
pub fn derive_cash_domain_node(root: &CashNode, host: &str) -> Result<CashNode> {
    let mut node = root.clone();
    for index in cash_domain_indices(root, host)? {
        node = derive_cash_child(&node, index)?;
    }
    Ok(node)
}

fn require_index(index: u32) -> Result<u32> {
    if index >= HARDENED {
        return Err(Error::Protocol(format!(
            "a note index must be below 2^31, not {index}"
        )));
    }
    Ok(index)
}

/// The i-th note secret beneath a mint's domain node, as 32 bytes of hex - the
/// size of a payment preimage, so `hash_k1` and every wire path treat it
/// exactly as they treat a randomly drawn one. The SERVICE sees no difference:
/// it only ever receives sha256(k1).
pub fn cash_secret_at(domain_node: &CashNode, index: u32) -> Result<String> {
    let leaf = derive_cash_child(domain_node, require_index(index)? + HARDENED)?;
    Ok(hex::encode(leaf.private_key))
}

/// The convenience form, from the root. Re-derives the domain node on every
/// call, which is up to four point multiplications - fine for one secret,
/// wasteful for a run of them. Hold the domain node for those.
pub fn derive_cash_secret(root: &CashNode, host: &str, index: u32) -> Result<String> {
    cash_secret_at(&derive_cash_domain_node(root, host)?, index)
}

/// privateKey || chainCode, 64 bytes of hex. Not a BIP-32 extended key: no
/// version bytes, no depth, no parent fingerprint, no base58check. This is the
/// same 64 bytes the reference wallet persists for its own root and the shape
/// a hardware signer is provisioned with, and nothing here is ever meant to
/// leave a wallet as a portable xprv.
pub fn cash_node_to_hex(node: &CashNode) -> String {
    format!(
        "{}{}",
        hex::encode(node.private_key),
        hex::encode(node.chain_code)
    )
}

pub fn cash_node_from_hex(value: &str) -> Result<CashNode> {
    let bytes = hex::decode(value.trim().to_lowercase())
        .map_err(|_| Error::Protocol("a cash node is 64 bytes of hex".into()))?;
    if bytes.len() != 64 {
        return Err(Error::Protocol(format!(
            "a cash node is 64 bytes - a 32-byte key and a 32-byte chain code - not {}",
            bytes.len()
        )));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&bytes[..32]);
    SecretKey::from_slice(&private_key)
        .map_err(|_| Error::Protocol("that cash node holds an invalid private key".into()))?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&bytes[32..]);
    Ok(CashNode {
        private_key,
        chain_code,
    })
}

/// Walks a mint's indices in order, so a caller can let rotate, split and
/// merge draw derived secrets without knowing anything about derivation.
/// `next_index` reads back the next unused index afterwards - a split consumes
/// two, a rotate one - which is the number the wallet persists as its counter
/// for that host. The domain node is derived once, here, rather than per
/// secret.
///
/// Persist that counter in the SAME write that stages the new records, and do
/// it BEFORE the hash goes on the wire. A crash between the bump and the
/// request wastes an index, which costs nothing; a crash the other way round
/// re-derives a secret the mint has already seen, and the second note minted
/// at it collides with the first.
///
/// The counter is not secret - an index reveals nothing without the root - so
/// it belongs in an ordinary backup, and a restore should merge counters
/// upwards only. It is also not optional: a gap scan cannot see a burned index
/// (LUD-25 requires a hash lookup to answer for a spent note exactly as it
/// answers for one that never existed), so a wallet that has rotated more
/// times than its gap limit cannot rediscover its own position from the mint.
pub struct CashSecretSource {
    domain_node: CashNode,
    next: u32,
}

impl std::fmt::Debug for CashSecretSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CashSecretSource")
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl CashSecretSource {
    pub fn new(root: &CashNode, host: &str, start: u32) -> Result<Self> {
        Ok(Self {
            domain_node: derive_cash_domain_node(root, host)?,
            next: require_index(start)?,
        })
    }

    /// The next secret, advancing the counter.
    pub fn next_secret(&mut self) -> Result<String> {
        let secret = cash_secret_at(&self.domain_node, self.next)?;
        self.next += 1;
        Ok(secret)
    }

    /// The next unused index - what the wallet persists.
    pub fn next_index(&self) -> u32 {
        self.next
    }
}
