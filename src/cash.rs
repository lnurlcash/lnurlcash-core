//! LUD-25's `m/139'` branch derivation: the BIP-32 walk from a wallet's cash
//! root down to a per-`SERVICE` domain node, exactly as Part 2's "Seed &
//! derivation" section specifies it:
//!
//! ```text
//! cashHashingKey   = derive(masterKey, m/139'/0)
//! domainMaterial   = hmacSha256(cashHashingKey, full SERVICE domain)
//! (d1, d2, d3, d4) = first 16 bytes of domainMaterial as 4 uint32
//! domainNode       = derive(masterKey, m/139'/d1/d2/d3/d4)
//! ```
//!
//! "exactly as LUD-05", says the draft of the middle two lines, and that
//! reference is what settles the one thing the path shape leaves open.
//! `d1..d4` are raw uint32 drawn from a hash, and BIP-32 already reads any
//! index >= 2^31 as hardened, so roughly half of any given mint's four levels
//! are hardened by magnitude alone. They are used exactly as they fall:
//! nothing is masked, and nothing is forced hardened. That is what LUD-05's
//! own corpus does with the same four longs, and what the reference wallet
//! does.
//!
//! An implementation that masks the top bit, or hardens all four, derives a
//! different tree from every conforming wallet - and a restore against it
//! finds nothing, silently, and only once the money is gone.
//!
//! Part 1 secrets are NOT derived from this node, or from the seed at all -
//! Part 1's own text has `WALLET` generate plain randomness. An earlier
//! reference-wallet extension did derive Part 1 secrets deterministically
//! from a sibling of this branch, hardened at the note's own index; it has
//! since been dropped as unspecified, and this module no longer provides it.
//! [`crate::secrets`]' legacy scheme (HMAC-SHA256 under `lnurlcash-note-v1`,
//! predating LUD-25 entirely) is still derived and still scanned on restore
//! forever, so nothing already minted under either scheme goes missing.
//!
//! Part 2's address branch is this exact domain node, for the same host: see
//! [`crate::recoverable::derive_cash_address_node`].

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

/// The BIP-32 master node of a seed. Public beside [`derive_cash_child`] for
/// the same reason: a consumer walking a path this crate does not name starts
/// here.
pub fn derive_cash_master(seed: &[u8]) -> Result<CashNode> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(Error::Protocol(format!(
            "a BIP-32 seed must be 16 to 64 bytes, not {}",
            seed.len()
        )));
    }
    let material = hmac512(b"Bitcoin seed", seed);
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&material[..32]);
    SecretKey::from_slice(&private_key).map_err(|_| {
        Error::Protocol("this seed does not produce a valid BIP-32 master key".into())
    })?;
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
    derive_cash_child(&derive_cash_master(seed)?, CASH_PURPOSE + HARDENED)
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
/// Its own step because it is the unit a signer is provisioned with, and the
/// node Part 2's address branch is (see
/// [`crate::recoverable::derive_cash_address_node`]). It does not spare a
/// signer the curve: the per-note tweak beneath it, and the `ck1` signature,
/// both need secp256k1.
///
/// Whoever derives it can derive every note key the wallet will ever hold AT
/// THIS MINT, so it is provisioning material rather than something to hand
/// out: one mint's subtree, not the wallet.
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
