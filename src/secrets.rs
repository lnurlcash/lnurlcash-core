//! Note secrets: where they come from, and what shape they are.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// A note's id: the `h`/`h2` a WALLET discloses on a rotate, split or merge,
/// and the key a SERVICE stores the note under. Never the secret itself.
pub fn hash_k1(k1: &str) -> Result<String> {
    let bytes = hex::decode(k1).map_err(|_| Error::Protocol("k1 is not hex".into()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// LUD-25: for a rotate, split or merge, the WALLET - never the SERVICE -
/// generates the replacement note's secret and discloses only its hash.
///
/// A fresh 32 bytes, the same size a Lightning payment preimage is, though
/// nothing is ever paid for it. Drawn from the OS CSPRNG.
pub fn generate_note_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Where replacement secrets come from. Substitute for a hardware RNG, or for
/// a deterministic test.
///
/// A caller substituting this takes responsibility for an unpredictable 32
/// bytes: anything guessable is a note anyone can spend.
pub type SecretSource = fn() -> String;

/// A payment preimage, and therefore a note secret: 32 bytes hex.
pub fn is_preimage(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---- the legacy derivation ----
//
// This crate's TypeScript sibling shipped this scheme before LUD-25 had a
// section on deriving note secrets at all:
//
//   root = HMAC-SHA256(key = utf8("lnurlcash-note-v1"), msg = seed)
//   k1_i = HMAC-SHA256(key = root,                      msg = utf8(host + ":" + index))
//
// It is NOT what a new wallet should mint under - see [`crate::cash`] for the
// scheme the draft actually specifies. It is here because notes minted under
// it are still money, and a restore that walked only the current scheme would
// leave them at a mint it can no longer name.

const NOTE_DERIVATION_DOMAIN: &[u8] = b"lnurlcash-note-v1";

/// The legacy scheme's root. `seed` is raw bytes, of any length.
pub fn derive_note_root(seed: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(NOTE_DERIVATION_DOMAIN).expect("HMAC takes a key of any length");
    mac.update(seed);
    let out = mac.finalize().into_bytes();
    let mut root = [0u8; 32];
    root.copy_from_slice(&out);
    root
}

/// The legacy scheme's i-th secret at `host`, as 32 bytes of hex.
///
/// `host` is the mint host as the wallet stores it - lowercase, port included
/// where there is one - and `index` is decimal ASCII counting from 0.
pub fn derive_note_secret(root: &[u8; 32], host: &str, index: u32) -> String {
    let mut mac = HmacSha256::new_from_slice(root).expect("HMAC takes a key of any length");
    mac.update(format!("{host}:{index}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
