//! Note secrets: where they come from, and what shape they are.

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::{Error, Result};

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
