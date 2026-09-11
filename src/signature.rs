//! LUD-25 offline verification.
//!
//! A SERVICE may sign each note it issues with its Lightning node identity key
//! (the same key it signs BOLT-11 invoices with), so a holder can confirm a
//! note's issuer and amount without contacting anyone. Signed via the node's
//! own signmessage RPC (lnd's `/v1/signmessage`, cln's `signmessage`), which
//! wraps the message with this prefix and double-SHA256s it before signing.
//! That is deliberate reuse: any tool that already verifies a Lightning node's
//! signed messages can verify a note, and neither backend can produce a
//! bespoke raw-digest scheme anyway.
//!
//! ```text
//! message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || note id
//! digest  = sha256(sha256("Lightning Signed Message:" || message))
//! ```
//!
//! The note id is `hex(sha256(k1))` for a Part 1 note, and for a Part 2 note
//! the hex public key its `ck1` recovers to (see [`crate::recoverable`]).
//! Either way the signature commits to the note's ID, not its secret, so a
//! holder can prove issuance - to expose a mint that will not honour its own
//! note - without revealing what would let anyone spend it.

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use sha2::{Digest, Sha256};

use crate::recoverable::{decode_cs1, note_id_of};

const LIGHTNING_SIGNED_MESSAGE_PREFIX: &[u8] = b"Lightning Signed Message:";
const DOMAIN_TAG: &str = "LNURLcash";

/// What a Lightning node's signmessage puts its pen to, and so what every
/// LNURLcash signature is made over, a Part 2 ownership proof included.
pub(crate) fn lightning_signed_digest(message: &str) -> [u8; 32] {
    let inner = Sha256::digest([LIGHTNING_SIGNED_MESSAGE_PREFIX, message.as_bytes()].concat());
    Sha256::digest(inner).into()
}

/// The message a SERVICE signs over a note. `None` for a k1 that is neither
/// 32 bytes of hex nor a `ck1` that recovers, since neither has an id to sign.
pub fn note_signature_message(k1: &str, amount_msat: u64) -> Option<String> {
    Some(note_signature_message_for_hash(
        &note_id_of(k1)?,
        amount_msat,
    ))
}

/// The same message from the note's id rather than its k1: a hash, or a Part
/// 2 note's public key as hex. What a caller holding only the `cp1`, or a
/// watcher holding the branch's `cx1`, checks a certificate against.
pub fn note_signature_message_for_hash(h: &str, amount_msat: u64) -> String {
    format!(
        "{DOMAIN_TAG}:{amount_msat}:{}",
        h.trim().to_ascii_lowercase()
    )
}

pub fn note_signature_digest(k1: &str, amount_msat: u64) -> Option<[u8; 32]> {
    Some(note_signature_digest_for_hash(
        &note_id_of(k1)?,
        amount_msat,
    ))
}

pub fn note_signature_digest_for_hash(h: &str, amount_msat: u64) -> [u8; 32] {
    lightning_signed_digest(&note_signature_message_for_hash(h, amount_msat))
}

/// Recover the signer's pubkey and check it against `mint_pubkey_hex`.
///
/// `k1` is a Part 1 secret or a Part 2 `ck1`; a `ck1`'s id is the key it
/// recovers to, found locally, so checking one needs no network either.
/// `signature_hex` is 65 bytes of hex, or a Part 2 `cs1`, which is the same
/// 65 bytes encoded.
///
/// Which end of those bytes carries the recovery id varies by implementation:
/// LUD-25 calls for `r || s || recovery_id`, the layout raw BOLT-11 signatures
/// use, while lnurl-mint once forwarded its node's signmessage output
/// unreordered as `recovery_id || r || s`. That is fixed upstream, but other
/// implementations may still get it wrong.
///
/// Trying both orderings costs nothing security-wise - recovering against the
/// wrong one yields an unrelated pubkey that cannot match - and means a note
/// verifies regardless of which convention issued it.
///
/// Never panics. An unverifiable signature is a `false`.
pub fn verify_note_signature(
    k1: &str,
    amount_msat: u64,
    signature_hex: &str,
    mint_pubkey_hex: &str,
) -> bool {
    let Some(h) = note_id_of(k1) else {
        // a malformed k1 has no id to check - not a panic, a "no"
        return false;
    };
    verify_note_signature_hash(&h, amount_msat, signature_hex, mint_pubkey_hex)
}

/// [`verify_note_signature`] by the note's id rather than its k1: a hash, or
/// a Part 2 note's public key as hex. For checking a certificate without the
/// secret that spends the note, which a Part 2 watcher never has.
pub fn verify_note_signature_hash(
    h: &str,
    amount_msat: u64,
    signature_hex: &str,
    mint_pubkey_hex: &str,
) -> bool {
    let h = h.trim();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let signature = match decode_cs1(signature_hex) {
        Some(certificate) => certificate.to_vec(),
        None => match hex::decode(signature_hex.trim()) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        },
    };
    if signature.len() != 65 {
        return false;
    }
    let digest = note_signature_digest_for_hash(h, amount_msat);
    let message = Message::from_digest(digest);
    let target = mint_pubkey_hex.trim().to_ascii_lowercase();
    let secp = Secp256k1::verification_only();

    // (compact 64 bytes, recovery id) under each candidate ordering
    let trailing = (&signature[..64], signature[64]);
    let leading = (&signature[1..65], signature[0]);

    for (compact, recovery) in [trailing, leading] {
        let Ok(id) = RecoveryId::from_i32(recovery as i32) else {
            continue;
        };
        let Ok(sig) = RecoverableSignature::from_compact(compact, id) else {
            continue;
        };
        if let Ok(recovered) = secp.recover_ecdsa(&message, &sig) {
            if hex::encode(recovered.serialize()) == target {
                return true;
            }
        }
    }
    false
}
