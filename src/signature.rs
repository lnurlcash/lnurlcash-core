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
//! message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(sha256(k1))
//! digest  = sha256(sha256("Lightning Signed Message:" || message))
//! ```
//!
//! The signature commits to the note's HASH, not its secret, so a holder can
//! prove issuance - to expose a mint that will not honour its own note -
//! without revealing what would let anyone spend it.

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use sha2::{Digest, Sha256};

use crate::secrets::hash_k1;

const LIGHTNING_SIGNED_MESSAGE_PREFIX: &[u8] = b"Lightning Signed Message:";
const DOMAIN_TAG: &str = "LNURLcash";

pub fn note_signature_message(k1: &str, amount_msat: u64) -> Option<String> {
    Some(format!("{DOMAIN_TAG}:{amount_msat}:{}", hash_k1(k1).ok()?))
}

pub fn note_signature_digest(k1: &str, amount_msat: u64) -> Option<[u8; 32]> {
    let message = note_signature_message(k1, amount_msat)?;
    let inner = Sha256::digest([LIGHTNING_SIGNED_MESSAGE_PREFIX, message.as_bytes()].concat());
    Some(Sha256::digest(inner).into())
}

/// Recover the signer's pubkey and check it against `mint_pubkey_hex`.
///
/// The signature is 65 bytes, but which end carries the recovery id varies by
/// implementation: LUD-25 calls for `r || s || recovery_id`, the layout raw
/// BOLT-11 signatures use, while lnurl-mint once forwarded its node's
/// signmessage output unreordered as `recovery_id || r || s`. That is fixed
/// upstream, but other implementations may still get it wrong.
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
    let Ok(signature) = hex::decode(signature_hex.trim()) else {
        return false;
    };
    if signature.len() != 65 {
        return false;
    }
    let Some(digest) = note_signature_digest(k1, amount_msat) else {
        // a malformed k1 cannot be hashed - not a panic, a "no"
        return false;
    };
    let Ok(message) = Message::from_digest_slice(&digest) else {
        return false;
    };
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
