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
//! the verified hex public key embedded in its `ck1` (see [`crate::recoverable`]).
//! Either way the signature commits to the note's ID, not its secret, so a
//! holder can prove issuance - to expose a mint that will not honour its own
//! note - without revealing what would let anyone spend it.

use k256::schnorr::SigningKey;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use sha2::{Digest, Sha256};

use crate::recoverable::{decode_any_cs1, note_id_of};

const LIGHTNING_SIGNED_MESSAGE_PREFIX: &[u8] = b"Lightning Signed Message:";
const DOMAIN_TAG: &str = "LNURLcash";

pub fn address_proof_message(action: &str, username: &str) -> crate::Result<String> {
    if action != "register" && action != "unregister" {
        return Err(crate::Error::Protocol(
            "an address proof action is register or unregister".into(),
        ));
    }
    Ok(format!("{DOMAIN_TAG}:{action}:{username}"))
}

/// [`address_proof_message`], hashed to a 32-byte digest before signing.
/// `username` is variable-length, so the raw message would otherwise only
/// rarely land on the 32 bytes most Schnorr signers require - the same
/// reason ownership proofs are hashed (see [`crate::recoverable`]).
pub fn address_proof_digest(action: &str, username: &str) -> crate::Result<[u8; 32]> {
    Ok(Sha256::digest(address_proof_message(action, username)?.as_bytes()).into())
}

/// Sign a register/update or unregister proof as a raw 64-byte BIP-340
/// signature over `sha256` of the protocol message. This is a fresh action a
/// WALLET initiates itself, never a stored bearer secret read back later, so
/// there is no old scheme to fall back to reading, unlike ownership proofs.
pub fn sign_address_proof(
    index_zero_secret_key: &[u8; 32],
    action: &str,
    username: &str,
) -> crate::Result<[u8; 64]> {
    let key = SigningKey::from_bytes(index_zero_secret_key).map_err(|_| {
        crate::Error::Protocol("an index-zero secret key is a 32-byte scalar in [1, n)".into())
    })?;
    key.sign_raw(&address_proof_digest(action, username)?, &[0u8; 32])
        .map(|signature| signature.to_bytes())
        .map_err(|_| crate::Error::Protocol("could not sign the address proof message".into()))
}

/// What a Lightning node's signmessage puts its pen to, and so what every
/// recoverable-ECDSA SERVICE signature is made over. WALLET Schnorr proofs
/// deliberately hash their own UTF-8 messages to a 32-byte digest instead
/// (see [`address_proof_digest`] and [`crate::recoverable::sign_note_ownership`]).
pub(crate) fn lightning_signed_digest(message: &str) -> [u8; 32] {
    let inner = Sha256::digest([LIGHTNING_SIGNED_MESSAGE_PREFIX, message.as_bytes()].concat());
    Sha256::digest(inner).into()
}

/// The message a SERVICE signs over a note. `None` for a k1 that is neither
/// 32 bytes of hex nor a valid `ck1`, since neither has an id to sign.
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
/// embeds and proves, found locally, so checking one needs no network either.
/// `signature_hex` is 65 bytes of hex, or either form of Part 2 `cs1`.
/// Amount-bearing certificates can be decoded separately when the caller
/// needs the amount carried on the wire.
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
    let signature = match decode_any_cs1(signature_hex) {
        Some(signature) => signature.to_vec(),
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
