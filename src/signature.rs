//! LUD-25 offline verification, and the address-registration proof.
//!
//! A SERVICE certifies each note it issues with its Lightning node identity
//! key (the same key it signs BOLT-11 invoices with), so a holder can confirm
//! a note's issuer and amount without contacting anyone. Signed via the
//! node's own signmessage RPC (lnd's `/v1/signmessage`, cln's `signmessage`),
//! which wraps the message with this prefix and double-SHA256s it before
//! signing. That is deliberate reuse: any tool that already verifies a
//! Lightning node's signed messages can verify a note.
//!
//! ```text
//! message = "LNURLcash:" || domain || ":" || amount_msat || ":" || hex(Q) || ":" || t
//! digest  = sha256(sha256("Lightning Signed Message:" || message))
//! cs1     = bech32m("cs" || amount suffix, r || s || recovery-id || u32be(t))
//! ```
//!
//! `domain` is the string the canonical spend transaction commits to, so a
//! certificate names the one mint on that domain and never vouches for a
//! note at another. `Q` is the note's taproot output key, for every kind of
//! note: a bearer note's `Q` is public too, so a SERVICE can certify one
//! without disclosing what spends it. `t` is the Unix time of signing in
//! seconds (luds `fd80cdd`): a certificate attests that `Q` was outstanding
//! with that value at `t`, and a holder weighs its age. Certificates from
//! before, 65 bytes without `t`, are refused: a clean break.
//!
//! A certificate proves issuance, not that the spend in hand opens the note:
//! a `ck1` states its `Q` in plain sight, so anyone who has seen a note's
//! `cp1` and `cs1` can pair them with a signature that opens nothing.
//! [`check_note`] makes both checks, which is why it needs the mint's domain.

use k256::schnorr::{Signature as SchnorrSignature, SigningKey, VerifyingKey};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::Message;
use sha2::{Digest, Sha256};

use crate::recoverable::{decode_cs1_with_amount, decode_cx1, encode_cx1, note_id_of};
use crate::spend::{check_spend, decode_note, spend_domain_of, SpendVerdict};

const LIGHTNING_SIGNED_MESSAGE_PREFIX: &[u8] = b"Lightning Signed Message:";
const DOMAIN_TAG: &str = "LNURLcash";

// ---- the address-registration proof ----
//
// LUD-26: a share's own key proves the share is the registrant's.
//
//   register    sha256("LNURLcash:register:" || domain || ":" || username || ":" || cx1)
//   update      sha256("LNURLcash:update:" || domain || ":" || username || ":" || new cx1)
//   unregister  sha256("LNURLcash:unregister:" || domain || ":" || username)
//
// signed BIP-340 by the share's private key at S/a'/2/n', and verified
// against x(P) of the cx1 being registered or, for update and unregister, the
// one on file. A PUT carries an update `sig` by the key on file and a
// register `newsig` by the new share.

/// The message for `action` (`register`, `update` or `unregister`).
///
/// `domain` is the SERVICE's own hostname: a URL or `host:port` is reduced
/// to it, as for a spend (see [`spend_domain_of`]). `username` is lowercased,
/// as LUD-26 has it signed and stored. `cx1` is the share being registered,
/// or for `update` the new one, and must be absent for `unregister`; it is
/// signed in its canonical lowercase spelling.
pub fn address_proof_message(
    action: &str,
    domain: &str,
    username: &str,
    cx1: Option<&str>,
) -> crate::Result<String> {
    let domain = spend_domain_of(domain).ok_or_else(|| {
        crate::Error::Protocol("an address proof names the SERVICE's domain".into())
    })?;
    let username = username.trim().to_lowercase();
    if username.is_empty() {
        return Err(crate::Error::Protocol(
            "an address proof names a username".into(),
        ));
    }
    let cx1 = cx1
        .map(|value| {
            decode_cx1(value)
                .map(|cx1| encode_cx1(&cx1))
                .ok_or_else(|| crate::Error::Protocol("that is not a cx1".into()))
        })
        .transpose()?;
    match (action, cx1) {
        ("register" | "update", Some(cx1)) => {
            Ok(format!("{DOMAIN_TAG}:{action}:{domain}:{username}:{cx1}"))
        }
        ("unregister", None) => Ok(format!("{DOMAIN_TAG}:unregister:{domain}:{username}")),
        ("register" | "update", None) => Err(crate::Error::Protocol(format!(
            "a {action} proof binds the cx1 it puts on file"
        ))),
        ("unregister", Some(_)) => Err(crate::Error::Protocol(
            "an unregister proof binds no cx1".into(),
        )),
        _ => Err(crate::Error::Protocol(
            "an address proof action is register, update or unregister".into(),
        )),
    }
}

/// [`address_proof_message`], hashed to the 32-byte digest that is signed:
/// most Schnorr signers only accept 32 bytes.
pub fn address_proof_digest(
    action: &str,
    domain: &str,
    username: &str,
    cx1: Option<&str>,
) -> crate::Result<[u8; 32]> {
    Ok(Sha256::digest(address_proof_message(action, domain, username, cx1)?.as_bytes()).into())
}

/// Sign an address proof as a raw 64-byte BIP-340 signature, with an
/// all-zero auxiliary input so a retried request resends the same proof.
/// The key is the signing share's own private key
/// ([`crate::recoverable::derive_share_node`]): the share being registered,
/// or for `update` and `unregister` the one on file.
pub fn sign_address_proof(
    share_secret_key: &[u8; 32],
    action: &str,
    domain: &str,
    username: &str,
    cx1: Option<&str>,
) -> crate::Result<[u8; 64]> {
    let key = SigningKey::from_slice(share_secret_key).map_err(|_| {
        crate::Error::Protocol("a share secret key is a 32-byte scalar in [1, n)".into())
    })?;
    key.sign_raw(
        &address_proof_digest(action, domain, username, cx1)?,
        &[0u8; 32],
    )
    .map(|signature| signature.to_bytes())
    .map_err(|_| crate::Error::Protocol("could not sign the address proof message".into()))
}

/// What a SERVICE checks: does `signature` (64 bytes) verify against `x(P)`
/// of `signer`, the `cx1` being registered or the one on file, over this
/// action's message? `false` for anything malformed.
pub fn verify_address_proof(
    signer: &str,
    signature: &[u8],
    action: &str,
    domain: &str,
    username: &str,
    cx1: Option<&str>,
) -> bool {
    let Some(signer) = decode_cx1(signer) else {
        return false;
    };
    let Ok(digest) = address_proof_digest(action, domain, username, cx1) else {
        return false;
    };
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_slice(&signer.pubkey_x_only()),
        SchnorrSignature::try_from(signature),
    ) else {
        return false;
    };
    key.verify_raw(&digest, &signature).is_ok()
}

// ---- certificates ----

/// What a Lightning node's signmessage puts its pen to, and so what every
/// recoverable-ECDSA SERVICE signature is made over.
pub(crate) fn lightning_signed_digest(message: &str) -> [u8; 32] {
    let inner = Sha256::digest([LIGHTNING_SIGNED_MESSAGE_PREFIX, message.as_bytes()].concat());
    Sha256::digest(inner).into()
}

/// The message a SERVICE certifies for the note `k1` spends at `domain` (a
/// note URL, a mint URL or a bare host), signed at Unix time `t`. `None` for
/// a `k1` that is no spend (see [`note_id_of`]) or a `domain` that names
/// none.
pub fn note_signature_message(k1: &str, domain: &str, amount_msat: u64, t: u32) -> Option<String> {
    note_signature_message_for_hash(&note_id_of(k1)?, domain, amount_msat, t)
}

/// The same message over a note id given directly, `hex(Q)`, used exactly
/// as given, lowercased. `None` for a `domain` that names none. What a
/// SERVICE hands its node's signmessage, `t` its own clock's now; then
/// [`crate::recoverable::encode_cs1_with_amount`] with the same `t`.
pub fn note_signature_message_for_hash(
    id: &str,
    domain: &str,
    amount_msat: u64,
    t: u32,
) -> Option<String> {
    Some(format!(
        "{DOMAIN_TAG}:{}:{amount_msat}:{}:{t}",
        spend_domain_of(domain)?,
        id.trim().to_ascii_lowercase()
    ))
}

pub fn note_signature_digest(k1: &str, domain: &str, amount_msat: u64, t: u32) -> Option<[u8; 32]> {
    note_signature_digest_for_hash(&note_id_of(k1)?, domain, amount_msat, t)
}

pub fn note_signature_digest_for_hash(
    id: &str,
    domain: &str,
    amount_msat: u64,
    t: u32,
) -> Option<[u8; 32]> {
    note_signature_message_for_hash(id, domain, amount_msat, t)
        .map(|message| lightning_signed_digest(&message))
}

fn is_hex_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

// Does `signature` (r || s || recovery-id) recover to `mint_pubkey_hex`?
fn recovers_to(digest: [u8; 32], signature: &[u8; 65], mint_pubkey_hex: &str) -> bool {
    let target = mint_pubkey_hex.trim().to_ascii_lowercase();
    let Ok(id) = RecoveryId::try_from(i32::from(signature[64])) else {
        return false;
    };
    let Ok(sig) = RecoverableSignature::from_compact(&signature[..64], id) else {
        return false;
    };
    sig.recover_ecdsa(Message::from_digest(digest))
        .is_ok_and(|recovered| hex::encode(recovered.serialize()) == target)
}

/// Check a certificate over exactly the 64-hex `id` given, `hex(Q)`, at
/// `domain` (a note URL, a mint URL or a bare host). The primitive the other
/// checks here are built on; prefer [`check_note`] or
/// [`check_note_certificate`], which work out the id themselves.
///
/// `signature` is a `cs1`, which must state `amount_msat` in its
/// human-readable part as well as sign it. Returns the time it was signed
/// at, `t`, or `None` when it does not verify. Never panics.
pub fn verify_note_signature_hash(
    id: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey_hex: &str,
) -> Option<u32> {
    let id = id.trim();
    if !is_hex_id(id) {
        return None;
    }
    let cs1 = decode_cs1_with_amount(signature)?;
    // A cs1 must state the amount it signs: a payload moved under another
    // amount's prefix would otherwise verify while displaying an amount
    // nobody certified.
    if cs1.amount_msat != amount_msat {
        return None;
    }
    let digest = note_signature_digest_for_hash(id, domain, amount_msat, cs1.t)?;
    recovers_to(digest, &cs1.signature, mint_pubkey_hex).then_some(cs1.t)
}

/// Check a certificate for a note named without its spend, at `domain`: a
/// `cp1`, or a bearer note's 64-hex `h` (the two things that go where a
/// `cp1` goes). What a watcher, or a device that discloses only `h`, checks a
/// note by. Returns the time it was signed at, `t`, or `None`.
pub fn check_note_certificate(
    reference: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<u32> {
    let output_key = decode_note(reference)?;
    verify_note_signature_hash(
        &hex::encode(output_key),
        domain,
        amount_msat,
        signature,
        mint_pubkey,
    )
}

/// What an offline check of a note found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteCheck {
    /// The note, `Q`.
    pub output_key: [u8; 32],
    /// Whether the spend opens `Q` at the note's domain.
    pub spend: SpendVerdict,
    /// When the certificate was signed, Unix seconds. It attests the note
    /// was outstanding then, not that it still is: weigh its age.
    pub signed_at: u32,
}

impl NoteCheck {
    /// Issued by the key on record for this amount, and opened by the spend
    /// in hand under a scheme mints accept.
    pub fn is_verified(&self) -> bool {
        self.spend.opens()
    }
}

/// LUD-25's offline verification of a certified note: derive `Q` from the
/// spend, check the spend opens `Q` at `domain` (the note URL's own host, as
/// a note URL, a mint URL or a bare host), and check the certificate over
/// `domain`, `Q`, `amount_msat` and its `t` recovers to `mint_pubkey`. The
/// age of `t` is the caller's to weigh against its own policy.
///
/// `None` when `k1` is no spend or the certificate does not verify.
/// Otherwise [`NoteCheck::spend`] says what the spend did: a `ck1` signed for
/// another mint, or a `cw1` whose witness does not satisfy its leaf, comes
/// back [`SpendVerdict::Fails`] with its valid certificate, so a caller can
/// tell a forged spend from a forged certificate. Time claims are left to
/// the SERVICE's clock.
///
/// A certificate proves the note was outstanding at `t`, not that it still
/// is: the previous holder still knows the spend. Rotate on receipt.
pub fn check_note(
    k1: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<NoteCheck> {
    let spend = check_spend(k1, domain)?;
    let signed_at = verify_note_signature_hash(
        &hex::encode(spend.output_key),
        domain,
        amount_msat,
        signature,
        mint_pubkey,
    )?;
    Some(NoteCheck {
        output_key: spend.output_key,
        spend: spend.verdict,
        signed_at,
    })
}

/// [`check_note`] as a yes or no: the certificate verifies and the spend
/// opens the note, under any scheme a mint accepts. A `cw1` whose script
/// this crate does not evaluate is a no.
///
/// `domain` is required because a `ck1` means nothing without it: the
/// certificate alone is public, and anyone could pair it with a signature
/// that opens nothing.
pub fn verify_note_signature(
    k1: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> bool {
    check_note(k1, domain, amount_msat, signature, mint_pubkey)
        .is_some_and(|check| check.is_verified())
}
