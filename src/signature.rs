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
//! message = "LNURLcash:" || domain || ":" || amount_msat (decimal ASCII) || ":" || hex(Q)
//! digest  = sha256(sha256("Lightning Signed Message:" || message))
//! ```
//!
//! `domain` is the mint's lowercase hostname, the string the canonical spend
//! transaction commits to, so a certificate names the one mint on that domain
//! and never vouches for a note at another. `Q` is the note's taproot output
//! key, for every kind of note: a bearer note's `Q` is public too, so a
//! SERVICE can certify one without disclosing what spends it.
//!
//! Two older messages are still read, never written, since notes people hold
//! carry them: `hex(Q)` without the domain (before luds 92abbb3), reported as
//! [`CertifiedOver::LegacyOutputKey`], and a bearer note's hash `h` from
//! before notes were keyed by `Q`, reported as [`CertifiedOver::LegacyHash`].
//!
//! A certificate proves issuance, not that the spend in hand opens the note:
//! a `ck1` states its `Q` in plain sight, so anyone who has seen a note's
//! `cp1` and `cs1` can pair them with a signature that opens nothing.
//! [`check_note`] makes both checks, which is why it needs the mint's domain.

use k256::schnorr::{Signature as SchnorrSignature, SigningKey, VerifyingKey};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::Message;
use sha2::{Digest, Sha256};

use crate::recoverable::{decode_cs1, decode_cs1_with_amount, decode_cx1, encode_cx1, note_id_of};
use crate::spend::{check_spend, decode_note, decode_spend, spend_domain_of, SpendVerdict};

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
    let key = SigningKey::from_bytes(share_secret_key).map_err(|_| {
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
        VerifyingKey::from_bytes(&signer.pubkey_x_only()),
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
/// note URL, a mint URL or a bare host). `None` for a `k1` that is no spend
/// (see [`note_id_of`]) or a `domain` that names none.
pub fn note_signature_message(k1: &str, domain: &str, amount_msat: u64) -> Option<String> {
    note_signature_message_for_hash(&note_id_of(k1)?, domain, amount_msat)
}

/// The same message over a note id given directly, `hex(Q)`, used exactly
/// as given, lowercased. `None` for a `domain` that names none.
pub fn note_signature_message_for_hash(id: &str, domain: &str, amount_msat: u64) -> Option<String> {
    Some(format!(
        "{DOMAIN_TAG}:{}:{amount_msat}:{}",
        spend_domain_of(domain)?,
        id.trim().to_ascii_lowercase()
    ))
}

pub fn note_signature_digest(k1: &str, domain: &str, amount_msat: u64) -> Option<[u8; 32]> {
    note_signature_digest_for_hash(&note_id_of(k1)?, domain, amount_msat)
}

pub fn note_signature_digest_for_hash(
    id: &str,
    domain: &str,
    amount_msat: u64,
) -> Option<[u8; 32]> {
    note_signature_message_for_hash(id, domain, amount_msat)
        .map(|message| lightning_signed_digest(&message))
}

/// The superseded message without a domain, `LNURLcash:<amount>:<id>`, over
/// `hex(Q)` or a bearer note's `h`. Read, never written: a SERVICE MUST NOT
/// issue it any more.
pub fn legacy_note_signature_message_for_hash(id: &str, amount_msat: u64) -> String {
    format!(
        "{DOMAIN_TAG}:{amount_msat}:{}",
        id.trim().to_ascii_lowercase()
    )
}

pub fn legacy_note_signature_digest_for_hash(id: &str, amount_msat: u64) -> [u8; 32] {
    lightning_signed_digest(&legacy_note_signature_message_for_hash(id, amount_msat))
}

/// Which message a certificate verified over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedOver {
    /// `hex(Q)` at the note's domain: LUD-25's certificate, for any note.
    OutputKey,
    /// `hex(Q)` with no domain, as a SERVICE signed before luds 92abbb3. It
    /// still proves issuance of that note for that amount by that key, but
    /// not at which of the key's mints.
    LegacyOutputKey,
    /// A bearer note's hash `h`, as a SERVICE signed before notes were keyed
    /// by `Q`. It still proves issuance of that note for that amount.
    LegacyHash,
}

fn is_hex_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

// The signature bytes, from a cs1 that states `amount_msat`, or for a legacy
// message also from a fixed-HRP cs1 or raw hex. `lenient` admits a recovery
// id outside 0..=3, which only a certificate in the leading layout has.
fn certificate_bytes(signature: &str, amount_msat: u64, lenient: bool) -> Option<Vec<u8>> {
    let trimmed = signature.trim();
    if let Some(cs1) = decode_cs1_with_amount(trimmed) {
        // An amount-bearing cs1 must state the amount it signs: a payload
        // moved under another amount's prefix would otherwise verify while
        // displaying an amount nobody certified.
        return (cs1.amount_msat == amount_msat).then(|| cs1.signature.to_vec());
    }
    if !lenient {
        return None;
    }
    decode_any_cs1_bytes(trimmed)
        .or_else(|| hex::decode(trimmed).ok())
        .filter(|bytes| bytes.len() == 65)
}

// A cs1 of any amount or none, recovery id unchecked, for the legacy layouts.
fn decode_any_cs1_bytes(value: &str) -> Option<Vec<u8>> {
    if let Some(signature) = decode_cs1(value) {
        return Some(signature.to_vec());
    }
    let separator = value.rfind('1')?;
    let hrp = value[..separator].to_ascii_lowercase();
    hrp.strip_prefix("cs")?;
    crate::long_bech32::decode::<crate::long_bech32::Bech32m>(&hrp, value)
}

// Which end of the raw bytes carries the recovery id varies by
// implementation: LUD-25 calls for `r || s || recovery_id`, the layout raw
// BOLT-11 signatures use, while lnurl-mint once forwarded its node's
// signmessage output unreordered as `recovery_id || r || s`. A current
// certificate is only ever the first; the legacy messages try both, which
// costs nothing security-wise - recovering against the wrong one yields an
// unrelated pubkey that cannot match.
fn recovers_to(
    digest: [u8; 32],
    signature: &[u8],
    both_layouts: bool,
    mint_pubkey_hex: &str,
) -> bool {
    let message = Message::from_digest(digest);
    let target = mint_pubkey_hex.trim().to_ascii_lowercase();
    let trailing = (&signature[..64], signature[64]);
    let leading = (&signature[1..65], signature[0]);
    let layouts: &[(&[u8], u8)] = if both_layouts {
        &[trailing, leading]
    } else {
        &[trailing]
    };
    layouts.iter().any(|&(compact, recovery)| {
        let Ok(id) = RecoveryId::try_from(i32::from(recovery)) else {
            return false;
        };
        let Ok(sig) = RecoverableSignature::from_compact(compact, id) else {
            return false;
        };
        sig.recover_ecdsa(message)
            .is_ok_and(|recovered| hex::encode(recovered.serialize()) == target)
    })
}

/// Check a current certificate over exactly the 64-hex `id` given, `hex(Q)`,
/// at `domain` (a note URL, a mint URL or a bare host). The primitive the
/// other checks here are built on; prefer [`check_note`] or
/// [`check_note_certificate`], which work out the id themselves and fall back
/// to the legacy messages.
///
/// `signature` is an amount-bearing `cs1`, which must state `amount_msat` in
/// its human-readable part as well as sign it, with its recovery id last.
///
/// Never panics. An unverifiable signature is a `false`.
pub fn verify_note_signature_hash(
    id: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey_hex: &str,
) -> bool {
    let id = id.trim();
    if !is_hex_id(id) {
        return false;
    }
    let (Some(digest), Some(signature)) = (
        note_signature_digest_for_hash(id, domain, amount_msat),
        certificate_bytes(signature, amount_msat, false),
    ) else {
        return false;
    };
    recovers_to(digest, &signature, false, mint_pubkey_hex)
}

/// [`verify_note_signature_hash`] for the superseded message without a
/// domain, over `hex(Q)` or a bearer note's `h`. `signature` may also be raw
/// hex or a fixed-HRP `cs1`, in either recovery-id layout, as certificates
/// were issued then.
pub fn verify_legacy_note_signature_hash(
    id: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey_hex: &str,
) -> bool {
    let id = id.trim();
    if !is_hex_id(id) {
        return false;
    }
    let Some(signature) = certificate_bytes(signature, amount_msat, true) else {
        return false;
    };
    recovers_to(
        legacy_note_signature_digest_for_hash(id, amount_msat),
        &signature,
        true,
        mint_pubkey_hex,
    )
}

fn certified_over(
    output_key: &[u8; 32],
    bearer_hash: Option<[u8; 32]>,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<CertifiedOver> {
    let q = hex::encode(output_key);
    if verify_note_signature_hash(&q, domain, amount_msat, signature, mint_pubkey) {
        return Some(CertifiedOver::OutputKey);
    }
    if verify_legacy_note_signature_hash(&q, amount_msat, signature, mint_pubkey) {
        return Some(CertifiedOver::LegacyOutputKey);
    }
    bearer_hash
        .filter(|h| {
            verify_legacy_note_signature_hash(&hex::encode(h), amount_msat, signature, mint_pubkey)
        })
        .map(|_| CertifiedOver::LegacyHash)
}

/// Check a certificate for a note named without its spend, at `domain`: a
/// `cp1`, or a bearer note's 64-hex `h` (the two things that go where a
/// `cp1` goes). Tries `hex(Q)` at the domain first, then the legacy messages:
/// `hex(Q)` without one and, for a bearer `h`, the pre-taproot message over
/// `h` itself. What a watcher, or a device that discloses only `h`, checks a
/// note by. `None` if none verifies.
pub fn check_note_certificate(
    reference: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<CertifiedOver> {
    let output_key = decode_note(reference)?;
    let bearer_hash = crate::secrets::is_preimage(reference)
        .then(|| hex::decode(reference.trim()).ok()?.try_into().ok())
        .flatten();
    certified_over(
        &output_key,
        bearer_hash,
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
    /// Which message the certificate verified over.
    pub certificate: CertifiedOver,
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
/// `domain`, `Q` and `amount_msat` recovers to `mint_pubkey`.
///
/// `None` when `k1` is no spend or the certificate does not verify.
/// Otherwise [`NoteCheck::spend`] says what the spend did: a `ck1` signed for
/// another mint, or a `cw1` whose witness does not satisfy its leaf, comes
/// back [`SpendVerdict::Fails`] with its valid certificate, so a caller can
/// tell a forged spend from a forged certificate. Time claims are left to
/// the SERVICE's clock.
///
/// A certificate proves issuance, not that the note is still outstanding:
/// the previous holder still knows the spend. Rotate on receipt.
pub fn check_note(
    k1: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey: &str,
) -> Option<NoteCheck> {
    let spend = check_spend(k1, domain)?;
    let bearer_hash = decode_spend(k1)?.bearer_hash();
    let certificate = certified_over(
        &spend.output_key,
        bearer_hash,
        domain,
        amount_msat,
        signature,
        mint_pubkey,
    )?;
    Some(NoteCheck {
        output_key: spend.output_key,
        spend: spend.verdict,
        certificate,
    })
}

/// [`check_note`] as a yes or no: the certificate verifies, over either
/// message, and the spend opens the note, under any scheme a mint accepts.
/// A `cw1` whose script this crate does not evaluate is a no.
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
