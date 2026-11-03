//! The foreign-language surface, behind the `ffi` feature.
//!
//! Only the PURE half of this crate crosses the boundary: request building,
//! response parsing, signature verification, note URLs, fee arithmetic. HTTP
//! stays on the other side, where a mobile app already has a stack it trusts
//! and a concurrency model it likes.
//!
//! That is a deliberate line. Async over FFI is where these bindings usually
//! turn painful, and there is nothing to gain from it: the interesting part of
//! LNURLcash is not the GET, it is knowing what a response means and which
//! secrets must survive a failure. Both of those are pure functions.
//!
//! The flow on the Kotlin or Swift side is always the same:
//!
//! 1. build a request, keeping `newSecrets` somewhere durable FIRST
//! 2. GET `request.url` with your own client
//! 3. hand the response body back to the matching `parse` function, with the
//!    request's `newSecrets` and `outputs` for a mutation
//! 4. if the GET failed, or parsing says the outcome is unknown, the secrets
//!    you saved in step 1 may be the only copy of the money

use crate::errors::Error;
use crate::{
    bolt11, cash, errors, fees, note, protocol, recoverable, secrets, signature, spend, urls,
};

/// One GET, and the secrets whose loss would destroy money.
#[derive(Debug, uniffi::Record)]
pub struct FfiRequest {
    pub url: String,
    /// Fresh preimages this request disclosed the hashes of. Persist these
    /// BEFORE performing the GET: if the answer is lost, they may be the only
    /// copies of notes the service has already minted.
    pub new_secrets: Vec<String>,
    /// The outputs a rotate, split or merge named, exactly as sent:
    /// `[output]` for a rotate or merge, `[output, change]` for a split, and
    /// empty for every other request. Hand them to [`parse_mutation`] with
    /// the response: a `cp1` output is owed a certificate whatever the
    /// policy, and this is how the parser knows which it asked for. Not
    /// secret.
    pub outputs: Vec<String>,
}

impl From<protocol::Request> for FfiRequest {
    fn from(request: protocol::Request) -> Self {
        FfiRequest {
            url: request.url,
            new_secrets: request.new_secrets,
            outputs: request.outputs,
        }
    }
}

/// What the parsers insist a service does, as [`protocol::Policy`]. The
/// defaults are the spec's: build one with no arguments unless you mean to
/// change something.
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct FfiPolicy {
    /// Demand a certificate for a bearer output named by its hash too. Off by
    /// default to admit a mint running without a signer. A `cp1` output is
    /// owed its `cs1` certificate whatever this says.
    #[uniffi(default = false)]
    pub require_signatures: bool,
    /// Refuse a withdrawRequest that publishes no valid `mintPubkey`. On by
    /// default; off only for a service that publishes none.
    #[uniffi(default = true)]
    pub require_mint_pubkey: bool,
}

impl Default for FfiPolicy {
    fn default() -> Self {
        protocol::Policy::default().into()
    }
}

impl From<protocol::Policy> for FfiPolicy {
    fn from(policy: protocol::Policy) -> Self {
        FfiPolicy {
            require_signatures: policy.require_signatures,
            require_mint_pubkey: policy.require_mint_pubkey,
        }
    }
}

impl From<FfiPolicy> for protocol::Policy {
    fn from(policy: FfiPolicy) -> Self {
        protocol::Policy {
            require_signatures: policy.require_signatures,
            require_mint_pubkey: policy.require_mint_pubkey,
        }
    }
}

/// The error taxonomy, flattened for the bindings. The distinction that matters
/// is the same one it is in Rust: [`LnurlcashError::Ambiguous`] means the
/// request MAY have been processed, and nothing may be assumed.
#[derive(Debug, uniffi::Error)]
pub enum LnurlcashError {
    /// Nothing was sent. The note is untouched.
    RequestRefused { detail: String },
    /// A non-mutating response did not match the spec.
    Protocol { detail: String },
    /// The service processed the request and refused it. Definitive.
    ServiceRejected { reason: String },
    /// A melt is in flight on this k1. Retry - never read this as spent.
    NotePending,
    /// Authoritative: the note is already burned.
    NoteSpent {
        reason: String,
        new_secrets: Vec<String>,
    },
    /// The service does not recognise this note.
    NoteUnknown {
        reason: String,
        new_secrets: Vec<String>,
    },
    /// The outcome is UNKNOWN. Preserve any secrets the request carried.
    Ambiguous {
        detail: String,
        new_secrets: Vec<String>,
    },

    /// The mutation LANDED and the SERVICE returned no certificate for a
    /// `cp1` output - or none for a bearer output when the policy asked for
    /// one. The note exists, and `new_secrets` is the only key to it. Persist
    /// them before deciding anything else. Empty when the caller named the
    /// output: this library never saw what stands behind it.
    Unverifiable {
        detail: String,
        new_secrets: Vec<String>,
    },
}

impl std::fmt::Display for LnurlcashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LnurlcashError::RequestRefused { detail } | LnurlcashError::Protocol { detail } => {
                write!(f, "{detail}")
            }
            LnurlcashError::ServiceRejected { reason }
            | LnurlcashError::NoteSpent { reason, .. }
            | LnurlcashError::NoteUnknown { reason, .. } => write!(f, "{reason}"),
            LnurlcashError::NotePending => write!(f, "pending"),
            LnurlcashError::Ambiguous { detail, .. }
            | LnurlcashError::Unverifiable { detail, .. } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for LnurlcashError {}

impl From<Error> for LnurlcashError {
    fn from(err: Error) -> Self {
        match err {
            Error::RequestRefused(detail) => LnurlcashError::RequestRefused { detail },
            Error::Protocol(detail) => LnurlcashError::Protocol { detail },
            Error::ServiceRejected(reason) => LnurlcashError::ServiceRejected { reason },
            Error::NotePending => LnurlcashError::NotePending,
            Error::NoteSpent {
                reason,
                new_secrets,
            } => LnurlcashError::NoteSpent {
                reason,
                new_secrets,
            },
            Error::NoteUnknown {
                reason,
                new_secrets,
            } => LnurlcashError::NoteUnknown {
                reason,
                new_secrets,
            },
            Error::Ambiguous {
                message,
                new_secrets,
            } => LnurlcashError::Ambiguous {
                detail: message,
                new_secrets,
            },
            Error::Unverifiable {
                message,
                new_secrets,
            } => LnurlcashError::Unverifiable {
                detail: message,
                new_secrets,
            },
        }
    }
}

type FfiResult<T> = Result<T, LnurlcashError>;

fn parse_body(body: &str) -> FfiResult<serde_json::Value> {
    // An unreadable body from a mutating call is ambiguous, not a failure: the
    // service may have applied the mutation and merely failed to say so. The
    // caller re-attaches the secrets it is holding.
    serde_json::from_str(body).map_err(|_| LnurlcashError::Ambiguous {
        detail: "the service returned an unreadable response".into(),
        new_secrets: Vec::new(),
    })
}

// ---- records ----

#[derive(Debug, uniffi::Record)]
pub struct FfiWithdrawInfo {
    pub callback: String,
    pub k1: String,
    /// The ONLY authoritative statement of what this note is worth. The
    /// `amount` in a note URL is an unverified claim.
    pub max_withdrawable: u64,
    pub min_withdrawable: u64,
    pub default_description: Option<String>,
    pub mint_pubkey: Option<String>,
    /// `c`: the service's `cs1` for the queried note, as sent and
    /// unverified. Check it with [`check_note`].
    pub signature: Option<String>,
}

/// What a `?p=` lookup returns: the same, with no `k1`, since the request
/// named the note without its spend.
#[derive(Debug, uniffi::Record)]
pub struct FfiNoteInfoByHash {
    pub callback: String,
    pub max_withdrawable: u64,
    pub min_withdrawable: u64,
    pub default_description: Option<String>,
    pub mint_pubkey: Option<String>,
    /// `c`, as sent and unverified. Check it with
    /// [`check_note_certificate`] against what was looked up.
    pub signature: Option<String>,
}

#[derive(Debug, uniffi::Record)]
pub struct FfiMintAddress {
    pub callback: String,
    pub pay_link: String,
    pub max_withdrawable: u64,
    pub min_withdrawable: u64,
    pub node_pubkey: Option<String>,
    pub node_alias: Option<String>,
    pub node_uri: Option<String>,
    pub node_color: Option<String>,
    pub node_capacity_msat: Option<u64>,
    pub node_num_channels: Option<u64>,
    pub node_num_peers: Option<u64>,
    pub node_uris: Option<Vec<String>>,
    pub sunset_date: Option<String>,
    pub outstanding_notes_msat: Option<u64>,
}

#[derive(Debug, uniffi::Record)]
pub struct FfiMintFee {
    pub base_fee_msat: u64,
    pub fee_ppm: u64,
    /// LUD-26's fee per Lightning Address registration. Null when not
    /// advertised: refuse to pay a registration invoice then.
    pub address_fee_msat: Option<u64>,
}

#[derive(Debug, uniffi::Record)]
pub struct FfiPayRequest {
    pub callback: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub metadata: String,
    pub withdraw_link: Option<String>,
    pub mint_pubkey: Option<String>,
    pub mint_fee: Option<FfiMintFee>,
    /// LUD-12's field, and LUD-25's minting capability: a mint must allow the
    /// 64 characters the output commitment needs.
    pub comment_allowed: Option<u64>,
    /// Additive ForgeSworn extension, never a substitute for the comment.
    pub mint_to_hash: bool,
    /// Whether this SERVICE can mint a current-draft note at all.
    pub names_mint_output: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct FfiInvoice {
    pub pr: String,
    pub verify: Option<String>,
    pub disposable: bool,
}

#[derive(Debug, uniffi::Record)]
pub struct FfiVerify {
    pub settled: bool,
    /// Settlement proof, not the note. Current LUD-25 binds a note to a
    /// wallet-chosen secret named in the mint comment, so a preimage here
    /// redeems nothing.
    pub preimage: Option<String>,
    pub pr: String,
}

/// Which mutation a response is being read as. A melt mints nothing and so
/// owes nothing; a split mints two notes, and each is owed what its kind is
/// owed.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiMutationKind {
    Melt,
    Rotate,
    Split,
    Merge,
}

impl From<FfiMutationKind> for protocol::MutationKind {
    fn from(kind: FfiMutationKind) -> Self {
        match kind {
            FfiMutationKind::Melt => protocol::MutationKind::Melt,
            FfiMutationKind::Rotate => protocol::MutationKind::Rotate,
            FfiMutationKind::Split => protocol::MutationKind::Split,
            FfiMutationKind::Merge => protocol::MutationKind::Merge,
        }
    }
}

#[derive(Debug, uniffi::Record)]
pub struct FfiMutation {
    /// The `cs1` for the first output. Always present for a `cp1` output; for
    /// a bearer output named by its hash, null from a mint with no signer.
    pub signature: Option<String>,
    /// The same for a split's change.
    pub change_signature: Option<String>,
    pub pr: Option<String>,
    pub verify: Option<String>,
}

// ---- secrets and signatures ----

/// A fresh 32-byte note secret from the OS CSPRNG. The WALLET generates these,
/// never the service.
#[uniffi::export]
pub fn generate_note_secret() -> String {
    secrets::generate_note_secret()
}

/// A bearer note's hash `h = sha256(preimage)`: its `cp1` short form, what a
/// mutation discloses as `p1`/`p2`. Not the note's id, which is `hex(Q)`
/// (see [`note_id_of`]).
#[uniffi::export]
pub fn hash_k1(k1: &str) -> FfiResult<String> {
    secrets::hash_k1(k1).map_err(Into::into)
}

#[uniffi::export]
pub fn is_preimage(value: &str) -> bool {
    secrets::is_preimage(value)
}

/// Which message a certificate verified over.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiCertifiedOver {
    /// `hex(Q)` at the note's domain, LUD-25's certificate for any note.
    OutputKey,
    /// `hex(Q)` without a domain, as a mint signed before luds 92abbb3.
    LegacyOutputKey,
    /// A bearer note's hash, as a mint signed before notes were keyed by `Q`.
    LegacyHash,
}

impl From<signature::CertifiedOver> for FfiCertifiedOver {
    fn from(over: signature::CertifiedOver) -> Self {
        match over {
            signature::CertifiedOver::OutputKey => FfiCertifiedOver::OutputKey,
            signature::CertifiedOver::LegacyOutputKey => FfiCertifiedOver::LegacyOutputKey,
            signature::CertifiedOver::LegacyHash => FfiCertifiedOver::LegacyHash,
        }
    }
}

/// Whether a spend opens its note.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiSpendVerdict {
    /// Under LUD-25's current rules.
    Opens,
    /// Only under a deprecated `ck1` scheme a mint still accepts: rotate it.
    OpensLegacy,
    /// A script path whose script this library does not evaluate. The mint
    /// decides.
    Unevaluated,
    /// It does not open the note.
    Fails { reason: String },
}

impl From<spend::SpendVerdict> for FfiSpendVerdict {
    fn from(verdict: spend::SpendVerdict) -> Self {
        match verdict {
            spend::SpendVerdict::Opens => FfiSpendVerdict::Opens,
            spend::SpendVerdict::OpensLegacy => FfiSpendVerdict::OpensLegacy,
            spend::SpendVerdict::Unevaluated => FfiSpendVerdict::Unevaluated,
            spend::SpendVerdict::Fails(reason) => FfiSpendVerdict::Fails { reason },
        }
    }
}

/// A spend's note, `hex(Q)`, and whether the spend opens it.
#[derive(Debug, uniffi::Record)]
pub struct FfiSpendCheck {
    pub output_key: String,
    pub verdict: FfiSpendVerdict,
}

/// What an offline check of a certified note found.
#[derive(Debug, uniffi::Record)]
pub struct FfiNoteCheck {
    /// The note, `hex(Q)`.
    pub output_key: String,
    pub spend: FfiSpendVerdict,
    pub certificate: FfiCertifiedOver,
    /// Certified, and opened by the spend under a scheme mints accept.
    pub verified: bool,
}

impl From<signature::NoteCheck> for FfiNoteCheck {
    fn from(check: signature::NoteCheck) -> Self {
        FfiNoteCheck {
            output_key: hex::encode(check.output_key),
            verified: check.is_verified(),
            spend: check.spend.into(),
            certificate: check.certificate.into(),
        }
    }
}

/// LUD-25's offline verification as a yes or no: the certificate covers the
/// note `k1` spends at `domain` (the note URL, or its host) and
/// `amount_msat`, recovering to `mint_pubkey_hex`, and the spend opens the
/// note there. A certificate over a superseded message still counts; see
/// [`check_note`] for which one it was.
///
/// `k1` is a 64-hex preimage, a `ck1` or a `cw1`; `signature` a `cs1` or 65
/// bytes of hex.
#[uniffi::export]
pub fn verify_note_signature(
    k1: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey_hex: &str,
) -> bool {
    signature::verify_note_signature(k1, domain, amount_msat, signature, mint_pubkey_hex)
}

/// The same check, reporting which certificate message verified and what the
/// spend did. Null when `k1` is no spend or the certificate does not verify.
#[uniffi::export]
pub fn check_note(
    k1: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey_hex: &str,
) -> Option<FfiNoteCheck> {
    signature::check_note(k1, domain, amount_msat, signature, mint_pubkey_hex).map(Into::into)
}

/// [`check_note`] from a certified note URL, `...?k1=<spend>&c=<cs1>`, with
/// the domain, spend, certificate and declared amount all read off it.
#[uniffi::export]
pub fn check_note_url(url: &str, mint_pubkey_hex: &str) -> Option<FfiNoteCheck> {
    note::check_note_url(url, mint_pubkey_hex).map(Into::into)
}

/// A certificate for a note named without its spend, at `domain`: a `cp1`,
/// or a bearer note's 64-hex hash. Falls back to the superseded messages,
/// reported as legacy. Null if none verifies.
#[uniffi::export]
pub fn check_note_certificate(
    reference: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey_hex: &str,
) -> Option<FfiCertifiedOver> {
    signature::check_note_certificate(reference, domain, amount_msat, signature, mint_pubkey_hex)
        .map(Into::into)
}

/// The raw current certificate check over exactly the 64-hex `hex(Q)` given,
/// at `domain`. Prefer [`check_note`] or [`check_note_certificate`], which
/// work the id out themselves.
#[uniffi::export]
pub fn verify_note_signature_hash(
    id: &str,
    domain: &str,
    amount_msat: u64,
    signature: &str,
    mint_pubkey_hex: &str,
) -> bool {
    signature::verify_note_signature_hash(id, domain, amount_msat, signature, mint_pubkey_hex)
}

/// The message a SERVICE certifies for `hex(Q)` at `domain`. Null for a
/// domain that names none.
#[uniffi::export]
pub fn note_signature_message_for_hash(id: &str, domain: &str, amount_msat: u64) -> Option<String> {
    signature::note_signature_message_for_hash(id, domain, amount_msat)
}

// ---- spends ----
//
// Every note is a taproot output key `Q`. Keys, scripts and control blocks
// cross as hex; a domain is a note URL, a mint URL or a bare host except
// where it is marked as the exact string.

/// The domain a spend at `value` (a note or mint URL, or a bare host) is
/// bound to: its lowercase hostname, never the scheme or port.
#[uniffi::export]
pub fn spend_domain_of(value: &str) -> Option<String> {
    spend::spend_domain_of(value)
}

/// Does the spend in `k1` open its note at `domain`, as the mint would
/// judge it? Null if `k1` is no spend. Time claims are the mint's to judge.
#[uniffi::export]
pub fn check_spend(k1: &str, domain: &str) -> Option<FfiSpendCheck> {
    spend::check_spend(k1, domain).map(|check| FfiSpendCheck {
        output_key: hex::encode(check.output_key),
        verdict: check.verdict.into(),
    })
}

/// `hex(Q)` of what goes where a `cp1` goes: a `cp1` whose key is a point, or
/// a bearer note's 64-hex hash.
#[uniffi::export]
pub fn decode_note(value: &str) -> Option<String> {
    spend::decode_note(value).map(hex::encode)
}

#[uniffi::export]
pub fn is_x_only_point(value_hex: &str) -> bool {
    hex::decode(value_hex.trim()).is_ok_and(|bytes| spend::is_x_only_point(&bytes))
}

/// What a `ck1`'s signature signs: the key-path sighash for `Q` at the exact
/// `domain` string given (lowercased), as hex.
#[uniffi::export]
pub fn key_path_sighash(output_key_hex: &str, domain: &str) -> FfiResult<String> {
    Ok(hex::encode(spend::key_path_sighash(
        &hex_array(output_key_hex, "an output key")?,
        domain,
    )))
}

/// What a `SIGHASH_DEFAULT` signature in a `cw1`'s leaf signs, at the exact
/// `domain` string given (lowercased), for the time the spend claims.
#[uniffi::export]
pub fn script_path_sighash(
    output_key_hex: &str,
    domain: &str,
    leaf_script_hex: &str,
    locktime: u32,
    sequence: u32,
) -> FfiResult<String> {
    let leaf = hex::decode(leaf_script_hex.trim())
        .map_err(|_| errors::Error::Protocol("a leaf script must be hex".into()))?;
    Ok(hex::encode(spend::script_path_sighash(
        &hex_array(output_key_hex, "an output key")?,
        domain,
        &leaf,
        locktime,
        sequence,
    )))
}

#[uniffi::export]
pub fn tapleaf_hash(script_hex: &str, leaf_version: u8) -> FfiResult<String> {
    let script = hex::decode(script_hex.trim())
        .map_err(|_| errors::Error::Protocol("a leaf script must be hex".into()))?;
    Ok(hex::encode(spend::tapleaf_hash(&script, leaf_version)))
}

#[uniffi::export]
pub fn tapbranch_hash(a_hex: &str, b_hex: &str) -> FfiResult<String> {
    Ok(hex::encode(spend::tapbranch_hash(
        &hex_array(a_hex, "a tree node")?,
        &hex_array(b_hex, "a tree node")?,
    )))
}

/// A tweaked output key and its parity, 0 or 1.
#[derive(Debug, uniffi::Record)]
pub struct FfiTaprootTweak {
    pub output_key: String,
    pub parity: u8,
}

/// `Q` for an internal key and a script tree's merkle root.
#[uniffi::export]
pub fn taproot_tweak(internal_key_hex: &str, merkle_root_hex: &str) -> FfiResult<FfiTaprootTweak> {
    let tweaked = spend::taproot_tweak(
        &hex_array(internal_key_hex, "an internal key")?,
        &hex_array(merkle_root_hex, "a merkle root")?,
    )
    .ok_or_else(|| errors::Error::Protocol("that key and tree tweak to no usable key".into()))?;
    Ok(FfiTaprootTweak {
        output_key: hex::encode(tweaked.output_key),
        parity: tweaked.parity,
    })
}

/// The secret key that signs for [`taproot_tweak`]'s `Q`. Bearer material.
#[uniffi::export]
pub fn taproot_tweak_secret_key(secret_key_hex: &str, merkle_root_hex: &str) -> FfiResult<String> {
    Ok(hex::encode(spend::taproot_tweak_secret_key(
        &hex_array(secret_key_hex, "an internal secret key")?,
        &hex_array(merkle_root_hex, "a merkle root")?,
    )?))
}

/// The `Q` a leaf and its control block commit to. Null for a control block
/// that commits to none.
#[uniffi::export]
pub fn output_key_of(script_hex: &str, control_block_hex: &str) -> Option<String> {
    let script = hex::decode(script_hex.trim()).ok()?;
    let control_block = hex::decode(control_block_hex.trim()).ok()?;
    spend::output_key_of(&script, &control_block).map(hex::encode)
}

/// A bearer note, as hex.
#[derive(Debug, uniffi::Record)]
pub struct FfiBearerNote {
    pub output_key: String,
    pub control_block: String,
    pub leaf: String,
}

/// The bearer note a 32-byte hash `h` names.
#[uniffi::export]
pub fn bearer_note(h_hex: &str) -> FfiResult<FfiBearerNote> {
    let note = spend::bearer_note(&hex_array(h_hex, "a bearer note hash")?)
        .ok_or_else(|| errors::Error::Protocol("that hash tweaks to no usable key".into()))?;
    Ok(FfiBearerNote {
        output_key: hex::encode(note.output_key),
        control_block: hex::encode(note.control_block),
        leaf: hex::encode(note.leaf),
    })
}

/// A bearer note's full `cw1` for this preimage: the spend its 64-hex short
/// form stands for. Bearer material.
#[uniffi::export]
pub fn bearer_cw1(preimage_hex: &str) -> FfiResult<String> {
    let preimage = hex::decode(preimage_hex.trim())
        .map_err(|_| errors::Error::Protocol("a preimage must be hex".into()))?;
    let cw1 = spend::bearer_cw1(&preimage)
        .ok_or_else(|| errors::Error::Protocol("that preimage tweaks to no usable key".into()))?;
    Ok(recoverable::encode_cw1(&cw1)?)
}

/// A script-path spend, every byte string as hex.
#[derive(Debug, uniffi::Record)]
pub struct FfiCw1 {
    pub locktime: u32,
    pub sequence: u32,
    pub script: String,
    pub control_block: String,
    /// Bottom of the stack first.
    pub witness: Vec<String>,
}

#[uniffi::export]
pub fn encode_cw1(cw1: FfiCw1) -> FfiResult<String> {
    let bytes = |value: &str, what: &str| {
        hex::decode(value.trim())
            .map_err(|_| errors::Error::Protocol(format!("{what} must be hex")))
    };
    Ok(recoverable::encode_cw1(&recoverable::Cw1 {
        locktime: cw1.locktime,
        sequence: cw1.sequence,
        script: bytes(&cw1.script, "a leaf script")?,
        control_block: bytes(&cw1.control_block, "a control block")?,
        witness: cw1
            .witness
            .iter()
            .map(|item| bytes(item, "a witness item"))
            .collect::<Result<_, _>>()?,
    })?)
}

/// Null unless the payload parses exactly and its control block commits to
/// a key.
#[uniffi::export]
pub fn decode_cw1(value: &str) -> Option<FfiCw1> {
    recoverable::decode_cw1(value).map(|cw1| FfiCw1 {
        locktime: cw1.locktime,
        sequence: cw1.sequence,
        script: hex::encode(cw1.script),
        control_block: hex::encode(cw1.control_block),
        witness: cw1.witness.iter().map(hex::encode).collect(),
    })
}

#[uniffi::export]
pub fn is_cw1(value: &str) -> bool {
    recoverable::is_cw1(value)
}

/// Why a mint refuses this leaf (an unknown leaf version, or an `OP_SUCCESS`
/// opcode outside pushed data), or null if it does not.
#[uniffi::export]
pub fn check_leaf(leaf_version: u8, script_hex: &str) -> FfiResult<Option<String>> {
    let script = hex::decode(script_hex.trim())
        .map_err(|_| errors::Error::Protocol("a leaf script must be hex".into()))?;
    Ok(spend::check_leaf(leaf_version, &script).map(str::to_string))
}

/// Whether a script path's time claim is due by a mint's clock, in Unix
/// seconds: null if it is, or why not. `locked_at` is when the mint credited
/// the note.
#[uniffi::export]
pub fn check_time_claim(locktime: u32, sequence: u32, now: u64, locked_at: u64) -> Option<String> {
    spend::check_time_claim(locktime, sequence, now, locked_at)
}

// ---- seed-recoverable note secrets ----
//
// Nodes cross this boundary as 64 bytes of hex - privateKey || chainCode - so
// a binding never has to model a BIP-32 key, and so the value a caller
// persists is the value it passes back. That hex IS bearer material for every
// note beneath it: store it the way the notes are stored, and never log it.

/// `m/139'` from a seed, as a 64-byte hex node. `seed_hex` is raw seed bytes;
/// a 64-byte BIP39 seed is the interop case.
#[uniffi::export]
pub fn derive_cash_root(seed_hex: &str) -> FfiResult<String> {
    let seed = hex::decode(seed_hex.trim())
        .map_err(|_| errors::Error::Protocol("a seed must be hex".into()))?;
    Ok(cash::cash_node_to_hex(&cash::derive_cash_root(&seed)?))
}

/// `m/139'/d1/d2/d3/d4` over `host` exactly as given, port included, as a
/// 64-byte hex node. LUD-26's root is [`derive_service_root`], which drops
/// the port first; for a host without one they are the same node. Bearer
/// material for one mint's subtree, not the wallet.
#[uniffi::export]
pub fn derive_cash_domain_node(root_hex: &str, host: &str) -> FfiResult<String> {
    let root = cash::cash_node_from_hex(root_hex)?;
    Ok(cash::cash_node_to_hex(&cash::derive_cash_domain_node(
        &root, host,
    )?))
}

/// The four raw uint32 levels a mint's subtree hangs off. Exposed for a wallet
/// diagnosing a restore that finds nothing.
#[uniffi::export]
pub fn cash_domain_indices(root_hex: &str, host: &str) -> FfiResult<Vec<u32>> {
    let root = cash::cash_node_from_hex(root_hex)?;
    Ok(cash::cash_domain_indices(&root, host)?.to_vec())
}

/// The BIP-32 master node of a seed, for walking a path this crate does not
/// name.
#[uniffi::export]
pub fn derive_cash_master(seed_hex: &str) -> FfiResult<String> {
    let seed = hex::decode(seed_hex.trim())
        .map_err(|_| errors::Error::Protocol("a seed must be hex".into()))?;
    Ok(cash::cash_node_to_hex(&cash::derive_cash_master(&seed)?))
}

/// One BIP-32 CKDpriv step, hardened when `index >= 2^31` and only then.
#[uniffi::export]
pub fn derive_cash_child(node_hex: &str, index: u32) -> FfiResult<String> {
    let node = cash::cash_node_from_hex(node_hex)?;
    Ok(cash::cash_node_to_hex(&cash::derive_cash_child(
        &node, index,
    )?))
}

/// The LEGACY scheme's root, for finding notes minted before LUD-25 specified
/// a derivation. Do not mint under it.
#[uniffi::export]
pub fn derive_note_root(seed_hex: &str) -> FfiResult<String> {
    let seed = hex::decode(seed_hex.trim())
        .map_err(|_| errors::Error::Protocol("a seed must be hex".into()))?;
    Ok(hex::encode(secrets::derive_note_root(&seed)))
}

/// The LEGACY scheme's i-th secret at `host`. Do not mint under it.
#[uniffi::export]
pub fn derive_note_secret(root_hex: &str, host: &str, index: u32) -> FfiResult<String> {
    let bytes = hex::decode(root_hex.trim())
        .map_err(|_| errors::Error::Protocol("a root must be hex".into()))?;
    if bytes.len() != 32 {
        return Err(errors::Error::Protocol("a legacy root is 32 bytes".into()).into());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Ok(secrets::derive_note_secret(&root, host, index))
}

// ---- key-path notes and the bech32m strings ----
//
// Raw bytes cross as hex, as everywhere else here, and the bech32m strings as
// themselves. A note secret key, a `ck1`, a `cw1`, a SERVICE root, a share
// node and a Nostr cash seed are all bearer material: store them the way the
// notes are stored, and never log them. A `cx1` spends nothing, but links
// every note on its share.

fn hex_array<const N: usize>(value: &str, what: &str) -> FfiResult<[u8; N]> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| errors::Error::Protocol(format!("{what} must be hex")))?;
    let length = bytes.len();
    bytes
        .try_into()
        .map_err(|_| errors::Error::Protocol(format!("{what} is {N} bytes, not {length}")).into())
}

/// A share's xpub, both halves as hex.
#[derive(Debug, uniffi::Record)]
pub struct FfiCx1 {
    pub chain_code: String,
    /// Compressed, 33 bytes.
    pub pubkey: String,
}

impl From<recoverable::Cx1> for FfiCx1 {
    fn from(cx1: recoverable::Cx1) -> Self {
        FfiCx1 {
            chain_code: hex::encode(cx1.chain_code),
            pubkey: hex::encode(cx1.pubkey),
        }
    }
}

/// An amount-bearing mint certificate, with its signature bytes as hex.
#[derive(Debug, uniffi::Record)]
pub struct FfiCs1 {
    pub amount_msat: u64,
    pub signature: String,
}

impl From<recoverable::Cs1> for FfiCs1 {
    fn from(cs1: recoverable::Cs1) -> Self {
        FfiCs1 {
            amount_msat: cs1.amount_msat,
            signature: hex::encode(cs1.signature),
        }
    }
}

/// A note's 32-byte output key `Q` as a `cp1`.
#[uniffi::export]
pub fn encode_cp1(pubkey_x_only_hex: &str) -> FfiResult<String> {
    Ok(recoverable::encode_cp1(&hex_array(
        pubkey_x_only_hex,
        "a note pubkey",
    )?))
}

/// Null for a `cp1` whose key is not a curve point: no spend opens it.
#[uniffi::export]
pub fn decode_cp1(value: &str) -> Option<String> {
    recoverable::decode_cp1(value).map(hex::encode)
}

#[uniffi::export]
pub fn is_cp1(value: &str) -> bool {
    recoverable::is_cp1(value)
}

/// A 96-byte `Q || sig` key-path spend as a `ck1`.
#[uniffi::export]
pub fn encode_ck1(signature_hex: &str) -> FfiResult<String> {
    Ok(recoverable::encode_ck1(&hex_array(
        signature_hex,
        "an ownership payload",
    )?))
}

#[uniffi::export]
pub fn decode_ck1(value: &str) -> Option<String> {
    recoverable::decode_ck1(value).map(|decoded| hex::encode(decoded.as_bytes()))
}

#[uniffi::export]
pub fn is_ck1(value: &str) -> bool {
    recoverable::is_ck1(value)
}

/// A legacy fixed-HRP mint certificate. New code should use
/// [`encode_cs1_with_amount`].
#[uniffi::export]
pub fn encode_cs1(signature_hex: &str) -> FfiResult<String> {
    Ok(recoverable::encode_cs1(&hex_array(
        signature_hex,
        "a certificate",
    )?))
}

#[uniffi::export]
pub fn decode_cs1(value: &str) -> Option<String> {
    recoverable::decode_cs1(value).map(hex::encode)
}

#[uniffi::export]
pub fn is_cs1(value: &str) -> bool {
    recoverable::is_cs1(value)
}

/// A current amount-bearing mint certificate.
#[uniffi::export]
pub fn encode_cs1_with_amount(amount_msat: u64, signature_hex: &str) -> FfiResult<String> {
    Ok(recoverable::encode_cs1_with_amount(
        amount_msat,
        &hex_array(signature_hex, "a certificate")?,
    ))
}

#[uniffi::export]
pub fn decode_cs1_with_amount(value: &str) -> Option<FfiCs1> {
    recoverable::decode_cs1_with_amount(value).map(Into::into)
}

#[uniffi::export]
pub fn is_cs1_with_amount(value: &str) -> bool {
    recoverable::is_cs1_with_amount(value)
}

#[uniffi::export]
pub fn decode_any_cs1(value: &str) -> Option<String> {
    recoverable::decode_any_cs1(value).map(hex::encode)
}

#[uniffi::export]
pub fn is_any_cs1(value: &str) -> bool {
    recoverable::is_any_cs1(value)
}

#[uniffi::export]
pub fn encode_cx1(chain_code_hex: &str, pubkey_hex: &str) -> FfiResult<String> {
    let cx1 = recoverable::Cx1 {
        chain_code: hex_array(chain_code_hex, "a chain code")?,
        pubkey: hex_array(pubkey_hex, "a compressed pubkey")?,
    };
    // round-tripped, so a pubkey that is no point is refused here
    recoverable::decode_cx1(&recoverable::encode_cx1(&cx1))
        .map(|cx1| recoverable::encode_cx1(&cx1))
        .ok_or_else(|| errors::Error::Protocol("not a compressed secp256k1 point".into()).into())
}

/// Null for anything but a 65-byte `chainCode || P`, P a curve point.
#[uniffi::export]
pub fn decode_cx1(value: &str) -> Option<FfiCx1> {
    recoverable::decode_cx1(value).map(Into::into)
}

#[uniffi::export]
pub fn is_cx1(value: &str) -> bool {
    recoverable::is_cx1(value)
}

/// Where a note sits below a SERVICE's root (LUD-26).
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiNotePath {
    Wallet {
        account: u32,
        index: u32,
    },
    Change {
        account: u32,
        index: u32,
    },
    Share {
        account: u32,
        share: u32,
        index: u32,
    },
}

impl From<FfiNotePath> for recoverable::NotePath {
    fn from(path: FfiNotePath) -> Self {
        match path {
            FfiNotePath::Wallet { account, index } => Self::Wallet { account, index },
            FfiNotePath::Change { account, index } => Self::Change { account, index },
            FfiNotePath::Share {
                account,
                share,
                index,
            } => Self::Share {
                account,
                share,
                index,
            },
        }
    }
}

/// A note's keys, as hex. The secret key is bearer material.
#[derive(Debug, uniffi::Record)]
pub struct FfiNoteKey {
    pub secret_key: String,
    /// Compressed, so its y parity is visible.
    pub pubkey: String,
    /// `Q`, the note.
    pub output_key: String,
}

/// `S = m/139'/d1/d2/d3/d4` for one mint, from the wallet's `m/139'` root,
/// as a 64-byte hex node. `domain` may be any URL or host; its port is
/// dropped. Bearer material for every note the wallet holds there.
#[uniffi::export]
pub fn derive_service_root(root_hex: &str, domain: &str) -> FfiResult<String> {
    let root = cash::cash_node_from_hex(root_hex)?;
    Ok(cash::cash_node_to_hex(&cash::derive_service_root(
        &root, domain,
    )?))
}

/// The note at `path` below a SERVICE root.
#[uniffi::export]
pub fn derive_note_key(service_root_hex: &str, path: FfiNotePath) -> FfiResult<FfiNoteKey> {
    let root = cash::cash_node_from_hex(service_root_hex)?;
    let key = recoverable::derive_note_key(&root, path.into())?;
    Ok(FfiNoteKey {
        secret_key: hex::encode(key.secret_key),
        pubkey: hex::encode(key.pubkey),
        output_key: hex::encode(key.output_key),
    })
}

/// `S/account'/2/share'` as a 64-byte hex node. Bearer material: hand out
/// its [`cash_node_to_cx1`], and sign its registration with its key.
#[uniffi::export]
pub fn derive_share_node(service_root_hex: &str, account: u32, share: u32) -> FfiResult<String> {
    let root = cash::cash_node_from_hex(service_root_hex)?;
    Ok(cash::cash_node_to_hex(&recoverable::derive_share_node(
        &root, account, share,
    )?))
}

/// `Q` of note `index` on the share a `cx1` exports, by CKDpub: what a
/// SERVICE credits next. An unusable index is an error: use the next one.
#[uniffi::export]
pub fn derive_note_pubkey(cx1: &str, index: u32) -> FfiResult<String> {
    let cx1 = recoverable::decode_cx1(cx1)
        .ok_or_else(|| errors::Error::Protocol("that is not a cx1".into()))?;
    Ok(hex::encode(recoverable::derive_note_pubkey(&cx1, index)?))
}

/// Superseded: `Q` under the per-note tweak before LUD-26, from a 64-byte
/// legacy `cx1`, for finding notes to sweep. `purpose` null is the scheme
/// before purposes existed.
#[uniffi::export]
pub fn legacy_derive_note_pubkey(
    legacy_cx1: &str,
    purpose: Option<u32>,
    index: u32,
) -> FfiResult<String> {
    let cx1 = recoverable::decode_legacy_cx1(legacy_cx1)
        .ok_or_else(|| errors::Error::Protocol("that is not a legacy cx1".into()))?;
    Ok(hex::encode(recoverable::legacy_derive_note_pubkey(
        &cx1, purpose, index,
    )?))
}

/// Superseded: the secret key behind [`legacy_derive_note_pubkey`], from a
/// [`legacy_branch_node`]. Bearer material.
#[uniffi::export]
pub fn legacy_derive_note_secret_key(
    node_hex: &str,
    purpose: Option<u32>,
    index: u32,
) -> FfiResult<String> {
    let node = cash::cash_node_from_hex(node_hex)?;
    Ok(hex::encode(recoverable::legacy_derive_note_secret_key(
        &node, purpose, index,
    )?))
}

/// The raw 96-byte `Q || sig` key-path spend of the note `x(sk·G)` at
/// `domain` (a note URL, a mint URL or a bare host), as hex. [`encode_ck1`]
/// it for the wire; either way, it spends the note, at that mint only.
#[uniffi::export]
pub fn sign_note_ownership(secret_key_hex: &str, domain: &str) -> FfiResult<String> {
    Ok(hex::encode(recoverable::sign_note_ownership(
        &hex_array(secret_key_hex, "a note secret key")?,
        domain,
    )?))
}

/// A register, update or unregister proof by a share's own key, bound to the
/// service's `domain`, the lowercased username and, for register and update,
/// the `cx1` put on file, as raw 64-byte BIP-340 signature hex.
#[uniffi::export]
pub fn sign_address_proof(
    share_secret_key_hex: &str,
    action: &str,
    domain: &str,
    username: &str,
    cx1: Option<String>,
) -> FfiResult<String> {
    Ok(hex::encode(signature::sign_address_proof(
        &hex_array(share_secret_key_hex, "a share secret key")?,
        action,
        domain,
        username,
        cx1.as_deref(),
    )?))
}

/// What a SERVICE checks: a proof by `signer_cx1`'s key over this action's
/// message.
#[uniffi::export]
pub fn verify_address_proof(
    signer_cx1: &str,
    signature_hex: &str,
    action: &str,
    domain: &str,
    username: &str,
    cx1: Option<String>,
) -> bool {
    hex::decode(signature_hex.trim()).is_ok_and(|signature| {
        signature::verify_address_proof(
            signer_cx1,
            &signature,
            action,
            domain,
            username,
            cx1.as_deref(),
        )
    })
}

/// A verified `ck1` payload's note key, and whether it was signed under a
/// deprecated scheme.
#[derive(Debug, uniffi::Record)]
pub struct FfiNoteOwner {
    pub pubkey_x_only: String,
    /// Signed over a fixed message, or the 65-byte recoverable shape: still
    /// spendable, but rotate it.
    pub legacy: bool,
}

/// Verify a raw `ck1` payload (96 or 65 bytes of hex) against the mint at
/// `domain`. Null for an invalid proof, or one signed for another mint.
#[uniffi::export]
pub fn recover_note_ownership_pubkey(signature_hex: &str, domain: &str) -> Option<FfiNoteOwner> {
    let signature = hex::decode(signature_hex.trim()).ok()?;
    recoverable::recover_note_ownership_pubkey(&signature, domain).map(|owner| FfiNoteOwner {
        pubkey_x_only: hex::encode(owner.pubkey_x_only),
        legacy: owner.legacy,
    })
}

/// The id a SERVICE files a note under, `hex(Q)`, for any spend: a 64-hex
/// preimage, a `ck1` or a `cw1`. Names the note without saying the spend
/// opens it (see [`check_spend`]). Compare notes by this, never by k1.
#[uniffi::export]
pub fn note_id_of(k1: &str) -> Option<String> {
    recoverable::note_id_of(k1)
}

/// What to look a note up by without disclosing it: a bearer note's hash for
/// a preimage, the `cp1` for any other spend. Pass it to
/// [`build_note_info_url_by_hash`].
#[uniffi::export]
pub fn note_lookup_of(k1: &str) -> Option<String> {
    recoverable::note_lookup_of(k1)
}

/// A share node's `cx1`.
#[uniffi::export]
pub fn cash_node_to_cx1(node_hex: &str) -> FfiResult<String> {
    let node = cash::cash_node_from_hex(node_hex)?;
    Ok(recoverable::encode_cx1(&recoverable::cash_node_to_cx1(
        &node,
    )?))
}

/// Superseded: the node the per-note tweak hung off, `m/139'/d1..d4` over the
/// host as stored, port included. Bearer material, for sweeping only.
#[uniffi::export]
pub fn legacy_branch_node(root_hex: &str, host: &str) -> FfiResult<String> {
    let root = cash::cash_node_from_hex(root_hex)?;
    Ok(cash::cash_node_to_hex(&recoverable::legacy_branch_node(
        &root, host,
    )?))
}

/// Superseded: a [`legacy_branch_node`]'s 64-byte `cx1`.
#[uniffi::export]
pub fn legacy_cx1_of(node_hex: &str) -> FfiResult<String> {
    let node = cash::cash_node_from_hex(node_hex)?;
    Ok(recoverable::encode_legacy_cx1(&recoverable::legacy_cx1_of(
        &node,
    )?))
}

/// Not LUD-26: the cash seed of a Nostr identity key. Bearer material.
#[uniffi::export]
pub fn derive_nostr_cash_seed(secret_key_hex: &str) -> FfiResult<String> {
    Ok(hex::encode(recoverable::derive_nostr_cash_seed(
        &hex_array(secret_key_hex, "a Nostr secret key")?,
    )))
}

/// Not LUD-26: one mint's root `S` for a Nostr identity key, as a 64-byte
/// hex node. Bearer material.
#[uniffi::export]
pub fn derive_nostr_service_root(secret_key_hex: &str, domain: &str) -> FfiResult<String> {
    Ok(cash::cash_node_to_hex(
        &recoverable::derive_nostr_service_root(
            &hex_array(secret_key_hex, "a Nostr secret key")?,
            domain,
        )?,
    ))
}

// ---- urls and notes ----

/// The informational GET for a note named by `?p=` rather than its spend, so
/// nothing spendable goes on the wire. What a restore walk uses. `h` is a
/// `cp1` or a bearer note's 64-hex hash.
#[uniffi::export]
pub fn build_note_info_url_by_hash(withdraw_link: &str, h: &str) -> Option<String> {
    note::build_note_info_url_by_hash(withdraw_link, h)
}

#[uniffi::export]
pub fn resolve_note_input(value: &str) -> Option<String> {
    note::resolve_note_input(value)
}

#[uniffi::export]
pub fn resolve_mint_input(value: &str) -> Option<String> {
    urls::resolve_mint_input(value)
}

#[uniffi::export]
pub fn resolve_lnurl_input(value: &str) -> Option<String> {
    urls::resolve_lnurl_input(value)
}

#[uniffi::export]
pub fn is_allowed_service_url(value: &str) -> bool {
    urls::is_allowed_service_url(value)
}

#[uniffi::export]
pub fn mint_address_url(pay_url: &str) -> Option<String> {
    urls::mint_address_url(pay_url)
}

#[uniffi::export]
pub fn note_k1(url: &str) -> Option<String> {
    note::note_k1(url)
}

#[uniffi::export]
pub fn note_declared_amount(url: &str) -> Option<u64> {
    note::note_declared_amount(url)
}

#[uniffi::export]
pub fn note_signature(url: &str) -> Option<String> {
    note::note_signature(url)
}

#[uniffi::export]
pub fn build_note_url(withdraw_link: &str, k1: &str, amount_msat: Option<u64>) -> Option<String> {
    note::build_note_url(withdraw_link, k1, amount_msat)
}

#[uniffi::export]
pub fn with_new_k1(
    url: &str,
    k1: &str,
    amount_msat: u64,
    signature: Option<String>,
) -> Option<String> {
    note::with_new_k1(url, k1, amount_msat, signature.as_deref())
}

#[uniffi::export]
pub fn without_k1(url: &str, amount_msat: u64, signature: Option<String>) -> Option<String> {
    note::without_k1(url, amount_msat, signature.as_deref())
}

// ---- fees ----

#[uniffi::export]
pub fn parse_mint_fee(metadata: &str) -> Option<FfiMintFee> {
    fees::parse_mint_fee(metadata).map(Into::into)
}

#[uniffi::export]
pub fn apply_mint_fee(gross_msat: u64, fee: FfiMintFee) -> u64 {
    fees::apply_mint_fee(gross_msat, fee.into())
}

#[uniffi::export]
pub fn gross_up_for_mint_fee(net_msat: u64, fee: FfiMintFee) -> u64 {
    fees::gross_up_for_mint_fee(net_msat, fee.into())
}

#[uniffi::export]
pub fn describe_mint_fee(fee: FfiMintFee) -> String {
    fees::describe_mint_fee(fee.into())
}

impl From<FfiMintFee> for fees::MintFee {
    fn from(fee: FfiMintFee) -> Self {
        fees::MintFee {
            base_fee_msat: fee.base_fee_msat,
            fee_ppm: fee.fee_ppm,
            address_fee_msat: fee.address_fee_msat,
        }
    }
}

impl From<fees::MintFee> for FfiMintFee {
    fn from(fee: fees::MintFee) -> Self {
        FfiMintFee {
            base_fee_msat: fee.base_fee_msat,
            fee_ppm: fee.fee_ppm,
            address_fee_msat: fee.address_fee_msat,
        }
    }
}

// ---- bolt11 ----

#[uniffi::export]
pub fn decode_bolt11_amount_msat(pr: &str) -> Option<u64> {
    bolt11::decode_bolt11_amount_msat(pr)
}

#[uniffi::export]
pub fn is_bolt11_invoice(value: &str) -> bool {
    bolt11::is_bolt11_invoice(value)
}

#[uniffi::export]
pub fn same_invoice(a: &str, b: &str) -> bool {
    bolt11::same_invoice(a, b)
}

// ---- requests ----

#[uniffi::export]
pub fn note_info_request(url: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::note_info_request(url)?.into())
}

#[uniffi::export]
pub fn mint_address_request(url: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::mint_address_request(url)?.into())
}

#[uniffi::export]
pub fn pay_request_request(url: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::pay_request_request(url)?.into())
}

/// A plain LUD-06 invoice request. Mints nothing - it names no output.
#[uniffi::export]
pub fn invoice_request(pay_callback: &str, amount_msat: u64) -> FfiResult<FfiRequest> {
    Ok(protocol::invoice_request(pay_callback, amount_msat)?.into())
}

/// Ask for a mint invoice, naming the note it will credit by a bearer note's
/// hash `h = sha256(preimage)`, or by a `cp1`, sent as the comment alone.
#[uniffi::export]
pub fn mint_invoice_request_with_hash(
    pay_callback: &str,
    amount_msat: u64,
    h: &str,
) -> FfiResult<FfiRequest> {
    Ok(protocol::mint_invoice_request_with_hash(pay_callback, amount_msat, h)?.into())
}

/// The same, from the secret itself. It comes back on the request's
/// `new_secrets`: persist it BEFORE paying the invoice.
#[uniffi::export]
pub fn mint_invoice_request(
    pay_callback: &str,
    amount_msat: u64,
    mint_secret: &str,
) -> FfiResult<FfiRequest> {
    Ok(protocol::mint_invoice_request(pay_callback, amount_msat, mint_secret)?.into())
}

#[uniffi::export]
pub fn verify_request(verify_url: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::verify_request(verify_url)?.into())
}

#[uniffi::export]
pub fn melt_request(callback: &str, k1: &str, pr: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::melt_request(callback, k1, pr)?.into())
}

/// LUD-26's internal transfer: send a whole note to a Lightning Address at
/// the note's own mint. `pay_request_body` is the address's payRequest JSON;
/// refused unless its `withdrawLink` is on `note_domain`.
#[uniffi::export]
pub fn internal_transfer_request(
    pay_request_body: &str,
    note_domain: &str,
    k1: &str,
    amount_msat: u64,
) -> FfiResult<FfiRequest> {
    let info = protocol::parse_pay_request(&parse_body(pay_request_body)?)?;
    Ok(protocol::internal_transfer_request(&info, note_domain, k1, amount_msat)?.into())
}

/// The answer to an [`internal_transfer_request`]. An ambiguous error means
/// the note may already be spent.
#[uniffi::export]
pub fn parse_internal_transfer(body: &str) -> FfiResult<()> {
    Ok(protocol::parse_internal_transfer(&parse_body(body)?)?)
}

/// Rotate. `new_secret` is generated by the CALLER - use
/// [`generate_note_secret`], or a hardware RNG. The service never sees it.
#[uniffi::export]
pub fn rotate_request(callback: &str, k1: &str, new_secret: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::rotate_request(callback, k1, new_secret)?.into())
}

#[uniffi::export]
pub fn split_request(
    callback: &str,
    k1s: Vec<String>,
    amount_msat: u64,
    new_secret: &str,
    change_secret: &str,
) -> FfiResult<FfiRequest> {
    Ok(protocol::split_request(callback, &k1s, amount_msat, new_secret, change_secret)?.into())
}

#[uniffi::export]
pub fn merge_request(callback: &str, k1s: Vec<String>, new_secret: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::merge_request(callback, &k1s, new_secret)?.into())
}

/// Rotate into an output the caller already holds: a `cp1`, or a bearer
/// note's hash, sent as `p1`. The request carries no secrets, because this
/// crate never saw one - persist whatever stands behind `h` BEFORE the GET.
/// Refused before sending unless `h` names a note.
#[uniffi::export]
pub fn rotate_request_with_hash(callback: &str, k1: &str, h: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::rotate_request_with_hash(callback, k1, h)?.into())
}

/// As [`rotate_request_with_hash`], for a split: `h` goes as `p1` and `h2`
/// as `p2`, each a `cp1` or a bearer note's hash.
#[uniffi::export]
pub fn split_request_with_hash(
    callback: &str,
    k1s: Vec<String>,
    amount_msat: u64,
    h: &str,
    h2: &str,
) -> FfiResult<FfiRequest> {
    Ok(protocol::split_request_with_hash(callback, &k1s, amount_msat, h, h2)?.into())
}

/// As [`rotate_request_with_hash`], for a merge.
#[uniffi::export]
pub fn merge_request_with_hash(callback: &str, k1s: Vec<String>, h: &str) -> FfiResult<FfiRequest> {
    Ok(protocol::merge_request_with_hash(callback, &k1s, h)?.into())
}

// ---- response parsing ----

/// Only `policy.require_mint_pubkey` matters here. Leave it on unless the
/// service publishes no `mintPubkey`, because a note with no key to check it
/// against is one whoever receives it must take on faith.
#[uniffi::export]
pub fn parse_note_info(
    body: &str,
    queried_url: &str,
    policy: FfiPolicy,
) -> FfiResult<FfiWithdrawInfo> {
    let value = parse_body(body)?;
    let info = protocol::parse_note_info(&value, queried_url, policy.into())?;
    Ok(FfiWithdrawInfo {
        callback: info.callback,
        k1: info.k1,
        max_withdrawable: info.max_withdrawable,
        min_withdrawable: info.min_withdrawable,
        default_description: info.default_description,
        mint_pubkey: info.mint_pubkey,
        signature: info.signature,
    })
}

/// The answer to a `?p=` lookup from [`build_note_info_url_by_hash`].
#[uniffi::export]
pub fn parse_note_info_by_hash(body: &str, policy: FfiPolicy) -> FfiResult<FfiNoteInfoByHash> {
    let value = parse_body(body)?;
    let info = protocol::parse_note_info_by_hash(&value, policy.into())?;
    Ok(FfiNoteInfoByHash {
        callback: info.callback,
        max_withdrawable: info.max_withdrawable,
        min_withdrawable: info.min_withdrawable,
        default_description: info.default_description,
        mint_pubkey: info.mint_pubkey,
        signature: info.signature,
    })
}

#[uniffi::export]
pub fn parse_mint_address(body: &str) -> FfiResult<FfiMintAddress> {
    let value = parse_body(body)?;
    let info = protocol::parse_mint_address(&value)?;
    Ok(FfiMintAddress {
        callback: info.callback,
        pay_link: info.pay_link,
        max_withdrawable: info.max_withdrawable,
        min_withdrawable: info.min_withdrawable,
        node_pubkey: info.node_pubkey,
        node_alias: info.node_alias,
        node_uri: info.node_uri,
        node_color: info.node_color,
        node_capacity_msat: info.node_capacity_msat,
        node_num_channels: info.node_num_channels,
        node_num_peers: info.node_num_peers,
        node_uris: info.node_uris,
        sunset_date: info.sunset_date,
        outstanding_notes_msat: info.outstanding_notes_msat,
    })
}

#[uniffi::export]
pub fn parse_pay_request(body: &str) -> FfiResult<FfiPayRequest> {
    let value = parse_body(body)?;
    let info = protocol::parse_pay_request(&value)?;
    // Computed before the struct literal moves `info` field by field.
    let names_mint_output = info.names_mint_output();
    Ok(FfiPayRequest {
        callback: info.callback,
        min_sendable: info.min_sendable,
        max_sendable: info.max_sendable,
        metadata: info.metadata,
        withdraw_link: info.withdraw_link,
        mint_pubkey: info.mint_pubkey,
        names_mint_output,
        mint_fee: info.mint_fee.map(Into::into),
        comment_allowed: info.comment_allowed,
        mint_to_hash: info.mint_to_hash,
    })
}

#[uniffi::export]
pub fn parse_invoice(body: &str, requested_msat: u64) -> FfiResult<FfiInvoice> {
    let value = parse_body(body)?;
    let invoice = protocol::parse_invoice(&value, requested_msat)?;
    Ok(FfiInvoice {
        pr: invoice.pr,
        verify: invoice.verify,
        disposable: invoice.disposable,
    })
}

#[uniffi::export]
pub fn parse_verify(body: &str) -> FfiResult<FfiVerify> {
    let value = parse_body(body)?;
    let result = protocol::parse_verify(&value)?;
    Ok(FfiVerify {
        settled: result.settled,
        preimage: result.preimage,
        pr: result.pr,
    })
}

/// Classify a mutating callback's response.
///
/// Pass the secrets the request carried: if the outcome turns out to be
/// unknown, they come back attached to the error, so nothing can lose them
/// between the call and the catch.
///
/// Pass the request's `outputs` too. A `cp1` output that comes back without
/// its certificate is [`LnurlcashError::Unverifiable`] whatever the policy
/// says; a bearer output named by its hash may come back with its signature
/// null, unless `policy.require_signatures` asks for one. An output missing
/// from `outputs` is read as a hash, so leaving them out quietly drops the
/// `cp1` check.
#[uniffi::export]
pub fn parse_mutation(
    body: &str,
    new_secrets: Vec<String>,
    kind: FfiMutationKind,
    outputs: Vec<String>,
    policy: FfiPolicy,
) -> FfiResult<FfiMutation> {
    let value = match parse_body(body) {
        Ok(value) => value,
        Err(LnurlcashError::Ambiguous { detail, .. }) => {
            return Err(LnurlcashError::Ambiguous {
                detail,
                new_secrets,
            })
        }
        Err(other) => return Err(other),
    };
    match protocol::parse_mutation(&value, kind.into(), &outputs, policy.into()) {
        Ok(response) => Ok(FfiMutation {
            signature: response.signature,
            change_signature: response.change_signature,
            pr: response.pr,
            verify: response.verify,
        }),
        Err(err) => Err(err.with_secrets(new_secrets).into()),
    }
}

/// Build the ambiguous error a caller should raise when the GET itself failed -
/// a timeout, a dropped connection - so the secrets travel with it exactly as
/// they would from a parsed response.
#[uniffi::export]
pub fn ambiguous_outcome(detail: &str, new_secrets: Vec<String>) -> LnurlcashError {
    LnurlcashError::Ambiguous {
        detail: detail.to_string(),
        new_secrets,
    }
}
