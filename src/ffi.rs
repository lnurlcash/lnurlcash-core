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
//! 3. hand the response body back to the matching `parse` function
//! 4. if the GET failed, or parsing says the outcome is unknown, the secrets
//!    you saved in step 1 may be the only copy of the money

use crate::errors::Error;
use crate::{bolt11, cash, errors, fees, note, protocol, secrets, signature, urls};

/// One GET, and the secrets whose loss would destroy money.
#[derive(Debug, uniffi::Record)]
pub struct FfiRequest {
    pub url: String,
    /// Fresh secrets this request disclosed the hashes of. Persist these
    /// BEFORE performing the GET: if the answer is lost, they may be the only
    /// copies of notes the service has already minted.
    pub new_secrets: Vec<String>,
}

impl From<protocol::Request> for FfiRequest {
    fn from(request: protocol::Request) -> Self {
        FfiRequest {
            url: request.url,
            new_secrets: request.new_secrets,
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

    /// The mutation LANDED and the SERVICE returned no signature over it.
    /// LUD-25 requires one, so this is a non-conforming SERVICE - but the note
    /// exists at the hash the wallet disclosed, and `new_secrets` is the only
    /// key to it. Persist them before deciding anything else.
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
/// owes no signature; a split mints two notes and owes one over each.
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
    pub signature: Option<String>,
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

/// A note's id: sha256 of the secret, which is the `h` disclosed on a mutation.
#[uniffi::export]
pub fn hash_k1(k1: &str) -> FfiResult<String> {
    secrets::hash_k1(k1).map_err(Into::into)
}

#[uniffi::export]
pub fn is_preimage(value: &str) -> bool {
    secrets::is_preimage(value)
}

/// Verify a note's signature against the mint's pubkey, offline. Accepts the
/// recovery id at either end, because implementations disagree about which.
#[uniffi::export]
pub fn verify_note_signature(
    k1: &str,
    amount_msat: u64,
    signature_hex: &str,
    mint_pubkey_hex: &str,
) -> bool {
    signature::verify_note_signature(k1, amount_msat, signature_hex, mint_pubkey_hex)
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

/// `m/139'/d1/d2/d3/d4` for one mint, as a 64-byte hex node.
///
/// Every unhardened level in LUD-25's path is at or above this node, so a
/// hardware signer given THIS rather than the seed needs no elliptic curve:
/// each index beneath it is one hardened step. Whoever derives it can derive
/// every note secret held at that mint, so it is provisioning material - one
/// mint's subtree, not the wallet.
#[uniffi::export]
pub fn derive_cash_domain_node(root_hex: &str, host: &str) -> FfiResult<String> {
    let root = cash::cash_node_from_hex(root_hex)?;
    Ok(cash::cash_node_to_hex(&cash::derive_cash_domain_node(
        &root, host,
    )?))
}

/// The i-th note secret beneath a mint's domain node.
#[uniffi::export]
pub fn cash_secret_at(domain_node_hex: &str, index: u32) -> FfiResult<String> {
    let node = cash::cash_node_from_hex(domain_node_hex)?;
    Ok(cash::cash_secret_at(&node, index)?)
}

/// The i-th note secret at a mint, from the root. Re-derives the domain node
/// each call; hold the node for a run of secrets.
#[uniffi::export]
pub fn derive_cash_secret(root_hex: &str, host: &str, index: u32) -> FfiResult<String> {
    let root = cash::cash_node_from_hex(root_hex)?;
    Ok(cash::derive_cash_secret(&root, host, index)?)
}

/// The four raw uint32 levels a mint's subtree hangs off. Exposed for a wallet
/// diagnosing a restore that finds nothing.
#[uniffi::export]
pub fn cash_domain_indices(root_hex: &str, host: &str) -> FfiResult<Vec<u32>> {
    let root = cash::cash_node_from_hex(root_hex)?;
    Ok(cash::cash_domain_indices(&root, host)?.to_vec())
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

// ---- urls and notes ----

/// The informational GET for a note named by its hash rather than its secret,
/// so nothing spendable goes on the wire. What a restore walk uses.
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
    fees::parse_mint_fee(metadata).map(|fee| FfiMintFee {
        base_fee_msat: fee.base_fee_msat,
        fee_ppm: fee.fee_ppm,
    })
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

/// Ask for a mint invoice, naming the note it will credit with
/// `h = sha256(secret)`.
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

// ---- response parsing ----

/// `require_signatures` mirrors [`protocol::Policy`]: leave it true unless the
/// SERVICE predates LUD-25's mandatory offline verification, because a note
/// with no key to check it against is one whoever receives it must take on
/// faith.
#[uniffi::export]
pub fn parse_note_info(
    body: &str,
    queried_url: &str,
    require_signatures: bool,
) -> FfiResult<FfiWithdrawInfo> {
    let value = parse_body(body)?;
    let info =
        protocol::parse_note_info(&value, queried_url, protocol::Policy { require_signatures })?;
    Ok(FfiWithdrawInfo {
        callback: info.callback,
        k1: info.k1,
        max_withdrawable: info.max_withdrawable,
        min_withdrawable: info.min_withdrawable,
        default_description: info.default_description,
        mint_pubkey: info.mint_pubkey,
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
        mint_fee: info.mint_fee.map(|fee| FfiMintFee {
            base_fee_msat: fee.base_fee_msat,
            fee_ppm: fee.fee_ppm,
        }),
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
#[uniffi::export]
pub fn parse_mutation(
    body: &str,
    new_secrets: Vec<String>,
    kind: FfiMutationKind,
    require_signatures: bool,
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
    match protocol::parse_mutation(&value, kind.into(), protocol::Policy { require_signatures }) {
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
