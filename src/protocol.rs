//! The protocol itself, with no I/O in it.
//!
//! Every operation is a [`Request`] - a URL to GET, plus the fresh secrets that
//! must survive if the answer is lost - paired with a `parse_*` function for
//! what comes back. A caller with its own HTTP stack needs nothing else; the
//! optional [`crate::client`] is a thin loop over exactly these.

use serde_json::Value;

use crate::bolt11::decode_bolt11_amount_msat;
use crate::errors::{classify_note_error, Error, Result};
use crate::fees::{parse_mint_fee, MintFee};
use crate::note::note_k1;
use crate::secrets::hash_k1;
use crate::urls::is_allowed_service_url;

/// One GET, and the secrets whose loss would destroy money.
#[derive(Debug, Clone)]
pub struct Request {
    pub url: String,
    /// Fresh WALLET-generated secrets this request disclosed the hashes of. If
    /// the outcome turns out to be unknown they may be the only copies of notes
    /// the SERVICE has already minted.
    pub new_secrets: Vec<String>,
}

impl Request {
    fn plain(url: String) -> Self {
        Request {
            url,
            new_secrets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawRequestInfo {
    pub callback: String,
    pub k1: String,
    pub max_withdrawable: u64,
    pub min_withdrawable: u64,
    pub default_description: Option<String>,
    pub mint_pubkey: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintAddressInfo {
    pub callback: String,
    pub pay_link: String,
    pub max_withdrawable: u64,
    pub min_withdrawable: u64,
    /// The wire field is `mintPubkey`, but at this endpoint it is never a
    /// note's signing key - always the SERVICE's own node identity.
    pub node_pubkey: Option<String>,
    pub node_alias: Option<String>,
    pub node_uri: Option<String>,
    pub node_color: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayRequestInfo {
    pub callback: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub metadata: String,
    pub withdraw_link: Option<String>,
    pub mint_pubkey: Option<String>,
    pub mint_fee: Option<MintFee>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceResult {
    pub pr: String,
    pub verify: Option<String>,
    /// LUD-11: absent MUST be read as true, so only an explicit false counts.
    pub disposable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub settled: bool,
    pub preimage: Option<String>,
    pub pr: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutationResponse {
    pub signature: Option<String>,
    pub change_signature: Option<String>,
    /// LUD-25 melt proof (optional), present only on a melt.
    pub pr: Option<String>,
    pub verify: Option<String>,
}

fn as_str(body: &Value, key: &str) -> Option<String> {
    body.get(key)?.as_str().map(|s| s.to_string())
}

fn as_u64(body: &Value, key: &str) -> Option<u64> {
    let value = body.get(key)?;
    if value.is_boolean() {
        return None;
    }
    value.as_u64()
}

/// A SERVICE's ERROR is definitive. The reason is carried through exactly as
/// sent, empty included - see [`classify_note_error`] for why substituting a
/// friendly default here would be a bug about somebody's money.
fn reject_error(body: &Value) -> Result<()> {
    if body.get("status").and_then(|v| v.as_str()) == Some("ERROR") {
        let reason = as_str(body, "reason").unwrap_or_default();
        return Err(Error::ServiceRejected(reason));
    }
    Ok(())
}

// ---- the informational GET ----

/// LUD-03 step one. Never burns, rotates or alters the note.
///
/// `sig` is stripped before the request: it is only meaningful to a holder
/// inspecting the note locally, since the SERVICE already knows what it signed.
/// `k1` and `amount` are left as they are.
pub fn note_info_request(url: &str) -> Result<Request> {
    let mut parsed = url::Url::parse(url)
        .map_err(|_| Error::RequestRefused("that note URL does not parse".into()))?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| k != "sig")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    parsed.set_query(None);
    if !pairs.is_empty() {
        let mut serializer = parsed.query_pairs_mut();
        for (key, value) in &pairs {
            serializer.append_pair(key, value);
        }
    }
    Ok(Request::plain(parsed.to_string()))
}

pub fn parse_note_info(body: &Value, queried_url: &str) -> Result<WithdrawRequestInfo> {
    if let Err(Error::ServiceRejected(reason)) = reject_error(body) {
        return Err(classify_note_error(&reason));
    }
    let invalid = || Error::Protocol("not a withdrawRequest (unexpected response)".into());
    if body.get("tag").and_then(|v| v.as_str()) != Some("withdrawRequest") {
        return Err(invalid());
    }
    let callback = as_str(body, "callback").ok_or_else(invalid)?;
    let k1 = as_str(body, "k1").ok_or_else(invalid)?;
    let max_withdrawable = as_u64(body, "maxWithdrawable").ok_or_else(invalid)?;
    let min_withdrawable = match body.get("minWithdrawable") {
        None | Some(Value::Null) => 0,
        Some(_) => as_u64(body, "minWithdrawable").ok_or_else(invalid)?,
    };
    if min_withdrawable > max_withdrawable {
        return Err(invalid());
    }
    // Spec MUST: the response's k1 is the bearer secret itself, never a derived
    // or opaque id. A SERVICE returning something else for the k1 it was queried
    // with is non-compliant - or the note was rotated by somebody else, which
    // matters more.
    if let Some(queried) = note_k1(queried_url) {
        if k1.to_ascii_lowercase() != queried {
            return Err(Error::Protocol(
                "the service echoed back a different k1 than was queried - the note may have been redeemed elsewhere, or the service isn't spec-compliant".into(),
            ));
        }
    }
    Ok(WithdrawRequestInfo {
        callback,
        k1: k1.to_ascii_lowercase(),
        max_withdrawable,
        min_withdrawable,
        default_description: as_str(body, "defaultDescription"),
        mint_pubkey: as_str(body, "mintPubkey"),
    })
}

/// LUD-25 mint address (experimental, optional). Best-effort discovery: most
/// SERVICEs will not have it, and a rejection means "no extra information".
pub fn mint_address_request(url: &str) -> Result<Request> {
    Ok(Request::plain(url.to_string()))
}

pub fn parse_mint_address(body: &Value) -> Result<MintAddressInfo> {
    reject_error(body)?;
    let invalid = || Error::Protocol("not a mint address response (unexpected shape)".into());
    if body.get("tag").and_then(|v| v.as_str()) != Some("withdrawRequest") {
        return Err(invalid());
    }
    Ok(MintAddressInfo {
        callback: as_str(body, "callback").ok_or_else(invalid)?,
        pay_link: as_str(body, "payLink").ok_or_else(invalid)?,
        max_withdrawable: as_u64(body, "maxWithdrawable").ok_or_else(invalid)?,
        min_withdrawable: as_u64(body, "minWithdrawable").unwrap_or(0),
        node_pubkey: as_str(body, "mintPubkey"),
        node_alias: as_str(body, "nodeAlias"),
        node_uri: as_str(body, "nodeUri"),
        node_color: as_str(body, "nodeColor"),
    })
}

// ---- the mutating callback ----

fn callback_url(callback: &str, params: &[(&str, String)]) -> Result<String> {
    if !is_allowed_service_url(callback) {
        return Err(Error::RequestRefused(
            "the service provided an invalid callback URL".into(),
        ));
    }
    if !params.iter().any(|(key, _)| *key == "k1") {
        // Nothing to operate on. Worth refusing here rather than letting it
        // become a callback with no k1, whose meaning is entirely up to the
        // SERVICE - and which, read generously, could burn something the caller
        // never named.
        return Err(Error::RequestRefused(
            "at least one k1 is required - there is no note to operate on".into(),
        ));
    }
    let mut url = url::Url::parse(callback).map_err(|_| {
        Error::RequestRefused("the service provided an invalid callback URL".into())
    })?;
    {
        // append, never replace: a merge repeats the k1 parameter, and a
        // callback may already carry parameters of its own
        let mut serializer = url.query_pairs_mut();
        for (key, value) in params {
            serializer.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

/// Burn a single note; the SERVICE pays `pr` of exactly its value. Merge several
/// notes first to melt them together - LUD-25 dropped multi-k1 melt.
///
/// `{"status":"OK"}` means the payment is IN FLIGHT, not that the note is spent.
/// The SERVICE pays asynchronously and only finalises the burn once the payment
/// settles, restoring the note if it fails - so a melt failure is never reported
/// through this call, only observed as the note becoming spendable again.
pub fn melt_request(callback: &str, k1: &str, pr: &str) -> Result<Request> {
    Ok(Request::plain(callback_url(
        callback,
        &[("k1", k1.to_string()), ("pr", pr.trim().to_string())],
    )?))
}

pub fn rotate_request_with_hash(callback: &str, k1: &str, h: &str) -> Result<Request> {
    Ok(Request::plain(callback_url(
        callback,
        &[("k1", k1.to_string()), ("h", h.to_string())],
    )?))
}

pub fn split_request_with_hash(
    callback: &str,
    k1s: &[String],
    amount_msat: u64,
    h: &str,
    h2: &str,
) -> Result<Request> {
    let mut params: Vec<(&str, String)> = k1s.iter().map(|k1| ("k1", k1.clone())).collect();
    params.push(("amount", amount_msat.to_string()));
    params.push(("h", h.to_string()));
    params.push(("h2", h2.to_string()));
    Ok(Request::plain(callback_url(callback, &params)?))
}

pub fn merge_request_with_hash(callback: &str, k1s: &[String], h: &str) -> Result<Request> {
    let mut params: Vec<(&str, String)> = k1s.iter().map(|k1| ("k1", k1.clone())).collect();
    params.push(("h", h.to_string()));
    Ok(Request::plain(callback_url(callback, &params)?))
}

// ---- the generating variants ----
//
// Per LUD-25 the WALLET generates the replacement secret and discloses only its
// hash. The SERVICE never sees, generates or persists it, which is what closes
// the prior-holder exposure a SERVICE-generated replacement would otherwise
// reopen on every single rotate.
//
// The secrets are passed in rather than drawn here, so a hardware wallet can
// supply them from its own RNG and a test can be deterministic.

pub fn rotate_request(callback: &str, k1: &str, new_secret: &str) -> Result<Request> {
    let mut request = rotate_request_with_hash(callback, k1, &hash_k1(new_secret)?)?;
    request.new_secrets = vec![new_secret.to_string()];
    Ok(request)
}

pub fn split_request(
    callback: &str,
    k1s: &[String],
    amount_msat: u64,
    new_secret: &str,
    change_secret: &str,
) -> Result<Request> {
    let mut request = split_request_with_hash(
        callback,
        k1s,
        amount_msat,
        &hash_k1(new_secret)?,
        &hash_k1(change_secret)?,
    )?;
    request.new_secrets = vec![new_secret.to_string(), change_secret.to_string()];
    Ok(request)
}

pub fn merge_request(callback: &str, k1s: &[String], new_secret: &str) -> Result<Request> {
    let mut request = merge_request_with_hash(callback, k1s, &hash_k1(new_secret)?)?;
    request.new_secrets = vec![new_secret.to_string()];
    Ok(request)
}

/// Classify a mutating callback's response.
///
/// A 200 that does not confirm is [`Error::Ambiguous`], not a failure: the
/// SERVICE may have applied the mutation and merely failed to say so.
pub fn parse_mutation(body: &Value) -> Result<MutationResponse> {
    if let Err(Error::ServiceRejected(reason)) = reject_error(body) {
        return Err(classify_note_error(&reason));
    }
    if body.get("status").and_then(|v| v.as_str()) != Some("OK") {
        return Err(Error::ambiguous(
            "the service did not confirm the operation - it may still have been applied",
        ));
    }
    Ok(MutationResponse {
        signature: as_str(body, "sig"),
        change_signature: as_str(body, "sig2"),
        pr: as_str(body, "pr"),
        verify: as_str(body, "verify"),
    })
}

// ---- minting ----

pub fn pay_request_request(url: &str) -> Result<Request> {
    Ok(Request::plain(url.to_string()))
}

pub fn parse_pay_request(body: &Value) -> Result<PayRequestInfo> {
    reject_error(body)?;
    let invalid = || Error::Protocol("not a payRequest (unexpected response)".into());
    if body.get("tag").and_then(|v| v.as_str()) != Some("payRequest") {
        return Err(invalid());
    }
    let metadata = as_str(body, "metadata").unwrap_or_default();
    Ok(PayRequestInfo {
        callback: as_str(body, "callback").ok_or_else(invalid)?,
        min_sendable: as_u64(body, "minSendable").unwrap_or(0),
        max_sendable: as_u64(body, "maxSendable").unwrap_or(0),
        mint_fee: parse_mint_fee(&metadata),
        metadata,
        withdraw_link: as_str(body, "withdrawLink"),
        mint_pubkey: as_str(body, "mintPubkey"),
    })
}

pub fn invoice_request(pay_callback: &str, amount_msat: u64) -> Result<Request> {
    let mut url = url::Url::parse(pay_callback)
        .map_err(|_| Error::RequestRefused("that pay callback does not parse".into()))?;
    url.query_pairs_mut()
        .append_pair("amount", &amount_msat.to_string());
    Ok(Request::plain(url.to_string()))
}

pub fn parse_invoice(body: &Value, requested_msat: u64) -> Result<InvoiceResult> {
    reject_error(body)?;
    let pr = as_str(body, "pr")
        .ok_or_else(|| Error::Protocol("the service did not return an invoice".into()))?;
    // A SERVICE answering an amount request with an invoice for a DIFFERENT
    // amount is broken or hostile. An amountless invoice passes through: there
    // is nothing to check it against here.
    if let Some(invoiced) = decode_bolt11_amount_msat(&pr) {
        if invoiced != requested_msat {
            return Err(Error::Protocol(format!(
                "the service returned an invoice for {invoiced} msat, not the {requested_msat} requested"
            )));
        }
    }
    Ok(InvoiceResult {
        pr,
        verify: as_str(body, "verify"),
        disposable: body.get("disposable").and_then(|v| v.as_bool()) != Some(false),
    })
}

/// LUD-21. For LNURLcash specifically, a settled invoice's preimage IS the
/// bearer note's spend secret, and a verify GET proves nothing about who is
/// asking - only that they know the payment hash, which travels inside the
/// invoice itself. A caller receiving a preimage here MUST rotate immediately.
pub fn verify_request(verify_url: &str) -> Result<Request> {
    Ok(Request::plain(verify_url.to_string()))
}

pub fn parse_verify(body: &Value) -> Result<VerifyResult> {
    reject_error(body)?;
    let invalid = || Error::Protocol("the service returned an unexpected verify response".into());
    let settled = body
        .get("settled")
        .and_then(|v| v.as_bool())
        .ok_or_else(invalid)?;
    Ok(VerifyResult {
        settled,
        preimage: as_str(body, "preimage"),
        pr: as_str(body, "pr").ok_or_else(invalid)?,
    })
}
