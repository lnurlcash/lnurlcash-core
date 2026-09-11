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
use crate::recoverable::{is_cp1, note_id_of};
use crate::secrets::{hash_k1, is_preimage};
use crate::urls::is_allowed_service_url;

/// What this crate insists a SERVICE does, rather than merely hopes it does.
///
/// LUD-25 makes offline verification mandatory: a SERVICE MUST publish
/// `mintPubkey` and MUST sign every note a rotate, split or merge mints. A
/// wallet that quietly accepted unsigned notes would be handing its holder
/// something nobody downstream can check, which is the exact gap offline
/// verification exists to close - so the default insists.
///
/// Turn `require_signatures` off only to talk to a SERVICE that predates the
/// requirement, and only knowing the cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub require_signatures: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            require_signatures: true,
        }
    }
}

/// Which mutation a response is being read as, which decides what it must
/// carry. A melt mints nothing, so it has no signature to return and none is
/// required; a split mints two notes and owes a signature over each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationKind {
    Melt,
    Rotate,
    Split,
    Merge,
}

/// A compressed secp256k1 point: 33 bytes hex, the leading byte naming which
/// of the two y values the x coordinate stands for.
///
/// Checked at the response rather than at the first signature check, because a
/// `mintPubkey` that is not one verifies nothing - and the same fault found
/// later looks like a forged note instead of a broken mint.
pub fn is_compressed_pubkey(value: &str) -> bool {
    let key = value.trim().to_ascii_lowercase();
    key.len() == 66
        && (key.starts_with("02") || key.starts_with("03"))
        && key.bytes().all(|b| b.is_ascii_hexdigit())
}

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

/// What a hash lookup returns. Deliberately NOT [`WithdrawRequestInfo`]: that
/// type's `k1` is the bearer secret, and the whole point of asking by hash is
/// that the caller already holds it and the SERVICE never sends it back. A
/// conforming SERVICE omits `k1` here (LUD-03's convenience of echoing the
/// queried value has nothing to echo), so a struct promising one would be
/// promising something no answer contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteInfoByHash {
    pub callback: String,
    pub max_withdrawable: u64,
    pub min_withdrawable: u64,
    pub default_description: Option<String>,
    pub mint_pubkey: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawRequestInfo {
    pub callback: String,
    pub k1: String,
    pub max_withdrawable: u64,
    pub min_withdrawable: u64,
    pub default_description: Option<String>,
    /// LUD-25 makes offline verification mandatory, so a conforming SERVICE
    /// always publishes the key its notes verify against here. Only ever
    /// `None` when the caller set [`Policy::require_signatures`] to false.
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
    /// The wire field is `nodeCapacity`, msat like every other amount here.
    /// Suffixed on this side so a caller cannot read it as sats.
    pub node_capacity_msat: Option<u64>,
    pub node_num_channels: Option<u64>,
    pub node_num_peers: Option<u64>,
    /// Every address the SERVICE's node announces, each already
    /// `node_key@host:port`. `node_uri` is the first of them; a node behind
    /// Tor as well as clearnet has more, and a caller that can only reach the
    /// other one needs the whole list. `None`, never an empty vector, when
    /// the SERVICE announces nothing.
    pub node_uris: Option<Vec<String>>,
    /// The day the SERVICE plans to close, ISO-8601 (`2026-12-31`). Advance
    /// warning while there is still time to spend, deliberately not the same
    /// thing as a mint that has already stopped minting. Nothing enforces it
    /// and nothing verifies it, so it is a prompt to move notes, never a
    /// deadline to compute against. A value that is not a real calendar day
    /// is dropped rather than passed on: the one thing a WALLET does with
    /// this is show it to a holder.
    pub sunset_date: Option<String>,
    /// What the SERVICE says it owes, msat: every note it has issued and not
    /// burned. Its own claim about its own database, with nothing to check it
    /// against, so it is worth reading next to what the node holds and worth
    /// little on its own.
    pub outstanding_notes_msat: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayRequestInfo {
    pub callback: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub metadata: String,
    /// LUD-25: present when paying this mints a bearer note. The raw LUD-17
    /// withdraw endpoint the note will live at, in either the plain or the
    /// `lnurlw://` spelling - the draft says "as described in LUD-17", and
    /// LUD-17 describes both, so a WALLET accepts either unchanged.
    pub withdraw_link: Option<String>,
    /// Rarely present here: a WALLET that pays the invoice recovers the
    /// SERVICE's node id from the invoice's own signature, so the draft only
    /// has a SERVICE publish this where there is no invoice to recover it
    /// from. Nothing forbids including it anyway.
    pub mint_pubkey: Option<String>,
    /// Absent means the SERVICE advertised no fee, which the draft says to
    /// read as fee-free rather than as unknown.
    pub mint_fee: Option<MintFee>,
    /// LUD-12's field, and the normative LUD-25 minting capability. A mint
    /// MUST allow the 64 characters a hex-encoded SHA-256 commitment needs.
    pub comment_allowed: Option<u64>,
    /// Additive ForgeSworn extension: this SERVICE also accepts the same
    /// commitment as an `h` parameter. Never a substitute for the mandatory
    /// comment, and anything that is not exactly `true` reads as false.
    pub mint_to_hash: bool,
}

impl PayRequestInfo {
    /// Whether this SERVICE can mint a current-draft LUD-25 note.
    ///
    /// `mint_to_hash` alone cannot stand in for it: that extension is additive
    /// and predates the comment spelling, and a SERVICE without the comment
    /// capacity has nowhere to put the commitment.
    pub fn names_mint_output(&self) -> bool {
        self.comment_allowed
            .is_some_and(|allowed| allowed >= MINT_COMMENT_LENGTH)
    }
}

/// The exact comment capacity minting needs: 32 bytes as lowercase hex.
pub const MINT_COMMENT_LENGTH: u64 = 64;

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

/// Non-empty strings only, and `None` rather than an empty vector for a list
/// that had none: a caller testing `is_some()` and one testing `len()` have to
/// reach the same conclusion about a SERVICE that announced nothing.
fn as_str_list(body: &Value, key: &str) -> Option<Vec<String>> {
    let entries: Vec<String> = body
        .get(key)?
        .as_array()?
        .iter()
        .filter_map(|item| item.as_str())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
        .collect();
    (!entries.is_empty()).then_some(entries)
}

/// A calendar day, `YYYY-MM-DD`, and nothing else. A timestamp, a
/// locale-formatted date or a typo is dropped rather than passed on, because
/// the one thing a WALLET does with this is put it in front of a holder and a
/// wrong date there is worse than no date. `2026-02-31` fails here rather than
/// arriving as a day nobody meant.
fn as_iso_date(body: &Value, key: &str) -> Option<String> {
    let raw = body.get(key)?.as_str()?;
    let bytes = raw.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !raw.char_indices().all(|(i, c)| {
        if i == 4 || i == 7 {
            c == '-'
        } else {
            c.is_ascii_digit()
        }
    }) {
        return None;
    }
    let year: u32 = raw[0..4].parse().ok()?;
    let month: u32 = raw[5..7].parse().ok()?;
    let day: u32 = raw[8..10].parse().ok()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (day >= 1 && day <= last).then(|| raw.to_string())
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

pub fn parse_note_info(
    body: &Value,
    queried_url: &str,
    policy: Policy,
) -> Result<WithdrawRequestInfo> {
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
        if !same_note(&k1, &queried) {
            return Err(Error::Protocol(
                "the service echoed back a different k1 than was queried - the note may have been redeemed elsewhere, or the service isn't spec-compliant".into(),
            ));
        }
    }
    let mint_pubkey = as_str(body, "mintPubkey");
    // Separate from the shape check above, and separately worded: this response
    // IS a withdrawRequest, it just describes a note nobody can check offline.
    // Saying "not a withdrawRequest" would send a caller after the wrong fault.
    if policy.require_signatures && !mint_pubkey.as_deref().is_some_and(is_compressed_pubkey) {
        return Err(Error::Protocol(
            match mint_pubkey {
                None => "this service publishes no mintPubkey, so its notes cannot be verified offline (LUD-25 requires one)",
                Some(_) => "this service published a mintPubkey that is not a 33-byte compressed secp256k1 key",
            }
            .into(),
        ));
    }
    Ok(WithdrawRequestInfo {
        callback,
        k1: k1.to_ascii_lowercase(),
        max_withdrawable,
        min_withdrawable,
        default_description: as_str(body, "defaultDescription"),
        mint_pubkey: mint_pubkey.map(|key| key.trim().to_ascii_lowercase()),
    })
}

/// Whether two k1s name one note. A Part 1 secret has one spelling, but a
/// Part 2 note has more than one valid `ck1`: anyone can flip a signature to
/// its high-S twin, and a signer drawing another nonce makes another. So a
/// SERVICE that echoes a different `ck1` recovering to the same key has named
/// the same note, while one recovering to any other key has not. A k1 with no
/// note id at all still has to come back as the same string.
fn same_note(a: &str, b: &str) -> bool {
    if a.trim().eq_ignore_ascii_case(b.trim()) {
        return true;
    }
    matches!((note_id_of(a), note_id_of(b)), (Some(x), Some(y)) if x == y)
}

/// The same response, for a lookup that named the note by its hash.
///
/// Differs from [`parse_note_info`] in exactly two places, both because there
/// was no secret in the request: `k1` is not required in the response, and
/// there is no echo to check against. Everything else - the shape, and the
/// mandatory `mintPubkey` - is enforced identically, because a note nobody can
/// verify offline is no more acceptable when it was looked up privately.
pub fn parse_note_info_by_hash(body: &Value, policy: Policy) -> Result<NoteInfoByHash> {
    if let Err(Error::ServiceRejected(reason)) = reject_error(body) {
        return Err(classify_note_error(&reason));
    }
    let invalid = || Error::Protocol("not a withdrawRequest (unexpected response)".into());
    if body.get("tag").and_then(|v| v.as_str()) != Some("withdrawRequest") {
        return Err(invalid());
    }
    let callback = as_str(body, "callback").ok_or_else(invalid)?;
    let max_withdrawable = as_u64(body, "maxWithdrawable").ok_or_else(invalid)?;
    let min_withdrawable = match body.get("minWithdrawable") {
        None | Some(Value::Null) => 0,
        Some(_) => as_u64(body, "minWithdrawable").ok_or_else(invalid)?,
    };
    if min_withdrawable > max_withdrawable {
        return Err(invalid());
    }
    let mint_pubkey = as_str(body, "mintPubkey");
    if policy.require_signatures && !mint_pubkey.as_deref().is_some_and(is_compressed_pubkey) {
        return Err(Error::Protocol(
            match mint_pubkey {
                None => "this service publishes no mintPubkey, so its notes cannot be verified offline (LUD-25 requires one)",
                Some(_) => "this service published a mintPubkey that is not a 33-byte compressed secp256k1 key",
            }
            .into(),
        ));
    }
    Ok(NoteInfoByHash {
        callback,
        max_withdrawable,
        min_withdrawable,
        default_description: as_str(body, "defaultDescription"),
        mint_pubkey: mint_pubkey.map(|key| key.trim().to_ascii_lowercase()),
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
        node_capacity_msat: as_u64(body, "nodeCapacity"),
        node_num_channels: as_u64(body, "nodeNumChannels"),
        node_num_peers: as_u64(body, "nodeNumPeers"),
        node_uris: as_str_list(body, "nodeUris"),
        sunset_date: as_iso_date(body, "sunsetDate"),
        outstanding_notes_msat: as_u64(body, "outstandingNotesMsat"),
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

// ---- the output-naming variants ----
//
// The mutation behind rotate, split and merge, taking an output the caller
// already holds rather than generating one: what a hardware wallet drives,
// and how a note moves to a Part 2 key.
//
// A k1 input may be a Part 1 secret or a Part 2 `ck1`; the SERVICE tells them
// apart by shape, and both pass through untouched. An output may be a hash or
// a Part 2 `cp1`. LUD-25 renamed the callback's `h`/`h2` to `p1`/`p2`: a hash
// keeps the old names, which every mint that ever took one accepts, and a key
// goes as `p1`/`p2`, which only a Part 2 mint takes anyway. Decided per
// value, never by a version flag, which is the rule lnurl-wallet and the
// TypeScript kit follow too.

fn output_param(
    value: &str,
    hash_name: &'static str,
    key_name: &'static str,
) -> (&'static str, String) {
    let name = if is_cp1(&value.trim().to_ascii_lowercase()) {
        key_name
    } else {
        hash_name
    };
    (name, value.to_string())
}

pub fn rotate_request_with_hash(callback: &str, k1: &str, h: &str) -> Result<Request> {
    Ok(Request::plain(callback_url(
        callback,
        &[("k1", k1.to_string()), output_param(h, "h", "p1")],
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
    params.push(output_param(h, "h", "p1"));
    params.push(output_param(h2, "h2", "p2"));
    Ok(Request::plain(callback_url(callback, &params)?))
}

pub fn merge_request_with_hash(callback: &str, k1s: &[String], h: &str) -> Result<Request> {
    let mut params: Vec<(&str, String)> = k1s.iter().map(|k1| ("k1", k1.clone())).collect();
    params.push(output_param(h, "h", "p1"));
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
pub fn parse_mutation(
    body: &Value,
    kind: MutationKind,
    policy: Policy,
) -> Result<MutationResponse> {
    if let Err(Error::ServiceRejected(reason)) = reject_error(body) {
        return Err(classify_note_error(&reason));
    }
    if body.get("status").and_then(|v| v.as_str()) != Some("OK") {
        return Err(Error::ambiguous(
            "the service did not confirm the operation - it may still have been applied",
        ));
    }
    let signature = as_str(body, "sig").filter(|s| !s.is_empty());
    let change_signature = as_str(body, "sig2").filter(|s| !s.is_empty());
    // Every mutation the replay rule covers owes a signature over each note it
    // mints. The mutation has already landed by the time this is checked -
    // `status` was OK - so the caller of this function must attach the fresh
    // secrets to the error, or enforcing the spec becomes the thing that loses
    // the money. See `Error::with_secrets`.
    if policy.require_signatures {
        let missing = match kind {
            MutationKind::Melt => None,
            MutationKind::Split if signature.is_none() => Some("split"),
            MutationKind::Split if change_signature.is_none() => Some("split's change"),
            MutationKind::Split => None,
            MutationKind::Rotate if signature.is_none() => Some("rotate"),
            MutationKind::Merge if signature.is_none() => Some("merge"),
            _ => None,
        };
        if let Some(what) = missing {
            return Err(Error::unverifiable(format!(
                "the service confirmed the {what} but returned no signature, so the note it just minted cannot be verified offline. The note exists - keep the secret"
            )));
        }
    }
    Ok(MutationResponse {
        signature,
        change_signature,
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
    let withdraw_link = match body.get("withdrawLink") {
        // A withdrawLink that is present but not a string is a broken mint,
        // not a mint without one. Reading it as absent would send the caller
        // down the well-known fallback and quietly mint against the wrong
        // endpoint.
        Some(value) if !value.is_string() => {
            return Err(Error::Protocol(
                "the mint's payRequest has an invalid withdrawLink".into(),
            ))
        }
        _ => as_str(body, "withdrawLink"),
    };
    let comment_allowed = as_u64(body, "commentAllowed");
    // LUD-25: minting is comment-bound. A payRequest that advertises a
    // withdrawLink but no room for the 64-character commitment is offering
    // something it cannot deliver, and the failure would otherwise land after
    // the caller had already paid.
    if withdraw_link.is_some()
        && !comment_allowed.is_some_and(|allowed| allowed >= MINT_COMMENT_LENGTH)
    {
        return Err(Error::Protocol(
            "this mint offers no room for the required output commitment - it cannot mint".into(),
        ));
    }
    Ok(PayRequestInfo {
        callback: as_str(body, "callback").ok_or_else(invalid)?,
        min_sendable: as_u64(body, "minSendable").unwrap_or(0),
        max_sendable: as_u64(body, "maxSendable").unwrap_or(0),
        mint_fee: parse_mint_fee(&metadata),
        metadata,
        withdraw_link,
        mint_pubkey: as_str(body, "mintPubkey"),
        comment_allowed,
        mint_to_hash: body.get("mintToHash").and_then(|v| v.as_bool()) == Some(true),
    })
}

/// A plain LUD-06 invoice request. Correct for paying an ordinary Lightning
/// address; it mints nothing, because it names no output.
///
/// To mint, use [`mint_invoice_request`], which names the note before the
/// invoice exists.
pub fn invoice_request(pay_callback: &str, amount_msat: u64) -> Result<Request> {
    let mut url = url::Url::parse(pay_callback)
        .map_err(|_| Error::RequestRefused("that pay callback does not parse".into()))?;
    url.query_pairs_mut()
        .append_pair("amount", &amount_msat.to_string());
    Ok(Request::plain(url.to_string()))
}

/// Ask for a mint invoice, naming the note it will credit.
///
/// `h` is `sha256(secret)` for a secret only the WALLET holds. LUD-25 carries
/// it as a mandatory LUD-12 `comment`; `h` repeats the identical value for
/// SERVICEs that took the parameter form first, which is what the vectors'
/// `mintToHash` profile pins. It is never an alternative to the comment.
///
/// The SERVICE learns a hash and nothing else, so the payment preimage is
/// settlement proof only - it can never redeem the note. That is the whole
/// point of the current draft: a preimage propagates to every routing node
/// that forwards the payment, and a note keyed by one is a note they can all
/// spend.
///
/// `h` may instead be a Part 2 `cp1`, minting the note to a key. That goes as
/// the comment alone: `h` is a hash-only extension, and a mint may refuse a
/// key under it.
pub fn mint_invoice_request_with_hash(
    pay_callback: &str,
    amount_msat: u64,
    h: &str,
) -> Result<Request> {
    // lowercase for the same reason a note's k1 is normalised: it is bytes,
    // not text, and a SERVICE filing notes under what it was given should be
    // given one spelling of it
    let h = h.trim().to_ascii_lowercase();
    let key = is_cp1(&h);
    // Refused here rather than sent, so a WALLET never pays for a quote the
    // SERVICE was always going to reject.
    if !key && !is_preimage(&h) {
        return Err(Error::RequestRefused(
            "an output commitment must be 32 bytes of hex or a cp1 key - no invoice was requested"
                .into(),
        ));
    }
    let mut url = url::Url::parse(pay_callback)
        .map_err(|_| Error::RequestRefused("that pay callback does not parse".into()))?;
    {
        let mut serializer = url.query_pairs_mut();
        serializer.append_pair("amount", &amount_msat.to_string());
        serializer.append_pair("comment", &h);
        if !key {
            serializer.append_pair("h", &h);
        }
    }
    Ok(Request::plain(url.to_string()))
}

/// [`mint_invoice_request_with_hash`], generating the commitment from the
/// secret the caller will hold the note by.
///
/// The secret comes back on [`Request::new_secrets`]. **Persist it before
/// paying the invoice this returns.** Paying for a note and then losing its
/// secret is the one way the comment-bound scheme is worse than the preimage
/// one it replaced, and persisting first removes it entirely. Drawing the
/// secret from the seed derivation rather than the CSPRNG makes the note
/// recoverable from birth, without any rotate at all.
pub fn mint_invoice_request(
    pay_callback: &str,
    amount_msat: u64,
    mint_secret: &str,
) -> Result<Request> {
    // Checked before hashing, so a malformed secret is RequestRefused - the
    // caller's own input, nothing sent - rather than the Protocol error
    // hash_k1 would raise, which in this crate's taxonomy accuses the SERVICE
    // of a broken response it never sent.
    if !is_preimage(mint_secret) {
        return Err(Error::RequestRefused(
            "a note secret must be 32 bytes of hex - no invoice was requested".into(),
        ));
    }
    let mut request =
        mint_invoice_request_with_hash(pay_callback, amount_msat, &hash_k1(mint_secret)?)?;
    request.new_secrets = vec![mint_secret.to_string()];
    Ok(request)
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

/// LUD-21, to learn whether a mint or melt has settled.
///
/// Under current LUD-25 this is unconditionally safe to call and its answer
/// unconditionally safe to disclose: minting is comment-bound, so the preimage
/// a settled invoice reveals is settlement proof and never the note's
/// credential. (It was not always so. An earlier draft keyed the note by the
/// payment preimage, which made this endpoint hand out the money; that
/// fallback is gone.)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn address(extra: Value) -> Value {
        let mut body = json!({
            "tag": "withdrawRequest",
            "callback": "https://mint.example/w/cb",
            "payLink": "https://mint.example/.well-known/lnurlp/mint",
            "minWithdrawable": 1000u64,
            "maxWithdrawable": 100_000_000u64,
        });
        for (key, value) in extra.as_object().unwrap() {
            body[key] = value.clone();
        }
        body
    }

    #[test]
    fn reads_every_address_the_node_announces() {
        let clearnet = "02aa@2.29.14.244:9735";
        let onion = "02aa@abcdefghijklmnop.onion:9735";
        let info = parse_mint_address(&address(json!({
            "nodeUri": clearnet,
            "nodeUris": [clearnet, onion],
        })))
        .unwrap();

        assert_eq!(
            info.node_uris,
            Some(vec![clearnet.to_string(), onion.to_string()])
        );
        // the singular field is unchanged and still the first address
        assert_eq!(info.node_uri.as_deref(), Some(clearnet));
    }

    #[test]
    fn an_announced_nothing_is_none_not_empty() {
        assert_eq!(
            parse_mint_address(&address(json!({}))).unwrap().node_uris,
            None
        );
        assert_eq!(
            parse_mint_address(&address(json!({"nodeUris": []})))
                .unwrap()
                .node_uris,
            None
        );
        assert_eq!(
            parse_mint_address(&address(json!({"nodeUris": "not a list"})))
                .unwrap()
                .node_uris,
            None
        );
        assert_eq!(
            parse_mint_address(&address(json!({"nodeUris": [1, "a", "", null]})))
                .unwrap()
                .node_uris,
            Some(vec!["a".to_string()])
        );
    }

    #[test]
    fn a_closing_date_is_a_calendar_day_or_nothing() {
        let date = |value: Value| {
            parse_mint_address(&address(json!({"sunsetDate": value})))
                .unwrap()
                .sunset_date
        };
        assert_eq!(date(json!("2026-12-31")), Some("2026-12-31".to_string()));
        assert_eq!(date(json!("2028-02-29")), Some("2028-02-29".to_string()));
        assert_eq!(date(json!("31/12/2026")), None);
        assert_eq!(date(json!("2026-12-31T09:00:00Z")), None);
        // not a real day: February never has 31, and 2026 is not a leap year
        assert_eq!(date(json!("2026-02-31")), None);
        assert_eq!(date(json!("2026-02-29")), None);
        assert_eq!(date(json!("2026-13-01")), None);
        assert_eq!(date(json!("2026-00-10")), None);
        assert_eq!(date(json!("2026-12-00")), None);
        assert_eq!(date(json!(20261231)), None);
        assert_eq!(
            parse_mint_address(&address(json!({}))).unwrap().sunset_date,
            None
        );
    }

    #[test]
    fn what_a_mint_says_it_owes_keeps_zero_distinct_from_silence() {
        let owed = |body: Value| parse_mint_address(&body).unwrap().outstanding_notes_msat;
        assert_eq!(
            owed(address(json!({"outstandingNotesMsat": 48_000u64}))),
            Some(48_000)
        );
        assert_eq!(
            owed(address(json!({"outstandingNotesMsat": 0u64}))),
            Some(0)
        );
        assert_eq!(owed(address(json!({}))), None);
        assert_eq!(
            owed(address(json!({"outstandingNotesMsat": "48000"}))),
            None
        );
    }
}
