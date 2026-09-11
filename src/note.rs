//! Note URLs: parsing what a note claims, and building the next one.

use url::Url;

use crate::recoverable::{is_cp1, note_id_of};
use crate::urls::{from_lud17, resolve_lnurl_input};

fn first_param(url: &str, key: &str) -> Option<String> {
    Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// The secret out of a note URL, normalised to lowercase hex: it is bytes, not
/// text, so casing carries no meaning, and normalising keeps duplicate
/// detection and the echo check on an informational GET from treating the same
/// secret in two casings as two different notes.
pub fn note_k1(url: &str) -> Option<String> {
    first_param(url, "k1").map(|v| v.to_ascii_lowercase())
}

/// What a note CLAIMS to carry. Only a claim by whoever encoded it - a SERVICE
/// ignores it at the informational endpoint - so it is safe to display before
/// contacting the SERVICE but must not be trusted without either a matching
/// signature or a fresh online GET.
pub fn note_declared_amount(url: &str) -> Option<u64> {
    first_param(url, "amount")?.parse().ok()
}

pub fn note_signature(url: &str) -> Option<String> {
    first_param(url, "sig")
}

/// Input only qualifies as a note if it resolves to a URL carrying a
/// well-formed k1: 32 bytes hex, or a Part 2 `ck1` that recovers to a key.
/// Anything else has no note id, and would fail the first offline signature
/// check later, so it is refused at the door.
pub fn resolve_note_input(value: &str) -> Option<String> {
    let url = resolve_lnurl_input(value)?;
    let k1 = note_k1(&url)?;
    note_id_of(&k1).is_some().then_some(url)
}

pub fn is_valid_note_input(value: &str) -> bool {
    resolve_note_input(value).is_some()
}

fn rebuild(url: &Url, pairs: Vec<(String, String)>) -> String {
    let mut out = url.clone();
    out.set_query(None);
    if pairs.is_empty() {
        return out.to_string();
    }
    {
        let mut serializer = out.query_pairs_mut();
        for (key, value) in &pairs {
            serializer.append_pair(key, value);
        }
    }
    out.to_string()
}

/// A withdrawLink plus a secret makes a note. Pass `None` for `amount_msat`
/// when the real value is not known yet: the spec has a SERVICE ignore it here
/// regardless, but some implementations validate it strictly, and a placeholder
/// like 0 risks being rejected rather than ignored.
pub fn build_note_url(withdraw_link: &str, k1: &str, amount_msat: Option<u64>) -> Option<String> {
    let url = Url::parse(&from_lud17(withdraw_link.trim())).ok()?;
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "k1" && k != "amount")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.push(("k1".into(), k1.trim().to_ascii_lowercase()));
    if let Some(amount) = amount_msat {
        pairs.push(("amount".into(), amount.to_string()));
    }
    Some(rebuild(&url, pairs))
}

/// The informational GET for a note named by its HASH rather than its secret.
///
/// LUD-25's "Checking a note without exposing it": a SERVICE MAY accept
/// `?h=<hex sha256 of k1>` in place of `?k1=`, on the informational GET only
/// and never at the callback. It already stores every note under that hash, so
/// this is a second way into a lookup it can do anyway - and the secret stays
/// off the wire, which is what a restore walk needs, since a walk queries a
/// whole gap window of indices the wallet has not minted into yet.
///
/// `k1`, `amount` and `sig` are dropped: naming the note twice, once in a form
/// that spends it, would defeat the point.
///
/// `h` may also be a Part 2 `cp1` key, sent as `p`, the name LUD-25 now uses.
/// A hash keeps the older `h`, which every mint that ever took a hash lookup
/// understands. [`crate::recoverable::note_lookup_of`] gives the right one
/// for either kind of k1.
///
/// A SERVICE that does not index by hash answers exactly as it answers for an
/// unknown `k1`, which LUD-25 requires, so a rejection here never distinguishes
/// "not supported" from "no such note" - and a burned note is deliberately
/// indistinguishable from one that never existed.
pub fn build_note_info_url_by_hash(withdraw_link: &str, h: &str) -> Option<String> {
    let value = h.trim().to_ascii_lowercase();
    let key = is_cp1(&value);
    if !key && (value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let url = Url::parse(&from_lud17(withdraw_link.trim())).ok()?;
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "k1" && k != "amount" && k != "sig")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.push((if key { "p" } else { "h" }.into(), value));
    Some(rebuild(&url, pairs))
}

/// The same note with its secret swapped out, after a rotate, split or merge.
///
/// A signature only carries over when the response actually returned a fresh
/// one: a mutation to a plain hash output, which is unsigned by design, drops
/// any stale sig, since it no longer matches the new secret.
pub fn with_new_k1(
    url: &str,
    k1: &str,
    amount_msat: u64,
    signature: Option<&str>,
) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let mut pairs = Vec::new();
    let (mut saw_k1, mut saw_amount, mut saw_sig) = (false, false, false);
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "k1" => {
                pairs.push(("k1".to_string(), k1.to_ascii_lowercase()));
                saw_k1 = true;
            }
            "amount" => {
                pairs.push(("amount".to_string(), amount_msat.to_string()));
                saw_amount = true;
            }
            "sig" => {
                if let Some(sig) = signature {
                    pairs.push(("sig".to_string(), sig.to_string()));
                    saw_sig = true;
                }
            }
            _ => pairs.push((key.into_owned(), value.into_owned())),
        }
    }
    if !saw_k1 {
        pairs.push(("k1".to_string(), k1.to_ascii_lowercase()));
    }
    if !saw_amount {
        pairs.push(("amount".to_string(), amount_msat.to_string()));
    }
    if let Some(sig) = signature {
        if !saw_sig {
            pairs.push(("sig".to_string(), sig.to_string()));
        }
    }
    Some(rebuild(&parsed, pairs))
}

/// Like [`with_new_k1`] but removes k1 - for re-deriving a hardware-backed
/// note's blank URL template after a mutation whose fresh secret now lives on
/// the device rather than in this process.
pub fn without_k1(url: &str, amount_msat: u64, signature: Option<&str>) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let mut pairs = Vec::new();
    let (mut saw_amount, mut saw_sig) = (false, false);
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "k1" => continue,
            "amount" => {
                pairs.push(("amount".to_string(), amount_msat.to_string()));
                saw_amount = true;
            }
            "sig" => {
                if let Some(sig) = signature {
                    pairs.push(("sig".to_string(), sig.to_string()));
                    saw_sig = true;
                }
            }
            _ => pairs.push((key.into_owned(), value.into_owned())),
        }
    }
    if !saw_amount {
        pairs.push(("amount".to_string(), amount_msat.to_string()));
    }
    if let Some(sig) = signature {
        if !saw_sig {
            pairs.push(("sig".to_string(), sig.to_string()));
        }
    }
    Some(rebuild(&parsed, pairs))
}
