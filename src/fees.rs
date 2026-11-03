//! LUD-25 mint fees (optional), and LUD-26's address fee.
//!
//! A SERVICE signals what it withholds on minting with a
//! `Mint fees: <base_fee_msat>,<fee_ppm>` token anywhere in its payRequest's
//! `text/plain` metadata entry, so a WALLET can warn the payer up front that
//! the note they end up holding is worth less than the invoice they paid. The
//! values are plain base-10 integers separated by commas, ending at
//! whitespace or the end of the entry. A third value is LUD-26's address fee,
//! what registering one Lightning Address costs. A SERVICE without the token
//! is fee-free, not unknown.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintFee {
    pub base_fee_msat: u64,
    pub fee_ppm: u64,
    /// LUD-26's third value: the fee per Lightning Address registration.
    /// `None` when it is not advertised, or does not parse; either way a
    /// WALLET should refuse to pay a registration invoice it was not told
    /// about.
    #[serde(default)]
    pub address_fee_msat: Option<u64>,
}

const TOKEN: &str = "Mint fees:";

// Above 2^53 most languages lose integer precision, and a fee read wrong is
// worse than no fee: refuse it rather than estimate with a mangled value.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn value_of(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= MAX_SAFE_INTEGER)
}

// The token's values: after "Mint fees:" and any spaces, up to the next
// whitespace. `None` when the first two do not parse, which LUD-25 calls an
// unknown fee: a WALLET relies on maxWithdrawable alone.
fn parse_token(text: &str) -> Option<MintFee> {
    let at = text.find(TOKEN)?;
    let rest = text[at + TOKEN.len()..].trim_start();
    let values = rest.split(char::is_whitespace).next().unwrap_or_default();
    let mut parts = values.split(',');
    let base_fee_msat = value_of(parts.next()?)?;
    let fee_ppm = value_of(parts.next()?)?;
    // A fee of 100% or more can never net anything. Refusing it here is also
    // what keeps gross_up_for_mint_fee's search bounded, so a SERVICE cannot
    // stall a caller simply by advertising one.
    if fee_ppm >= 1_000_000 {
        return None;
    }
    let address_fee_msat = parts.next().and_then(value_of);
    Some(MintFee {
        base_fee_msat,
        fee_ppm,
        address_fee_msat,
    })
}

/// The first parseable `Mint fees` token in a payRequest's `text/plain`
/// entries. `None` when there is none, which is fee-free, when it does not
/// parse, which is a fee the WALLET does not know, and when every value is
/// zero, so a caller never has to special-case a fee that withholds nothing.
pub fn parse_mint_fee(metadata: &str) -> Option<MintFee> {
    let entries: Vec<Vec<serde_json::Value>> = serde_json::from_str(metadata).ok()?;
    let fee = entries
        .iter()
        .filter(|entry| entry.first().and_then(|v| v.as_str()) == Some("text/plain"))
        .filter_map(|entry| entry.get(1).and_then(|v| v.as_str()))
        .find_map(parse_token)?;
    if fee.base_fee_msat == 0 && fee.fee_ppm == 0 && fee.address_fee_msat.unwrap_or(0) == 0 {
        return None;
    }
    Some(fee)
}

/// `floor(gross * ppm / 1_000_000)`, computed so it cannot overflow.
///
/// The obvious `gross * ppm` is wrong at realistic amounts: 21M BTC is 2.1e15
/// msat, and at 999_999 ppm the product is about 2.1e21 - past `u64::MAX` at
/// 1.8e19. Splitting the multiplication keeps both halves small: the quotient
/// half reaches at most 2.1e15, the remainder half at most 1e12.
///
/// This is the single most likely thing for a port of this crate to get wrong,
/// because a naive version passes every small test.
fn proportional_fee(gross_msat: u64, fee_ppm: u64) -> u64 {
    (gross_msat / 1_000_000) * fee_ppm + ((gross_msat % 1_000_000) * fee_ppm) / 1_000_000
}

/// What a SERVICE is expected to credit after withholding its advertised fee.
/// Only ever an estimate to show before paying: the authoritative value is
/// whatever the informational GET reports once the note is claimed.
pub fn apply_mint_fee(gross_msat: u64, fee: MintFee) -> u64 {
    gross_msat
        .saturating_sub(fee.base_fee_msat)
        .saturating_sub(proportional_fee(gross_msat, fee.fee_ppm))
}

/// The SMALLEST invoice amount whose note nets `net_msat` after the fee.
///
/// [`apply_mint_fee`] is non-decreasing in gross with per-msat steps of 0 or 1
/// (the proportional term grows by at most 1 per msat, since ppm is below
/// 1_000_000), so the minimal such gross exists and binary search finds it
/// exactly. The tempting alternative - estimate linearly, then walk one msat at
/// a time - is both unbounded and wrong at the edge: at 999_999 ppm the walk is
/// roughly a million steps, so any guard on it returns a non-minimal answer,
/// and the SERVICE picks the fee.
pub fn gross_up_for_mint_fee(net_msat: u64, fee: MintFee) -> u64 {
    if net_msat == 0 {
        return 0;
    }
    let mut hi = net_msat.saturating_add(fee.base_fee_msat).max(1);
    while apply_mint_fee(hi, fee) < net_msat {
        match hi.checked_mul(2) {
            Some(doubled) => hi = doubled,
            // unreachable with ppm < 1_000_000, but a saturating fallback is
            // better than a panic in a library holding somebody's money
            None => return u64::MAX,
        }
    }
    let mut lo = 0u64;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if apply_mint_fee(mid, fee) >= net_msat {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

/// ppm is parts per million: /10_000 for a percent, then trim the trailing
/// zeros (2000 ppm -> "0.2000" -> "0.2")
pub fn format_fee_percent(ppm: u64) -> String {
    let text = format!("{:.4}", ppm as f64 / 10_000.0);
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn describe_mint_fee(fee: MintFee) -> String {
    let mut parts = Vec::new();
    if fee.base_fee_msat > 0 {
        parts.push(format!("{} sat flat", (fee.base_fee_msat + 500) / 1000));
    }
    if fee.fee_ppm > 0 {
        parts.push(format!(
            "{}% of the amount paid",
            format_fee_percent(fee.fee_ppm)
        ));
    }
    parts.join(" + ")
}
