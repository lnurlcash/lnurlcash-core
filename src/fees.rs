//! LUD-25 mint fees (optional).
//!
//! A SERVICE signals what it withholds on minting via an extra
//! `["text/plain", "Mint fees: <base_fee_msat>,<fee_percent_ppm>"]` entry in a
//! payRequest's metadata, so a WALLET can warn the payer up front that the note
//! they end up holding is worth less than the invoice they paid. A SERVICE that
//! omits the entry is fee-free, not unknown.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintFee {
    pub base_fee_msat: u64,
    pub fee_ppm: u64,
}

pub fn parse_mint_fee(metadata: &str) -> Option<MintFee> {
    let entries: Vec<Vec<serde_json::Value>> = serde_json::from_str(metadata).ok()?;
    for entry in entries {
        let Some(kind) = entry.first().and_then(|v| v.as_str()) else {
            continue;
        };
        if kind != "text/plain" {
            continue;
        }
        let Some(text) = entry.get(1).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(rest) = text.strip_prefix("Mint fees:") else {
            continue;
        };
        let mut parts = rest.split(',');
        let (Some(base), Some(ppm), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let (base, ppm) = (base.trim(), ppm.trim());
        if base.is_empty()
            || ppm.is_empty()
            || !base.bytes().all(|b| b.is_ascii_digit())
            || !ppm.bytes().all(|b| b.is_ascii_digit())
        {
            continue;
        }
        let (Ok(base_fee_msat), Ok(fee_ppm)) = (base.parse::<u64>(), ppm.parse::<u64>()) else {
            continue;
        };
        // A fee of 100% or more can never net anything. Refusing it here is also
        // what keeps gross_up_for_mint_fee's search bounded, so a SERVICE cannot
        // stall a caller simply by advertising one.
        if fee_ppm >= 1_000_000 {
            continue;
        }
        // An explicit "Mint fees: 0,0" has exactly the effect of omitting the
        // entry - treat it identically, so callers never have to special-case a
        // fee that is present but withholds nothing.
        if base_fee_msat == 0 && fee_ppm == 0 {
            return None;
        }
        return Some(MintFee {
            base_fee_msat,
            fee_ppm,
        });
    }
    None
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
