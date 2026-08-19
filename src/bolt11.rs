//! Only what a caller needs to bind a SERVICE's response to the payment it
//! asked for. No full TLV decode: the amount lives in the human-readable part,
//! and equality is a normalised string compare.

/// A loose shape check, anchored to actual bolt11 prefixes rather than a bare
/// "ln", which a bech32 LNURL would also match.
///
/// Split at the separator first, exactly as the decoder does. Scanning left to
/// right instead is subtly wrong: an amountless invoice's separator IS a digit,
/// so a greedy digit scan swallows it and then finds no separator at all. The
/// equivalent regex gets away with it only because it backtracks.
pub fn is_bolt11_invoice(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    let Some((hrp, data)) = split_at_separator(&lowered) else {
        return false;
    };
    if data.is_empty()
        || !data
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }
    parse_hrp(hrp).is_some()
}

/// bolt11 is bech32, so case-insensitive. Used to bind a verify response, or a
/// melt proof, to the exact invoice it claims to report on - a settled result
/// for some OTHER invoice must never confirm this payment.
pub fn same_invoice(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

fn strip_network_prefix(lowered: &str) -> Option<&str> {
    let rest = lowered.strip_prefix("ln")?;
    // longest first: "bcrt" must win over "bc"
    for prefix in ["bcrt", "bc", "tbs", "tb", "sb"] {
        if let Some(tail) = rest.strip_prefix(prefix) {
            return Some(tail);
        }
    }
    None
}

/// The bech32 separator is the LAST '1' in the string, since data characters
/// can be '1' too.
fn split_at_separator(lowered: &str) -> Option<(&str, &str)> {
    let separator = lowered.rfind('1')?;
    if separator < 2 {
        return None;
    }
    Some((&lowered[..separator], &lowered[separator + 1..]))
}

/// The human-readable part after "ln" and the network: an optional amount and
/// an optional multiplier, and nothing else.
fn parse_hrp(hrp: &str) -> Option<(Option<u64>, &str)> {
    let rest = strip_network_prefix(hrp)?;
    let digits_end = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let (digits, multiplier) = rest.split_at(digits_end);
    if !matches!(multiplier, "" | "m" | "u" | "n" | "p") {
        return None;
    }
    let amount = if digits.is_empty() {
        None
    } else {
        Some(digits.parse().ok()?)
    };
    Some((amount, multiplier))
}

/// The amount out of an invoice's human-readable part.
///
/// The bech32 separator is the LAST '1' in the string, since data characters
/// can be '1' too. `None` for an amountless invoice, for anything that does not
/// parse, and for a pico amount that is not a whole number of msat.
pub fn decode_bolt11_amount_msat(pr: &str) -> Option<u64> {
    let trimmed = pr.trim().to_ascii_lowercase();
    let (hrp, _data) = split_at_separator(&trimmed)?;
    let (amount, multiplier) = parse_hrp(hrp)?;
    let value = amount?;
    match multiplier {
        "" => value.checked_mul(100_000_000_000),
        "m" => value.checked_mul(100_000_000),
        "u" => value.checked_mul(100_000),
        "n" => value.checked_mul(100),
        // 1 pico-BTC is 0.1 msat, so only multiples of 10 are whole msat
        "p" => (value % 10 == 0).then_some(value / 10),
        _ => None,
    }
}
