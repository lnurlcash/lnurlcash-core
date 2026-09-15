//! LUD-25 Part 2: notes keyed by a public key and spent by a Schnorr proof.
//!
//! A Part 2 note is filed under a public key rather than a hash. The holder
//! keeps `sk`, discloses `pk` as `cp1<pk>`, and spends the note with `ck1`, a
//! BIP-340 signature by `sk` over a fixed message, paired with `pk`: the
//! SERVICE verifies the pair and looks the note up by `pk`. It certifies each note with
//! `cs1`, the same signature it has always made, over `hex(pk)` instead of a
//! hash. Its human-readable part also carries the signed amount using BOLT-11
//! amount rules, so a recipient can check issuance offline with nothing but
//! the `ck1` and the `cs1` (see [`crate::signature`]).
//!
//! The names and semantics follow the TypeScript kit, which follows
//! lnurl-wallet's `src/lib`. Where the draft's text and that code disagree,
//! this follows the code: see [`derive_cash_address_node`].

use bech32::{FromBase32, ToBase32, Variant};
use hmac::{Hmac, Mac};
use k256::schnorr::{Signature as SchnorrSignature, SigningKey, VerifyingKey};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Keypair, Message, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::cash::{derive_cash_child, derive_cash_domain_node, derive_cash_root, CashNode};
use crate::errors::{Error, Result};
use crate::secrets::{hash_k1, is_preimage};
use crate::signature::lightning_signed_digest;

type HmacSha256 = Hmac<Sha256>;

// ---- bech32m ----
//
// Each type has a fixed payload length, so there is no length limit to pick:
// `ck1`, `cs1` and `cx1` all run past BIP-173's 90 characters, which the draft
// deliberately does not adopt, and bech32 0.9 enforces none. BIP-350's own
// rules do apply, as lnurl-mint applies them: one case throughout (all
// uppercase is the same string, mixed case is refused), a bech32m checksum
// rather than a bech32 one, and zero padding bits.

fn encode_fixed(hrp: &str, bytes: &[u8]) -> String {
    bech32::encode(hrp, bytes.to_base32(), Variant::Bech32m)
        .expect("a fixed, valid human-readable part")
}

/// Never panics: anything that is not exactly this type, at exactly this
/// length, is a `None`.
fn decode_fixed<const N: usize>(hrp: &str, value: &str) -> Option<[u8; N]> {
    let (prefix, words, variant) = bech32::decode(value.trim()).ok()?;
    if prefix != hrp || variant != Variant::Bech32m {
        return None;
    }
    // non-zero padding bits, or a whole spare group of them, fail here
    Vec::<u8>::from_base32(&words).ok()?.try_into().ok()
}

/// A note's public key, 32-byte x-only (BIP-340), as a `cp1`. What a WALLET
/// discloses as an output, and what a SERVICE files the note under.
pub fn encode_cp1(pubkey_x_only: &[u8; 32]) -> String {
    encode_fixed("cp", pubkey_x_only)
}

pub fn decode_cp1(value: &str) -> Option<[u8; 32]> {
    decode_fixed("cp", value)
}

pub fn is_cp1(value: &str) -> bool {
    decode_cp1(value).is_some()
}

/// A note's bearer secret: its 32-byte x-only public key followed by its
/// 64-byte BIP-340 signature, as a `ck1`. Whoever has it can spend the note.
pub fn encode_ck1(payload: &[u8; 96]) -> String {
    encode_fixed("ck", payload)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedCk1 {
    Current([u8; 96]),
    /// Pre-Schnorr recoverable-ECDSA bearer, accepted only so existing notes
    /// remain spendable long enough to rotate into the current format.
    Legacy([u8; 65]),
}

impl DecodedCk1 {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Current(payload) => payload,
            Self::Legacy(signature) => signature,
        }
    }
}

pub fn decode_ck1(value: &str) -> Option<DecodedCk1> {
    decode_fixed("ck", value)
        .map(DecodedCk1::Current)
        .or_else(|| decode_fixed("ck", value).map(DecodedCk1::Legacy))
}

pub fn is_ck1(value: &str) -> bool {
    decode_ck1(value).is_some()
}

/// A decoded current `cs1`: the amount committed in its human-readable part
/// and the mint's raw 65-byte recoverable signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cs1 {
    pub amount_msat: u64,
    pub signature: [u8; 65],
}

fn encode_amount_suffix(amount_msat: u64) -> String {
    for (suffix, unit) in [
        ("", 100_000_000_000u64),
        ("m", 100_000_000u64),
        ("u", 100_000u64),
        ("n", 100u64),
    ] {
        if amount_msat % unit == 0 {
            return format!("{}{suffix}", amount_msat / unit);
        }
    }
    // One pico-BTC unit is 0.1 msat. u128 keeps amount * 10 safe for every
    // u64 amount before it is rendered as decimal digits.
    format!("{}p", u128::from(amount_msat) * 10)
}

fn decode_amount_suffix(value: &str) -> Option<u64> {
    let (digits, unit) = match value.as_bytes().last().copied() {
        Some(b'm') => (&value[..value.len() - 1], 'm'),
        Some(b'u') => (&value[..value.len() - 1], 'u'),
        Some(b'n') => (&value[..value.len() - 1], 'n'),
        Some(b'p') => (&value[..value.len() - 1], 'p'),
        _ => (value, '\0'),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = digits.parse::<u128>().ok()?;
    let amount = match unit {
        '\0' => digits.checked_mul(100_000_000_000)?,
        'm' => digits.checked_mul(100_000_000)?,
        'u' => digits.checked_mul(100_000)?,
        'n' => digits.checked_mul(100)?,
        'p' if digits % 10 == 0 => digits / 10,
        'p' => return None,
        _ => unreachable!(),
    };
    amount.try_into().ok()
}

/// Legacy fixed-HRP certificate, retained for compatibility with notes made
/// before the amount moved into `cs1`. New code should use
/// [`encode_cs1_with_amount`].
pub fn encode_cs1(signature: &[u8; 65]) -> String {
    encode_fixed("cs", signature)
}

pub fn decode_cs1(value: &str) -> Option<[u8; 65]> {
    decode_fixed("cs", value)
}

pub fn is_cs1(value: &str) -> bool {
    decode_cs1(value).is_some()
}

/// A SERVICE's current issuance certificate. The HRP is `cs` followed by
/// the signed amount using BOLT-11's amount suffix rules; the payload is the
/// mint's 65-byte recoverable signature over that amount and the note key.
pub fn encode_cs1_with_amount(amount_msat: u64, signature: &[u8; 65]) -> String {
    encode_fixed(
        &format!("cs{}", encode_amount_suffix(amount_msat)),
        signature,
    )
}

pub fn decode_cs1_with_amount(value: &str) -> Option<Cs1> {
    let trimmed = value.trim();
    let separator = trimmed.rfind('1')?;
    let hrp = trimmed[..separator].to_ascii_lowercase();
    let amount_msat = decode_amount_suffix(hrp.strip_prefix("cs")?)?;
    let signature = decode_fixed(&hrp, trimmed)?;
    Some(Cs1 {
        amount_msat,
        signature,
    })
}

pub fn is_cs1_with_amount(value: &str) -> bool {
    decode_cs1_with_amount(value).is_some()
}

/// The raw signature from either current or legacy `cs1` form.
pub fn decode_any_cs1(value: &str) -> Option<[u8; 65]> {
    decode_cs1_with_amount(value)
        .map(|cs1| cs1.signature)
        .or_else(|| decode_cs1(value))
}

pub fn is_any_cs1(value: &str) -> bool {
    decode_any_cs1(value).is_some()
}

/// A watch-only branch export: the branch's x-only public key and its chain
/// code. Whoever holds one can derive every note key on the branch, and link
/// them all to each other, but can spend none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cx1 {
    pub pubkey_x_only: [u8; 32],
    pub chain_code: [u8; 32],
}

pub fn encode_cx1(pubkey_x_only: &[u8; 32], chain_code: &[u8; 32]) -> String {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(pubkey_x_only);
    bytes[32..].copy_from_slice(chain_code);
    encode_fixed("cx", &bytes)
}

pub fn decode_cx1(value: &str) -> Option<Cx1> {
    let bytes: [u8; 64] = decode_fixed("cx", value)?;
    let mut pubkey_x_only = [0u8; 32];
    let mut chain_code = [0u8; 32];
    pubkey_x_only.copy_from_slice(&bytes[..32]);
    chain_code.copy_from_slice(&bytes[32..]);
    Some(Cx1 {
        pubkey_x_only,
        chain_code,
    })
}

pub fn is_cx1(value: &str) -> bool {
    decode_cx1(value).is_some()
}

// ---- the per-note key tweak ----
//
//   t    = tagged_hash("LNURLcash/derive", P || chainCode || ser32_be(i))
//   pk_i = x(lift_x(P) + t*G)
//   sk_i = ((P has even y ? p : n - p) + t) mod n
//
// BIP-341's taproot tweak, so a watcher holding only the `cx1` computes the
// same `pk_i` the holder does, and libsecp256k1 already implements both
// halves of it. `i` is any u32 and is never hardened. The 4-byte big-endian
// width is what lnurl-wallet and lnurl-mint both use; the draft text does not
// pin it.

const NOTE_DERIVE_TAG: &[u8] = b"LNURLcash/derive";

fn unusable(index: u32) -> Error {
    Error::Protocol(format!(
        "note index {index} is unusable on this branch - use the next index"
    ))
}

fn tweak_for(pubkey_x_only: &[u8; 32], chain_code: &[u8; 32], index: u32) -> Result<Scalar> {
    let tag = Sha256::digest(NOTE_DERIVE_TAG);
    let t: [u8; 32] = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(pubkey_x_only)
        .chain_update(chain_code)
        .chain_update(index.to_be_bytes())
        .finalize()
        .into();
    // BIP-341 refuses t >= n rather than reducing it, and so does lnurl-mint.
    // A ~2^-128 event, but a key reduced here is one no watcher derives, and
    // a note minted to it is a note nobody can find.
    Scalar::from_be_bytes(t).map_err(|_| unusable(index))
}

/// A note's public key at `index`, from the `cx1` half of a branch alone.
///
/// Watch-only: no private key anywhere, which is what lets a SERVICE holding a
/// registered `cx1` mint straight to the holder's next key.
pub fn derive_note_pubkey(
    branch_pubkey_x_only: &[u8; 32],
    chain_code: &[u8; 32],
    index: u32,
) -> Result<[u8; 32]> {
    let secp = Secp256k1::verification_only();
    let branch = XOnlyPublicKey::from_slice(branch_pubkey_x_only)
        .map_err(|_| Error::Protocol("a branch key is not an x-only secp256k1 point".into()))?;
    let tweak = tweak_for(branch_pubkey_x_only, chain_code, index)?;
    // lift_x(P) + t*G, refusing the point at infinity
    let (note, _parity) = branch
        .add_tweak(&secp, &tweak)
        .map_err(|_| unusable(index))?;
    Ok(note.serialize())
}

/// The holder's half: the secret key behind [`derive_note_pubkey`].
///
/// The branch key's own point may have odd y, and a `cx1` only carries x,
/// which names the even-y point, so the key is negated first or its note keys
/// would not match what a watcher derives. libsecp256k1's x-only keypair tweak
/// does exactly that, and refuses a zero result.
pub fn derive_note_secret_key(
    branch_private_key: &[u8; 32],
    chain_code: &[u8; 32],
    index: u32,
) -> Result<[u8; 32]> {
    let secp = Secp256k1::new();
    let branch = Keypair::from_seckey_slice(&secp, branch_private_key).map_err(|_| {
        Error::Protocol("a branch private key is a 32-byte scalar in [1, n)".into())
    })?;
    let (branch_x, _parity) = branch.x_only_public_key();
    let tweak = tweak_for(&branch_x.serialize(), chain_code, index)?;
    let note = branch
        .add_xonly_tweak(&secp, &tweak)
        .map_err(|_| unusable(index))?;
    Ok(note.secret_bytes())
}

// ---- ownership proofs ----
//
//   sig = BIP340.Sign(sk, "LNURLcash")
//   ck1 = bech32m("ck", pk || sig)
//
// One fixed message and fixed all-zero BIP-340 auxiliary input make the bearer
// value deterministic: re-deriving a key reproduces its one `ck1` byte for byte.

const NOTE_OWNERSHIP_MESSAGE: &[u8] = b"LNURLcash";
const LEGACY_NOTE_OWNERSHIP_MESSAGE: &str = "LNURLcash";

/// The raw message every ownership signature is made over.
pub fn note_ownership_message() -> &'static [u8] {
    NOTE_OWNERSHIP_MESSAGE
}

/// The 96-byte `pk || sig` ownership payload. Encode it with [`encode_ck1`]
/// for the wire: that string spends the note, so it is as secret as the key.
pub fn sign_note_ownership(secret_key: &[u8; 32]) -> Result<[u8; 96]> {
    let key = SigningKey::from_bytes(secret_key)
        .map_err(|_| Error::Protocol("a note secret key is a 32-byte scalar in [1, n)".into()))?;
    let signature = key
        .sign_raw(NOTE_OWNERSHIP_MESSAGE, &[0u8; 32])
        .map_err(|_| Error::Protocol("could not sign the note ownership message".into()))?;
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(&key.verifying_key().to_bytes());
    out[32..].copy_from_slice(signature.to_bytes().as_ref());
    Ok(out)
}

/// Validate a `pk || sig` ownership payload and return its embedded x-only
/// public key. `None` for an invalid proof or wrong length.
pub fn recover_note_ownership_pubkey(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.len() == 96 {
        let key = VerifyingKey::from_bytes(&payload[..32]).ok()?;
        let signature = SchnorrSignature::try_from(&payload[32..]).ok()?;
        key.verify_raw(NOTE_OWNERSHIP_MESSAGE, &signature).ok()?;
        return payload[..32].try_into().ok();
    }
    if payload.len() != 65 {
        return None;
    }
    let recovery = RecoveryId::from_i32(i32::from(payload[64])).ok()?;
    let signature = RecoverableSignature::from_compact(&payload[..64], recovery).ok()?;
    let key = Secp256k1::verification_only()
        .recover_ecdsa(
            &Message::from_digest(lightning_signed_digest(LEGACY_NOTE_OWNERSHIP_MESSAGE)),
            &signature,
        )
        .ok()?;
    Some(key.x_only_public_key().0.serialize())
}

// ---- a note's k1, either kind ----

/// The verified key embedded in a `ck1`, from a k1 already trimmed and lowercased.
fn part2_key_of(value: &str) -> Option<[u8; 32]> {
    recover_note_ownership_pubkey(decode_ck1(value)?.as_bytes())
}

/// The id a SERVICE files a note under: sha256(k1) as hex for a Part 1 secret,
/// the verified public key as hex for a Part 2 `ck1`, and `None` for anything
/// else, an invalid `ck1` included.
///
/// Compare notes by this, never by an unverified payload.
///
/// The k1 is lowercased first, the way [`crate::note::note_k1`] normalises
/// every k1, so casing never makes one note into two.
pub fn note_id_of(k1: &str) -> Option<String> {
    let value = k1.trim().to_ascii_lowercase();
    if is_preimage(&value) {
        return hash_k1(&value).ok();
    }
    part2_key_of(&value).map(hex::encode)
}

/// What to look a note up by without disclosing it: the hash for a Part 1
/// secret, and the `cp1` for a Part 2 note. Pass it to
/// [`crate::note::build_note_info_url_by_hash`], which sends a hash as `h` and
/// a `cp1` as `p`.
pub fn note_lookup_of(k1: &str) -> Option<String> {
    let value = k1.trim().to_ascii_lowercase();
    if is_preimage(&value) {
        return hash_k1(&value).ok();
    }
    part2_key_of(&value).map(|key| encode_cp1(&key))
}

// ---- the address branch ----

/// `m/139'/1'`: the node the address branches of every mint hang off.
const ADDRESS_PURPOSE: u32 = 1 + 0x8000_0000;

/// `m/139'/1'/d1/d2/d3/d4` for one mint, with `d1..d4` the four raw
/// big-endian uint32 of HMAC-SHA256(key = the private key at `m/139'/1'/0`,
/// msg = host), used exactly as they fall, as in [`crate::cash`].
///
/// This is lnurl-wallet's path, and the one every implementation uses. The
/// draft's text roots the branch at `m/139'/d1..d4` with the hashing key at
/// `m/139'/0`, which is the very node [`derive_cash_domain_node`] already
/// derives for Part 1 secrets, so a wallet following the text would find none
/// of the reference wallet's notes.
///
/// Bearer material for every note on the branch. Hand out
/// [`cash_node_to_cx1`] of it, never the node.
pub fn derive_cash_address_node(root: &CashNode, host: &str) -> Result<CashNode> {
    derive_cash_domain_node(&derive_cash_child(root, ADDRESS_PURPOSE)?, host)
}

/// The watch-only half of a branch node.
pub fn cash_node_to_cx1(node: &CashNode) -> Result<Cx1> {
    let secp = Secp256k1::signing_only();
    let key = SecretKey::from_slice(&node.private_key)
        .map_err(|_| Error::Protocol("cash node holds an invalid private key".into()))?;
    let (pubkey, _parity) = key.x_only_public_key(&secp);
    Ok(Cx1 {
        pubkey_x_only: pubkey.serialize(),
        chain_code: node.chain_code,
    })
}

// ---- a branch rooted in a Nostr key ----
//
// An extension, not LUD-25. A lightning address on a Nostr-native mint
// belongs to an npub, and a holder with no BIP-39 words (a hardware signer
// that keeps only its identity key, or a wallet that never made any) can
// still be paid to keys of its own:
//
//   seed = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
//
// then the address path above from that seed, unchanged. The TypeScript kit
// derives the same branch, and so does at least one hardware signer. The
// identity key rebuilds every note paid to the branch, so whoever can restore
// that key can recover the notes, with or without the device that received
// them. A mint sees an ordinary `cx1` either way.

pub const NOSTR_CASH_SEED_LABEL: &str = "LNURLcash/nostr-seed";

/// Bearer material: the seed every note on the identity's branches grows
/// from.
pub fn derive_nostr_cash_seed(secret_key: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret_key).expect("HMAC takes a key of any length");
    mac.update(NOSTR_CASH_SEED_LABEL.as_bytes());
    mac.finalize().into_bytes().into()
}

/// One mint's address branch for a Nostr identity. Bearer material, like any
/// address node: hand out [`cash_node_to_cx1`] of it.
pub fn derive_nostr_address_node(secret_key: &[u8; 32], host: &str) -> Result<CashNode> {
    let mut seed = derive_nostr_cash_seed(secret_key);
    let root = derive_cash_root(&seed);
    seed.fill(0);
    derive_cash_address_node(&root?, host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cash::cash_node_to_hex;

    const SEED: [u8; 32] = [0x42; 32];

    fn words_of(value: &str) -> (String, Vec<bech32::u5>) {
        let (hrp, words, _) = bech32::decode(value).expect("a valid string");
        (hrp, words)
    }

    fn samples() -> [(&'static str, String); 4] {
        let ownership = sign_note_ownership(&[0x11; 32]).expect("a valid key");
        let pubkey = recover_note_ownership_pubkey(&ownership).expect("verifies");
        [
            ("cp", encode_cp1(&pubkey)),
            ("ck", encode_ck1(&ownership)),
            ("cs", encode_cs1_with_amount(21_000, &[0x33; 65])),
            ("cx", encode_cx1(&pubkey, &[0x22; 32])),
        ]
    }

    fn decodes(hrp: &str, value: &str) -> bool {
        match hrp {
            "cp" => is_cp1(value),
            "ck" => is_ck1(value),
            "cs" => is_cs1_with_amount(value),
            "cx" => is_cx1(value),
            _ => unreachable!(),
        }
    }

    #[test]
    fn every_type_round_trips_and_runs_past_ninety_characters() {
        for (hrp, value) in samples() {
            assert!(decodes(hrp, &value), "{value}");
            if hrp != "cp" {
                assert!(value.len() > 90, "{hrp}: no limit to hide behind");
            }
        }
    }

    #[test]
    fn all_uppercase_is_the_same_string_and_mixed_case_is_not() {
        for (hrp, value) in samples() {
            assert!(decodes(hrp, &value.to_ascii_uppercase()), "{hrp}");
            let mut mixed = value.clone();
            mixed.replace_range(..3, &value[..3].to_ascii_uppercase());
            assert!(!decodes(hrp, &mixed), "{hrp}: mixed case");
        }
    }

    #[test]
    fn a_bech32_checksum_is_not_a_bech32m_one() {
        for (hrp, value) in samples() {
            let (_, words) = words_of(&value);
            let classic = bech32::encode(hrp, words, Variant::Bech32).expect("encodes");
            assert!(!decodes(hrp, &classic), "{hrp}");
        }
    }

    #[test]
    fn non_zero_padding_is_refused() {
        // 32, 64 and 96 bytes leave spare bits in the last five-bit group,
        // which must be zero. 65-byte cs1 fills its groups exactly.
        for (hrp, value) in samples() {
            if hrp == "cs" {
                continue;
            }
            let (_, mut words) = words_of(&value);
            let last = words.len() - 1;
            assert_eq!(
                words[last].to_u8() & 1,
                0,
                "{hrp}: a valid string pads with zero"
            );
            words[last] = bech32::u5::try_from_u8(words[last].to_u8() | 1).expect("five bits");
            let forged = bech32::encode(hrp, words, Variant::Bech32m).expect("encodes");
            assert!(!decodes(hrp, &forged), "{hrp}: padding");
        }
    }

    #[test]
    fn decoders_refuse_hostile_input_without_panicking() {
        let long = format!("cp1{}", "q".repeat(10_000));
        for value in [
            "",
            "1",
            "cp1",
            "cp1q",
            "ck1\u{e9}\u{e9}\u{e9}",
            "\u{1f4b8}1qqqqqq",
            "cp1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            long.as_str(),
        ] {
            for hrp in ["cp", "ck", "cs", "cx"] {
                assert!(!decodes(hrp, value), "{hrp}: {value:?}");
            }
            assert_eq!(note_id_of(value), None);
            assert_eq!(note_lookup_of(value), None);
        }
        assert_eq!(recover_note_ownership_pubkey(&[]), None);
        assert_eq!(recover_note_ownership_pubkey(&[0xff; 96]), None);
    }

    #[test]
    fn tells_the_four_types_apart() {
        let samples = samples();
        for (hrp, value) in &samples {
            for (other, _) in &samples {
                assert_eq!(decodes(other, value), hrp == other, "{other} of {value}");
            }
        }
        let k1 = "11".repeat(32);
        for hrp in ["cp", "ck", "cs", "cx"] {
            assert!(!decodes(hrp, &k1), "a plain hex k1 is never a {hrp}1");
        }
    }

    #[test]
    fn a_truncated_or_corrupted_signature_is_not_the_note() {
        let signature = sign_note_ownership(&[0x11; 32]).expect("a valid key");
        let pubkey = recover_note_ownership_pubkey(&signature);
        assert_eq!(recover_note_ownership_pubkey(&signature[..95]), None);
        let mut corrupted = signature;
        corrupted[10] ^= 0xff;
        assert_ne!(recover_note_ownership_pubkey(&corrupted), pubkey);
    }

    #[test]
    fn one_key_reproduces_one_ck1() {
        let a = sign_note_ownership(&[0x11; 32]).expect("a valid key");
        let b = sign_note_ownership(&[0x11; 32]).expect("a valid key");
        assert_eq!(a, b);
        assert_eq!(encode_ck1(&a), encode_ck1(&b));
    }

    #[test]
    fn a_legacy_ck1_stays_readable_for_rotation() {
        let secret = SecretKey::from_slice(&[0x11; 32]).expect("a valid key");
        let signature = Secp256k1::signing_only().sign_ecdsa_recoverable(
            &Message::from_digest(lightning_signed_digest(LEGACY_NOTE_OWNERSHIP_MESSAGE)),
            &secret,
        );
        let (recovery, compact) = signature.serialize_compact();
        let mut payload = [0u8; 65];
        payload[..64].copy_from_slice(&compact);
        payload[64] = recovery.to_i32() as u8;
        let ck1 = encode_fixed("ck", &payload);

        assert_eq!(decode_ck1(&ck1), Some(DecodedCk1::Legacy(payload)));
        assert!(is_ck1(&ck1));
        assert_eq!(
            note_id_of(&ck1),
            Some(hex::encode(
                secret.x_only_public_key(&Secp256k1::new()).0.serialize()
            ))
        );
    }

    #[test]
    fn signing_refuses_a_key_outside_the_curve_order() {
        assert!(sign_note_ownership(&[0; 32]).is_err());
        assert!(sign_note_ownership(&[0xff; 32]).is_err());
        assert!(derive_note_secret_key(&[0; 32], &[0; 32], 0).is_err());
        // above the field prime, so not an x coordinate at all
        assert!(derive_note_pubkey(&[0xff; 32], &[0; 32], 0).is_err());
    }

    #[test]
    fn the_address_branch_never_shares_a_node_with_the_part1_ladder() {
        let root = derive_cash_root(&SEED).expect("root");
        let address = derive_cash_address_node(&root, "mint.example").expect("address node");
        let domain = derive_cash_domain_node(&root, "mint.example").expect("domain node");
        assert_ne!(cash_node_to_hex(&address), cash_node_to_hex(&domain));
    }

    #[test]
    fn a_watcher_and_the_holder_agree_on_every_note_key() {
        let root = derive_cash_root(&SEED).expect("root");
        let node = derive_cash_address_node(&root, "mint.example").expect("address node");
        let cx1 = cash_node_to_cx1(&node).expect("cx1");
        for index in [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let pubkey =
                derive_note_pubkey(&cx1.pubkey_x_only, &cx1.chain_code, index).expect("pubkey");
            let secret =
                derive_note_secret_key(&node.private_key, &node.chain_code, index).expect("sk");
            let signature = sign_note_ownership(&secret).expect("signs");
            assert_eq!(
                recover_note_ownership_pubkey(&signature),
                Some(pubkey),
                "{index}"
            );
        }
    }

    #[test]
    fn a_nostr_branch_is_the_address_path_from_its_seed() {
        let identity = [0x07; 32];
        let seed = derive_nostr_cash_seed(&identity);
        let expected =
            derive_cash_address_node(&derive_cash_root(&seed).expect("root"), "moneyer.dev")
                .expect("address node");
        let node = derive_nostr_address_node(&identity, "moneyer.dev").expect("nostr node");
        assert_eq!(cash_node_to_hex(&node), cash_node_to_hex(&expected));
    }
}
