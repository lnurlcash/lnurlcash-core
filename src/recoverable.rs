//! LUD-25 Part 2: notes keyed by a public key and spent by a recoverable
//! signature.
//!
//! A Part 2 note is filed under a public key rather than a hash. The holder
//! keeps `sk`, discloses `pk` as `cp1<pk>`, and spends the note with `ck1`, a
//! recoverable signature by `sk` over a fixed message: the SERVICE recovers
//! `pk` from it and looks the note up. The SERVICE certifies each note with
//! `cs1`, the same signature it has always made, over `hex(pk)` instead of a
//! hash, so a recipient can check issuance offline with nothing but the `ck1`
//! and the `cs1` (see [`crate::signature`]).
//!
//! The names and semantics follow the TypeScript kit, which follows
//! lnurl-wallet's `src/lib`. Where the draft's text and that code disagree,
//! this follows the code: see [`derive_cash_address_node`].

use bech32::{FromBase32, ToBase32, Variant};
use hmac::{Hmac, Mac};
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

/// A note's bearer secret: the 65-byte `r || s || recovery id` ownership
/// signature, as a `ck1`. Whoever has it can spend the note.
pub fn encode_ck1(signature: &[u8; 65]) -> String {
    encode_fixed("ck", signature)
}

pub fn decode_ck1(value: &str) -> Option<[u8; 65]> {
    decode_fixed("ck", value)
}

pub fn is_ck1(value: &str) -> bool {
    decode_ck1(value).is_some()
}

/// A SERVICE's issuance certificate: the same 65-byte layout, signed by the
/// mint over the note's key, as a `cs1`.
pub fn encode_cs1(signature: &[u8; 65]) -> String {
    encode_fixed("cs", signature)
}

pub fn decode_cs1(value: &str) -> Option<[u8; 65]> {
    decode_fixed("cs", value)
}

pub fn is_cs1(value: &str) -> bool {
    decode_cs1(value).is_some()
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
//   message = "LNURLcash"
//   digest  = sha256(sha256("Lightning Signed Message:" || message))
//
// One fixed message for every note, so the value submitted to spend a note is
// the value shown to prove it, and RFC6979 makes it deterministic: re-deriving
// a key reproduces its `ck1` byte for byte. Deterministic is not unique,
// though. The high-S twin of a signature recovers to the same key, so one
// note has more than one valid `ck1` string, which is why notes are compared
// by [`note_id_of`] and never by k1.

const NOTE_OWNERSHIP_MESSAGE: &str = "LNURLcash";

/// The digest every ownership signature is made over. Public because
/// conformance pins it, and a signer that holds note keys needs nothing else.
pub fn note_ownership_digest() -> [u8; 32] {
    lightning_signed_digest(NOTE_OWNERSHIP_MESSAGE)
}

/// The raw 65-byte ownership signature, `r || s || recovery id`. Encode it
/// with [`encode_ck1`] for the wire: that string spends the note, so it is as
/// secret as the key that made it.
pub fn sign_note_ownership(secret_key: &[u8; 32]) -> Result<[u8; 65]> {
    let secp = Secp256k1::signing_only();
    let key = SecretKey::from_slice(secret_key)
        .map_err(|_| Error::Protocol("a note secret key is a 32-byte scalar in [1, n)".into()))?;
    // libsecp256k1 draws its nonce by RFC6979 and always normalises to low S
    let signature =
        secp.sign_ecdsa_recoverable(&Message::from_digest(note_ownership_digest()), &key);
    let (recovery, compact) = signature.serialize_compact();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&compact);
    // the library hands the recovery id back separately; the wire puts it last
    out[64] = recovery.to_i32() as u8;
    Ok(out)
}

/// The note's x-only public key, recovered offline from its ownership
/// signature. `None` for anything that does not recover, the wrong length
/// included.
///
/// Only the wire layout, `r || s || recovery id`, is tried. Unlike a
/// certificate, a `ck1` is a new encoding with no older byte order out there
/// to be lenient about.
pub fn recover_note_ownership_pubkey(signature: &[u8]) -> Option<[u8; 32]> {
    if signature.len() != 65 {
        return None;
    }
    let id = RecoveryId::from_i32(i32::from(signature[64])).ok()?;
    let recoverable = RecoverableSignature::from_compact(&signature[..64], id).ok()?;
    let secp = Secp256k1::verification_only();
    let key = secp
        .recover_ecdsa(&Message::from_digest(note_ownership_digest()), &recoverable)
        .ok()?;
    Some(key.x_only_public_key().0.serialize())
}

// ---- a note's k1, either kind ----

/// The key a `ck1` recovers to, from a k1 already trimmed and lowercased.
fn part2_key_of(value: &str) -> Option<[u8; 32]> {
    recover_note_ownership_pubkey(&decode_ck1(value)?)
}

/// The id a SERVICE files a note under: sha256(k1) as hex for a Part 1 secret,
/// the recovered public key as hex for a Part 2 `ck1`, and `None` for anything
/// else, a `ck1` that does not recover included.
///
/// Compare notes by this, never by k1. Two different `ck1` strings can share
/// an id, and a WALLET deduplicating by string would hold one note twice.
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
        let signature = sign_note_ownership(&[0x11; 32]).expect("a valid key");
        let pubkey = recover_note_ownership_pubkey(&signature).expect("recovers");
        [
            ("cp", encode_cp1(&pubkey)),
            ("ck", encode_ck1(&signature)),
            ("cs", encode_cs1(&signature)),
            ("cx", encode_cx1(&pubkey, &[0x22; 32])),
        ]
    }

    fn decodes(hrp: &str, value: &str) -> bool {
        match hrp {
            "cp" => is_cp1(value),
            "ck" => is_ck1(value),
            "cs" => is_cs1(value),
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
        // 32 and 64 bytes leave spare bits in the last five-bit group, which
        // must be zero. 65 bytes fill theirs exactly, so ck1 and cs1 have none.
        for (hrp, value) in samples() {
            if hrp == "ck" || hrp == "cs" {
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
        assert_eq!(recover_note_ownership_pubkey(&[0xff; 65]), None);
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
        assert_eq!(recover_note_ownership_pubkey(&signature[..64]), None);
        let mut corrupted = signature;
        corrupted[10] ^= 0xff;
        assert_ne!(recover_note_ownership_pubkey(&corrupted), pubkey);
    }

    #[test]
    fn one_note_has_more_than_one_ck1_so_notes_compare_by_id() {
        let signature = sign_note_ownership(&[0x11; 32]).expect("a valid key");
        // the high-S twin: s' = n - s, and the other recovery id
        let s = SecretKey::from_slice(&signature[32..64]).expect("s is in [1, n)");
        let mut twin = signature;
        twin[32..64].copy_from_slice(&s.negate().secret_bytes());
        twin[64] ^= 1;
        let (a, b) = (encode_ck1(&signature), encode_ck1(&twin));
        assert_ne!(a, b);
        assert_eq!(note_id_of(&a), note_id_of(&b));
        assert!(note_id_of(&a).is_some());
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
