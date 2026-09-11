//! The LUD-25 Part 2 wire: a `ck1` wherever a k1 goes, a `cp1` wherever an
//! output goes. Pure request building and response parsing, so no mint is
//! needed. Most values are made here from fixed keys with the crate's own
//! functions; the echo check starts from a conformance `ck1`. The bytes
//! themselves are graded in vectors.rs.

use std::path::PathBuf;

use lnurlcash_core::note::build_note_info_url_by_hash;
use lnurlcash_core::protocol::{
    melt_request, merge_request_with_hash, mint_invoice_request_with_hash, note_info_request,
    parse_note_info, rotate_request_with_hash, split_request_with_hash, Policy,
};
use lnurlcash_core::recoverable::{
    decode_ck1, encode_ck1, encode_cp1, encode_cs1, recover_note_ownership_pubkey,
    sign_note_ownership,
};
use lnurlcash_core::{
    hash_k1, note_id_of, note_lookup_of, note_signature_message, resolve_note_input, Error,
};
use secp256k1::SecretKey;
use serde_json::{json, Value};
use url::Url;

const CB: &str = "https://mint.example/w/cb";
const PAY_CB: &str = "https://mint.example/p/cb";

struct Part2Note {
    pubkey: String,
    cp1: String,
    ck1: String,
    cs1_shaped: String,
}

fn part2_note(fill: u8) -> Part2Note {
    let signature = sign_note_ownership(&[fill; 32]).expect("a valid key");
    let pubkey = recover_note_ownership_pubkey(&signature).expect("recovers");
    Part2Note {
        pubkey: hex::encode(pubkey),
        cp1: encode_cp1(&pubkey),
        ck1: encode_ck1(&signature),
        // the same 65 bytes under the certificate's prefix
        cs1_shaped: encode_cs1(&signature),
    }
}

fn k1() -> String {
    "11".repeat(32)
}

fn all(url: &str, key: &str) -> Vec<String> {
    Url::parse(url)
        .expect("a URL")
        .query_pairs()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .collect()
}

fn one(url: &str, key: &str) -> Option<String> {
    all(url, key).into_iter().next()
}

// ---- note ids ----

#[test]
fn a_part1_secret_is_filed_and_looked_up_under_its_hash() {
    let hash = hash_k1(&k1()).expect("hash");
    assert_eq!(note_id_of(&k1()), Some(hash.clone()));
    assert_eq!(note_lookup_of(&k1()), Some(hash));
}

#[test]
fn a_part2_note_is_filed_under_the_key_its_ck1_recovers_to() {
    let a = part2_note(0x11);
    assert_eq!(note_id_of(&a.ck1), Some(a.pubkey.clone()));
    assert_eq!(note_id_of(&a.ck1.to_ascii_uppercase()), Some(a.pubkey));
    assert_eq!(note_lookup_of(&a.ck1), Some(a.cp1));
}

#[test]
fn nothing_else_has_a_note_id() {
    let a = part2_note(0x11);
    let last = a.ck1.chars().last().expect("non-empty");
    let corrupted = format!(
        "{}{}",
        &a.ck1[..a.ck1.len() - 1],
        if last == 'q' { 'p' } else { 'q' }
    );
    for bad in [
        String::new(),
        "zz".into(),
        "11".repeat(31),
        a.cp1,
        a.cs1_shaped,
        corrupted,
    ] {
        assert_eq!(note_id_of(&bad), None, "{bad}");
        assert_eq!(note_lookup_of(&bad), None, "{bad}");
    }
}

#[test]
fn the_signed_message_names_the_key_for_a_ck1() {
    let a = part2_note(0x11);
    assert_eq!(
        note_signature_message(&a.ck1, 21_000),
        Some(format!("LNURLcash:21000:{}", a.pubkey))
    );
    assert_eq!(note_signature_message("not a k1", 21_000), None);
}

// ---- note URLs and lookups ----

#[test]
fn a_note_url_may_carry_a_ck1_but_never_a_cp1() {
    let a = part2_note(0x11);
    let url = format!("https://mint.example/w?k1={}&amount=21000", a.ck1);
    assert_eq!(resolve_note_input(&url), Some(url.clone()));
    // the informational GET carries it exactly as it carries a secret
    assert_eq!(
        one(&note_info_request(&url).expect("builds").url, "k1"),
        Some(a.ck1)
    );
    let key_only = format!("https://mint.example/w?k1={}&amount=21000", a.cp1);
    assert_eq!(resolve_note_input(&key_only), None);
}

#[test]
fn a_part2_note_is_looked_up_by_p_and_a_hash_by_h() {
    let a = part2_note(0x11);
    let by_key = build_note_info_url_by_hash("https://mint.example/w?k1=ab", &a.cp1)
        .expect("a cp1 is a lookup");
    assert_eq!(one(&by_key, "p"), Some(a.cp1.clone()));
    assert_eq!(one(&by_key, "h"), None);
    assert_eq!(one(&by_key, "k1"), None);
    // note_lookup_of is what a caller holding the ck1 passes in
    assert_eq!(
        build_note_info_url_by_hash(
            "https://mint.example/w",
            &note_lookup_of(&a.ck1).expect("lookup")
        ),
        build_note_info_url_by_hash("https://mint.example/w", &a.cp1)
    );

    let hash = hash_k1(&k1()).expect("hash");
    let by_hash = build_note_info_url_by_hash("https://mint.example/w", &hash).expect("a hash");
    assert_eq!(one(&by_hash, "h"), Some(hash));
    assert_eq!(one(&by_hash, "p"), None);

    // the value that spends the note is never a lookup
    assert_eq!(
        build_note_info_url_by_hash("https://mint.example/w", &a.ck1),
        None
    );
}

// ---- the echo on an informational GET ----

fn part2_vectors() -> Value {
    let dir = match std::env::var("LNURLCASH_CONFORMANCE") {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate has a parent directory")
            .join("lnurlcash-conformance"),
    };
    let path = dir.join("vectors").join("part2.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()));
    serde_json::from_str(&text).expect("vector file is valid JSON")
}

/// The same signature with s replaced by n - s and the recovery id flipped.
/// Anyone holding a `ck1` can make this, and it recovers to the same key.
fn high_s_twin(signature: &[u8; 65]) -> [u8; 65] {
    let s = SecretKey::from_slice(&signature[32..64]).expect("s is in [1, n)");
    let mut twin = *signature;
    twin[32..64].copy_from_slice(&s.negate().secret_bytes());
    twin[64] ^= 1;
    twin
}

#[test]
fn an_echoed_ck1_is_the_same_note_when_it_recovers_to_the_same_key() {
    let vectors = part2_vectors();
    let notes = vectors["branches"][0]["notes"].as_array().expect("notes");
    let ours = notes[0]["ck1"].as_str().expect("ck1").to_string();
    let other = notes[1]["ck1"].as_str().expect("ck1").to_string();
    let twin = encode_ck1(&high_s_twin(&decode_ck1(&ours).expect("a vector ck1")));
    assert_ne!(twin, ours, "the twin is a different string");

    let url = format!("https://mint.example/w?k1={ours}&amount=21000");
    let answer = |echoed: &str| {
        parse_note_info(
            &json!({
                "tag": "withdrawRequest",
                "callback": CB,
                "k1": echoed,
                "minWithdrawable": 21_000,
                "maxWithdrawable": 21_000,
                "mintPubkey": vectors["mint"]["mintPubkey"],
            }),
            &url,
            Policy::default(),
        )
    };

    // the same note, however the SERVICE spells its ck1
    for echoed in [ours.clone(), ours.to_ascii_uppercase(), twin.clone()] {
        let info = answer(&echoed).unwrap_or_else(|err| panic!("{echoed}: {err}"));
        assert_eq!(note_id_of(&info.k1), note_id_of(&ours), "{echoed}");
    }

    // a different note, the note's id in place of its k1, or nothing that is
    // a note at all, is still refused
    let id_of_ours = note_id_of(&ours).expect("an id");
    for echoed in [other, k1(), id_of_ours, "zz".into()] {
        assert!(
            matches!(answer(&echoed), Err(Error::Protocol(_))),
            "{echoed} must be refused"
        );
    }
}

// ---- mutations ----

#[test]
fn a_ck1_rotates_into_a_cp1_sent_as_p1() {
    let (a, b) = (part2_note(0x11), part2_note(0x22));
    let url = rotate_request_with_hash(CB, &a.ck1, &b.cp1)
        .expect("builds")
        .url;
    assert_eq!(one(&url, "k1"), Some(a.ck1));
    assert_eq!(one(&url, "p1"), Some(b.cp1));
    assert_eq!(one(&url, "h"), None);
}

#[test]
fn a_hash_output_keeps_h_which_every_mint_understands() {
    let a = part2_note(0x11);
    let hash = hash_k1(&k1()).expect("hash");
    let url = rotate_request_with_hash(CB, &a.ck1, &hash)
        .expect("builds")
        .url;
    assert_eq!(one(&url, "h"), Some(hash));
    assert_eq!(one(&url, "p1"), None);
}

#[test]
fn a_split_names_a_key_and_a_hash_each_under_its_own_name() {
    let (a, b) = (part2_note(0x11), part2_note(0x22));
    let hash = hash_k1(&k1()).expect("hash");
    let url = split_request_with_hash(CB, &[a.ck1], 5_000, &b.cp1, &hash)
        .expect("builds")
        .url;
    assert_eq!(one(&url, "p1"), Some(b.cp1.clone()));
    assert_eq!(one(&url, "h2"), Some(hash.clone()));
    assert_eq!((one(&url, "h"), one(&url, "p2")), (None, None));

    // and the other way round
    let url = split_request_with_hash(CB, &[k1()], 5_000, &hash, &b.cp1)
        .expect("builds")
        .url;
    assert_eq!(one(&url, "h"), Some(hash));
    assert_eq!(one(&url, "p2"), Some(b.cp1));
    assert_eq!((one(&url, "p1"), one(&url, "h2")), (None, None));
}

#[test]
fn a_merge_takes_a_part1_secret_and_a_part2_note_together() {
    let (a, c) = (part2_note(0x11), part2_note(0x33));
    let url = merge_request_with_hash(CB, &[k1(), a.ck1.clone()], &c.cp1)
        .expect("builds")
        .url;
    assert_eq!(all(&url, "k1"), vec![k1(), a.ck1]);
    assert_eq!(one(&url, "p1"), Some(c.cp1));
}

#[test]
fn a_ck1_melts_like_any_k1() {
    let a = part2_note(0x11);
    let url = melt_request(CB, &a.ck1, "lnbc210n1pjqrstuvwxyz")
        .expect("builds")
        .url;
    assert_eq!(one(&url, "k1"), Some(a.ck1));
}

// ---- minting to a key ----

#[test]
fn a_cp1_mints_through_the_comment_alone() {
    let a = part2_note(0x11);
    let url = mint_invoice_request_with_hash(PAY_CB, 21_000, &a.cp1)
        .expect("builds")
        .url;
    assert_eq!(one(&url, "comment"), Some(a.cp1.clone()));
    assert_eq!(one(&url, "h"), None);
    // normalised like a hash is
    let upper = mint_invoice_request_with_hash(PAY_CB, 21_000, &a.cp1.to_ascii_uppercase())
        .expect("builds")
        .url;
    assert_eq!(one(&upper, "comment"), Some(a.cp1));
}

#[test]
fn a_hash_still_mints_through_both_comment_and_h() {
    let hash = hash_k1(&k1()).expect("hash");
    let url = mint_invoice_request_with_hash(PAY_CB, 21_000, &hash)
        .expect("builds")
        .url;
    assert_eq!(one(&url, "comment"), Some(hash.clone()));
    assert_eq!(one(&url, "h"), Some(hash));
}

#[test]
fn nothing_else_is_asked_for_an_invoice() {
    let a = part2_note(0x11);
    for bad in [a.ck1, a.cs1_shaped, "not-a-32-byte-hash".into()] {
        assert!(
            matches!(
                mint_invoice_request_with_hash(PAY_CB, 21_000, &bad),
                Err(Error::RequestRefused(_))
            ),
            "{bad}"
        );
    }
}
