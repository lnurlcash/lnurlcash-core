//! Every assertion here comes from lnurlcash-conformance. Nothing in this file
//! states what the protocol is - the vectors do, and this suite only binds them
//! to the crate's functions.

use std::collections::HashMap;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use lnurlcash_core::cash::{
    cash_domain_indices, cash_node_from_hex, cash_node_to_hex, derive_cash_child,
    derive_cash_domain_node, derive_cash_root,
};
use lnurlcash_core::protocol::{
    melt_request, mint_invoice_request, mint_invoice_request_with_hash, note_info_request,
    parse_invoice, parse_mutation, parse_note_info, parse_pay_request, parse_verify,
    rotate_request, rotate_request_with_hash, split_request, split_request_with_hash, MutationKind,
    MutationResponse, Policy, Request,
};
use lnurlcash_core::recoverable::{
    cash_node_to_cx1, decode_ck1, decode_cp1, decode_cs1_with_amount, decode_cw1, decode_cx1,
    derive_cash_address_node, derive_nostr_address_node, derive_nostr_cash_seed,
    derive_note_pubkey, derive_note_secret_key, encode_ck1, encode_cp1, encode_cs1_with_amount,
    encode_cw1, encode_cx1, is_ck1, is_cp1, is_cs1_with_amount, is_cw1, is_cx1,
    recover_note_ownership_pubkey, sign_note_ownership, Cw1, DecodedCk1, NOSTR_CASH_SEED_LABEL,
    PURPOSE_WALLET,
};
use lnurlcash_core::secrets::{derive_note_root, derive_note_secret};
use lnurlcash_core::spend::{
    bearer_cw1, bearer_leaf, bearer_note, check_leaf, check_spend, check_time_claim, decode_note,
    decode_spend, key_path_sighash, output_key_of, script_path_sighash, spend_domain_of,
    spend_prevout, spend_sig_msg, tagged_hash, tapbranch_hash, tapleaf_hash, taproot_tweak,
    taproot_tweak_secret_key, Spend, SpendVerdict, NUMS_H, TAPLEAF_VERSION,
};
use lnurlcash_core::{
    address_proof_digest, address_proof_message, apply_mint_fee, build_note_url, check_note,
    check_note_certificate, check_note_url, decode_bolt11_amount_msat, format_fee_percent,
    from_bech32_lnurl, gross_up_for_mint_fee, is_allowed_service_url, is_bolt11_invoice,
    is_preimage, lightning_address_username, mint_address_url, note_declared_amount, note_id_of,
    note_k1, note_lookup_of, note_signature, note_signature_digest, note_signature_digest_for_hash,
    note_signature_message, note_signature_message_for_hash, parse_mint_fee, resolve_lnurl_input,
    resolve_mint_input, resolve_note_input, same_invoice, sign_address_proof, to_bech32_lnurl,
    verify_note_signature, verify_note_signature_hash, with_new_k1, without_k1, CertifiedOver,
    MintFee,
};
use lnurlcash_core::{hash_k1, Error};
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, Parity, PublicKey, SecretKey};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    match std::env::var("LNURLCASH_CONFORMANCE") {
        Ok(path) => PathBuf::from(path).join("vectors"),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate has a parent directory")
            .join("lnurlcash-conformance")
            .join("vectors"),
    }
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("could not read {}: {err}", path.display()));
    serde_json::from_str(&text).expect("vector file is valid JSON")
}

fn str_of(value: &Value, key: &str) -> String {
    value[key].as_str().expect("string field").to_string()
}

fn opt_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

fn fee_of(value: &Value) -> MintFee {
    MintFee {
        base_fee_msat: value["baseFeeMsat"].as_u64().expect("baseFeeMsat"),
        fee_ppm: value["feePpm"].as_u64().expect("feePpm"),
    }
}

/// signature.json predates notes keyed by `Q`: every certificate there is
/// over a bearer note's hash `h`, the message a mint signed before LUD-25
/// moved certificates onto `hex(Q)`. The verdicts still hold through the
/// legacy reading, reported as such; the message a current mint signs for
/// the same note is over `Q` instead.
#[test]
fn signature_vectors() {
    let vectors = load("signature.json");
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 5, "too few signature cases to be meaningful");

    for case in cases {
        let name = str_of(case, "name");
        let k1 = str_of(case, "k1");
        let amount = case["amountMsat"].as_u64().expect("amountMsat");
        let signature = str_of(case, "signature");
        let pubkey = str_of(case, "mintPubkey");
        let expected = case["valid"].as_bool().expect("valid");

        // a bearer preimage opens its note anywhere, so the domain is moot
        assert_eq!(
            verify_note_signature(&k1, "mint.example", amount, &signature, &pubkey),
            expected,
            "{name}"
        );
        if expected {
            let check = check_note(&k1, "mint.example", amount, &signature, &pubkey)
                .unwrap_or_else(|| panic!("{name}: a valid certificate"));
            assert_eq!(check.certificate, CertifiedOver::LegacyHash, "{name}");
            let h = str_of(case, "noteId");
            assert_eq!(
                check_note_certificate(&h, amount, &signature, &pubkey),
                Some(CertifiedOver::LegacyHash),
                "{name}: by h"
            );
        }

        if let Some(message) = case["message"].as_str() {
            let h = str_of(case, "noteId");
            assert_eq!(
                note_signature_message_for_hash(&h, amount),
                message,
                "{name}: message"
            );
            assert_eq!(
                hex::encode(note_signature_digest_for_hash(&h, amount)),
                str_of(case, "digest"),
                "{name}: digest"
            );
            // a current mint certifies the same note over its Q instead
            if let Some(id) = note_id_of(&k1) {
                assert_eq!(
                    note_signature_message(&k1, amount),
                    Some(format!("LNURLcash:{amount}:{id}")),
                    "{name}"
                );
                assert_ne!(id, h, "{name}: a bearer note's id is its Q, not h");
                assert_eq!(
                    note_signature_digest(&k1, amount).map(hex::encode),
                    Some(hex::encode(note_signature_digest_for_hash(&id, amount))),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn bech32_vectors() {
    let vectors = load("bech32.json");
    for case in vectors["encode"].as_array().expect("encode") {
        let url = str_of(case, "url");
        let lnurl = str_of(case, "lnurl");
        assert_eq!(to_bech32_lnurl(&url).as_deref(), Some(lnurl.as_str()));
        assert_eq!(from_bech32_lnurl(&lnurl).as_deref(), Some(url.as_str()));
    }
    for case in vectors["decodeInvalid"].as_array().expect("decodeInvalid") {
        let input = str_of(case, "input");
        assert_eq!(from_bech32_lnurl(&input), None, "{}", str_of(case, "why"));
    }
    let insensitive = &vectors["caseInsensitive"];
    let url = str_of(insensitive, "url");
    assert_eq!(
        from_bech32_lnurl(&str_of(insensitive, "lower")).as_deref(),
        Some(url.as_str())
    );
    assert_eq!(
        from_bech32_lnurl(&str_of(insensitive, "upper")).as_deref(),
        Some(url.as_str())
    );
}

#[test]
fn url_admission_vectors() {
    let vectors = load("url-admission.json");
    for url in vectors["allowed"].as_array().expect("allowed") {
        let url = url.as_str().expect("string");
        assert!(is_allowed_service_url(url), "should allow {url}");
    }
    for case in vectors["rejected"].as_array().expect("rejected") {
        let url = str_of(case, "url");
        assert!(
            !is_allowed_service_url(&url),
            "should reject {url} ({})",
            str_of(case, "why")
        );
    }
}

#[test]
fn input_resolution_vectors() {
    let vectors = load("input-resolution.json");

    for case in vectors["lnurl"].as_array().expect("lnurl") {
        let input = str_of(case, "input");
        assert_eq!(
            resolve_lnurl_input(&input),
            opt_str(case, "expect"),
            "lnurl input {input:?}"
        );
    }
    for case in vectors["mint"].as_array().expect("mint") {
        let input = str_of(case, "input");
        assert_eq!(
            resolve_mint_input(&input),
            opt_str(case, "expect"),
            "mint input {input:?}"
        );
    }
    for case in vectors["note"].as_array().expect("note") {
        let input = str_of(case, "input");
        assert_eq!(
            resolve_note_input(&input),
            opt_str(case, "expect"),
            "note input {input:?}"
        );
    }
    for case in vectors["mintAddressUrl"]
        .as_array()
        .expect("mintAddressUrl")
    {
        let pay_url = str_of(case, "payUrl");
        assert_eq!(
            mint_address_url(&pay_url),
            opt_str(case, "expect"),
            "mirror of {pay_url}"
        );
    }
    for case in vectors["lightningAddressUsername"]
        .as_array()
        .expect("lightningAddressUsername")
    {
        let pay_url = str_of(case, "payUrl");
        assert_eq!(
            lightning_address_username(&pay_url),
            opt_str(case, "expect"),
            "username of {pay_url}"
        );
    }
}

#[test]
fn note_url_vectors() {
    let vectors = load("note-url.json");

    for case in vectors["parse"].as_array().expect("parse") {
        let url = str_of(case, "url");
        assert_eq!(note_k1(&url), opt_str(case, "k1"), "k1 of {url}");
        assert_eq!(
            note_declared_amount(&url),
            case["declaredAmountMsat"].as_u64(),
            "declared amount of {url}"
        );
        assert_eq!(
            note_signature(&url),
            opt_str(case, "signature"),
            "signature of {url}"
        );
    }

    for case in vectors["build"].as_array().expect("build") {
        let built = build_note_url(
            &str_of(case, "withdrawLink"),
            &str_of(case, "k1"),
            case["amountMsat"].as_u64(),
        );
        assert_eq!(built.as_deref(), Some(str_of(case, "expect").as_str()));
    }

    for case in vectors["withNewK1"].as_array().expect("withNewK1") {
        let built = with_new_k1(
            &str_of(case, "url"),
            &str_of(case, "k1"),
            case["amountMsat"].as_u64().expect("amountMsat"),
            case["signature"].as_str(),
        );
        assert_eq!(built.as_deref(), Some(str_of(case, "expect").as_str()));
    }

    for case in vectors["withoutK1"].as_array().expect("withoutK1") {
        let built = without_k1(
            &str_of(case, "url"),
            case["amountMsat"].as_u64().expect("amountMsat"),
            case["signature"].as_str(),
        );
        assert_eq!(built.as_deref(), Some(str_of(case, "expect").as_str()));
    }
}

#[test]
fn fee_vectors() {
    let vectors = load("fees.json");

    for case in vectors["parse"].as_array().expect("parse") {
        let metadata = str_of(case, "metadata");
        let expected = case["expect"].as_object().map(|_| fee_of(&case["expect"]));
        assert_eq!(parse_mint_fee(&metadata), expected, "metadata {metadata}");
    }

    for case in vectors["apply"].as_array().expect("apply") {
        let gross = case["grossMsat"].as_u64().expect("grossMsat");
        let fee = fee_of(&case["fee"]);
        assert_eq!(
            apply_mint_fee(gross, fee),
            case["expect"].as_u64().expect("expect"),
            "apply {fee:?} to {gross}"
        );
    }

    for case in vectors["grossUp"].as_array().expect("grossUp") {
        let net = case["netMsat"].as_u64().expect("netMsat");
        let fee = fee_of(&case["fee"]);
        assert_eq!(
            gross_up_for_mint_fee(net, fee),
            case["expect"].as_u64().expect("expect"),
            "gross up {net} through {fee:?}"
        );
    }

    let round_trip = &vectors["grossUpRoundTrip"];
    for raw_fee in round_trip["fees"].as_array().expect("fees") {
        let fee = fee_of(raw_fee);
        for net in round_trip["netAmountsMsat"].as_array().expect("amounts") {
            let net = net.as_u64().expect("amount");
            let gross = gross_up_for_mint_fee(net, fee);
            assert_eq!(apply_mint_fee(gross, fee), net, "{net} through {fee:?}");
            assert!(
                apply_mint_fee(gross - 1, fee) < net,
                "{net} through {fee:?}: {gross} is not the minimum"
            );
        }
    }

    for case in vectors["formatPercent"].as_array().expect("formatPercent") {
        let ppm = case["ppm"].as_u64().expect("ppm");
        assert_eq!(format_fee_percent(ppm), str_of(case, "expect"), "{ppm} ppm");
    }
}

#[test]
fn bolt11_vectors() {
    let vectors = load("bolt11.json");

    for case in vectors["decodeAmountMsat"]
        .as_array()
        .expect("decodeAmountMsat")
    {
        let pr = str_of(case, "pr");
        assert_eq!(
            decode_bolt11_amount_msat(&pr),
            case["expect"].as_u64(),
            "amount of {pr:?}"
        );
    }
    for case in vectors["isInvoice"].as_array().expect("isInvoice") {
        let pr = str_of(case, "pr");
        assert_eq!(
            is_bolt11_invoice(&pr),
            case["expect"].as_bool().expect("expect"),
            "shape of {pr:?}"
        );
    }
    for case in vectors["sameInvoice"].as_array().expect("sameInvoice") {
        assert_eq!(
            same_invoice(&str_of(case, "a"), &str_of(case, "b")),
            case["expect"].as_bool().expect("expect")
        );
    }
    for case in vectors["isPreimage"].as_array().expect("isPreimage") {
        let value = str_of(case, "value");
        assert_eq!(
            is_preimage(&value),
            case["expect"].as_bool().expect("expect"),
            "preimage shape of {value:?}"
        );
    }
}

/// LUD-25 minting, from pay-request.json.
///
/// This is the suite that would have caught the crate sitting on the deleted
/// preimage-keyed model for a month: nothing here binds an opinion of its own,
/// so a draft change lands as a red test rather than as a silent divergence
/// discovered by a wallet that could not mint.
#[test]
fn pay_request_vectors() {
    let vectors = load("pay-request.json");

    for case in vectors["accepted"].as_array().expect("accepted") {
        let name = str_of(case, "name");
        let info = parse_pay_request(&case["body"])
            .unwrap_or_else(|err| panic!("{name}: expected a parse, got {err}"));
        assert_eq!(info.withdraw_link, opt_str(case, "withdrawLink"), "{name}");
        assert_eq!(
            info.comment_allowed,
            case.get("commentAllowed").and_then(|v| v.as_u64()),
            "{name}"
        );
        let expected_fee = case.get("mintFee").filter(|v| !v.is_null()).map(fee_of);
        assert_eq!(info.mint_fee, expected_fee, "{name}");
        // A payRequest is only a mint if it can carry the commitment, and a
        // mint is only a mint if it advertises where the note will live.
        assert_eq!(
            info.names_mint_output(),
            info.withdraw_link.is_some(),
            "{name}: minting capability must track withdrawLink"
        );
    }

    for case in vectors["rejected"].as_array().expect("rejected") {
        let name = str_of(case, "name");
        assert!(
            parse_pay_request(&case["body"]).is_err(),
            "{name}: must not parse"
        );
    }

    // The mint callback names the note before the invoice exists.
    let callback = "https://mint.example/p/cb";
    for case in vectors["mintCallback"]["accepted"]
        .as_array()
        .expect("mintCallback.accepted")
    {
        let name = str_of(case, "name");
        let comment = str_of(case, "comment");
        let amount = case["amountMsat"].as_u64().expect("amountMsat");
        let request = mint_invoice_request_with_hash(callback, amount, &comment)
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        // LUD-25 carries the commitment as a mandatory LUD-12 comment; `h`
        // repeats it for the additive ForgeSworn profile.
        assert!(
            request.url.contains(&format!("comment={comment}")),
            "{name}: the commitment must ride as a comment - got {}",
            request.url
        );
        assert!(request.url.contains(&format!("h={comment}")), "{name}");
        assert!(request.url.contains(&format!("amount={amount}")), "{name}");
        assert_eq!(
            case["noteId"].as_str(),
            Some(comment.as_str()),
            "{name}: the note is keyed by the commitment"
        );
        assert_eq!(
            case["paymentPreimageIsBearerK1"].as_bool(),
            Some(false),
            "{name}: the preimage is settlement proof, never the note"
        );
    }

    for case in vectors["mintCallback"]["rejected"]
        .as_array()
        .expect("mintCallback.rejected")
    {
        let name = str_of(case, "name");
        let amount = case["amountMsat"].as_u64().expect("amountMsat");
        // A null comment is the unnamed mint the draft forbids: this crate
        // cannot express one, because the minting builder requires the
        // commitment. A malformed one is refused before anything is sent.
        match case["comment"].as_str() {
            None => assert!(
                mint_invoice_request(callback, amount, "").is_err(),
                "{name}: an unnamed mint must be impossible to build"
            ),
            Some(comment) => assert!(
                mint_invoice_request_with_hash(callback, amount, comment).is_err(),
                "{name}: a malformed commitment must be refused before it is sent"
            ),
        }
    }

    for case in vectors["invoice"]["accepted"]
        .as_array()
        .expect("invoice.accepted")
    {
        let name = str_of(case, "name");
        let requested = case["requestedMsat"].as_u64().expect("requestedMsat");
        let invoice =
            parse_invoice(&case["body"], requested).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(
            invoice.disposable,
            case["disposable"].as_bool().expect("disposable"),
            "{name}"
        );
        assert_eq!(invoice.verify, opt_str(case, "verify"), "{name}");
    }

    for case in vectors["invoice"]["rejected"]
        .as_array()
        .expect("invoice.rejected")
    {
        let name = str_of(case, "name");
        let requested = case["requestedMsat"].as_u64().expect("requestedMsat");
        assert!(
            parse_invoice(&case["body"], requested).is_err(),
            "{name}: must not parse"
        );
    }

    for case in vectors["verify"]["accepted"]
        .as_array()
        .expect("verify.accepted")
    {
        let name = str_of(case, "name");
        let verified = parse_verify(&case["body"]).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(
            verified.settled,
            case["settled"].as_bool().expect("settled"),
            "{name}"
        );
        assert_eq!(verified.preimage, opt_str(case, "preimage"), "{name}");
    }

    for case in vectors["verify"]["rejected"]
        .as_array()
        .expect("verify.rejected")
    {
        let name = str_of(case, "name");
        assert!(
            parse_verify(&case["body"]).is_err(),
            "{name}: must not parse"
        );
    }
}

// ---- classifying a mutation's response ----
//
// responses.json says which call each case goes through (`op`) and, since
// 0.10.0, which kind of note it mints: `output: "cp1"` or `change: "cp1"`,
// and a plain hash wherever neither is said. A `cp1` output is owed a `cs1`
// certificate; a legacy hash may carry a raw Part 1 signature, while a bare
// OK is accepted only by the default no-signer-compatible policy.
//
// This grades every case that carries a JSON answer, through the same request
// builders and parser a caller uses, with the default policy. The rest carry
// no answer this parser ever sees - an unreadable body, a 500, a dropped
// connection, a timeout - so tests/protocol.rs drives those through the
// client's own transport.

const RESPONSE_CB: &str = "https://mint.example/w/cb";

fn response_outcome(result: &lnurlcash_core::Result<MutationResponse>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(Error::Unverifiable { .. }) => "unverifiable",
        Err(Error::NotePending) => "pending",
        Err(Error::NoteSpent { .. }) => "spent",
        Err(Error::NoteUnknown { .. }) => "unknown",
        Err(Error::ServiceRejected(_)) => "error",
        Err(Error::Ambiguous { .. }) => "ambiguous",
        Err(other) => panic!("not an outcome responses.json names: {other:?}"),
    }
}

/// The request a case is an answer to. A plain note goes through the
/// generating builders, as a wallet's own rotate does, so its fresh secrets
/// ride the request; a `cp1` output is one the caller names, so the request
/// carries none.
fn response_case_request(case: &Value, cp1s: &[String]) -> (Request, MutationKind) {
    let k1 = "11".repeat(32);
    let (secret, change_secret) = ("22".repeat(32), "33".repeat(32));
    let cp1_output = case["output"].as_str() == Some("cp1");
    let cp1_change = case["change"].as_str() == Some("cp1");
    for (field, value) in [("output", &case["output"]), ("change", &case["change"])] {
        assert!(
            value.is_null() || value.as_str() == Some("cp1"),
            "{}: a {field} this suite does not know: {value}",
            str_of(case, "name")
        );
    }
    match case["op"].as_str().expect("op") {
        "melt" => (
            melt_request(RESPONSE_CB, &k1, "lnbc210n1pjq").expect("builds"),
            MutationKind::Melt,
        ),
        "split" => {
            let request = if cp1_output || cp1_change {
                let output = if cp1_output {
                    cp1s[0].clone()
                } else {
                    hash_k1(&secret).expect("hash")
                };
                let change = if cp1_change {
                    cp1s[1].clone()
                } else {
                    hash_k1(&change_secret).expect("hash")
                };
                split_request_with_hash(RESPONSE_CB, &[k1], 5_000, &output, &change)
            } else {
                split_request(RESPONSE_CB, &[k1], 5_000, &secret, &change_secret)
            };
            (request.expect("builds"), MutationKind::Split)
        }
        "mutation" => {
            assert!(!cp1_change, "a rotate has no change");
            let request = if cp1_output {
                rotate_request_with_hash(RESPONSE_CB, &k1, &cp1s[0])
            } else {
                rotate_request(RESPONSE_CB, &k1, &secret)
            };
            (request.expect("builds"), MutationKind::Rotate)
        }
        other => panic!("an op this suite does not know: {other}"),
    }
}

#[test]
fn response_vectors() {
    let vectors = load("responses.json");
    // two real Part 2 keys from the same suite, for the cases that mint one
    let part2 = load("part2.json");
    let cp1s: Vec<String> = part2["branches"][0]["notes"]
        .as_array()
        .expect("notes")
        .iter()
        .take(2)
        .map(|note| str_of(note, "cp1"))
        .collect();

    let cases = vectors["cases"].as_array().expect("cases");
    let (mut graded, mut cp1_graded) = (0, 0);
    for case in cases {
        let name = str_of(case, "name");
        let Some(body) = case.get("body") else {
            // no JSON answer at all: the transport's business, graded in
            // tests/protocol.rs. Only ever an outcome that may have landed.
            assert_eq!(str_of(case, "expect"), "ambiguous", "{name}");
            continue;
        };
        let (request, kind) = response_case_request(case, &cp1s);
        let result = parse_mutation(body, kind, &request.outputs, Policy::default());
        let expected = str_of(case, "expect");
        assert_eq!(response_outcome(&result), expected, "{name}: {result:?}");
        match result {
            Ok(response) => {
                assert_eq!(response.signature, opt_str(case, "signature"), "{name}");
                assert_eq!(
                    response.change_signature,
                    opt_str(case, "changeSignature"),
                    "{name}"
                );
            }
            // The mutation may have landed, or did: whatever secrets the
            // request carried have to survive the error.
            Err(err) if matches!(expected.as_str(), "ambiguous" | "unverifiable") => {
                let carried = err.with_secrets(request.new_secrets.clone());
                assert_eq!(carried.new_secrets(), request.new_secrets, "{name}");
            }
            Err(_) => {}
        }
        graded += 1;
        if !case["output"].is_null() || !case["change"].is_null() {
            cp1_graded += 1;
        }
    }
    assert!(
        graded > 10,
        "too few response cases graded to mean anything"
    );
    assert!(cp1_graded >= 3, "0.10.0 carries three cp1 cases");
}

// ---- the informational GET ----
//
// withdraw-info.json: what a note's informational GET may answer, and what the
// request carrying it may send. Through the same request builder and parser a
// caller uses, which the client and the FFI both call, with the default
// policy. Every case carries a JSON answer, so the parser sees all of them.

fn assert_graded_fields(value: &Value, known: &[&str], what: &str) {
    // a field this suite does not read is one nobody is grading
    for key in value.as_object().expect("an object").keys() {
        assert!(
            known.contains(&key.as_str()),
            "{what}: a field this suite does not grade: {key}"
        );
    }
}

fn query_pairs_of(url: &str) -> Vec<(String, String)> {
    url::Url::parse(url)
        .expect("a URL")
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

#[test]
fn withdraw_info_vectors() {
    let vectors = load("withdraw-info.json");
    assert_eq!(vectors["version"], 1, "these tests read version 1");
    assert_graded_fields(
        &vectors,
        &[
            "version",
            "spec",
            "description",
            "queriedUrl",
            "requestMustNotSend",
            "requestMustSendUnchanged",
            "accepted",
            "rejected",
        ],
        "withdraw-info.json",
    );

    let queried = str_of(&vectors, "queriedUrl");
    let sent = query_pairs_of(&note_info_request(&queried).expect("builds").url);
    let asked = query_pairs_of(&queried);
    let values = |pairs: &[(String, String)], key: &str| -> Vec<String> {
        pairs
            .iter()
            .filter(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .collect()
    };
    for key in vectors["requestMustNotSend"].as_array().expect("a list") {
        let key = key.as_str().expect("a parameter name");
        assert!(
            values(&sent, key).is_empty(),
            "sent {key}, which the SERVICE must never see"
        );
    }
    for key in vectors["requestMustSendUnchanged"]
        .as_array()
        .expect("a list")
    {
        let key = key.as_str().expect("a parameter name");
        assert_eq!(
            values(&sent, key),
            values(&asked, key),
            "{key} did not go out as queried"
        );
    }

    let accepted = vectors["accepted"].as_array().expect("accepted");
    for case in accepted {
        let name = str_of(case, "name");
        assert_graded_fields(case, &["name", "body", "maxWithdrawable", "why"], &name);
        let expected = case["maxWithdrawable"].as_u64().expect("maxWithdrawable");
        let info = parse_note_info(&case["body"], &queried, Policy::default())
            .unwrap_or_else(|err| panic!("{name}: refused: {err:?}"));
        assert_eq!(info.max_withdrawable, expected, "{name}");
    }
    let rejected = vectors["rejected"].as_array().expect("rejected");
    for case in rejected {
        let name = str_of(case, "name");
        assert_graded_fields(case, &["name", "body", "why"], &name);
        let result = parse_note_info(&case["body"], &queried, Policy::default());
        assert!(
            matches!(result, Err(Error::Protocol(_))),
            "{name}: {result:?}, want a protocol error"
        );
    }
    assert!(
        !accepted.is_empty() && !rejected.is_empty(),
        "no cases graded"
    );
}

// ---- derivation ----
//
// The two schemes a wallet may mint under. `cash-derivation.json` is the one
// LUD-25 specifies and the one a new wallet uses; `derivation.json` is the
// pre-spec HMAC scheme, kept because notes minted under it are still money.
//
// A disagreement with either file is a wallet that cannot restore what
// another implementation of the same seed phrase minted, which is the whole
// reason these vectors exist rather than each library testing itself.

#[test]
fn cash_derivation_vectors() {
    let vectors = load("cash-derivation.json");

    assert_eq!(
        vectors["scheme"]["purpose"].as_str(),
        Some("m/139'"),
        "the vector must describe the scheme this crate implements"
    );
    // The one thing an implementation can silently get wrong: d1..d4 are raw
    // uint32, hardened only where they happen to land at or above 2^31.
    assert_eq!(
        vectors["scheme"]["hardenedByMagnitudeOnly"].as_bool(),
        Some(true)
    );

    // BIP-32's own published vector 1, so a failure here says CKDpriv is
    // wrong rather than the LUD-25 path above it. The chain alternates
    // hardened and unhardened, which is exactly the pair of legs the domain
    // levels land on.
    let steps = vectors["bip32Vector1"]
        .as_array()
        .expect("bip32Vector1 is an array");
    let mut node =
        cash_node_from_hex(str_of(&steps[0], "node").as_str()).expect("vector 1 master parses");
    for step in &steps[1..] {
        let index = step["index"].as_u64().expect("index") as u32;
        node = derive_cash_child(&node, index).expect("BIP-32 vector 1 derives");
        assert_eq!(cash_node_to_hex(&node), str_of(step, "node"), "at {index}");
    }

    for case in vectors["cases"].as_array().expect("cases") {
        let name = str_of(case, "name");
        let host = str_of(case, "host");
        let seed = hex::decode(str_of(case, "seedHex")).expect("seedHex is hex");

        let root = derive_cash_root(&seed).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(cash_node_to_hex(&root), str_of(case, "cashRoot"), "{name}");

        let indices: Vec<u32> = case["domainIndices"]
            .as_array()
            .expect("domainIndices")
            .iter()
            .map(|value| value.as_u64().expect("index") as u32)
            .collect();
        assert_eq!(
            cash_domain_indices(&root, &host).expect("indices").to_vec(),
            indices,
            "{name}"
        );

        let domain_node = derive_cash_domain_node(&root, &host).expect("domain node");
        assert_eq!(
            cash_node_to_hex(&domain_node),
            str_of(case, "domainNode"),
            "{name}"
        );
    }
}

#[test]
fn legacy_derivation_vectors() {
    let vectors = load("derivation.json");

    assert_eq!(
        vectors["scheme"]["rootKey"].as_str(),
        Some("lnurlcash-note-v1")
    );

    for case in vectors["cases"].as_array().expect("cases") {
        let name = str_of(case, "name");
        let seed = hex::decode(str_of(case, "seedHex")).expect("seedHex is hex");
        let root = derive_note_root(&seed);
        let k1 = derive_note_secret(
            &root,
            &str_of(case, "host"),
            case["index"].as_u64().unwrap() as u32,
        );
        assert_eq!(k1, str_of(case, "k1"), "{name}");
        assert_eq!(
            hash_k1(&k1).expect("hash"),
            str_of(case, "noteId"),
            "{name}"
        );
    }
}

// ---- key-path notes ----
//
// part2.json pins the reference wallet's address branch, the per-note key
// tweak, each key's key-path spend for its host's domain, mint certificates
// and the bech32m strings. Every field is graded on every branch and note: a
// wallet that disagrees with one of them cannot find, spend or check a note
// that another implementation of the same seed made.

fn bytes32(value: &Value, key: &str) -> [u8; 32] {
    hex::decode(str_of(value, key))
        .expect("hex")
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is 32 bytes"))
}

fn bytes_of(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(str_of(value, key)).unwrap_or_else(|_| panic!("{key} is hex"))
}

fn u32_of(value: &Value, key: &str) -> u32 {
    u32::try_from(value[key].as_u64().unwrap_or_else(|| panic!("{key}"))).expect("a u32")
}

fn index_of(note: &Value) -> u32 {
    u32::try_from(note["index"].as_u64().expect("index")).expect("a note index is a u32")
}

fn purpose_of(note: &Value) -> u32 {
    u32::try_from(note["purpose"].as_u64().expect("purpose")).expect("a purpose is a u32")
}

/// BIP-39's seed from its mnemonic: PBKDF2-HMAC-SHA512, 2048 rounds, salt
/// "mnemonic" and no passphrase. Only here so the vectors' `mnemonic` is
/// graded against their `seedHex`: the crate itself takes raw seed bytes and
/// deliberately carries no wordlist.
fn bip39_seed(mnemonic: &str) -> Vec<u8> {
    let prf = Hmac::<sha2::Sha512>::new_from_slice(mnemonic.as_bytes())
        .expect("HMAC takes a key of any length");
    let mut first = prf.clone();
    first.update(b"mnemonic");
    first.update(&1u32.to_be_bytes());
    let mut round = first.finalize().into_bytes();
    let mut seed = round;
    for _ in 1..2048 {
        let mut next = prf.clone();
        next.update(&round);
        round = next.finalize().into_bytes();
        for (out, byte) in seed.iter_mut().zip(round.iter()) {
            *out ^= byte;
        }
    }
    seed.to_vec()
}

fn parity_of(private_key: &[u8; 32]) -> &'static str {
    let key = SecretKey::from_secret_bytes(*private_key).expect("a valid key");
    match key.x_only_public_key().1 {
        Parity::Even => "even",
        Parity::Odd => "odd",
    }
}

fn x_only_of(secret_key: &[u8; 32]) -> String {
    let key = SecretKey::from_secret_bytes(*secret_key).expect("a valid key");
    hex::encode(key.x_only_public_key().0.to_byte_array())
}

/// One key-path note's spend fields, as part2.json and nostr-seed.json both
/// carry them: the sighash for its domain, the signature, the `ck1`, and what
/// the SERVICE makes of it there and elsewhere.
fn grade_key_path_note(note: &Value, secret: &[u8; 32], host: &str, domain: &str, at: &str) {
    let pubkey = bytes32(note, "notePubkey");
    assert_eq!(
        hex::encode(key_path_sighash(&pubkey, domain)),
        str_of(note, "sighash"),
        "{at}: sighash"
    );
    // Fixed BIP-340 auxiliary input: the same key reproduces the same ck1 for
    // the same domain byte for byte, for seed recovery. Signing from the host
    // as stored reduces it to the domain first.
    let payload = sign_note_ownership(secret, host).expect("signs");
    assert_eq!(&payload[..32], &pubkey, "{at}");
    assert_eq!(
        hex::encode(&payload[32..]),
        str_of(note, "keyPathSignature"),
        "{at}"
    );
    let ck1 = str_of(note, "ck1");
    assert_eq!(encode_ck1(&payload), ck1, "{at}");
    assert_eq!(decode_ck1(&ck1), Some(DecodedCk1::Current(payload)), "{at}");

    // the SERVICE's side: the ck1 names its note, and opens it at its own
    // domain under the current scheme, and nowhere else
    let owner = recover_note_ownership_pubkey(&payload, domain).expect("verifies");
    assert_eq!((owner.pubkey_x_only, owner.legacy), (pubkey, false), "{at}");
    assert_eq!(note_id_of(&ck1), Some(str_of(note, "notePubkey")), "{at}");
    assert_eq!(note_lookup_of(&ck1), Some(str_of(note, "cp1")), "{at}");
    assert_eq!(
        check_spend(&ck1, domain).map(|check| check.verdict),
        Some(SpendVerdict::Opens),
        "{at}"
    );
    assert!(
        matches!(
            check_spend(&ck1, "elsewhere.example").map(|check| check.verdict),
            Some(SpendVerdict::Fails(_))
        ),
        "{at}: another mint"
    );
}

#[test]
fn part2_branch_vectors() {
    let vectors = load("part2.json");

    // The conventions this crate implements, named in the file, so a vector
    // regenerated under a different one fails here and not as a byte mismatch
    // three levels down.
    let conventions = &vectors["conventions"];
    assert_eq!(
        conventions["addressBranch"].as_str(),
        Some("m/139'/d1/d2/d3/d4")
    );
    assert_eq!(conventions["hashingKey"].as_str(), Some("m/139'/0"));
    assert_eq!(
        conventions["certificateMessage"].as_str(),
        Some("LNURLcash:<amount_msat>:<hex(pk)>")
    );
    assert_eq!(
        conventions["addressProofMessage"].as_str(),
        Some("LNURLcash:<register|unregister>:<domain>:<username>")
    );
    assert!(
        conventions.get("ownershipMessage").is_none(),
        "a ck1 no longer signs a fixed message"
    );

    let branches = vectors["branches"].as_array().expect("branches");
    // An odd branch is the only thing that exercises the negation, and the
    // top of the u32 range is where a hardened-index mistake would show.
    assert!(branches.iter().any(|b| b["branchParity"] == "odd"));
    assert!(branches.iter().any(|b| b["branchParity"] == "even"));
    // and a host with a port is where the derivation and the spend domain
    // part company
    assert!(branches.iter().any(|b| b["host"] != b["domain"]));
    let indices: Vec<u32> = branches[0]["notes"]
        .as_array()
        .expect("notes")
        .iter()
        .map(index_of)
        .collect();
    assert!(indices.contains(&0x8000_0000) && indices.contains(&u32::MAX));

    for branch in branches {
        let host = str_of(branch, "host");
        let domain = str_of(branch, "domain");
        assert_eq!(spend_domain_of(&host), Some(domain.clone()), "{host}");
        let seed = hex::decode(str_of(branch, "seedHex")).expect("seedHex is hex");
        assert_eq!(
            bip39_seed(&str_of(branch, "mnemonic")),
            seed,
            "{host}: mnemonic"
        );

        let root = derive_cash_root(&seed).expect("root");
        assert_eq!(
            cash_node_to_hex(&root),
            str_of(branch, "cashRoot"),
            "{host}"
        );
        // the hashing key is m/139'/0, so the four levels hang off the root
        // itself, derived from the host exactly as stored, port included
        let domain_indices: Vec<u32> = branch["domainIndices"]
            .as_array()
            .expect("domainIndices")
            .iter()
            .map(|value| u32::try_from(value.as_u64().expect("index")).expect("u32"))
            .collect();
        assert_eq!(
            cash_domain_indices(&root, &host).expect("indices").to_vec(),
            domain_indices,
            "{host}"
        );

        let node = derive_cash_address_node(&root, &host).expect("address node");
        assert_eq!(
            cash_node_to_hex(&node),
            str_of(branch, "addressNode"),
            "{host}"
        );
        assert_eq!(
            parity_of(&node.private_key),
            str_of(branch, "branchParity"),
            "{host}"
        );

        let cx1 = cash_node_to_cx1(&node).expect("cx1");
        assert_eq!(
            hex::encode(cx1.pubkey_x_only),
            str_of(branch, "branchPubkey"),
            "{host}"
        );
        assert_eq!(
            hex::encode(cx1.chain_code),
            str_of(branch, "chainCode"),
            "{host}"
        );
        assert_eq!(
            encode_cx1(&cx1.pubkey_x_only, &cx1.chain_code),
            str_of(branch, "cx1"),
            "{host}"
        );
        // a watcher starts from the string, never the node
        let watched = decode_cx1(&str_of(branch, "cx1")).expect("cx1 decodes");
        assert_eq!(watched, cx1, "{host}");

        for note in branch["notes"].as_array().expect("notes") {
            let index = index_of(note);
            let at = format!("{host} p{} #{index}", purpose_of(note));

            let pubkey = derive_note_pubkey(
                &watched.pubkey_x_only,
                &watched.chain_code,
                purpose_of(note),
                index,
            )
            .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(pubkey), str_of(note, "notePubkey"), "{at}");
            assert_eq!(encode_cp1(&pubkey), str_of(note, "cp1"), "{at}");
            assert_eq!(decode_cp1(&str_of(note, "cp1")), Some(pubkey), "{at}");

            let secret = derive_note_secret_key(
                &node.private_key,
                &node.chain_code,
                purpose_of(note),
                index,
            )
            .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(secret), str_of(note, "noteSecretKey"), "{at}");

            grade_key_path_note(note, &secret, &host, &domain, &at);
        }
    }
}

#[test]
fn address_proof_vectors() {
    let vectors = load("part2.json");
    let proofs = vectors["addressProofs"].as_array().expect("addressProofs");
    assert!(!proofs.is_empty());
    for proof in proofs {
        let action = str_of(proof, "action");
        let domain = str_of(proof, "domain");
        let username = str_of(proof, "username");
        let at = format!("{action} {username}@{domain}");
        let secret = bytes32(proof, "indexZeroSecretKey");
        assert_eq!(x_only_of(&secret), str_of(proof, "indexZeroPubkey"), "{at}");
        assert_eq!(
            address_proof_message(&action, &domain, &username).expect("valid action"),
            str_of(proof, "message"),
            "{at}"
        );
        assert_eq!(
            hex::encode(address_proof_digest(&action, &domain, &username).expect("digest")),
            str_of(proof, "digest"),
            "{at}"
        );
        let signature = sign_address_proof(&secret, &action, &domain, &username).expect("signs");
        assert_eq!(hex::encode(signature), str_of(proof, "signature"), "{at}");

        // what the SERVICE checks: BIP-340 against pk_0, over the digest
        let verifier = k256::schnorr::VerifyingKey::from_slice(&bytes32(proof, "indexZeroPubkey"))
            .expect("a key");
        let parsed = k256::schnorr::Signature::try_from(&signature[..]).expect("a signature");
        assert!(verifier
            .verify_raw(
                &address_proof_digest(&action, &domain, &username).expect("digest"),
                &parsed
            )
            .is_ok());

        // bound to its domain: the proof for another SERVICE is another proof
        assert_ne!(
            sign_address_proof(&secret, &action, "elsewhere.example", &username).expect("signs"),
            signature,
            "{at}"
        );
    }
    assert!(address_proof_message("delete", "mint.example", "alice").is_err());
    assert!(address_proof_message("register", "", "alice").is_err());
}

#[test]
fn part2_certificate_vectors() {
    let vectors = load("part2.json");
    let mint = &vectors["mint"];
    let mint_pubkey = str_of(mint, "mintPubkey");
    let mint_key =
        SecretKey::from_secret_bytes(bytes32(mint, "privateKey")).expect("the mint's key");
    assert_eq!(
        hex::encode(PublicKey::from_secret_key(&mint_key).serialize()),
        mint_pubkey,
        "the mint's key pair"
    );

    // Every note in the file by key, so each certificate is checked the way a
    // recipient checks one: from the note's ck1 and its domain, nothing else.
    let ck1_of: HashMap<String, (String, String)> = vectors["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .flat_map(|branch| {
            let domain = str_of(branch, "domain");
            branch["notes"]
                .as_array()
                .expect("notes")
                .iter()
                .map(move |note| {
                    (
                        str_of(note, "notePubkey"),
                        (str_of(note, "ck1"), domain.clone()),
                    )
                })
        })
        .collect();

    let certificates = vectors["certificates"].as_array().expect("certificates");
    assert!(!certificates.is_empty());
    for certificate in certificates {
        let pubkey = str_of(certificate, "notePubkey");
        let amount = certificate["amountMsat"].as_u64().expect("amountMsat");
        let at = format!("{amount} msat");
        let message = str_of(certificate, "message");
        let digest = str_of(certificate, "digest");

        assert_eq!(
            note_signature_message_for_hash(&pubkey, amount),
            message,
            "{at}"
        );
        assert_eq!(
            hex::encode(note_signature_digest_for_hash(&pubkey, amount)),
            digest,
            "{at}"
        );
        let (ck1, domain) = ck1_of
            .get(&pubkey)
            .unwrap_or_else(|| panic!("{at}: the certificate names a note in the file"));
        assert_eq!(
            note_signature_message(ck1, amount).as_deref(),
            Some(message.as_str()),
            "{at}"
        );
        assert_eq!(
            note_signature_digest(ck1, amount).map(hex::encode),
            Some(digest.clone()),
            "{at}"
        );

        let signature_hex = str_of(certificate, "signature");
        let signature: [u8; 65] = hex::decode(&signature_hex)
            .expect("hex")
            .try_into()
            .expect("65 bytes");
        let cs1 = str_of(certificate, "cs1");
        assert_eq!(encode_cs1_with_amount(amount, &signature), cs1, "{at}");
        let decoded = decode_cs1_with_amount(&cs1).unwrap_or_else(|| panic!("{at}: cs1 decodes"));
        assert_eq!(decoded.amount_msat, amount, "{at}");
        assert_eq!(decoded.signature, signature, "{at}");

        // RFC6979 on the mint's side too: its key over the digest reproduces
        // the certificate
        let digest_bytes: [u8; 32] = hex::decode(&digest)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let (recovery, compact) = RecoverableSignature::sign_ecdsa_recoverable(
            Message::from_digest(digest_bytes),
            &mint_key,
        )
        .serialize_compact();
        assert_eq!(&signature[..64], &compact[..], "{at}");
        assert_eq!(signature[64], u8::from(recovery), "{at}");

        // Each recovers to the mint's key: by the note's id, in either
        // spelling of the signature, by its cp1, and from the ck1 at its
        // domain...
        assert!(
            verify_note_signature_hash(&pubkey, amount, &signature_hex, &mint_pubkey),
            "{at}"
        );
        assert!(
            verify_note_signature_hash(&pubkey, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        let cp1 = encode_cp1(&bytes32(certificate, "notePubkey"));
        assert_eq!(
            check_note_certificate(&cp1, amount, &cs1, &mint_pubkey),
            Some(CertifiedOver::OutputKey),
            "{at}"
        );
        let check = check_note(ck1, domain, amount, &cs1, &mint_pubkey).expect("verifies");
        assert_eq!(check.certificate, CertifiedOver::OutputKey, "{at}");
        assert_eq!(check.spend, SpendVerdict::Opens, "{at}");
        assert!(
            verify_note_signature(ck1, domain, amount, &signature_hex, &mint_pubkey),
            "{at}"
        );
        // ...and to nothing it does not cover
        assert!(
            !verify_note_signature(ck1, domain, amount + 1, &cs1, &mint_pubkey),
            "{at}: another amount"
        );
        let (other, other_domain) = ck1_of
            .iter()
            .find(|(key, _)| **key != pubkey)
            .map(|(_, other)| other)
            .expect("another note");
        assert!(
            !verify_note_signature(other, other_domain, amount, &cs1, &mint_pubkey),
            "{at}: another note"
        );
        // A cs1 whose prefix states another amount than the one it signs
        // proves nothing, whichever amount is asked about.
        let relabelled = encode_cs1_with_amount(amount + 1000, &signature);
        assert!(
            !verify_note_signature_hash(&pubkey, amount, &relabelled, &mint_pubkey),
            "{at}: relabelled"
        );
        assert!(
            !verify_note_signature_hash(&pubkey, amount + 1000, &relabelled, &mint_pubkey),
            "{at}: relabelled"
        );

        // The certificate is public, and so is Q. A ck1 pairing them with a
        // signature that does not open the note must not pass as the note,
        // however good the certificate: it is refused at the note's own
        // domain, and so is the genuine ck1 at any other.
        let mut forged = decode_ck1(ck1).expect("a ck1").as_bytes().to_vec();
        forged[40] ^= 0x01;
        let forged = encode_ck1(&forged.try_into().expect("96 bytes"));
        let check = check_note(&forged, domain, amount, &cs1, &mint_pubkey)
            .expect("the certificate itself is good");
        assert!(matches!(check.spend, SpendVerdict::Fails(_)), "{at}");
        assert!(!check.is_verified(), "{at}");
        assert!(
            !verify_note_signature(&forged, domain, amount, &cs1, &mint_pubkey),
            "{at}: forged"
        );
        assert!(
            !verify_note_signature(ck1, "elsewhere.example", amount, &cs1, &mint_pubkey),
            "{at}: another mint"
        );
    }
}

#[test]
fn part2_string_vectors() {
    let vectors = load("part2.json");

    // the payload as hex, or None, for each type
    let decode = |kind: &str, value: &str| -> Option<String> {
        let (decoded, is) = match kind {
            "cp1" => (decode_cp1(value).map(hex::encode), is_cp1(value)),
            "ck1" => (
                decode_ck1(value).map(|decoded| hex::encode(decoded.as_bytes())),
                is_ck1(value),
            ),
            "cw1" => (
                decode_cw1(value).map(|cw1| format!("{cw1:?}")),
                is_cw1(value),
            ),
            "cs1" => (
                decode_cs1_with_amount(value).map(|cs1| hex::encode(cs1.signature)),
                is_cs1_with_amount(value),
            ),
            "cx1" => (
                decode_cx1(value).map(|cx1| {
                    format!(
                        "{}{}",
                        hex::encode(cx1.pubkey_x_only),
                        hex::encode(cx1.chain_code)
                    )
                }),
                is_cx1(value),
            ),
            other => panic!("a string type this crate does not know: {other}"),
        };
        assert_eq!(
            decoded.is_some(),
            is,
            "{kind} {value}: is_ and decode_ disagree"
        );
        decoded
    };

    for case in vectors["valid"].as_array().expect("valid") {
        let why = str_of(case, "why");
        assert_eq!(
            decode(&str_of(case, "type"), &str_of(case, "value")),
            Some(str_of(case, "bytes")),
            "{why}"
        );
    }
    let invalid = vectors["invalid"].as_array().expect("invalid");
    assert!(!invalid.is_empty());
    for case in invalid {
        let why = str_of(case, "why");
        assert!(!why.is_empty(), "an invalid string without a reason");
        assert_eq!(
            decode(&str_of(case, "type"), &str_of(case, "value")),
            None,
            "{why}"
        );
    }
}

/// An extension, not LUD-25: a key-path branch rooted in a Nostr identity key.
#[test]
fn nostr_seed_vectors() {
    let vectors = load("nostr-seed.json");
    assert_eq!(vectors["extension"].as_bool(), Some(true));
    assert_eq!(vectors["label"].as_str(), Some(NOSTR_CASH_SEED_LABEL));

    let cases = vectors["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let host = str_of(case, "host");
        let domain = str_of(case, "domain");
        assert_eq!(spend_domain_of(&host), Some(domain.clone()), "{host}");
        let identity = bytes32(case, "identity");

        assert_eq!(
            hex::encode(derive_nostr_cash_seed(&identity)),
            str_of(case, "seed"),
            "{host}"
        );
        // the npub a lightning address on this branch belongs to
        assert_eq!(
            x_only_of(&identity),
            str_of(case, "identityPubkey"),
            "{host}"
        );

        let node = derive_nostr_address_node(&identity, &host).expect("address node");
        assert_eq!(
            cash_node_to_hex(&node),
            str_of(case, "addressNode"),
            "{host}"
        );
        let cx1 = cash_node_to_cx1(&node).expect("cx1");
        assert_eq!(
            encode_cx1(&cx1.pubkey_x_only, &cx1.chain_code),
            str_of(case, "cx1"),
            "{host}"
        );

        for note in case["notes"].as_array().expect("notes") {
            let index = index_of(note);
            let at = format!("{host} p{} #{index}", purpose_of(note));
            let secret = derive_note_secret_key(
                &node.private_key,
                &node.chain_code,
                purpose_of(note),
                index,
            )
            .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(secret), str_of(note, "noteSecretKey"), "{at}");
            let pubkey =
                derive_note_pubkey(&cx1.pubkey_x_only, &cx1.chain_code, purpose_of(note), index)
                    .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(pubkey), str_of(note, "notePubkey"), "{at}");
            assert_eq!(encode_cp1(&pubkey), str_of(note, "cp1"), "{at}");
            grade_key_path_note(note, &secret, &host, &domain, &at);
        }
    }
}

/// The canonical spend transaction, serialised with its witness, the way
/// spec vector 3 prints it: nVersion 2, segwit marker and flag, one input
/// spending (prevout, 0) with an empty scriptSig and the given sequence, one
/// output of value 0 with an empty scriptPubKey, the witness, and the
/// locktime. The crate never builds one - nothing is ever broadcast - but a
/// port can check its sighash against Bitcoin Core's by it.
fn canonical_spend_transaction(
    prevout: &[u8; 32],
    sequence: u32,
    locktime: u32,
    witness: &[&[u8]],
) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&2u32.to_le_bytes());
    tx.extend_from_slice(&[0x00, 0x01, 0x01]);
    tx.extend_from_slice(prevout);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0x00);
    tx.extend_from_slice(&sequence.to_le_bytes());
    tx.push(0x01);
    tx.extend_from_slice(&0u64.to_le_bytes());
    tx.push(0x00);
    tx.push(u8::try_from(witness.len()).expect("a short witness"));
    for item in witness {
        tx.push(u8::try_from(item.len()).expect("a short item"));
        tx.extend_from_slice(item);
    }
    tx.extend_from_slice(&locktime.to_le_bytes());
    tx
}

/// LUD-25's own published "Test Vectors" section (25.md), transcribed as
/// spec-vectors.json - every value here is what the spec document itself
/// publishes, not just this project's own internally-generated fixtures.
#[test]
fn spec_vectors() {
    let vectors = load("spec-vectors.json");

    let branch_of = |case: &Value| -> lnurlcash_core::cash::CashNode {
        let seed = hex::decode(str_of(case, "seedHex")).expect("seedHex is hex");
        let root = derive_cash_root(&seed).expect("root");
        let host = str_of(case, "domain");

        let hashing = derive_cash_child(&root, 0).expect("hashing key");
        assert_eq!(
            hex::encode(hashing.private_key),
            str_of(case, "cashHashingKey")
        );

        let indices: Vec<u32> = case["domainIndices"]
            .as_array()
            .expect("domainIndices")
            .iter()
            .map(|v| v.as_u64().expect("index") as u32)
            .collect();
        assert_eq!(
            cash_domain_indices(&root, &host).expect("indices").to_vec(),
            indices
        );

        let branch = derive_cash_domain_node(&root, &host).expect("branch");
        assert_eq!(
            hex::encode(branch.private_key),
            str_of(case, "branchPrivateKey")
        );
        assert_eq!(hex::encode(branch.chain_code), str_of(case, "chainCode"));

        let cx1 = cash_node_to_cx1(&branch).expect("cx1");
        assert_eq!(
            hex::encode(cx1.pubkey_x_only),
            str_of(case, "branchPubkeyXOnly")
        );
        assert_eq!(
            encode_cx1(&cx1.pubkey_x_only, &cx1.chain_code),
            str_of(case, "cx1")
        );
        branch
    };

    for vector_name in ["vector1", "vector2"] {
        let case = &vectors[vector_name];
        let branch = branch_of(case);
        let cx1 = cash_node_to_cx1(&branch).expect("cx1");

        for note in case["notes"].as_array().expect("notes") {
            let index = note["index"].as_u64().expect("index") as u32;
            let at = format!("{vector_name} p{} #{index}", purpose_of(note));

            let pk =
                derive_note_pubkey(&cx1.pubkey_x_only, &cx1.chain_code, purpose_of(note), index)
                    .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(pk), str_of(note, "pk"), "{at}");
            assert_eq!(encode_cp1(&pk), str_of(note, "cp1"), "{at}");

            let sk = derive_note_secret_key(
                &branch.private_key,
                &branch.chain_code,
                purpose_of(note),
                index,
            )
            .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(sk), str_of(note, "sk"), "{at}");

            // x(sk_i . G) == pk_i, the round-trip 25.md calls out explicitly
            assert_eq!(
                x_only_of(&sk),
                str_of(note, "pk"),
                "{at}: sk_i.G round-trip"
            );
        }
    }

    // vector 2's LN address registration proofs, signed by sk_0 and bound to
    // the vector's own domain
    let v2 = &vectors["vector2"];
    let branch2 = branch_of(v2);
    let sk0 = derive_note_secret_key(&branch2.private_key, &branch2.chain_code, PURPOSE_WALLET, 0)
        .expect("sk_0");
    for proof in v2["addressProofs"].as_array().expect("addressProofs") {
        let action = str_of(proof, "action");
        let domain = str_of(proof, "domain");
        let username = str_of(proof, "username");
        assert_eq!(domain, str_of(v2, "domain"));
        assert_eq!(
            address_proof_message(&action, &domain, &username).expect("message"),
            str_of(proof, "message")
        );
        assert_eq!(
            hex::encode(address_proof_digest(&action, &domain, &username).expect("digest")),
            str_of(proof, "digest")
        );
        let signature = sign_address_proof(&sk0, &action, &domain, &username).expect("signs");
        assert_eq!(
            hex::encode(signature),
            str_of(proof, "signature"),
            "{action}"
        );
    }

    // vector 3: a key-path spend, every step from domain to signature
    let v3 = &vectors["vector3"];
    let sk3 = bytes32(v3, "secretKey");
    let q3 = bytes32(v3, "Q");
    let domain3 = str_of(v3, "domain");
    assert_eq!(x_only_of(&sk3), str_of(v3, "Q"));
    assert_eq!(encode_cp1(&q3), str_of(v3, "cp1"));
    let prevout = spend_prevout(&domain3);
    assert_eq!(hex::encode(prevout), str_of(v3, "prevoutTxid"));
    assert_eq!(
        format!("5120{}", hex::encode(q3)),
        str_of(v3, "spentScriptPubKey")
    );
    let sig_msg = spend_sig_msg(&q3, &domain3, 0, 0xffff_ffff, None);
    assert_eq!(hex::encode(&sig_msg), str_of(v3, "sigMsg"));
    assert_eq!(sig_msg.len(), 174);
    let fields = &v3["sigMsgFields"];
    for (name, range) in [
        ("hash_type", 0..1),
        ("nVersion", 1..5),
        ("nLockTime", 5..9),
        ("sha_prevouts", 9..41),
        ("sha_amounts", 41..73),
        ("sha_scriptpubkeys", 73..105),
        ("sha_sequences", 105..137),
        ("sha_outputs", 137..169),
        ("spend_type", 169..170),
        ("input_index", 170..174),
    ] {
        assert_eq!(hex::encode(&sig_msg[range]), str_of(fields, name), "{name}");
    }
    let sighash = key_path_sighash(&q3, &domain3);
    assert_eq!(hex::encode(sighash), str_of(v3, "sighash"));
    assert_eq!(tagged_hash("TapSighash", &[&[0x00], &sig_msg]), sighash);
    assert_eq!(str_of(v3, "auxRand"), "00".repeat(32));
    let payload = sign_note_ownership(&sk3, &domain3).expect("signs");
    assert_eq!(&payload[..32], &q3);
    assert_eq!(hex::encode(&payload[32..]), str_of(v3, "signature"));
    assert_eq!(
        hex::encode(canonical_spend_transaction(
            &prevout,
            0xffff_ffff,
            0,
            &[&payload[32..]]
        )),
        str_of(v3, "spendTransaction")
    );
    let ck1 = str_of(v3, "ck1");
    assert_eq!(encode_ck1(&payload), ck1);
    assert_eq!(
        check_spend(&ck1, &domain3).map(|check| check.verdict),
        Some(SpendVerdict::Opens)
    );
    // "The same ck1 submitted to a SERVICE on any other domain fails"
    assert!(matches!(
        check_spend(&ck1, "moneyer.dev").map(|check| check.verdict),
        Some(SpendVerdict::Fails(_))
    ));

    // vector 4: cs1 mint offline certificate, over pk_0/pk_1 from vector 1
    let v4 = &vectors["vector4"];
    let mint_key =
        SecretKey::from_secret_bytes(bytes32(v4, "mintPrivateKey")).expect("valid mint key");
    let mint_pubkey = hex::encode(PublicKey::from_secret_key(&mint_key).serialize());
    assert_eq!(mint_pubkey, str_of(v4, "mintPubkey"));
    let sign_certificate = |digest: [u8; 32]| -> String {
        let (recovery, compact) =
            RecoverableSignature::sign_ecdsa_recoverable(Message::from_digest(digest), &mint_key)
                .serialize_compact();
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&compact);
        signature[64] = u8::from(recovery);
        hex::encode(signature)
    };

    let pk = str_of(v4, "notePubkey");
    let other_pk = str_of(v4, "otherNotePubkey");
    for cert in v4["certificates"].as_array().expect("certificates") {
        let amount = cert["amountMsat"].as_u64().expect("amountMsat");
        let at = format!("{amount} msat");

        assert_eq!(
            note_signature_message_for_hash(&pk, amount),
            str_of(cert, "message"),
            "{at}"
        );
        let digest = note_signature_digest_for_hash(&pk, amount);
        assert_eq!(hex::encode(digest), str_of(cert, "digest"), "{at}");

        let signature_hex = sign_certificate(digest);
        assert_eq!(signature_hex, str_of(cert, "signature"), "{at}");
        let signature: [u8; 65] = hex::decode(&signature_hex)
            .expect("hex")
            .try_into()
            .expect("65 bytes");
        let cs1 = encode_cs1_with_amount(amount, &signature);
        assert_eq!(cs1, str_of(cert, "cs1"), "{at}");

        assert!(
            verify_note_signature_hash(&pk, amount, &signature_hex, &mint_pubkey),
            "{at}"
        );
        assert!(
            !verify_note_signature_hash(&other_pk, amount, &signature_hex, &mint_pubkey),
            "{at}: another note"
        );
        // by its cp1, and from vector 3's ck1 of the same key
        let cp1 = encode_cp1(&bytes32(v4, "notePubkey"));
        assert_eq!(
            check_note_certificate(&cp1, amount, &cs1, &mint_pubkey),
            Some(CertifiedOver::OutputKey),
            "{at}"
        );
        assert!(
            verify_note_signature(&ck1, &domain3, amount, &cs1, &mint_pubkey),
            "{at}"
        );
    }

    // vector 5: a bearer note, from preimage to cw1 and its certificate
    let v5 = &vectors["vector5"];
    let preimage = str_of(v5, "preimage");
    let h = bytes32(v5, "h");
    let q5 = bytes32(v5, "Q");
    assert_eq!(hash_k1(&preimage).expect("hash"), str_of(v5, "h"));
    assert_eq!(hex::encode(bearer_leaf(&h)), str_of(v5, "leaf"));
    assert_eq!(
        hex::encode(tapleaf_hash(&bearer_leaf(&h), TAPLEAF_VERSION)),
        str_of(v5, "tapleafHash")
    );
    assert_eq!(hex::encode(NUMS_H), str_of(v5, "H"));
    assert_eq!(
        hex::encode(tagged_hash(
            "TapTweak",
            &[&NUMS_H, &bytes32(v5, "tapleafHash")]
        )),
        str_of(v5, "t")
    );
    let note = bearer_note(&h).expect("a bearer note");
    assert_eq!(note.output_key, q5);
    assert_eq!(hex::encode(note.control_block), str_of(v5, "controlBlock"));
    let cp1 = str_of(v5, "cp1");
    assert_eq!(encode_cp1(&q5), cp1);
    // "The hex h and cp1<Q> name the same note"
    assert_eq!(decode_note(&str_of(v5, "h")), Some(q5));
    assert_eq!(decode_note(&cp1), Some(q5));
    // "the hex preimage and the full cw1 are the same spend"
    let cw1 = str_of(v5, "cw1");
    let preimage_bytes = hex::decode(&preimage).expect("hex");
    assert_eq!(
        encode_cw1(&bearer_cw1(&preimage_bytes).expect("a cw1")).expect("encodes"),
        cw1
    );
    assert_eq!(note_id_of(&preimage), Some(str_of(v5, "Q")));
    assert_eq!(note_id_of(&cw1), Some(str_of(v5, "Q")));
    assert_eq!(note_lookup_of(&preimage), Some(str_of(v5, "h")));
    assert_eq!(note_lookup_of(&cw1), Some(cp1.clone()));
    // "and open Q at any domain, since the leaf checks no signature"
    for domain in ["mint.example", "moneyer.dev"] {
        for spend in [&preimage, &cw1] {
            assert_eq!(
                check_spend(spend, domain),
                Some(lnurlcash_core::SpendCheck {
                    output_key: q5,
                    verdict: SpendVerdict::Opens
                }),
                "{spend} at {domain}"
            );
        }
    }

    let mint_pubkey5 = str_of(v5, "mintPubkey");
    assert_eq!(mint_pubkey5, mint_pubkey, "vector 4's SERVICE key");
    let cert = &v5["certificate"];
    let amount = cert["amountMsat"].as_u64().expect("amountMsat");
    assert_eq!(
        note_signature_message(&preimage, amount),
        Some(str_of(cert, "message"))
    );
    let digest = note_signature_digest(&preimage, amount).expect("digest");
    assert_eq!(hex::encode(digest), str_of(cert, "digest"));
    assert_eq!(sign_certificate(digest), str_of(cert, "signature"));
    let cs1 = str_of(cert, "cs1");
    for spend in [&preimage, &cw1] {
        let check = check_note(spend, "mint.example", amount, &cs1, &mint_pubkey)
            .unwrap_or_else(|| panic!("{spend}: certified"));
        assert_eq!(check.output_key, q5);
        assert_eq!(check.certificate, CertifiedOver::OutputKey);
        assert!(check.is_verified());
    }
    for reference in [str_of(v5, "h"), cp1] {
        assert_eq!(
            check_note_certificate(&reference, amount, &cs1, &mint_pubkey),
            Some(CertifiedOver::OutputKey),
            "{reference}"
        );
    }
    let url = str_of(v5, "certifiedNoteUrl");
    assert_eq!(note_declared_amount(&url), Some(amount));
    let check = check_note_url(&url, &mint_pubkey).expect("a certified note");
    assert_eq!(
        (check.output_key, check.certificate, check.is_verified()),
        (q5, CertifiedOver::OutputKey, true)
    );
}

// ---- spends ----
//
// spends.json: bearer notes, key-path spends across domains, a script tree,
// a CHECKSIG leaf's script-path sighash, time claims, leaf rules, malformed
// cw1s, off-curve cp1s and the short forms. The mint's rules are here too,
// so a wallet can tell a holder what a mint will do with a note.

#[test]
fn spends_bearer_vectors() {
    let vectors = load("spends.json");
    assert_eq!(str_of(&vectors, "nums"), hex::encode(NUMS_H));
    let bearers = vectors["bearers"].as_array().expect("bearers");
    // both parities, so both control-block leading bytes
    assert!(bearers.iter().any(|b| b["parity"] == 0));
    assert!(bearers.iter().any(|b| b["parity"] == 1));
    for bearer in bearers {
        let name = str_of(bearer, "name");
        let preimage = str_of(bearer, "preimage");
        let h = bytes32(bearer, "h");
        assert_eq!(
            hash_k1(&preimage).expect("hash"),
            str_of(bearer, "h"),
            "{name}"
        );
        assert_eq!(
            hex::encode(bearer_leaf(&h)),
            str_of(bearer, "leaf"),
            "{name}"
        );
        let leaf_hash = tapleaf_hash(&bearer_leaf(&h), TAPLEAF_VERSION);
        assert_eq!(
            hex::encode(leaf_hash),
            str_of(bearer, "tapleafHash"),
            "{name}"
        );
        assert_eq!(
            hex::encode(tagged_hash("TapTweak", &[&NUMS_H, &leaf_hash])),
            str_of(bearer, "tweak"),
            "{name}"
        );
        let tweaked = taproot_tweak(&NUMS_H, &leaf_hash).expect("tweaks");
        assert_eq!(
            hex::encode(tweaked.output_key),
            str_of(bearer, "Q"),
            "{name}"
        );
        assert_eq!(
            u64::from(tweaked.parity),
            bearer["parity"].as_u64().expect("parity"),
            "{name}"
        );
        let note = bearer_note(&h).expect("a bearer note");
        assert_eq!(
            hex::encode(note.control_block),
            str_of(bearer, "controlBlock"),
            "{name}"
        );
        assert_eq!(
            encode_cp1(&note.output_key),
            str_of(bearer, "cp1"),
            "{name}"
        );
        let cw1 = str_of(bearer, "cw1");
        assert_eq!(
            encode_cw1(&bearer_cw1(&hex::decode(&preimage).expect("hex")).expect("a cw1"))
                .expect("encodes"),
            cw1,
            "{name}"
        );
        assert_eq!(note_id_of(&cw1), Some(str_of(bearer, "Q")), "{name}");
        assert_eq!(note_id_of(&preimage), Some(str_of(bearer, "Q")), "{name}");
    }
}

#[test]
fn spends_key_path_vectors() {
    let vectors = load("spends.json");
    let key_path = &vectors["keyPath"];
    let secret = bytes32(key_path, "secretKey");
    let q = bytes32(key_path, "Q");
    assert_eq!(x_only_of(&secret), str_of(key_path, "Q"));
    assert_eq!(encode_cp1(&q), str_of(key_path, "cp1"));

    let mut ck1_at = HashMap::new();
    for spend in key_path["spends"].as_array().expect("spends") {
        let domain = str_of(spend, "domain");
        let normalised = str_of(spend, "normalisedDomain");
        assert_eq!(
            spend_domain_of(&domain),
            Some(normalised.clone()),
            "{domain}"
        );
        assert_eq!(
            hex::encode(spend_prevout(&normalised)),
            str_of(spend, "prevoutTxid"),
            "{domain}"
        );
        assert_eq!(
            hex::encode(key_path_sighash(&q, &normalised)),
            str_of(spend, "sighash"),
            "{domain}"
        );
        let payload = sign_note_ownership(&secret, &domain).expect("signs");
        assert_eq!(
            hex::encode(&payload[32..]),
            str_of(spend, "signature"),
            "{domain}"
        );
        let ck1 = str_of(spend, "ck1");
        assert_eq!(encode_ck1(&payload), ck1, "{domain}");
        assert_eq!(
            check_spend(&ck1, &domain).map(|check| check.verdict),
            Some(SpendVerdict::Opens),
            "{domain}"
        );
        ck1_at.insert(normalised, ck1);
    }
    let cross = key_path["crossDomain"].as_array().expect("crossDomain");
    assert!(cross.iter().any(|case| case["valid"] == true));
    assert!(cross.iter().any(|case| case["valid"] == false));
    for case in cross {
        let signed_for = str_of(case, "signedFor");
        let verified_at = str_of(case, "verifiedAt");
        let ck1 = &ck1_at[&signed_for];
        assert_eq!(
            check_spend(ck1, &verified_at).is_some_and(|check| check.verdict.opens()),
            case["valid"].as_bool().expect("valid"),
            "{signed_for} at {verified_at}: {}",
            str_of(case, "why")
        );
    }

    for case in vectors["domains"].as_array().expect("domains") {
        let url = str_of(case, "url");
        assert_eq!(spend_domain_of(&url), Some(str_of(case, "domain")), "{url}");
    }
}

#[test]
fn spends_tree_vectors() {
    let vectors = load("spends.json");
    let tree = &vectors["tree"];
    let internal_secret = bytes32(tree, "internalSecretKey");
    let internal = bytes32(tree, "internalKey");
    assert_eq!(x_only_of(&internal_secret), str_of(tree, "internalKey"));
    assert_eq!(
        str_of(tree, "shape"),
        "root = branch(branch(leaves[0], leaves[1]), leaves[2])"
    );

    let leaves = tree["leaves"].as_array().expect("leaves");
    let hashes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let version = u8::try_from(leaf["version"].as_u64().expect("version")).expect("a byte");
            let hash = tapleaf_hash(&bytes_of(leaf, "script"), version);
            assert_eq!(hex::encode(hash), str_of(leaf, "tapleafHash"));
            hash
        })
        .collect();
    let root = tapbranch_hash(&tapbranch_hash(&hashes[0], &hashes[1]), &hashes[2]);
    assert_eq!(hex::encode(root), str_of(tree, "merkleRoot"));
    assert_eq!(
        hex::encode(tagged_hash("TapTweak", &[&internal, &root])),
        str_of(tree, "tweak")
    );
    let tweaked = taproot_tweak(&internal, &root).expect("tweaks");
    let q = bytes32(tree, "Q");
    assert_eq!(tweaked.output_key, q);
    assert_eq!(
        u64::from(tweaked.parity),
        tree["parity"].as_u64().expect("parity")
    );
    assert_eq!(encode_cp1(&q), str_of(tree, "cp1"));

    for (index, leaf) in leaves.iter().enumerate() {
        let at = format!("leaf {index}");
        let script = bytes_of(leaf, "script");
        let control_block = bytes_of(leaf, "controlBlock");
        // whatever the leaf version, its control block commits to Q: the
        // version is policed by the mint, not the fold
        assert_eq!(output_key_of(&script, &control_block), Some(q), "{at}");
        let cw1 = Cw1 {
            locktime: 0,
            sequence: 0xffff_ffff,
            script,
            control_block,
            witness: leaf["witness"]
                .as_array()
                .expect("witness")
                .iter()
                .map(|item| hex::decode(item.as_str().expect("hex")).expect("hex"))
                .collect(),
        };
        let encoded = str_of(leaf, "cw1");
        assert_eq!(encode_cw1(&cw1).expect("encodes"), encoded, "{at}");
        assert_eq!(decode_cw1(&encoded), Some(cw1), "{at}");
        assert_eq!(note_id_of(&encoded), Some(str_of(tree, "Q")), "{at}");
        let verdict = check_spend(&encoded, "mint.example")
            .expect("a spend")
            .verdict;
        match str_of(leaf, "verdict").as_str() {
            "accept" => assert_eq!(verdict, SpendVerdict::Opens, "{at}"),
            "reject" => {
                let reason = str_of(leaf, "reason");
                assert!(
                    matches!(&verdict, SpendVerdict::Fails(why) if why.contains(&reason)),
                    "{at}: {verdict:?}, want {reason}"
                );
            }
            other => panic!("{at}: a verdict this suite does not know: {other}"),
        }
    }

    // and by its key path, with the key tweaked by the tree
    let key_path = &tree["keyPath"];
    let domain = str_of(key_path, "domain");
    let tweaked_secret = taproot_tweak_secret_key(&internal_secret, &root).expect("tweaks");
    assert_eq!(
        hex::encode(tweaked_secret),
        str_of(key_path, "tweakedSecretKey")
    );
    assert_eq!(
        hex::encode(key_path_sighash(&q, &domain)),
        str_of(key_path, "sighash")
    );
    let payload = sign_note_ownership(&tweaked_secret, &domain).expect("signs");
    assert_eq!(&payload[..32], &q);
    assert_eq!(hex::encode(&payload[32..]), str_of(key_path, "signature"));
    let ck1 = str_of(key_path, "ck1");
    assert_eq!(encode_ck1(&payload), ck1);
    assert_eq!(
        check_spend(&ck1, &domain).map(|check| check.verdict),
        Some(SpendVerdict::Opens)
    );
}

#[test]
fn spends_checksig_vectors() {
    let vectors = load("spends.json");
    let checksig = &vectors["checksig"];
    let secret = bytes32(checksig, "secretKey");
    let pubkey = str_of(checksig, "pubkey");
    assert_eq!(x_only_of(&secret), pubkey);
    let leaf = bytes_of(checksig, "leaf");
    assert_eq!(
        hex::encode(&leaf),
        format!("20{pubkey}ac"),
        "<pk> OP_CHECKSIG"
    );
    let control_block = bytes_of(checksig, "controlBlock");
    let q = bytes32(checksig, "Q");
    assert_eq!(output_key_of(&leaf, &control_block), Some(q));
    assert_eq!(encode_cp1(&q), str_of(checksig, "cp1"));
    let domain = str_of(checksig, "domain");
    let signer = k256::schnorr::SigningKey::from_slice(&secret).expect("a key");

    for spend in checksig["spends"].as_array().expect("spends") {
        let locktime = u32_of(spend, "locktime");
        let sequence = u32_of(spend, "sequence");
        let at = format!("locktime {locktime}, sequence {sequence}");
        let sig_msg = spend_sig_msg(&q, &domain, locktime, sequence, Some(&leaf));
        assert_eq!(hex::encode(&sig_msg), str_of(spend, "sigMsg"), "{at}");
        let sighash = script_path_sighash(&q, &domain, &leaf, locktime, sequence);
        assert_eq!(hex::encode(sighash), str_of(spend, "sighash"), "{at}");
        // a leaf signature is an ordinary BIP-340 signature over that sighash
        let signature = bytes_of(spend, "signature");
        let parsed = k256::schnorr::Signature::try_from(&signature[..]).expect("a signature");
        assert!(signer.verifying_key().verify_raw(&sighash, &parsed).is_ok());
        let cw1 = Cw1 {
            locktime,
            sequence,
            script: leaf.clone(),
            control_block: control_block.clone(),
            witness: vec![signature],
        };
        let encoded = str_of(spend, "cw1");
        assert_eq!(encode_cw1(&cw1).expect("encodes"), encoded, "{at}");
        assert_eq!(decode_cw1(&encoded), Some(cw1), "{at}");
        // Named, and within the leaf rules, but a CHECKSIG leaf is a script
        // this crate leaves to the mint's interpreter rather than half-runs.
        assert_eq!(
            check_spend(&encoded, &domain),
            Some(lnurlcash_core::SpendCheck {
                output_key: q,
                verdict: SpendVerdict::Unevaluated
            }),
            "{at}"
        );
        match decode_spend(&encoded) {
            Some(Spend::ScriptPath { cw1, .. }) => {
                assert_eq!((cw1.locktime, cw1.sequence), (locktime, sequence), "{at}")
            }
            other => panic!("{at}: {other:?}"),
        }
    }
}

#[test]
fn spends_rule_vectors() {
    let vectors = load("spends.json");

    let time_claims = vectors["timeClaims"].as_array().expect("timeClaims");
    assert!(time_claims.len() > 10);
    for case in time_claims {
        let name = str_of(case, "name");
        let problem = check_time_claim(
            u32_of(case, "locktime"),
            u32_of(case, "sequence"),
            case["now"].as_u64().expect("now"),
            case["lockedAt"].as_u64().expect("lockedAt"),
        );
        assert_eq!(
            problem.is_none(),
            str_of(case, "verdict") == "accept",
            "{name}: {problem:?} ({})",
            str_of(case, "why")
        );
    }

    let leaf_policy = vectors["leafPolicy"].as_array().expect("leafPolicy");
    assert!(leaf_policy.len() > 5);
    for case in leaf_policy {
        let name = str_of(case, "name");
        let version = u8::try_from(case["version"].as_u64().expect("version")).expect("a byte");
        let problem = check_leaf(version, &bytes_of(case, "script"));
        assert_eq!(
            problem.is_none(),
            str_of(case, "verdict") == "allowed",
            "{name}: {problem:?} ({})",
            str_of(case, "why")
        );
    }

    let malformed = vectors["malformedCw1"].as_array().expect("malformedCw1");
    assert!(malformed.len() > 5);
    for case in malformed {
        let name = str_of(case, "name");
        let value = str_of(case, "value");
        assert_eq!(decode_cw1(&value), None, "{name}");
        assert!(!is_cw1(&value), "{name}");
        assert_eq!(decode_spend(&value), None, "{name}");
        assert_eq!(note_id_of(&value), None, "{name}");
        assert_eq!(check_spend(&value, "mint.example"), None, "{name}");
    }

    let invalid = vectors["invalidCp1"].as_array().expect("invalidCp1");
    assert!(!invalid.is_empty());
    for case in invalid {
        let cp1 = str_of(case, "cp1");
        let why = str_of(case, "why");
        assert_eq!(decode_cp1(&cp1), None, "{why}");
        assert!(!is_cp1(&cp1), "{why}");
        assert_eq!(decode_note(&cp1), None, "{why}");
        // Never named as an output: a mint that failed to check would burn
        // the inputs into a note no spend can open.
        assert_eq!(
            lnurlcash_core::note::build_note_info_url_by_hash("https://mint.example/w", &cp1),
            None,
            "{why}"
        );
        assert!(
            matches!(
                mint_invoice_request_with_hash("https://mint.example/p/cb", 21_000, &cp1),
                Err(Error::RequestRefused(_))
            ),
            "{why}"
        );
        assert!(
            matches!(
                rotate_request_with_hash("https://mint.example/w/cb", &"11".repeat(32), &cp1),
                Err(Error::RequestRefused(_))
            ),
            "{why}"
        );
    }

    let short_forms = vectors["shortForms"].as_array().expect("shortForms");
    assert!(!short_forms.is_empty());
    for case in short_forms {
        let q = bytes32(case, "Q");
        let cp1_slot = &case["cp1Slot"];
        let k1_slot = &case["k1Slot"];
        assert_eq!(decode_note(&str_of(cp1_slot, "hex")), Some(q));
        assert_eq!(decode_note(&str_of(cp1_slot, "sameAs")), Some(q));
        assert_eq!(note_id_of(&str_of(k1_slot, "hex")), Some(hex::encode(q)));
        assert_eq!(note_id_of(&str_of(k1_slot, "sameAs")), Some(hex::encode(q)));
        // the 64 hex in each slot means something different: never Q itself
        assert_ne!(str_of(cp1_slot, "hex"), hex::encode(q));
    }
}
