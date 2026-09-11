//! Every assertion here comes from lnurlcash-conformance. Nothing in this file
//! states what the protocol is - the vectors do, and this suite only binds them
//! to the crate's functions.

use std::collections::HashMap;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use lnurlcash_core::cash::{
    cash_domain_indices, cash_node_from_hex, cash_node_to_hex, cash_secret_at, derive_cash_child,
    derive_cash_domain_node, derive_cash_root, derive_cash_secret,
};
use lnurlcash_core::protocol::{
    melt_request, mint_invoice_request, mint_invoice_request_with_hash, note_info_request,
    parse_invoice, parse_mutation, parse_note_info, parse_pay_request, parse_verify,
    rotate_request, rotate_request_with_hash, split_request, split_request_with_hash, MutationKind,
    MutationResponse, Policy, Request,
};
use lnurlcash_core::recoverable::{
    cash_node_to_cx1, decode_ck1, decode_cp1, decode_cs1, decode_cx1, derive_cash_address_node,
    derive_nostr_address_node, derive_nostr_cash_seed, derive_note_pubkey, derive_note_secret_key,
    encode_ck1, encode_cp1, encode_cs1, encode_cx1, is_ck1, is_cp1, is_cs1, is_cx1,
    note_ownership_digest, recover_note_ownership_pubkey, sign_note_ownership,
    NOSTR_CASH_SEED_LABEL,
};
use lnurlcash_core::secrets::{derive_note_root, derive_note_secret};
use lnurlcash_core::{
    apply_mint_fee, build_note_url, decode_bolt11_amount_msat, format_fee_percent,
    from_bech32_lnurl, gross_up_for_mint_fee, is_allowed_service_url, is_bolt11_invoice,
    is_preimage, lightning_address_username, mint_address_url, note_declared_amount, note_id_of,
    note_k1, note_lookup_of, note_signature, note_signature_digest, note_signature_digest_for_hash,
    note_signature_message, note_signature_message_for_hash, parse_mint_fee, resolve_lnurl_input,
    resolve_mint_input, resolve_note_input, same_invoice, to_bech32_lnurl, verify_note_signature,
    verify_note_signature_hash, with_new_k1, without_k1, MintFee,
};
use lnurlcash_core::{hash_k1, Error};
use secp256k1::{ecdsa, Message, Parity, PublicKey, Secp256k1, SecretKey};
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

        assert_eq!(
            verify_note_signature(&k1, amount, &signature, &pubkey),
            expected,
            "{name}"
        );

        if let Some(message) = case["message"].as_str() {
            assert_eq!(
                note_signature_message(&k1, amount).as_deref(),
                Some(message),
                "{name}: message"
            );
            let digest = note_signature_digest(&k1, amount).expect("digest");
            assert_eq!(
                hex::encode(digest),
                str_of(case, "digest"),
                "{name}: digest"
            );
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
// certificate; a hash output is owed nothing, and a bare OK to one is `ok`.
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
        let index = case["index"].as_u64().expect("index") as u32;
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

        let k1 = str_of(case, "k1");
        assert_eq!(
            derive_cash_secret(&root, &host, index).expect("secret"),
            k1,
            "{name}"
        );
        // The hardware-signer path: given only this mint's subtree, with no
        // seed and no elliptic curve, every note index still resolves.
        assert_eq!(
            cash_secret_at(&domain_node, index).expect("secret"),
            k1,
            "{name}: from the domain node alone"
        );
        assert_eq!(
            hash_k1(&k1).expect("hash"),
            str_of(case, "noteId"),
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

// ---- LUD-25 Part 2 ----
//
// part2.json pins the reference wallet's address branch, the per-note key
// tweak, ownership signatures, mint certificates and the four bech32m
// strings. Every field is graded on every branch and note: a wallet that
// disagrees with one of them cannot find, spend or check a note that another
// implementation of the same seed made.

fn bytes32(value: &Value, key: &str) -> [u8; 32] {
    hex::decode(str_of(value, key))
        .expect("hex")
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is 32 bytes"))
}

fn index_of(note: &Value) -> u32 {
    u32::try_from(note["index"].as_u64().expect("index")).expect("a note index is a u32")
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
    let key = SecretKey::from_slice(private_key).expect("a valid key");
    match key.x_only_public_key(&Secp256k1::signing_only()).1 {
        Parity::Even => "even",
        Parity::Odd => "odd",
    }
}

fn is_low_s(signature: &[u8; 65]) -> bool {
    let original = ecdsa::Signature::from_compact(&signature[..64]).expect("r || s");
    let mut normalised = original;
    normalised.normalize_s();
    normalised == original
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
        Some("m/139'/1'/d1/d2/d3/d4")
    );
    assert_eq!(conventions["hashingKey"].as_str(), Some("m/139'/1'/0"));
    assert_eq!(conventions["ownershipMessage"].as_str(), Some("LNURLcash"));
    assert_eq!(
        conventions["certificateMessage"].as_str(),
        Some("LNURLcash:<amount_msat>:<hex(pk)>")
    );
    assert_eq!(
        hex::encode(note_ownership_digest()),
        str_of(conventions, "ownershipDigest")
    );

    let branches = vectors["branches"].as_array().expect("branches");
    // An odd branch is the only thing that exercises the negation, and the
    // top of the u32 range is where a hardened-index mistake would show.
    assert!(branches.iter().any(|b| b["branchParity"] == "odd"));
    assert!(branches.iter().any(|b| b["branchParity"] == "even"));
    let indices: Vec<u32> = branches[0]["notes"]
        .as_array()
        .expect("notes")
        .iter()
        .map(index_of)
        .collect();
    assert!(indices.contains(&0x8000_0000) && indices.contains(&u32::MAX));

    for branch in branches {
        let host = str_of(branch, "host");
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
        // the hashing key is m/139'/1'/0, so the four levels hang off m/139'/1'
        let purpose = derive_cash_child(&root, 1 + 0x8000_0000).expect("m/139'/1'");
        let domain_indices: Vec<u32> = branch["domainIndices"]
            .as_array()
            .expect("domainIndices")
            .iter()
            .map(|value| u32::try_from(value.as_u64().expect("index")).expect("u32"))
            .collect();
        assert_eq!(
            cash_domain_indices(&purpose, &host)
                .expect("indices")
                .to_vec(),
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
            let at = format!("{host} #{index}");

            let pubkey = derive_note_pubkey(&watched.pubkey_x_only, &watched.chain_code, index)
                .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(pubkey), str_of(note, "notePubkey"), "{at}");
            assert_eq!(encode_cp1(&pubkey), str_of(note, "cp1"), "{at}");
            assert_eq!(decode_cp1(&str_of(note, "cp1")), Some(pubkey), "{at}");

            let secret = derive_note_secret_key(&node.private_key, &node.chain_code, index)
                .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(secret), str_of(note, "noteSecretKey"), "{at}");

            // RFC6979: the same key reproduces the same ck1, byte for byte
            let signature = sign_note_ownership(&secret).expect("signs");
            assert_eq!(
                hex::encode(signature),
                str_of(note, "ownershipSignature"),
                "{at}"
            );
            assert!(signature[64] <= 3, "{at}: recovery id");
            assert!(is_low_s(&signature), "{at}: high S");
            let ck1 = str_of(note, "ck1");
            assert_eq!(encode_ck1(&signature), ck1, "{at}");
            assert_eq!(decode_ck1(&ck1), Some(signature), "{at}");

            // the SERVICE's side: the ck1 alone gives the key the note is
            // filed under, which is also the one the watcher derived
            assert_eq!(
                recover_note_ownership_pubkey(&signature),
                Some(pubkey),
                "{at}"
            );
            assert_eq!(note_id_of(&ck1), Some(str_of(note, "notePubkey")), "{at}");
            assert_eq!(note_lookup_of(&ck1), Some(str_of(note, "cp1")), "{at}");
        }
    }
}

#[test]
fn part2_certificate_vectors() {
    let vectors = load("part2.json");
    let mint = &vectors["mint"];
    let mint_pubkey = str_of(mint, "mintPubkey");
    let mint_key = SecretKey::from_slice(&bytes32(mint, "privateKey")).expect("the mint's key");
    let secp = Secp256k1::new();
    assert_eq!(
        hex::encode(PublicKey::from_secret_key(&secp, &mint_key).serialize()),
        mint_pubkey,
        "the mint's key pair"
    );

    // Every note in the file by key, so each certificate is checked the way a
    // recipient checks one: from the note's ck1 and nothing else.
    let ck1_of: HashMap<String, String> = vectors["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .flat_map(|branch| branch["notes"].as_array().expect("notes"))
        .map(|note| (str_of(note, "notePubkey"), str_of(note, "ck1")))
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
        let ck1 = ck1_of
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
        assert_eq!(encode_cs1(&signature), cs1, "{at}");
        assert_eq!(decode_cs1(&cs1), Some(signature), "{at}");

        // RFC6979 on the mint's side too: its key over the digest reproduces
        // the certificate
        let digest_bytes: [u8; 32] = hex::decode(&digest)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let (recovery, compact) = secp
            .sign_ecdsa_recoverable(&Message::from_digest(digest_bytes), &mint_key)
            .serialize_compact();
        assert_eq!(&signature[..64], &compact[..], "{at}");
        assert_eq!(i32::from(signature[64]), recovery.to_i32(), "{at}");

        // Each recovers to the mint's key: by the note's key, in either
        // spelling of the signature, and from the ck1 alone...
        assert!(
            verify_note_signature_hash(&pubkey, amount, &signature_hex, &mint_pubkey),
            "{at}"
        );
        assert!(
            verify_note_signature_hash(&pubkey, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        assert!(
            verify_note_signature(ck1, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        assert!(
            verify_note_signature(ck1, amount, &signature_hex, &mint_pubkey),
            "{at}"
        );
        // ...and to nothing it does not cover
        assert!(
            !verify_note_signature(ck1, amount + 1, &cs1, &mint_pubkey),
            "{at}: another amount"
        );
        let other = ck1_of
            .iter()
            .find(|(key, _)| **key != pubkey)
            .map(|(_, other)| other)
            .expect("another note");
        assert!(
            !verify_note_signature(other, amount, &cs1, &mint_pubkey),
            "{at}: another note"
        );
    }
}

#[test]
fn part2_string_vectors() {
    let vectors = load("part2.json");

    // the payload as hex, or None, for each of the four types
    let decode = |kind: &str, value: &str| -> Option<String> {
        let (decoded, is) = match kind {
            "cp1" => (decode_cp1(value).map(hex::encode), is_cp1(value)),
            "ck1" => (decode_ck1(value).map(hex::encode), is_ck1(value)),
            "cs1" => (decode_cs1(value).map(hex::encode), is_cs1(value)),
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

/// An extension, not LUD-25: a Part 2 branch rooted in a Nostr identity key.
#[test]
fn nostr_seed_vectors() {
    let vectors = load("nostr-seed.json");
    assert_eq!(vectors["extension"].as_bool(), Some(true));
    assert_eq!(vectors["label"].as_str(), Some(NOSTR_CASH_SEED_LABEL));

    let cases = vectors["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let host = str_of(case, "host");
        let identity = bytes32(case, "identity");

        assert_eq!(
            hex::encode(derive_nostr_cash_seed(&identity)),
            str_of(case, "seed"),
            "{host}"
        );
        // the npub a lightning address on this branch belongs to
        let identity_key = SecretKey::from_slice(&identity).expect("a valid identity");
        assert_eq!(
            hex::encode(
                identity_key
                    .x_only_public_key(&Secp256k1::signing_only())
                    .0
                    .serialize()
            ),
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
            let at = format!("{host} #{index}");
            let secret = derive_note_secret_key(&node.private_key, &node.chain_code, index)
                .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(secret), str_of(note, "noteSecretKey"), "{at}");
            let pubkey = derive_note_pubkey(&cx1.pubkey_x_only, &cx1.chain_code, index)
                .unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(pubkey), str_of(note, "notePubkey"), "{at}");
            assert_eq!(encode_cp1(&pubkey), str_of(note, "cp1"), "{at}");
            let ck1 = encode_ck1(&sign_note_ownership(&secret).expect("signs"));
            assert_eq!(ck1, str_of(note, "ck1"), "{at}");
            assert_eq!(
                note_id_of(&str_of(note, "ck1")),
                Some(str_of(note, "notePubkey")),
                "{at}: ck1 recovery"
            );
        }
    }
}
