//! Every assertion here comes from lnurlcash-conformance. Nothing in this file
//! states what the protocol is - the vectors do, and this suite only binds them
//! to the crate's functions.

use std::collections::HashMap;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use lnurlcash_core::cash::{
    cash_domain_indices, cash_node_from_hex, cash_node_to_hex, derive_cash_child,
    derive_cash_domain_node, derive_cash_root, derive_service_root, CashNode,
};
use lnurlcash_core::protocol::{
    melt_request, mint_invoice_request, mint_invoice_request_with_hash, note_info_request,
    parse_invoice, parse_mutation, parse_note_info, parse_pay_request, parse_verify,
    rotate_request, rotate_request_with_hash, split_request, split_request_with_hash, MutationKind,
    MutationResponse, Policy, Request,
};
use lnurlcash_core::recoverable::{
    cash_node_to_cx1, decode_ck1, decode_cp1, decode_cs1_with_amount, decode_cw1, decode_cx1,
    decode_legacy_cx1, derive_nostr_cash_seed, derive_nostr_service_root, derive_note_key,
    derive_note_pubkey, derive_share_node, encode_ck1, encode_cp1, encode_cs1_with_amount,
    encode_cw1, encode_cx1, encode_legacy_cx1, is_ck1, is_cp1, is_cs1_with_amount, is_cw1, is_cx1,
    legacy_branch_node, legacy_cx1_of, legacy_derive_note_pubkey, legacy_derive_note_secret_key,
    recover_note_ownership_pubkey, sign_note_ownership, Cw1, DecodedCk1, NotePath,
    NOSTR_CASH_SEED_LABEL,
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
    is_preimage, legacy_note_signature_digest_for_hash, legacy_note_signature_message_for_hash,
    lightning_address_username, mint_address_url, note_declared_amount, note_id_of, note_k1,
    note_lookup_of, note_signature, note_signature_digest, note_signature_digest_for_hash,
    note_signature_message, note_signature_message_for_hash, parse_mint_fee, resolve_lnurl_input,
    resolve_mint_input, resolve_note_input, same_invoice, sign_address_proof, to_bech32_lnurl,
    verify_address_proof, verify_legacy_note_signature_hash, verify_note_signature,
    verify_note_signature_hash, with_new_k1, without_k1, CertifiedOver, MintFee,
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
        // absent from the apply and grossUp cases, which do not use it
        address_fee_msat: value["addressFeeMsat"].as_u64(),
    }
}

/// signature.json predates notes keyed by `Q`: every certificate there is
/// over a bearer note's hash `h`, with no domain, the message a mint signed
/// before LUD-25 moved certificates onto `hex(Q)` at the mint's domain. The
/// verdicts still hold through the legacy reading, reported as such; the
/// message a current mint signs for the same note is over its domain and `Q`
/// instead.
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
                check_note_certificate(&h, "mint.example", amount, &signature, &pubkey),
                Some(CertifiedOver::LegacyHash),
                "{name}: by h"
            );
        }

        if let Some(message) = case["message"].as_str() {
            let h = str_of(case, "noteId");
            assert_eq!(
                legacy_note_signature_message_for_hash(&h, amount),
                message,
                "{name}: message"
            );
            assert_eq!(
                hex::encode(legacy_note_signature_digest_for_hash(&h, amount)),
                str_of(case, "digest"),
                "{name}: digest"
            );
            // a current mint certifies the same note over its domain and Q
            if let Some(id) = note_id_of(&k1) {
                assert_eq!(
                    note_signature_message(&k1, "mint.example", amount),
                    Some(format!("LNURLcash:mint.example:{amount}:{id}")),
                    "{name}"
                );
                assert_ne!(id, h, "{name}: a bearer note's id is its Q, not h");
                assert_eq!(
                    note_signature_digest(&k1, "mint.example", amount).map(hex::encode),
                    note_signature_digest_for_hash(&id, "mint.example", amount).map(hex::encode),
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
    let cp1s: Vec<String> = part2["branches"][0]["accounts"][0]["wallet"]
        .as_array()
        .expect("wallet notes")
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
// part2.json pins LUD-26's tree below each SERVICE root, each key's key-path
// spend for its host's domain, share cx1s, address proofs, mint certificates,
// the superseded tweak schemes and the bech32m strings. Every field is graded on every branch and note: a
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

/// One note's keys, derived from the SERVICE root at `path`, and its spend.
fn grade_note(root: &CashNode, path: NotePath, note: &Value, host: &str, domain: &str, at: &str) {
    let key = derive_note_key(root, path).unwrap_or_else(|err| panic!("{at}: {err}"));
    assert_eq!(
        hex::encode(key.secret_key),
        str_of(note, "noteSecretKey"),
        "{at}"
    );
    assert_eq!(
        hex::encode(key.pubkey),
        str_of(note, "notePubkeyCompressed"),
        "{at}"
    );
    assert_eq!(
        hex::encode(key.output_key),
        str_of(note, "notePubkey"),
        "{at}"
    );
    let cp1 = str_of(note, "cp1");
    assert_eq!(encode_cp1(&key.output_key), cp1, "{at}");
    assert_eq!(decode_cp1(&cp1), Some(key.output_key), "{at}");
    grade_key_path_note(note, &key.secret_key, host, domain, at);
}

/// Every account as part2.json and nostr-seed.json carry them: each wallet
/// and change note from the root, each share's `cx1`, and each share note
/// both from the root and, as a SERVICE derives it, from the `cx1` alone.
fn grade_accounts(root: &CashNode, accounts: &Value, host: &str, domain: &str, at: &str) {
    for account in accounts.as_array().expect("accounts") {
        let a = u32_of(account, "account");
        for (chain, notes) in [
            ("wallet", &account["wallet"]),
            ("change", &account["change"]),
        ] {
            for note in notes.as_array().expect("notes") {
                let index = index_of(note);
                let path = if chain == "wallet" {
                    NotePath::Wallet { account: a, index }
                } else {
                    NotePath::Change { account: a, index }
                };
                grade_note(
                    root,
                    path,
                    note,
                    host,
                    domain,
                    &format!("{at} {a}'/{chain}/{index}"),
                );
            }
        }
        for share in account["shares"].as_array().expect("shares") {
            let n = u32_of(share, "share");
            let at = format!("{at} {a}'/2/{n}'");
            let node = derive_share_node(root, a, n).expect("share node");
            assert_eq!(
                hex::encode(node.private_key),
                str_of(share, "sharePrivateKey"),
                "{at}"
            );
            assert_eq!(
                hex::encode(node.chain_code),
                str_of(share, "chainCode"),
                "{at}"
            );
            let cx1 = cash_node_to_cx1(&node).expect("cx1");
            assert_eq!(
                hex::encode(cx1.pubkey),
                str_of(share, "sharePubkey"),
                "{at}"
            );
            let text = str_of(share, "cx1");
            assert_eq!(encode_cx1(&cx1), text, "{at}");
            assert_eq!(text.len(), 113, "{at}: a cx1 is 113 characters");
            // a SERVICE starts from the string, never the node
            let watched = decode_cx1(&text).expect("cx1 decodes");
            assert_eq!(watched, cx1, "{at}");
            for note in share["notes"].as_array().expect("notes") {
                let index = index_of(note);
                let at = format!("{at}/{index}");
                grade_note(
                    root,
                    NotePath::Share {
                        account: a,
                        share: n,
                        index,
                    },
                    note,
                    host,
                    domain,
                    &at,
                );
                assert_eq!(
                    derive_note_pubkey(&watched, index).map(hex::encode).ok(),
                    Some(str_of(note, "notePubkey")),
                    "{at}: CKDpub from the cx1"
                );
            }
        }
    }
}

fn all_notes(accounts: &Value) -> Vec<&Value> {
    accounts
        .as_array()
        .expect("accounts")
        .iter()
        .flat_map(|account| {
            let chains = ["wallet", "change"]
                .into_iter()
                .flat_map(move |chain| account[chain].as_array().expect("notes").iter());
            let shares = account["shares"]
                .as_array()
                .expect("shares")
                .iter()
                .flat_map(|share| share["notes"].as_array().expect("notes").iter());
            chains.chain(shares)
        })
        .collect()
}

#[test]
fn part2_branch_vectors() {
    let vectors = load("part2.json");

    // The conventions this crate implements, named in the file, so a vector
    // regenerated under a different one fails here and not as a byte mismatch
    // three levels down.
    let conventions = &vectors["conventions"];
    assert_eq!(
        conventions["serviceRoot"].as_str(),
        Some("m/139'/d1/d2/d3/d4")
    );
    assert_eq!(conventions["hashingKey"].as_str(), Some("m/139'/0"));
    assert_eq!(conventions["walletChain"].as_str(), Some("S/a'/0/i"));
    assert_eq!(conventions["changeChain"].as_str(), Some("S/a'/1/i"));
    assert_eq!(conventions["shareNote"].as_str(), Some("S/a'/2/n'/i"));
    assert_eq!(
        conventions["certificateMessage"].as_str(),
        Some("LNURLcash:<domain>:<amount_msat>:<hex(Q)>")
    );

    let branches = vectors["branches"].as_array().expect("branches");
    // a host with a port is where the host as stored and the domain part
    // company, and the derivation now follows the domain
    assert!(branches.iter().any(|b| b["host"] != b["domain"]));
    let notes: Vec<&Value> = branches
        .iter()
        .flat_map(|branch| all_notes(&branch["accounts"]))
        .collect();
    // both parities, so the BIP-340 signer's negation is exercised, and the
    // largest index that is not a hardened step
    assert!(notes
        .iter()
        .any(|n| str_of(n, "notePubkeyCompressed").starts_with("02")));
    assert!(notes
        .iter()
        .any(|n| str_of(n, "notePubkeyCompressed").starts_with("03")));
    assert!(notes.iter().any(|n| index_of(n) == 0x7fff_ffff));

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
            hex::encode(
                derive_cash_child(&root, 0)
                    .expect("hashing key")
                    .private_key
            ),
            str_of(branch, "cashHashingKey"),
            "{host}"
        );
        let domain_indices: Vec<u32> = branch["domainIndices"]
            .as_array()
            .expect("domainIndices")
            .iter()
            .map(|value| u32::try_from(value.as_u64().expect("index")).expect("u32"))
            .collect();
        assert_eq!(
            cash_domain_indices(&root, &domain)
                .expect("indices")
                .to_vec(),
            domain_indices,
            "{host}"
        );
        // from the host as stored, which drops its port first
        let service_root = derive_service_root(&root, &host).expect("service root");
        assert_eq!(
            cash_node_to_hex(&service_root),
            str_of(branch, "serviceRoot"),
            "{host}"
        );
        grade_accounts(&service_root, &branch["accounts"], &host, &domain, &host);
    }

    // a note index is never a hardened step
    let root = derive_cash_root(&[0x42; 32]).expect("root");
    let service_root = derive_service_root(&root, "mint.example").expect("service root");
    for path in [
        NotePath::Wallet {
            account: 0,
            index: 0x8000_0000,
        },
        NotePath::Change {
            account: 0x8000_0000,
            index: 0,
        },
        NotePath::Share {
            account: 0,
            share: 0x8000_0000,
            index: 0,
        },
    ] {
        assert!(derive_note_key(&service_root, path).is_err(), "{path:?}");
    }
    let share =
        cash_node_to_cx1(&derive_share_node(&service_root, 0, 0).expect("share")).expect("cx1");
    assert!(derive_note_pubkey(&share, 0x8000_0000).is_err());
}

/// The tweak schemes before LUD-26, kept so a wallet can find and sweep the
/// notes it holds under them.
#[test]
fn legacy_tweak_vectors() {
    let vectors = load("part2.json");
    let legacy = &vectors["legacy"];
    assert_eq!(legacy["superseded"].as_bool(), Some(true));
    let branches = legacy["branches"].as_array().expect("branches");
    assert!(branches.iter().any(|b| b["branchParity"] == "odd"));
    assert!(branches.iter().any(|b| b["branchParity"] == "even"));

    for branch in branches {
        let host = str_of(branch, "host");
        let root = derive_cash_root(&bip39_seed(&str_of(branch, "mnemonic"))).expect("root");
        let node = legacy_branch_node(&root, &host).expect("legacy node");
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
        let cx1 = legacy_cx1_of(&node).expect("legacy cx1");
        let text = str_of(branch, "cx1");
        assert_eq!(encode_legacy_cx1(&cx1), text, "{host}");
        assert_eq!(decode_legacy_cx1(&text), Some(cx1.clone()), "{host}");
        assert_eq!(decode_cx1(&text), None, "{host}: no longer a cx1");

        let notes = branch["notes"]
            .as_array()
            .expect("notes")
            .iter()
            .map(|note| (Some(purpose_of(note)), note));
        let pre = branch["prePurpose"]
            .as_array()
            .expect("prePurpose")
            .iter()
            .map(|note| (None, note));
        for (purpose, note) in notes.chain(pre) {
            let index = index_of(note);
            let at = format!("{host} {purpose:?}/{index}");
            assert_eq!(
                legacy_derive_note_pubkey(&cx1, purpose, index)
                    .map(hex::encode)
                    .ok(),
                Some(str_of(note, "notePubkey")),
                "{at}"
            );
            let secret = legacy_derive_note_secret_key(&node, purpose, index).expect("secret");
            assert_eq!(hex::encode(secret), str_of(note, "noteSecretKey"), "{at}");
            assert_eq!(x_only_of(&secret), str_of(note, "notePubkey"), "{at}");
        }
    }
}

#[test]
fn address_proof_vectors() {
    let vectors = load("part2.json");
    let share_key: HashMap<String, [u8; 32]> = vectors["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .flat_map(|branch| branch["accounts"].as_array().expect("accounts").iter())
        .flat_map(|account| account["shares"].as_array().expect("shares").iter())
        .map(|share| (str_of(share, "cx1"), bytes32(share, "sharePrivateKey")))
        .collect();
    let proofs = vectors["addressProofs"].as_array().expect("addressProofs");
    for action in ["register", "update", "unregister"] {
        assert!(proofs.iter().any(|p| p["action"] == action), "{action}");
    }

    for proof in proofs {
        let action = str_of(proof, "action");
        let domain = str_of(proof, "domain");
        let username = str_of(proof, "username");
        let cx1 = opt_str(proof, "cx1");
        let signer = str_of(proof, "signerCx1");
        let at = format!("{action} {username}@{domain}");
        let secret = share_key
            .get(&signer)
            .unwrap_or_else(|| panic!("{at}: the signer is a share in the file"));
        assert_eq!(x_only_of(secret), str_of(proof, "signerPubkey"), "{at}");
        assert_eq!(
            address_proof_message(&action, &domain, &username, cx1.as_deref())
                .expect("a valid proof"),
            str_of(proof, "message"),
            "{at}"
        );
        assert_eq!(
            hex::encode(
                address_proof_digest(&action, &domain, &username, cx1.as_deref()).expect("digest")
            ),
            str_of(proof, "digest"),
            "{at}"
        );
        let signature =
            sign_address_proof(secret, &action, &domain, &username, cx1.as_deref()).expect("signs");
        assert_eq!(hex::encode(signature), str_of(proof, "signature"), "{at}");

        // what the SERVICE checks: BIP-340 against x(P) of the signer's cx1
        assert!(
            verify_address_proof(
                &signer,
                &signature,
                &action,
                &domain,
                &username,
                cx1.as_deref()
            ),
            "{at}"
        );
        // bound to its domain, its signer and, where there is one, its cx1
        assert!(
            !verify_address_proof(
                &signer,
                &signature,
                &action,
                "elsewhere.example",
                &username,
                cx1.as_deref()
            ),
            "{at}: another SERVICE"
        );
        let other = share_key
            .keys()
            .find(|key| **key != signer)
            .expect("another share");
        assert!(
            !verify_address_proof(
                other,
                &signature,
                &action,
                &domain,
                &username,
                cx1.as_deref()
            ),
            "{at}: another signer"
        );
        if cx1.is_some() {
            assert!(
                !verify_address_proof(
                    &signer,
                    &signature,
                    &action,
                    &domain,
                    &username,
                    Some(other)
                ),
                "{at}: another cx1"
            );
        }
    }

    let cx1 = share_key.keys().next().expect("a share").clone();
    let legacy_cx1 = str_of(&vectors["legacy"]["branches"][0], "cx1");
    for (action, cx1) in [
        ("register", None),
        ("update", None),
        ("unregister", Some(cx1.as_str())),
        ("delete", Some(cx1.as_str())),
        ("register", Some(legacy_cx1.as_str())),
    ] {
        assert!(
            address_proof_message(action, "mint.example", "alice", cx1).is_err(),
            "{action} {cx1:?}"
        );
    }
    assert!(address_proof_message("register", "", "alice", Some(&cx1)).is_err());
    assert!(address_proof_message("unregister", "mint.example", " ", None).is_err());
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
            all_notes(&branch["accounts"]).into_iter().map(move |note| {
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
        let domain = str_of(certificate, "domain");
        let amount = certificate["amountMsat"].as_u64().expect("amountMsat");
        let at = format!("{amount} msat at {domain}");
        let message = str_of(certificate, "message");
        let digest = str_of(certificate, "digest");

        assert_eq!(
            note_signature_message_for_hash(&pubkey, &domain, amount),
            Some(message.clone()),
            "{at}"
        );
        assert_eq!(
            note_signature_digest_for_hash(&pubkey, &domain, amount).map(hex::encode),
            Some(digest.clone()),
            "{at}"
        );
        let (ck1, note_domain) = ck1_of
            .get(&pubkey)
            .unwrap_or_else(|| panic!("{at}: the certificate names a note in the file"));
        assert_eq!(
            note_signature_message(ck1, &domain, amount).as_deref(),
            Some(message.as_str()),
            "{at}"
        );
        assert_eq!(
            note_signature_digest(ck1, &domain, amount).map(hex::encode),
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

        // Each recovers to the mint's key: by the note's id and by its cp1 at
        // the certificate's domain, and nowhere else. A current certificate
        // is a cs1, never raw hex.
        assert!(
            verify_note_signature_hash(&pubkey, &domain, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        assert!(
            !verify_note_signature_hash(&pubkey, &domain, amount, &signature_hex, &mint_pubkey),
            "{at}: raw hex"
        );
        assert!(
            !verify_note_signature_hash(&pubkey, "elsewhere.example", amount, &cs1, &mint_pubkey),
            "{at}: another domain"
        );
        let cp1 = encode_cp1(&bytes32(certificate, "notePubkey"));
        assert_eq!(
            check_note_certificate(&cp1, &domain, amount, &cs1, &mint_pubkey),
            Some(CertifiedOver::OutputKey),
            "{at}"
        );
        assert_eq!(
            check_note_certificate(&cp1, "elsewhere.example", amount, &cs1, &mint_pubkey),
            None,
            "{at}: another domain"
        );

        // A certificate for another domain than the note's own vouches for
        // nothing there.
        if domain != *note_domain {
            assert!(
                check_note(ck1, note_domain, amount, &cs1, &mint_pubkey).is_none(),
                "{at}: certified at {note_domain} too"
            );
            continue;
        }
        let check = check_note(ck1, &domain, amount, &cs1, &mint_pubkey).expect("verifies");
        assert_eq!(check.certificate, CertifiedOver::OutputKey, "{at}");
        assert_eq!(check.spend, SpendVerdict::Opens, "{at}");
        assert!(
            verify_note_signature(ck1, &domain, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        // ...and to nothing it does not cover
        assert!(
            !verify_note_signature(ck1, &domain, amount + 1, &cs1, &mint_pubkey),
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
            !verify_note_signature_hash(&pubkey, &domain, amount, &relabelled, &mint_pubkey),
            "{at}: relabelled"
        );
        assert!(
            !verify_note_signature_hash(&pubkey, &domain, amount + 1000, &relabelled, &mint_pubkey),
            "{at}: relabelled"
        );

        // The certificate is public, and so is Q. A ck1 pairing them with a
        // signature that does not open the note must not pass as the note,
        // however good the certificate: it is refused at the note's own
        // domain, and so is the genuine ck1 at any other.
        let mut forged = decode_ck1(ck1).expect("a ck1").as_bytes().to_vec();
        forged[40] ^= 0x01;
        let forged = encode_ck1(&forged.try_into().expect("96 bytes"));
        let check = check_note(&forged, &domain, amount, &cs1, &mint_pubkey)
            .expect("the certificate itself is good");
        assert!(matches!(check.spend, SpendVerdict::Fails(_)), "{at}");
        assert!(!check.is_verified(), "{at}");
        assert!(
            !verify_note_signature(&forged, &domain, amount, &cs1, &mint_pubkey),
            "{at}: forged"
        );
        assert!(
            !verify_note_signature(ck1, "elsewhere.example", amount, &cs1, &mint_pubkey),
            "{at}: another mint"
        );
    }

    // Certificates over the superseded message without a domain: still read
    // on notes people hold, reported as legacy, and never the current one.
    let legacy = vectors["legacyCertificates"]
        .as_array()
        .expect("legacyCertificates");
    assert!(!legacy.is_empty());
    for certificate in legacy {
        let pubkey = str_of(certificate, "notePubkey");
        let amount = certificate["amountMsat"].as_u64().expect("amountMsat");
        let cs1 = str_of(certificate, "cs1");
        let at = format!("legacy {amount} msat");
        assert_eq!(
            legacy_note_signature_message_for_hash(&pubkey, amount),
            str_of(certificate, "message"),
            "{at}"
        );
        assert_eq!(
            hex::encode(legacy_note_signature_digest_for_hash(&pubkey, amount)),
            str_of(certificate, "digest"),
            "{at}"
        );
        assert!(
            verify_legacy_note_signature_hash(&pubkey, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        assert!(
            !verify_note_signature_hash(&pubkey, "mint.example", amount, &cs1, &mint_pubkey),
            "{at}: not current"
        );
        let (ck1, domain) = &ck1_of[&pubkey];
        let check = check_note(ck1, domain, amount, &cs1, &mint_pubkey).expect("verifies");
        assert_eq!(check.certificate, CertifiedOver::LegacyOutputKey, "{at}");
        assert!(check.is_verified(), "{at}");
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
                    format!("{}{}", hex::encode(cx1.chain_code), hex::encode(cx1.pubkey))
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

/// An extension, not LUD-25/26: the LUD-26 tree rooted in a Nostr identity key.
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
        // the npub a lightning address on this tree belongs to
        assert_eq!(
            x_only_of(&identity),
            str_of(case, "identityPubkey"),
            "{host}"
        );

        let root = derive_nostr_service_root(&identity, &host).expect("service root");
        assert_eq!(
            cash_node_to_hex(&root),
            str_of(case, "serviceRoot"),
            "{host}"
        );
        grade_accounts(&root, &case["accounts"], &host, &domain, &host);
    }
}

/// The canonical spend transaction, serialised with its witness, the way the
/// spec's key_path_spend vectors print it: nVersion 2, segwit marker and
/// flag, one input spending (prevout, 0) with an empty scriptSig and the
/// given sequence, one output of value 0 with an empty scriptPubKey, the
/// witness, and the locktime. The crate never builds one - nothing is ever
/// broadcast - but a port can check its sighash against Bitcoin Core's by it.
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

/// A key-path spend as 25-vectors.json and 26-vectors.json print one, every
/// step from the domain to the serialised spend.
fn grade_key_path_spend(v: &Value, sk: &[u8; 32], at: &str) -> String {
    let q = bytes32(v, "Q");
    let domain = str_of(v, "domain");
    assert_eq!(x_only_of(sk), str_of(v, "Q"), "{at}");
    assert_eq!(encode_cp1(&q), str_of(v, "cp1"), "{at}");
    let prevout = spend_prevout(&domain);
    assert_eq!(hex::encode(prevout), str_of(v, "prevout_txid"), "{at}");
    assert_eq!(
        format!("5120{}", hex::encode(q)),
        str_of(v, "spent_script_pubkey"),
        "{at}"
    );
    let sig_msg = spend_sig_msg(&q, &domain, 0, 0xffff_ffff, None);
    assert_eq!(hex::encode(&sig_msg), str_of(v, "sigmsg"), "{at}");
    assert_eq!(sig_msg.len(), 174, "{at}");
    let fields = &v["sigmsg_fields"];
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
        assert_eq!(
            hex::encode(&sig_msg[range]),
            str_of(fields, name),
            "{at}: {name}"
        );
    }
    let sighash = key_path_sighash(&q, &domain);
    assert_eq!(hex::encode(sighash), str_of(v, "sighash"), "{at}");
    assert_eq!(tagged_hash("TapSighash", &[&[0x00], &sig_msg]), sighash);
    assert_eq!(str_of(v, "aux_rand"), "00".repeat(32), "{at}");
    let payload = sign_note_ownership(sk, &domain).expect("signs");
    assert_eq!(&payload[..32], &q, "{at}");
    assert_eq!(hex::encode(&payload[32..]), str_of(v, "sig"), "{at}");
    assert_eq!(
        hex::encode(canonical_spend_transaction(
            &prevout,
            0xffff_ffff,
            0,
            &[&payload[32..]]
        )),
        str_of(v, "spend_tx"),
        "{at}"
    );
    let ck1 = str_of(v, "ck1");
    assert_eq!(encode_ck1(&payload), ck1, "{at}");
    assert_eq!(
        check_spend(&ck1, &domain).map(|check| check.verdict),
        Some(SpendVerdict::Opens),
        "{at}"
    );
    // "the same ck1 fails at any other domain"
    assert!(
        matches!(
            check_spend(&ck1, "moneyer.dev").map(|check| check.verdict),
            Some(SpendVerdict::Fails(_))
        ),
        "{at}"
    );
    ck1
}

/// LUD-25's own published test vectors, luds' 25-vectors.json, as
/// spec-vectors.json's `lud25`: every value here is what the spec itself
/// publishes, not just this project's own fixtures.
#[test]
fn lud25_spec_vectors() {
    let vectors = load("spec-vectors.json");
    let v = &vectors["lud25"];

    let spend = &v["key_path_spend"];
    let ck1 = grade_key_path_spend(spend, &bytes32(spend, "sk"), "key_path_spend");
    let spend_domain = str_of(spend, "domain");

    let certificates = &v["certificates"];
    let mint_key =
        SecretKey::from_secret_bytes(bytes32(certificates, "service_sk")).expect("valid mint key");
    let mint_pubkey = hex::encode(PublicKey::from_secret_key(&mint_key).serialize());
    assert_eq!(mint_pubkey, str_of(certificates, "mintPubkey"));
    let sign_certificate = |digest: [u8; 32]| -> String {
        let (recovery, compact) =
            RecoverableSignature::sign_ecdsa_recoverable(Message::from_digest(digest), &mint_key)
                .serialize_compact();
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&compact);
        signature[64] = u8::from(recovery);
        hex::encode(signature)
    };

    let q = str_of(certificates, "Q");
    let domain = str_of(certificates, "domain");
    assert_eq!(q, str_of(spend, "Q"));
    for cert in certificates["cases"].as_array().expect("cases") {
        let amount = cert["amount_msat"].as_u64().expect("amount_msat");
        let at = format!("{amount} msat");
        assert_eq!(
            note_signature_message_for_hash(&q, &domain, amount),
            Some(str_of(cert, "message")),
            "{at}"
        );
        let digest = note_signature_digest_for_hash(&q, &domain, amount).expect("digest");
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
            verify_note_signature_hash(&q, &domain, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        let cp1 = encode_cp1(&bytes32(certificates, "Q"));
        assert_eq!(
            check_note_certificate(&cp1, &domain, amount, &cs1, &mint_pubkey),
            Some(CertifiedOver::OutputKey),
            "{at}"
        );
        assert!(
            verify_note_signature(&ck1, &spend_domain, amount, &cs1, &mint_pubkey),
            "{at}"
        );
        assert!(
            !verify_note_signature(&ck1, "moneyer.dev", amount, &cs1, &mint_pubkey),
            "{at}: another mint"
        );
    }

    // a bearer note, from preimage to cw1 and its certificate
    let b = &v["bearer_note"];
    let preimage = str_of(b, "preimage");
    let h = bytes32(b, "h");
    let q = bytes32(b, "Q");
    assert_eq!(hash_k1(&preimage).expect("hash"), str_of(b, "h"));
    assert_eq!(hex::encode(bearer_leaf(&h)), str_of(b, "leaf"));
    assert_eq!(
        hex::encode(tapleaf_hash(&bearer_leaf(&h), TAPLEAF_VERSION)),
        str_of(b, "tapleaf_hash")
    );
    assert_eq!(hex::encode(NUMS_H), str_of(b, "H"));
    assert_eq!(
        hex::encode(tagged_hash(
            "TapTweak",
            &[&NUMS_H, &bytes32(b, "tapleaf_hash")]
        )),
        str_of(b, "tweak")
    );
    let note = bearer_note(&h).expect("a bearer note");
    assert_eq!(note.output_key, q);
    assert_eq!(hex::encode(note.control_block), str_of(b, "control_block"));
    let cp1 = str_of(b, "cp1");
    assert_eq!(encode_cp1(&q), cp1);
    // "the hex h and cp1<Q> name the same note"
    assert_eq!(decode_note(&str_of(b, "h")), Some(q));
    assert_eq!(decode_note(&cp1), Some(q));
    // "the hex preimage and the full cw1 are the same spend"
    let cw1 = str_of(b, "cw1");
    let preimage_bytes = hex::decode(&preimage).expect("hex");
    assert_eq!(
        encode_cw1(&bearer_cw1(&preimage_bytes).expect("a cw1")).expect("encodes"),
        cw1
    );
    assert_eq!(note_id_of(&preimage), Some(str_of(b, "Q")));
    assert_eq!(note_id_of(&cw1), Some(str_of(b, "Q")));
    assert_eq!(note_lookup_of(&preimage), Some(str_of(b, "h")));
    assert_eq!(note_lookup_of(&cw1), Some(cp1.clone()));
    // "and open Q at any domain, since the leaf checks no signature"
    for domain in ["mint.example", "moneyer.dev"] {
        for spend in [&preimage, &cw1] {
            assert_eq!(
                check_spend(spend, domain),
                Some(lnurlcash_core::SpendCheck {
                    output_key: q,
                    verdict: SpendVerdict::Opens
                }),
                "{spend} at {domain}"
            );
        }
    }

    let cert = &b["certificate"];
    let amount = cert["amount_msat"].as_u64().expect("amount_msat");
    let url = str_of(b, "note_url");
    let domain = spend_domain_of(&url).expect("a domain");
    assert_eq!(
        note_signature_message(&preimage, &url, amount),
        Some(str_of(cert, "message"))
    );
    let digest = note_signature_digest(&preimage, &url, amount).expect("digest");
    assert_eq!(hex::encode(digest), str_of(cert, "digest"));
    assert_eq!(sign_certificate(digest), str_of(cert, "signature"));
    let cs1 = str_of(cert, "cs1");
    for spend in [&preimage, &cw1] {
        let check = check_note(spend, &domain, amount, &cs1, &mint_pubkey)
            .unwrap_or_else(|| panic!("{spend}: certified"));
        assert_eq!(check.output_key, q);
        assert_eq!(check.certificate, CertifiedOver::OutputKey);
        assert!(check.is_verified());
        // the spend opens Q anywhere, but the certificate names one mint
        assert!(check_note(spend, "moneyer.dev", amount, &cs1, &mint_pubkey).is_none());
    }
    for reference in [str_of(b, "h"), cp1] {
        assert_eq!(
            check_note_certificate(&reference, &domain, amount, &cs1, &mint_pubkey),
            Some(CertifiedOver::OutputKey),
            "{reference}"
        );
    }
    assert_eq!(note_declared_amount(&url), Some(amount));
    let check = check_note_url(&url, &mint_pubkey).expect("a certified note");
    assert_eq!(
        (check.output_key, check.certificate, check.is_verified()),
        (q, CertifiedOver::OutputKey, true)
    );
}

/// LUD-26's own published test vectors, luds' 26-vectors.json, as
/// spec-vectors.json's `lud26`.
#[test]
fn lud26_spec_vectors() {
    let vectors = load("spec-vectors.json");
    let v = &vectors["lud26"];

    let mut service_roots = Vec::new();
    for dv in v["derivation"].as_array().expect("derivation") {
        let domain = str_of(dv, "domain");
        let seed = hex::decode(str_of(dv, "seed")).expect("seed is hex");
        let root = derive_cash_root(&seed).expect("root");
        assert_eq!(
            hex::encode(
                derive_cash_child(&root, 0)
                    .expect("hashing key")
                    .private_key
            ),
            str_of(dv, "cashHashingKey"),
            "{domain}"
        );
        let d: Vec<u32> = dv["d"]
            .as_array()
            .expect("d")
            .iter()
            .map(|value| u32::try_from(value.as_u64().expect("index")).expect("u32"))
            .collect();
        assert_eq!(
            cash_domain_indices(&root, &domain)
                .expect("indices")
                .to_vec(),
            d,
            "{domain}"
        );
        let service_root = derive_service_root(&root, &domain).expect("service root");

        let grade = |path: NotePath, note: &Value, at: &str| {
            let key =
                derive_note_key(&service_root, path).unwrap_or_else(|err| panic!("{at}: {err}"));
            assert_eq!(hex::encode(key.secret_key), str_of(note, "sk"), "{at}");
            assert_eq!(hex::encode(key.pubkey), str_of(note, "pk"), "{at}");
            assert_eq!(hex::encode(key.output_key), str_of(note, "Q"), "{at}");
            assert_eq!(encode_cp1(&key.output_key), str_of(note, "cp1"), "{at}");
        };
        for account in dv["accounts"].as_array().expect("accounts") {
            let a = u32_of(account, "account");
            for note in account["wallet"]["notes"].as_array().expect("wallet") {
                let index = u32_of(note, "i");
                grade(
                    NotePath::Wallet { account: a, index },
                    note,
                    &format!("{domain} {a}'/0/{index}"),
                );
            }
            for note in account["change"]["notes"].as_array().expect("change") {
                let index = u32_of(note, "i");
                grade(
                    NotePath::Change { account: a, index },
                    note,
                    &format!("{domain} {a}'/1/{index}"),
                );
            }
            for share in account["shareable"].as_array().expect("shareable") {
                let n = u32_of(share, "share");
                let at = format!("{domain} {a}'/2/{n}'");
                let node = derive_share_node(&service_root, a, n).expect("share");
                assert_eq!(hex::encode(node.private_key), str_of(share, "p"), "{at}");
                assert_eq!(
                    hex::encode(node.chain_code),
                    str_of(share, "chaincode"),
                    "{at}"
                );
                let cx1 = cash_node_to_cx1(&node).expect("cx1");
                assert_eq!(hex::encode(cx1.pubkey), str_of(share, "P"), "{at}");
                assert_eq!(encode_cx1(&cx1), str_of(share, "cx1"), "{at}");
                let watched = decode_cx1(&str_of(share, "cx1")).expect("cx1 decodes");
                for note in share["notes"].as_array().expect("notes") {
                    let index = u32_of(note, "i");
                    let at = format!("{at}/{index}");
                    grade(
                        NotePath::Share {
                            account: a,
                            share: n,
                            index,
                        },
                        note,
                        &at,
                    );
                    assert_eq!(
                        derive_note_pubkey(&watched, index).map(hex::encode).ok(),
                        Some(str_of(note, "Q")),
                        "{at}: CKDpub"
                    );
                }
            }
        }
        service_roots.push(service_root);
    }

    // a key-path spend of an odd-y note: the signer negates the key
    let spend = &v["key_path_spend"];
    let first = &v["derivation"][0]["accounts"][0]["wallet"]["notes"][0];
    assert_eq!(str_of(spend, "path"), str_of(first, "path"));
    let key = derive_note_key(
        &service_roots[0],
        NotePath::Wallet {
            account: 0,
            index: 0,
        },
    )
    .expect("note key");
    assert_eq!(hex::encode(key.secret_key), str_of(spend, "sk"));
    assert_eq!(hex::encode(key.pubkey), str_of(spend, "pk"));
    assert_eq!(key.pubkey[0], 0x03, "the vector's note has odd y");
    let negated = SecretKey::from_secret_bytes(key.secret_key)
        .expect("a key")
        .negate();
    assert_eq!(
        hex::encode(negated.to_secret_bytes()),
        str_of(spend, "signing_sk")
    );
    grade_key_path_spend(spend, &key.secret_key, "lud26 key_path_spend");

    // register share 0, update to share 1, unregister with share 1
    let r = &v["registration"];
    let domain = str_of(r, "domain");
    let username = str_of(r, "username");
    let account = &v["derivation"][1]["accounts"][0];
    assert_eq!(domain, str_of(&v["derivation"][1], "domain"));
    let old = derive_share_node(&service_roots[1], 0, 0).expect("share 0");
    let new = derive_share_node(&service_roots[1], 0, 1).expect("share 1");
    let (cx1, new_cx1) = (str_of(r, "cx1"), str_of(r, "new_cx1"));
    assert_eq!(cx1, str_of(&account["shareable"][0], "cx1"));
    assert_eq!(new_cx1, str_of(&account["shareable"][1], "cx1"));
    for (proof, action, bound, signer, signer_cx1) in [
        (&r["register"], "register", Some(&cx1), &old, &cx1),
        (&r["update"]["sig"], "update", Some(&new_cx1), &old, &cx1),
        (
            &r["update"]["newsig"],
            "register",
            Some(&new_cx1),
            &new,
            &new_cx1,
        ),
        (&r["unregister"], "unregister", None, &new, &new_cx1),
    ] {
        let bound = bound.map(String::as_str);
        assert_eq!(
            address_proof_message(action, &domain, &username, bound).expect("message"),
            str_of(proof, "message"),
            "{action}"
        );
        assert_eq!(
            hex::encode(address_proof_digest(action, &domain, &username, bound).expect("digest")),
            str_of(proof, "digest"),
            "{action}"
        );
        let signature = sign_address_proof(&signer.private_key, action, &domain, &username, bound)
            .expect("signs");
        assert_eq!(hex::encode(signature), str_of(proof, "sig"), "{action}");
        assert!(
            verify_address_proof(signer_cx1, &signature, action, &domain, &username, bound),
            "{action}"
        );
    }
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
    let signer = k256::schnorr::SigningKey::from_bytes(&secret).expect("a key");

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
