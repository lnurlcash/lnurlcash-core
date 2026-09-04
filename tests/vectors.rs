//! Every assertion here comes from lnurlcash-conformance. Nothing in this file
//! states what the protocol is - the vectors do, and this suite only binds them
//! to the crate's functions.

use std::path::PathBuf;

use lnurlcash_core::protocol::{
    mint_invoice_request, mint_invoice_request_with_hash, parse_invoice, parse_pay_request,
    parse_verify,
};
use lnurlcash_core::cash::{
    cash_domain_indices, cash_node_from_hex, cash_node_to_hex, cash_secret_at, derive_cash_child,
    derive_cash_domain_node, derive_cash_root, derive_cash_secret,
};
use lnurlcash_core::secrets::{derive_note_root, derive_note_secret};
use lnurlcash_core::hash_k1;
use lnurlcash_core::{
    apply_mint_fee, build_note_url, decode_bolt11_amount_msat, format_fee_percent,
    from_bech32_lnurl, gross_up_for_mint_fee, is_allowed_service_url, is_bolt11_invoice,
    is_preimage, lightning_address_username, mint_address_url, note_declared_amount, note_k1,
    note_signature, note_signature_digest, note_signature_message, parse_mint_fee,
    resolve_lnurl_input, resolve_mint_input, resolve_note_input, same_invoice, to_bech32_lnurl,
    verify_note_signature, with_new_k1, without_k1, MintFee,
};
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
        assert_eq!(hash_k1(&k1).expect("hash"), str_of(case, "noteId"), "{name}");
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
        let k1 = derive_note_secret(&root, &str_of(case, "host"), case["index"].as_u64().unwrap() as u32);
        assert_eq!(k1, str_of(case, "k1"), "{name}");
        assert_eq!(hash_k1(&k1).expect("hash"), str_of(case, "noteId"), "{name}");
    }
}
