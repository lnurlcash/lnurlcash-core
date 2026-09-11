//! Runs against the conformance repo's mock mint - a real HTTP server that can
//! be told to misbehave. The happy paths matter, but the adversarial modes are
//! the reason this suite exists: a crate that only works against a well-behaved
//! SERVICE has not been tested at all.

#![cfg(feature = "client")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use lnurlcash_core::client::{Client, ClientConfig, NoteFate};
use lnurlcash_core::protocol::Policy;
use lnurlcash_core::{build_note_url, hash_k1, verify_note_signature, Error};
use serde_json::Value;

struct MockMint {
    url: String,
    pubkey: String,
    process: Child,
}

impl Drop for MockMint {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn conformance_dir() -> PathBuf {
    match std::env::var("LNURLCASH_CONFORMANCE") {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate has a parent directory")
            .join("lnurlcash-conformance"),
    }
}

impl MockMint {
    /// `None` only when the conformance repo is not checked out at all - the
    /// single case a local run may legitimately skip. Everything else (no
    /// node, dependencies not installed, the mint dying on startup) is a hard
    /// failure. A silent skip there lets this entire suite pass while testing
    /// nothing, reporting the same "24 passed" either way, which is precisely
    /// how it once went green in CI against a mint that never started.
    fn start(flags: &[&str]) -> Option<Self> {
        let script = conformance_dir().join("mock-mint").join("index.mjs");
        if !script.exists() {
            assert!(
                std::env::var_os("CI").is_none(),
                "no mock mint at {} - CI must run the adversarial suite, never skip it",
                script.display()
            );
            eprintln!("skipping: no mock mint at {}", script.display());
            return None;
        }
        let mut command = Command::new("node");
        command
            .arg(&script)
            .arg("--port=0")
            .arg("--testHooks=true")
            .stdout(Stdio::piped())
            // inherited, not silenced: when the mint fails to boot its stderr
            // is the only thing that says why
            .stderr(Stdio::inherit());
        for flag in flags {
            command.arg(flag);
        }
        let mut process = command
            .spawn()
            .expect("the mock mint script is present, so node must be able to run it");
        let stdout = process.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let (mut url, mut pubkey) = (None, None);
        let mut line = String::new();
        while reader.read_line(&mut line).expect("read the mint's stdout") > 0 {
            if let Some(rest) = line.split("listening on ").nth(1) {
                url = Some(rest.trim().to_string());
            }
            if let Some(rest) = line.split("mint pubkey:").nth(1) {
                pubkey = Some(rest.trim().to_string());
            }
            if url.is_some() && pubkey.is_some() {
                break;
            }
            line.clear();
        }
        Some(MockMint {
            url: url.expect("the mint announced the address it is listening on"),
            pubkey: pubkey.expect("the mint announced its pubkey"),
            process,
        })
    }

    async fn hook(&self, path: &str) -> serde_json::Value {
        let text = reqwest::get(format!("{}{path}", self.url))
            .await
            .expect("test hook reachable")
            .text()
            .await
            .expect("test hook body");
        serde_json::from_str(&text).expect("test hook returns JSON")
    }

    /// Bring a note into existence. Returns the signature the mint issued.
    async fn credit(&self, k1: &str, amount_msat: u64) -> Option<String> {
        let body = self
            .hook(&format!("/_test/credit?k1={k1}&amount={amount_msat}"))
            .await;
        assert_eq!(body["status"], "OK", "credit failed: {body}");
        body["sig"].as_str().map(str::to_string)
    }

    /// What the SERVICE thinks of a note - the difference between what a mint
    /// says and what it did.
    async fn note_state(&self, k1: &str) -> Option<String> {
        let body = self.hook(&format!("/_test/state?k1={k1}")).await;
        body["state"].as_str().map(str::to_string)
    }

    async fn settle(&self, payment_hash: &str) {
        let body = self
            .hook(&format!("/_test/settle?payment_hash={payment_hash}"))
            .await;
        assert_eq!(body["status"], "OK", "settle failed: {body}");
    }

    fn note_url(&self, k1: &str) -> String {
        format!("{}/w?k1={k1}", self.url)
    }

    fn callback(&self) -> String {
        format!("{}/w/cb", self.url)
    }
}

fn secret(seed: u8) -> String {
    hex::encode([seed; 32])
}

macro_rules! mint_or_skip {
    ($flags:expr) => {
        match MockMint::start($flags) {
            Some(mint) => mint,
            None => return,
        }
    };
}

// ---- the informational GET ----

#[tokio::test]
async fn reports_value_and_never_burns() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let k1 = secret(1);
    mint.credit(&k1, 21000).await;

    let info = client.fetch_note_info(&mint.note_url(&k1)).await.unwrap();
    assert_eq!(info.max_withdrawable, 21000);
    assert_eq!(info.k1, k1);
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("outstanding"));

    let again = client.fetch_note_info(&mint.note_url(&k1)).await.unwrap();
    assert_eq!(again.max_withdrawable, 21000);
}

#[tokio::test]
async fn reads_the_node_stats_a_mint_address_advertises() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();

    let info = client
        .fetch_mint_address(&format!("{}/.well-known/lnurlw/mint", mint.url))
        .await
        .unwrap();
    assert_eq!(info.node_alias.as_deref(), Some("mock-mint"));
    // the wire field is nodeCapacity - renamed here, so it only arrives if
    // it is mapped rather than passed through under its own name
    assert_eq!(info.node_capacity_msat, Some(500_000_000));
    assert_eq!(info.node_num_channels, Some(4));
    assert_eq!(info.node_num_peers, Some(6));
}

#[tokio::test]
async fn max_withdrawable_beats_the_urls_own_claim() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let k1 = secret(2);
    mint.credit(&k1, 21000).await;

    let url = format!("{}&amount=2100000", mint.note_url(&k1));
    let info = client.fetch_note_info(&url).await.unwrap();
    assert_eq!(info.max_withdrawable, 21000);
}

#[tokio::test]
async fn refuses_a_service_that_echoes_a_different_k1() {
    let mint = mint_or_skip!(&["--echoWrongK1=true"]);
    let client = Client::new();
    let k1 = secret(3);
    mint.credit(&k1, 21000).await;

    let err = client
        .fetch_note_info(&mint.note_url(&k1))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Protocol(_)), "got {err:?}");
}

#[tokio::test]
async fn unknown_and_spent_are_different_answers() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let known = secret(4);
    mint.credit(&known, 21000).await;

    let err = client
        .fetch_note_info(&mint.note_url(&secret(5)))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoteUnknown { .. }), "got {err:?}");

    client.rotate_note(&mint.callback(), &known).await.unwrap();
    let err = client
        .fetch_note_info(&mint.note_url(&known))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoteSpent { .. }), "got {err:?}");
}

// ---- rotate, split, merge ----

#[tokio::test]
async fn rotate_burns_the_old_secret_and_mints_one_the_service_never_saw() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let k1 = secret(6);
    mint.credit(&k1, 21000).await;

    let rotated = client.rotate_note(&mint.callback(), &k1).await.unwrap();
    assert_ne!(rotated.k1, k1);
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("burned"));
    assert_eq!(
        mint.note_state(&rotated.k1).await.as_deref(),
        Some("outstanding")
    );

    let signature = rotated.signature.expect("mint signs");
    assert!(verify_note_signature(
        &rotated.k1,
        21000,
        &signature,
        &mint.pubkey
    ));
    assert!(!verify_note_signature(
        &rotated.k1,
        21001,
        &signature,
        &mint.pubkey
    ));
}

#[tokio::test]
async fn accepts_the_other_recovery_id_layout() {
    let mint = mint_or_skip!(&["--signatureLayout=leading"]);
    let client = Client::new();
    let k1 = secret(7);
    mint.credit(&k1, 21000).await;

    let rotated = client.rotate_note(&mint.callback(), &k1).await.unwrap();
    let signature = rotated.signature.expect("mint signs");
    assert!(verify_note_signature(
        &rotated.k1,
        21000,
        &signature,
        &mint.pubkey
    ));
}

#[tokio::test]
async fn ignores_a_secret_the_service_tries_to_hand_back() {
    let mint = mint_or_skip!(&["--serverGeneratedSecrets=true"]);
    let client = Client::new();
    let k1 = secret(8);
    mint.credit(&k1, 21000).await;

    let rotated = client.rotate_note(&mint.callback(), &k1).await.unwrap();
    // taking the mint's offered secret would hand it a permanent copy of the
    // note it just issued
    assert_ne!(rotated.k1, "a".repeat(64));
    assert_eq!(
        mint.note_state(&rotated.k1).await.as_deref(),
        Some("outstanding")
    );
}

#[tokio::test]
async fn split_produces_an_amount_and_its_change() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let k1 = secret(9);
    mint.credit(&k1, 21000).await;

    let result = client
        .split_note(&mint.callback(), std::slice::from_ref(&k1), 5000)
        .await
        .unwrap();
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("burned"));
    assert_eq!(
        client
            .fetch_note_info(&mint.note_url(&result.k1))
            .await
            .unwrap()
            .max_withdrawable,
        5000
    );
    assert_eq!(
        client
            .fetch_note_info(&mint.note_url(&result.change))
            .await
            .unwrap()
            .max_withdrawable,
        16000
    );
    assert!(verify_note_signature(
        &result.k1,
        5000,
        &result.signature.unwrap(),
        &mint.pubkey
    ));
}

#[tokio::test]
async fn merge_sums() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let parts: Vec<String> = (10..13).map(secret).collect();
    for (index, k1) in parts.iter().enumerate() {
        mint.credit(k1, 1000 * (index as u64 + 1)).await;
    }

    let merged = client.merge_notes(&mint.callback(), &parts).await.unwrap();
    for part in &parts {
        assert_eq!(mint.note_state(part).await.as_deref(), Some("burned"));
    }
    assert_eq!(
        client
            .fetch_note_info(&mint.note_url(&merged.k1))
            .await
            .unwrap()
            .max_withdrawable,
        6000
    );
}

#[tokio::test]
async fn refuses_a_mutation_naming_no_note() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let err = client.merge_notes(&mint.callback(), &[]).await.unwrap_err();
    assert!(matches!(err, Error::RequestRefused(_)), "got {err:?}");
}

#[tokio::test]
async fn settle_resolves_what_an_output_is_really_worth() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let k1 = secret(14);
    mint.credit(&k1, 21000).await;

    let result = client
        .split_note(&mint.callback(), std::slice::from_ref(&k1), 5000)
        .await
        .unwrap();
    // the caller does not know the change is 16000 - only the service does
    let settled = client
        .settle_note(
            &mint.note_url(&k1),
            &result.change,
            0,
            result.change_signature.as_deref(),
        )
        .await
        .unwrap();
    assert_eq!(settled.amount_msat, 16000);
    assert_ne!(settled.k1, result.change);
    assert_eq!(
        mint.note_state(&result.change).await.as_deref(),
        Some("burned")
    );
}

// settle_note's rotate is best-effort by design: a SERVICE that refuses it
// keeps the exposed k1 rather than failing the whole operation. What that must
// never cover is a rotate that MAY HAVE LANDED. Both used to return the old k1,
// shaped identically to a success - and when the request had landed, that k1
// was burned and the fresh secret riding the error was the only copy of the
// note the SERVICE had just minted.

#[tokio::test]
async fn settle_surfaces_an_unconfirmable_rotate_rather_than_the_burned_k1() {
    let mint = mint_or_skip!(&["--unconfirmedMutation=true"]);
    let client = no_retry_client();
    let k1 = secret(50);
    mint.credit(&k1, 21000).await;

    let err = client
        .settle_note(&mint.note_url(&k1), &k1, 0, None)
        .await
        .expect_err("an unconfirmable rotate must not come back looking settled");

    // the request did land, so the k1 the caller holds is dead
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("burned"));
    assert!(err.is_ambiguous(), "got {err:?}");

    // and the fresh secret has to survive: it is the only copy of the note
    let rescued = err.new_secrets();
    assert_eq!(rescued.len(), 1, "the fresh secret must survive");
    assert_ne!(rescued[0], k1);
    assert_eq!(
        mint.note_state(&rescued[0]).await.as_deref(),
        Some("outstanding")
    );
}

#[tokio::test]
async fn settle_reports_a_note_whose_melt_is_still_in_flight_as_pending() {
    let mint = mint_or_skip!(&["--meltNeverSettles=true"]);
    let client = Client::new();
    let k1 = secret(51);
    mint.credit(&k1, 21000).await;
    // a melt in flight locks every other operation on the note out, and the
    // SERVICE now says so on the informational GET as well as the mutation:
    // an unresolved melt answers `pending` rather than describing the note
    client
        .melt_note(&mint.callback(), &k1, "lnbc210n1pjqrstuvwxyz")
        .await
        .unwrap();

    // So settling stops before the rotate, and the caller hears the one word
    // that matters. This USED to come back as a settled 21000 msat note, on
    // the reasoning that a refusal which burned nothing leaves the note
    // alone - true of the rotate, but the wrong thing to tell a holder: the
    // melt may be about to consume this note, and a caller told it settled
    // would be counting money that is already leaving. Pending is not a
    // failure, it is an answer, and the caller reconciles rather than
    // believing either that the note is gone or that it is safely theirs.
    let err = client
        .settle_note(&mint.note_url(&k1), &k1, 0, None)
        .await
        .expect_err("a note with a melt in flight is not a settled note");
    assert!(matches!(err, Error::NotePending), "got {err:?}");

    // nothing was burned getting that answer, and no fresh secret was minted
    // that a caller would now have to keep
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("pending"));
    assert!(err.new_secrets().is_empty());
}

/// A retried mutation the SERVICE already performed looks exactly like this
/// from the wire, so the fresh secret still matters - see [`Error::NoteSpent`].
/// Swallowing it returned the burned k1 as settled.
#[tokio::test]
async fn settle_surfaces_a_spent_refusal_that_may_describe_an_applied_rotate() {
    let mint = mint_or_skip!(&["--unconfirmedMutation=true", "--retriedMutation=refuse"]);
    let client = Client::new();
    let k1 = secret(52);
    mint.credit(&k1, 21000).await;

    let err = client
        .settle_note(&mint.note_url(&k1), &k1, 0, None)
        .await
        .expect_err("a spent refusal must not come back looking settled");

    assert!(matches!(err, Error::NoteSpent { .. }), "got {err:?}");
    let rescued = err.new_secrets();
    assert_eq!(rescued.len(), 1);
    assert_ne!(rescued[0], k1);
    assert_eq!(
        mint.note_state(&rescued[0]).await.as_deref(),
        Some("outstanding")
    );
}

// ---- melt ----

#[tokio::test]
async fn melt_ok_means_in_flight_not_spent() {
    let mint = mint_or_skip!(&["--meltNeverSettles=true"]);
    let client = Client::new();
    let k1 = secret(15);
    mint.credit(&k1, 21000).await;

    let result = client
        .melt_note(&mint.callback(), &k1, "lnbc210n1pjqrstuvwxyz")
        .await
        .unwrap();
    assert_eq!(result.pr.as_deref(), Some("lnbc210n1pjqrstuvwxyz"));
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("pending"));

    // and every other operation is locked out until it resolves
    let err = client.rotate_note(&mint.callback(), &k1).await.unwrap_err();
    assert!(matches!(err, Error::NotePending), "got {err:?}");
}

#[tokio::test]
async fn a_failed_melt_restores_the_note() {
    let mint = mint_or_skip!(&["--meltAlwaysFails=true"]);
    let client = Client::new();
    let k1 = secret(16);
    mint.credit(&k1, 21000).await;

    client
        .melt_note(&mint.callback(), &k1, "lnbc210n1pjqrstuvwxyz")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    // a failed melt is never reported through the callback - it is only
    // observable as the note becoming spendable again
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("outstanding"));
}

// ---- minting ----

#[tokio::test]
async fn mints_a_note_the_service_never_saw_the_secret_of() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let pay = client
        .fetch_pay_request(&format!("{}/.well-known/lnurlp/mint", mint.url))
        .await
        .unwrap();
    // LUD-25 minting is comment-bound, so a mint MUST leave room for the
    // 64-character commitment. Without it there is nowhere to name the note.
    assert!(pay.names_mint_output());
    assert_eq!(pay.comment_allowed, Some(64));
    let withdraw_link = pay.withdraw_link.clone().expect("a minting payRequest");

    // The wallet chooses the secret, before any invoice exists, and persists
    // it before paying. The SERVICE is told sha256 of it and nothing more.
    let mint_secret = secret(42);
    let invoice = client
        .request_mint_invoice(&pay.callback, 21000, &mint_secret)
        .await
        .unwrap();
    assert!(!invoice.disposable);
    let verify_url = invoice.verify.expect("LUD-21 verify");
    let payment_hash = verify_url.rsplit('/').next().unwrap().to_string();
    mint.settle(&payment_hash).await;

    let verified = client
        .fetch_invoice_verification(&verify_url)
        .await
        .unwrap();
    assert!(verified.settled);
    // The preimage is settlement proof and nothing else. Every node that
    // forwarded the payment learned it; under the earlier draft that made all
    // of them holders of the note. Here it redeems nothing.
    let preimage = verified.preimage.expect("preimage disclosed");
    assert_eq!(hash_k1(&preimage).unwrap(), payment_hash);
    assert_ne!(preimage, mint_secret);
    let preimage_url = build_note_url(&withdraw_link, &preimage, None).unwrap();
    assert!(
        client.fetch_note_info(&preimage_url).await.is_err(),
        "the payment preimage must not redeem the note"
    );

    // The wallet's own secret is the note.
    let note_url = build_note_url(&withdraw_link, &mint_secret, None).unwrap();
    let info = client.fetch_note_info(&note_url).await.unwrap();
    assert_eq!(info.max_withdrawable, 21000);

    let rotated = client
        .rotate_note(&info.callback, &mint_secret)
        .await
        .unwrap();
    assert_eq!(
        mint.note_state(&mint_secret).await.as_deref(),
        Some("burned")
    );
    assert_eq!(
        mint.note_state(&rotated.k1).await.as_deref(),
        Some("outstanding")
    );
}

#[tokio::test]
async fn refuses_to_pay_for_a_note_it_cannot_name() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let pay = client
        .fetch_pay_request(&format!("{}/.well-known/lnurlp/mint", mint.url))
        .await
        .unwrap();

    // A malformed commitment is refused before the request leaves, so a
    // WALLET never pays for a quote the SERVICE was always going to reject.
    let err = client
        .request_mint_invoice(&pay.callback, 21000, "not-a-32-byte-secret")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::RequestRefused(_)), "got {err:?}");

    // And an unnamed mint quote is refused by the SERVICE itself, before any
    // invoice exists to pay.
    let err = client
        .request_invoice(&pay.callback, 21000)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::ServiceRejected(_)), "got {err:?}");
}

#[tokio::test]
async fn reads_an_advertised_fee() {
    let mint = mint_or_skip!(&["--baseFeeMsat=1000", "--feePpm=2000"]);
    let client = Client::new();
    let pay = client
        .fetch_pay_request(&format!("{}/.well-known/lnurlp/mint", mint.url))
        .await
        .unwrap();
    let fee = pay.mint_fee.expect("fee advertised");
    assert_eq!(fee.base_fee_msat, 1000);
    assert_eq!(fee.fee_ppm, 2000);
}

// ---- a plain note is unsigned ----

/// LUD-25 Part 2 certifies cp1 notes only: a hash has nothing to attest to
/// without disclosing the secret behind it. So a mint answering a plain
/// rotate or split with a bare OK is following the spec, and the notes come
/// back unsigned - which is what a plain note is.
#[tokio::test]
async fn an_unsigned_plain_note_is_the_spec_not_a_fault() {
    let mint = mint_or_skip!(&["--signatures=false"]);
    let client = Client::new();
    let k1 = secret(29);
    mint.credit(&k1, 21000).await;

    let info = client.fetch_note_info(&mint.note_url(&k1)).await.unwrap();
    let rotated = client.rotate_note(&info.callback, &k1).await.unwrap();
    assert!(rotated.signature.is_none());
    assert_eq!(
        mint.note_state(&rotated.k1).await.as_deref(),
        Some("outstanding")
    );

    let split = client
        .split_note(&info.callback, std::slice::from_ref(&rotated.k1), 5000)
        .await
        .unwrap();
    assert!(split.signature.is_none() && split.change_signature.is_none());
    assert_eq!(
        mint.note_state(&split.change).await.as_deref(),
        Some("outstanding")
    );
}

/// A caller who still wants the old Part 1 signature over the hash can ask
/// for it. The refusal has to be the loud kind - but the rotate LANDED, and
/// the fresh secret is the only key to the note it minted, so the error
/// carries it out. Refusing without it would be this crate destroying real
/// money to make a point about a signature.
#[tokio::test]
async fn requiring_signatures_refuses_an_unsigned_rotate_without_losing_the_note() {
    let mint = mint_or_skip!(&["--signatures=false"]);
    let client = Client::with_config(ClientConfig {
        policy: Policy {
            require_signatures: true,
            ..Policy::default()
        },
        ..ClientConfig::default()
    });
    let k1 = secret(28);
    mint.credit(&k1, 21000).await;

    let err = client.rotate_note(&mint.callback(), &k1).await.unwrap_err();
    assert!(matches!(err, Error::Unverifiable { .. }), "got {err:?}");
    let kept = err.new_secrets().to_vec();
    assert_eq!(kept.len(), 1);
    // the note the caller was refused is real, outstanding, and reachable with
    // nothing but the secret the error handed back
    assert_eq!(
        mint.note_state(&kept[0]).await.as_deref(),
        Some("outstanding")
    );
}

// ---- classifying a response, from the vectors ----

enum Canned {
    Answer(u16, String),
    Drop,
    Stall,
}

/// A one-shot HTTP service on loopback that answers the first request it is
/// sent the way a responses.json case says: with a status and a body, by
/// dropping the connection, or by never answering at all.
fn canned_service(canned: Canned) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        // the whole request head first, so the client is past sending before
        // anything happens to the connection
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => head.extend_from_slice(&chunk[..read]),
            }
        }
        match canned {
            Canned::Answer(status, body) => {
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} Canned\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
            Canned::Drop => drop(stream),
            Canned::Stall => std::thread::sleep(Duration::from_secs(5)),
        }
    });
    url
}

/// responses.json through the client's own transport, a 500, a dropped
/// connection and a timeout included. Every case whose outputs are plain
/// notes, which is every note this client mints; the cp1 cases need an output
/// the caller names, and tests/vectors.rs grades those through the parser.
/// Retries are off, so one case is one request - the replay has its own tests.
#[tokio::test]
async fn response_vectors_through_the_client() {
    let path = conformance_dir().join("vectors").join("responses.json");
    if !path.exists() {
        assert!(
            std::env::var_os("CI").is_none(),
            "no vectors at {} - CI must grade them, never skip",
            path.display()
        );
        eprintln!("skipping: no vectors at {}", path.display());
        return;
    }
    let text = std::fs::read_to_string(&path).expect("read responses.json");
    let vectors: Value = serde_json::from_str(&text).expect("valid JSON");

    let mut graded = 0;
    for case in vectors["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        if !case["output"].is_null() || !case["change"].is_null() {
            continue;
        }
        let (canned, timeout) = if case["transportError"] == true {
            (Canned::Drop, Duration::from_secs(10))
        } else if case["timeout"] == true {
            (Canned::Stall, Duration::from_millis(200))
        } else {
            let status = u16::try_from(case["http"].as_u64().expect("http")).expect("a status");
            let body = match case.get("body") {
                Some(body) => body.to_string(),
                None => case["bodyRaw"].as_str().expect("bodyRaw").to_string(),
            };
            (Canned::Answer(status, body), Duration::from_secs(10))
        };
        let client = Client::with_config(ClientConfig {
            timeout,
            mutation_retries: 0,
            ..ClientConfig::default()
        });
        let callback = format!("{}/w/cb", canned_service(canned));
        let k1 = secret(60);

        // what came back, and how many fresh secrets the request carried
        let (result, minted) = match case["op"].as_str().expect("op") {
            "melt" => (
                client
                    .melt_note(&callback, &k1, "lnbc210n1pjq")
                    .await
                    .map(|_| (None, None)),
                0,
            ),
            "split" => (
                client
                    .split_note(&callback, std::slice::from_ref(&k1), 5000)
                    .await
                    .map(|split| (split.signature, split.change_signature)),
                2,
            ),
            "mutation" => (
                client
                    .rotate_note(&callback, &k1)
                    .await
                    .map(|rotated| (rotated.signature, None)),
                1,
            ),
            other => panic!("{name}: an op this suite does not know: {other}"),
        };
        let outcome = match &result {
            Ok(_) => "ok",
            Err(Error::Unverifiable { .. }) => "unverifiable",
            Err(Error::NotePending) => "pending",
            Err(Error::NoteSpent { .. }) => "spent",
            Err(Error::NoteUnknown { .. }) => "unknown",
            Err(Error::ServiceRejected(_)) => "error",
            Err(Error::Ambiguous { .. }) => "ambiguous",
            Err(other) => panic!("{name}: not an outcome responses.json names: {other:?}"),
        };
        assert_eq!(
            outcome,
            case["expect"].as_str().expect("expect"),
            "{name}: {result:?}"
        );
        match result {
            Ok((signature, change_signature)) => {
                assert_eq!(signature.as_deref(), case["signature"].as_str(), "{name}");
                assert_eq!(
                    change_signature.as_deref(),
                    case["changeSignature"].as_str(),
                    "{name}"
                );
            }
            Err(err) if matches!(outcome, "ambiguous" | "unverifiable") => {
                assert_eq!(
                    err.new_secrets().len(),
                    minted,
                    "{name}: the fresh secrets must survive"
                );
            }
            Err(_) => {}
        }
        graded += 1;
    }
    assert!(
        graded > 10,
        "too few response cases graded to mean anything"
    );
}

// ---- a mutation the transport retried ----

/// The old sharpest edge in the protocol, now closed. A SERVICE that has
/// implemented the replay rule answers the second, byte-identical attempt with
/// the success it already gave, so an unstoppable transport retry is invisible.
/// One that has not still answers "already spent" - and then the crate does
/// what it always did, and hands the secrets back rather than a verdict.
#[tokio::test]
async fn a_mint_that_will_not_replay_still_hands_the_secrets_back() {
    let mint = mint_or_skip!(&["--dropAfterMutation=true", "--retriedMutation=refuse"]);
    let client = Client::new();
    let k1 = secret(30);
    mint.credit(&k1, 21000).await;

    let err = client.rotate_note(&mint.callback(), &k1).await.unwrap_err();
    let rescued = err.new_secrets().to_vec();
    assert_eq!(rescued.len(), 1);
    assert_eq!(
        mint.note_state(&rescued[0]).await.as_deref(),
        Some("outstanding")
    );
}

// ---- ambiguous outcomes ----

/// A client that gives up on the first ambiguous answer, as every client did
/// before LUD-25 required a SERVICE to replay a retried mutation. The tests
/// that assert what an unresolved mutation carries need it: with retries on,
/// a conforming mint simply answers again and there is nothing left to carry.
fn no_retry_client() -> Client {
    Client::with_config(ClientConfig {
        mutation_retries: 0,
        ..ClientConfig::default()
    })
}

/// The mutation landed and the answer was lost on the way back. LUD-25 now
/// requires the SERVICE to answer the identical request with the success it
/// already gave, so asking a second time turns this from an unresolved maybe
/// into a completed rotate - the caller never sees an error at all.
#[tokio::test]
async fn a_lost_rotate_completes_by_asking_again() {
    let mint = mint_or_skip!(&["--dropAfterMutation=true"]);
    let client = Client::new();
    let k1 = secret(27);
    mint.credit(&k1, 21000).await;

    let rotated = client.rotate_note(&mint.callback(), &k1).await.unwrap();
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("burned"));
    // the replay repeats the signature, so a note recovered this way is as
    // verifiable as one whose first answer arrived
    assert!(rotated.signature.is_some());
    assert_eq!(
        client
            .fetch_note_info(&mint.note_url(&rotated.k1))
            .await
            .unwrap()
            .max_withdrawable,
        21000
    );
}

/// The same mint, for a client that will not ask again: this is the shape the
/// ambiguous machinery has always had, and it still has to work.
#[tokio::test]
async fn a_lost_rotate_preserves_its_fresh_secret() {
    let mint = mint_or_skip!(&["--dropAfterMutation=true"]);
    let client = no_retry_client();
    let k1 = secret(17);
    mint.credit(&k1, 21000).await;

    let err = client.rotate_note(&mint.callback(), &k1).await.unwrap_err();
    assert!(err.is_ambiguous(), "got {err:?}");
    let rescued = err.new_secrets().to_vec();
    assert_eq!(rescued.len(), 1);

    // the mutation did land: the input is burned and the output exists, keyed by
    // the hash of a secret only the caller holds
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("burned"));
    assert_eq!(
        client
            .fetch_note_info(&mint.note_url(&rescued[0]))
            .await
            .unwrap()
            .max_withdrawable,
        21000
    );
}

#[tokio::test]
async fn a_lost_split_preserves_both_secrets_in_output_order() {
    let mint = mint_or_skip!(&["--dropAfterMutation=true"]);
    let client = no_retry_client();
    let k1 = secret(18);
    mint.credit(&k1, 21000).await;

    let err = client
        .split_note(&mint.callback(), std::slice::from_ref(&k1), 5000)
        .await
        .unwrap_err();
    let rescued = err.new_secrets().to_vec();
    assert_eq!(rescued.len(), 2);
    assert_eq!(
        client
            .fetch_note_info(&mint.note_url(&rescued[0]))
            .await
            .unwrap()
            .max_withdrawable,
        5000
    );
    assert_eq!(
        client
            .fetch_note_info(&mint.note_url(&rescued[1]))
            .await
            .unwrap()
            .max_withdrawable,
        16000
    );
}

#[tokio::test]
async fn probing_resolves_the_ambiguity() {
    let mint = mint_or_skip!(&["--dropAfterMutation=true"]);
    let client = Client::new();
    let k1 = secret(19);
    mint.credit(&k1, 21000).await;
    let _ = client.rotate_note(&mint.callback(), &k1).await;
    assert_eq!(
        client.probe_burned_note(&mint.note_url(&k1)).await,
        NoteFate::Gone
    );

    let live = mint_or_skip!(&[]);
    let alive = secret(20);
    live.credit(&alive, 21000).await;
    assert_eq!(
        client.probe_burned_note(&live.note_url(&alive)).await,
        NoteFate::Live
    );

    let offline = Client::with_config(ClientConfig {
        offline: true,
        ..Default::default()
    });
    assert_eq!(
        offline.probe_burned_note(&live.note_url(&alive)).await,
        NoteFate::Unknown
    );
}

#[tokio::test]
async fn a_200_that_confirms_nothing_is_ambiguous() {
    let mint = mint_or_skip!(&["--unconfirmedMutation=true"]);
    let client = no_retry_client();
    let k1 = secret(21);
    mint.credit(&k1, 21000).await;

    let err = client.rotate_note(&mint.callback(), &k1).await.unwrap_err();
    assert!(err.is_ambiguous(), "got {err:?}");
    assert_eq!(err.new_secrets().len(), 1, "the fresh secret must survive");
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("burned"));
}

#[tokio::test]
async fn an_unreadable_response_is_ambiguous() {
    let mint = mint_or_skip!(&["--malformedJson=true"]);
    let client = Client::new();
    let k1 = secret(22);
    mint.credit(&k1, 21000).await;

    let err = client.rotate_note(&mint.callback(), &k1).await.unwrap_err();
    assert!(err.is_ambiguous(), "got {err:?}");
    assert_eq!(err.new_secrets().len(), 1);
}

#[tokio::test]
async fn a_timeout_is_ambiguous_not_failure() {
    let mint = mint_or_skip!(&["--slowMs=500"]);
    let client = Client::with_config(ClientConfig {
        timeout: std::time::Duration::from_millis(50),
        ..Default::default()
    });
    let k1 = secret(23);
    mint.credit(&k1, 21000).await;

    let err = client.rotate_note(&mint.callback(), &k1).await.unwrap_err();
    assert!(err.is_ambiguous(), "got {err:?}");
    assert_eq!(err.new_secrets().len(), 1);
}

#[tokio::test]
async fn a_refused_request_is_definitely_not_sent() {
    let mint = mint_or_skip!(&[]);
    let k1 = secret(24);
    mint.credit(&k1, 21000).await;

    let offline = Client::with_config(ClientConfig {
        offline: true,
        ..Default::default()
    });
    let err = offline
        .rotate_note(&mint.callback(), &k1)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::RequestRefused(_)), "got {err:?}");
    assert!(!err.is_ambiguous());
    assert_eq!(mint.note_state(&k1).await.as_deref(), Some("outstanding"));
}

#[tokio::test]
async fn refuses_a_callback_url_it_would_not_fetch() {
    let client = Client::new();
    let err = client
        .rotate_note("http://evil.example/cb", &secret(25))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::RequestRefused(_)), "got {err:?}");
}

// ---- a service that lies ----

#[tokio::test]
async fn a_lying_service_cannot_inflate_past_what_it_signed() {
    let mint = mint_or_skip!(&["--lieAboutValue=1000000"]);
    let client = Client::new();
    let k1 = secret(26);
    let signature = mint.credit(&k1, 21000).await.expect("mint signs");

    let info = client.fetch_note_info(&mint.note_url(&k1)).await.unwrap();
    assert_eq!(info.max_withdrawable, 1_021_000);
    // the signature was issued over the true amount, so the inflated one does
    // not verify - an offline holder catches this without asking anyone
    assert!(!verify_note_signature(
        &k1,
        info.max_withdrawable,
        &signature,
        &mint.pubkey
    ));
    assert!(verify_note_signature(&k1, 21000, &signature, &mint.pubkey));
}
