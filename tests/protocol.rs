//! Runs against the conformance repo's mock mint - a real HTTP server that can
//! be told to misbehave. The happy paths matter, but the adversarial modes are
//! the reason this suite exists: a crate that only works against a well-behaved
//! SERVICE has not been tested at all.

#![cfg(feature = "client")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use lnurlcash_core::client::{Client, ClientConfig, NoteFate};
use lnurlcash_core::{build_note_url, hash_k1, verify_note_signature, Error};

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
    fn start(flags: &[&str]) -> Option<Self> {
        let script = conformance_dir().join("mock-mint").join("index.mjs");
        if !script.exists() {
            eprintln!("skipping: no mock mint at {}", script.display());
            return None;
        }
        let mut command = Command::new("node");
        command
            .arg(&script)
            .arg("--port=0")
            .arg("--testHooks=true")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for flag in flags {
            command.arg(flag);
        }
        let mut process = command.spawn().ok()?;
        let stdout = process.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let (mut url, mut pubkey) = (None, None);
        let mut line = String::new();
        while reader.read_line(&mut line).ok()? > 0 {
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
            url: url?,
            pubkey: pubkey?,
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
    assert!(matches!(err, Error::NoteUnknown(_)), "got {err:?}");

    client.rotate_note(&mint.callback(), &known).await.unwrap();
    let err = client
        .fetch_note_info(&mint.note_url(&known))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoteSpent(_)), "got {err:?}");
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
async fn mints_a_note_from_a_paid_invoice_and_rotates_it() {
    let mint = mint_or_skip!(&[]);
    let client = Client::new();
    let pay = client
        .fetch_pay_request(&format!("{}/.well-known/lnurlp/mint", mint.url))
        .await
        .unwrap();
    let withdraw_link = pay.withdraw_link.expect("a minting payRequest");

    let invoice = client.request_invoice(&pay.callback, 21000).await.unwrap();
    assert!(!invoice.disposable);
    let verify_url = invoice.verify.expect("LUD-21 verify");
    let payment_hash = verify_url.rsplit('/').next().unwrap().to_string();
    mint.settle(&payment_hash).await;

    let verified = client
        .fetch_invoice_verification(&verify_url)
        .await
        .unwrap();
    assert!(verified.settled);
    // the preimage IS the note secret - which the mint necessarily saw
    let claimed = verified.preimage.expect("preimage disclosed");
    assert_eq!(hash_k1(&claimed).unwrap(), payment_hash);

    let note_url = build_note_url(&withdraw_link, &claimed, None).unwrap();
    let info = client.fetch_note_info(&note_url).await.unwrap();
    assert_eq!(info.max_withdrawable, 21000);

    let rotated = client.rotate_note(&info.callback, &claimed).await.unwrap();
    // after rotating, the secret the mint generated is worthless
    assert_eq!(mint.note_state(&claimed).await.as_deref(), Some("burned"));
    assert_eq!(
        mint.note_state(&rotated.k1).await.as_deref(),
        Some("outstanding")
    );
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

// ---- ambiguous outcomes ----

#[tokio::test]
async fn a_lost_rotate_preserves_its_fresh_secret() {
    let mint = mint_or_skip!(&["--dropAfterMutation=true"]);
    let client = Client::new();
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
    let client = Client::new();
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
    let client = Client::new();
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
