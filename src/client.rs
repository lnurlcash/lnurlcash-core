//! An HTTP client over reqwest, behind the `client` feature.
//!
//! It is deliberately thin: everything about the protocol lives in
//! [`crate::protocol`], and this module only performs the GET and classifies
//! its failure by whether the request could have been processed. A caller with
//! its own HTTP stack should use `protocol` directly and skip this entirely.

use std::time::Duration;

use serde_json::Value;

use crate::errors::{Error, Result};
use crate::note::with_new_k1;
use crate::protocol::{self, Request};
use crate::secrets::generate_note_secret;
use crate::urls::is_allowed_service_url;

/// What a probe learned about a note whose fate was uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteFate {
    /// Still outstanding: the request never landed, so the fresh secrets minted
    /// nothing and can be discarded.
    Live,
    /// The SERVICE reports it spent or unknown: the burn landed, and the
    /// carried secrets are the only money left.
    Gone,
    /// The probe itself failed. No information either way - keep everything.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Bounded wait. Without one a hung SERVICE blocks the caller forever.
    pub timeout: Duration,
    /// Refuse to make any request at all. A caller holding notes offline
    /// deliberately can set this to be certain nothing reaches the network,
    /// rather than trusting that it happens not to.
    pub offline: bool,
    /// Where replacement note secrets come from. Substitute for a hardware RNG
    /// or a deterministic test - and see [`generate_note_secret`] for what a
    /// caller takes on by doing so.
    pub secret_source: fn() -> String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            timeout: Duration::from_secs(30),
            offline: false,
            secret_source: generate_note_secret,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RotateOutcome {
    pub k1: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SplitOutcome {
    pub k1: String,
    pub change: String,
    pub signature: Option<String>,
    pub change_signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MeltOutcome {
    pub pr: Option<String>,
    pub verify: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SettledNote {
    pub k1: String,
    pub amount_msat: u64,
    pub signature: Option<String>,
    pub callback: String,
}

#[derive(Debug)]
pub struct Client {
    http: reqwest::Client,
    config: ClientConfig,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }

    pub fn with_config(config: ClientConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_default();
        Client { http, config }
    }

    async fn run(&self, request: Request) -> Result<Value> {
        let attach = |err: Error| err.with_secrets(request.new_secrets.clone());

        if self.config.offline {
            return Err(Error::RequestRefused(
                "offline mode is on - no request was made".into(),
            ));
        }
        if !is_allowed_service_url(&request.url) {
            return Err(Error::RequestRefused(
                "refusing to fetch that URL - only https, or http to a loopback or .onion host, is allowed".into(),
            ));
        }

        // Transport failures are ambiguous for a mutating request: the request
        // may well have arrived, and only the answer was lost.
        let response = match self.http.get(&request.url).send().await {
            Ok(response) => response,
            Err(err) if err.is_timeout() => {
                return Err(attach(Error::ambiguous(
                    "the service took too long to respond - its answer, if any, was lost",
                )))
            }
            Err(_) => {
                return Err(attach(Error::ambiguous(
                    "failed to reach the service - it may be offline or unreachable",
                )))
            }
        };
        let text = match response.text().await {
            Ok(text) => text,
            Err(_) => {
                return Err(attach(Error::ambiguous(
                    "the service's response could not be read",
                )))
            }
        };
        serde_json::from_str(&text).map_err(|_| {
            attach(Error::ambiguous(
                "the service returned an unreadable response",
            ))
        })
    }

    async fn run_mutation(&self, request: Request) -> Result<protocol::MutationResponse> {
        let secrets = request.new_secrets.clone();
        let body = self.run(request).await?;
        protocol::parse_mutation(&body).map_err(|err| err.with_secrets(secrets))
    }

    pub async fn fetch_note_info(&self, url: &str) -> Result<protocol::WithdrawRequestInfo> {
        let body = self.run(protocol::note_info_request(url)?).await?;
        protocol::parse_note_info(&body, url)
    }

    pub async fn fetch_mint_address(&self, url: &str) -> Result<protocol::MintAddressInfo> {
        let body = self.run(protocol::mint_address_request(url)?).await?;
        protocol::parse_mint_address(&body)
    }

    pub async fn melt_note(&self, callback: &str, k1: &str, pr: &str) -> Result<MeltOutcome> {
        let response = self
            .run_mutation(protocol::melt_request(callback, k1, pr)?)
            .await?;
        Ok(MeltOutcome {
            pr: response.pr,
            verify: response.verify,
        })
    }

    pub async fn rotate_note(&self, callback: &str, k1: &str) -> Result<RotateOutcome> {
        let fresh = (self.config.secret_source)();
        let response = self
            .run_mutation(protocol::rotate_request(callback, k1, &fresh)?)
            .await?;
        Ok(RotateOutcome {
            k1: fresh,
            signature: response.signature,
        })
    }

    pub async fn split_note(
        &self,
        callback: &str,
        k1s: &[String],
        amount_msat: u64,
    ) -> Result<SplitOutcome> {
        let fresh = (self.config.secret_source)();
        let change = (self.config.secret_source)();
        let response = self
            .run_mutation(protocol::split_request(
                callback,
                k1s,
                amount_msat,
                &fresh,
                &change,
            )?)
            .await?;
        Ok(SplitOutcome {
            k1: fresh,
            change,
            signature: response.signature,
            change_signature: response.change_signature,
        })
    }

    pub async fn merge_notes(&self, callback: &str, k1s: &[String]) -> Result<RotateOutcome> {
        let fresh = (self.config.secret_source)();
        let response = self
            .run_mutation(protocol::merge_request(callback, k1s, &fresh)?)
            .await?;
        Ok(RotateOutcome {
            k1: fresh,
            signature: response.signature,
        })
    }

    pub async fn fetch_pay_request(&self, url: &str) -> Result<protocol::PayRequestInfo> {
        let body = self.run(protocol::pay_request_request(url)?).await?;
        protocol::parse_pay_request(&body)
    }

    pub async fn request_invoice(
        &self,
        pay_callback: &str,
        amount_msat: u64,
    ) -> Result<protocol::InvoiceResult> {
        let body = self
            .run(protocol::invoice_request(pay_callback, amount_msat)?)
            .await?;
        protocol::parse_invoice(&body, amount_msat)
    }

    pub async fn fetch_invoice_verification(
        &self,
        verify_url: &str,
    ) -> Result<protocol::VerifyResult> {
        let body = self.run(protocol::verify_request(verify_url)?).await?;
        protocol::parse_verify(&body)
    }

    /// After an ambiguous mutation: did the burn actually happen?
    pub async fn probe_burned_note(&self, url: &str) -> NoteFate {
        match self.fetch_note_info(url).await {
            Ok(_) => NoteFate::Live,
            Err(Error::NoteSpent(_)) | Err(Error::NoteUnknown(_)) => NoteFate::Gone,
            Err(_) => NoteFate::Unknown,
        }
    }

    /// Resolve what a split's change or a merge's output is ACTUALLY worth, then
    /// rotate it before further use.
    ///
    /// Neither response carries an amount - the spec's only source of truth is
    /// an informational GET - and a fee-charging SERVICE may have deducted from
    /// a split's change or refunded into a merge's result. That GET puts k1 on
    /// the wire, so a rotate follows, best-effort.
    pub async fn settle_note(
        &self,
        base_url: &str,
        k1: &str,
        expected_amount_msat: u64,
        signature: Option<&str>,
    ) -> Result<SettledNote> {
        let url = with_new_k1(base_url, k1, expected_amount_msat, signature)
            .ok_or_else(|| Error::RequestRefused("that note URL does not parse".into()))?;
        let info = self.fetch_note_info(&url).await?;
        match self.rotate_note(&info.callback, k1).await {
            Ok(rotated) => Ok(SettledNote {
                k1: rotated.k1,
                amount_msat: info.max_withdrawable,
                signature: rotated.signature,
                callback: info.callback,
            }),
            Err(_) => Ok(SettledNote {
                k1: k1.to_string(),
                amount_msat: info.max_withdrawable,
                signature: signature.map(|s| s.to_string()),
                callback: info.callback,
            }),
        }
    }
}
