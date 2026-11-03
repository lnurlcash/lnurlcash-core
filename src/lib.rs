//! LNURLcash ([LUD-25 draft](https://github.com/lnurl/luds/pull/301)) bearer
//! notes: the money-critical logic, in one place.
//!
//! A bearer note is an ordinary LUD-03 withdrawRequest link whose `k1` IS the
//! asset:
//!
//! ```text
//! lnurlw://mint.example/w?k1=<spend>&c=<cs1>
//! ```
//!
//! Whoever holds the spend controls the sats behind it, like a banknote. Any
//! `amount` alongside it is only a claim by whoever encoded the note; the
//! authoritative value is always `maxWithdrawable` from an informational GET.
//!
//! Every note is a BIP-341 taproot output key `Q`, named `cp1<Q>`, and a
//! spend opens it: a 64-hex preimage (the plain bearer note), a `ck1` (its
//! key path) or a `cw1` (a leaf of its script tree). See [`spend`].
//!
//! Every mutating operation is a GET on the `callback` from that
//! withdrawRequest, naming each resulting note by its `cp1` or, for a bearer
//! note, its hash `h`:
//!
//! ```text
//! callback?k1=X&pr=<bolt11>                  melt
//! callback?k1=X&p1=<h or cp1>                rotate
//! callback?k1=X&amount=<msat>&p1=..&p2=..    split
//! callback?k1=X&k1=Y&p1=<h or cp1>           merge
//! ```
//!
//! # What this crate is for
//!
//! It exists so there is exactly one audited implementation of the parts that
//! lose money when they are wrong - ambiguous mutations, melt semantics, who
//! generates a replacement secret, which end of a signature carries the
//! recovery id - and so the mobile bindings are a wrapper over that rather than
//! a fifth hand-written port drifting away from a draft spec.
//!
//! # Amounts
//!
//! Integers in milli-satoshis, everywhere, with no exceptions.
//!
//! # Reference implementations
//!
//! Both by dni, both MIT:
//! [lnurl-mint](https://github.com/dni/lnurl-mint) (the service) and
//! [lnurl-wallet](https://github.com/dni/lnurl-wallet) (the wallet).

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod bolt11;
pub mod cash;
#[cfg(feature = "client")]
pub mod client;
pub mod errors;
#[cfg(feature = "ffi")]
pub mod ffi;

// The UniFFI scaffolding has to be generated at the crate root, so it lives
// here even though everything it exports is defined in `ffi`.
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
pub mod fees;
mod long_bech32;
pub mod note;
pub mod protocol;
pub mod recoverable;
pub mod secrets;
pub mod signature;
pub mod spend;
pub mod urls;

pub use bolt11::{decode_bolt11_amount_msat, is_bolt11_invoice, same_invoice};
pub use errors::{classify_note_error, Error, Result};
pub use fees::{
    apply_mint_fee, describe_mint_fee, format_fee_percent, gross_up_for_mint_fee, parse_mint_fee,
    MintFee,
};
pub use note::{
    build_note_url, check_note_url, is_valid_note_input, note_declared_amount, note_k1,
    note_signature, resolve_note_input, with_new_k1, without_k1,
};
pub use protocol::{
    InvoiceResult, MintAddressInfo, MutationResponse, PayRequestInfo, Request, VerifyResult,
    WithdrawRequestInfo, MINT_COMMENT_LENGTH,
};
pub use recoverable::{note_id_of, note_lookup_of};
pub use secrets::{generate_note_secret, hash_k1, is_preimage};
pub use signature::{
    address_proof_digest, address_proof_message, check_note, check_note_certificate,
    legacy_note_signature_digest_for_hash, legacy_note_signature_message_for_hash,
    note_signature_digest, note_signature_digest_for_hash, note_signature_message,
    note_signature_message_for_hash, sign_address_proof, verify_address_proof,
    verify_legacy_note_signature_hash, verify_note_signature, verify_note_signature_hash,
    CertifiedOver, NoteCheck,
};
pub use spend::{
    check_spend, decode_note, decode_spend, spend_domain_of, SpendCheck, SpendVerdict,
};
pub use urls::{
    from_bech32_lnurl, from_lud17, is_allowed_service_url, is_bech32_lnurl, is_lightning_address,
    lightning_address_username, mint_address_url, resolve_lnurl_input, resolve_mint_input,
    server_of, to_bech32_lnurl, to_lud17w,
};

#[cfg(feature = "client")]
pub use client::{Client, ClientConfig, NoteFate};
