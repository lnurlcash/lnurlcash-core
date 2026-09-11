//! LNURLcash ([LUD-25 draft](https://github.com/lnurl/luds/pull/301)) bearer
//! notes: the money-critical logic, in one place.
//!
//! A bearer note is an ordinary LUD-03 withdrawRequest link whose `k1` IS the
//! asset:
//!
//! ```text
//! lnurlw://mint.example/w?k1=<secret>&amount=<msat>
//! ```
//!
//! Whoever knows the `k1` controls the sats behind it, like a banknote. The
//! `amount` alongside it is only a claim by whoever encoded the note; the
//! authoritative value is always `maxWithdrawable` from an informational GET.
//!
//! Every mutating operation is a GET on the `callback` from that
//! withdrawRequest:
//!
//! ```text
//! callback?k1=X&pr=<bolt11>              melt
//! callback?k1=X&h=<sha256(X')>           rotate
//! callback?k1=X&amount=<msat>&h=..&h2=.. split
//! callback?k1=X&k1=Y&h=<sha256(Z)>       merge
//! ```
//!
//! A LUD-25 Part 2 note is keyed by a public key instead: its k1 is a `ck1`
//! signature, and its output a `cp1` key sent as `p1`/`p2`. See
//! [`recoverable`].
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
pub mod note;
pub mod protocol;
pub mod recoverable;
pub mod secrets;
pub mod signature;
pub mod urls;

pub use bolt11::{decode_bolt11_amount_msat, is_bolt11_invoice, same_invoice};
pub use errors::{classify_note_error, Error, Result};
pub use fees::{
    apply_mint_fee, describe_mint_fee, format_fee_percent, gross_up_for_mint_fee, parse_mint_fee,
    MintFee,
};
pub use note::{
    build_note_url, is_valid_note_input, note_declared_amount, note_k1, note_signature,
    resolve_note_input, with_new_k1, without_k1,
};
pub use protocol::{
    InvoiceResult, MintAddressInfo, MutationResponse, PayRequestInfo, Request, VerifyResult,
    WithdrawRequestInfo, MINT_COMMENT_LENGTH,
};
pub use recoverable::{note_id_of, note_lookup_of};
pub use secrets::{generate_note_secret, hash_k1, is_preimage};
pub use signature::{
    note_signature_digest, note_signature_digest_for_hash, note_signature_message,
    note_signature_message_for_hash, verify_note_signature, verify_note_signature_hash,
};
pub use urls::{
    from_bech32_lnurl, from_lud17, is_allowed_service_url, is_bech32_lnurl, is_lightning_address,
    lightning_address_username, mint_address_url, resolve_lnurl_input, resolve_mint_input,
    server_of, to_bech32_lnurl, to_lud17w,
};

#[cfg(feature = "client")]
pub use client::{Client, ClientConfig, NoteFate};
