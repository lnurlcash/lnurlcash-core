//! The error taxonomy, which is the safety-critical part of this crate.
//!
//! What each variant means for the money involved:
//!
//! - [`Error::RequestRefused`] — nothing was sent. The note is untouched.
//! - [`Error::ServiceRejected`] and its note-specific variants — the SERVICE
//!   processed the request and refused it. Definitive.
//! - [`Error::Ambiguous`] — the outcome is unknown. The request MAY have been
//!   processed. Nothing may be assumed either way.
//! - [`Error::Protocol`] — a non-mutating response did not match the spec.
//!
//! Two families carry the fresh secrets a mutation generated: the ambiguous
//! and unverifiable ones always, and a spent-or-unknown refusal because at a
//! SERVICE that will not replay a retried mutation, that refusal is also what
//! a mutation it ALREADY applied looks like. Read them with
//! [`Error::new_secrets`] and persist them before believing anything.
//! - [`Error::Unverifiable`] — a MUTATION landed and the SERVICE returned no
//!   signature over it. The note exists; it just cannot be verified offline.
//!
//! Treating an ambiguous failure as a definitive one is how wallets lose
//! money: a rotate that times out after the SERVICE burned the input has
//! already minted the output, and the fresh secret the caller generated is the
//! only copy of it in existence.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// The request never left: offline, a URL this crate will not fetch, or a
    /// callback that does not parse. Safe to treat as a no-op.
    #[error("{0}")]
    RequestRefused(String),

    /// A non-mutating response that does not match the protocol.
    #[error("{0}")]
    Protocol(String),

    /// The SERVICE answered `{"status":"ERROR"}`: it processed the request and
    /// declined it. Definitive - the operation did not happen.
    #[error("{0}")]
    ServiceRejected(String),

    /// The exact `{"status":"ERROR","reason":"pending"}` case: this k1 has a
    /// melt in flight, and every other operation on it is refused until that
    /// resolves. Retry shortly - never read this as spent.
    #[error("this note has another operation in progress - try again in a moment")]
    NotePending,

    /// The SERVICE reports the k1 as unambiguously already burned. At the
    /// informational GET that statement is authoritative, so a holder may lock
    /// the note as spent.
    ///
    /// At a MUTATION it is weaker, and the weakness costs money. A SERVICE that
    /// has not implemented LUD-25's replay rule answers a retried rotate,
    /// split or merge with exactly this refusal, its inputs having been burned
    /// by the first attempt - so the caller is told the mutation never happened
    /// while a note sits at the hash it disclosed. That is why `new_secrets`
    /// exists here: read it before believing the refusal.
    #[error("this note has already been spent (service says: \"{reason}\")")]
    NoteSpent {
        reason: String,
        new_secrets: Vec<String>,
    },

    /// The SERVICE does not recognise the k1 at all. Distinct from
    /// [`Error::NoteSpent`] because nothing here proves the holder's copy was
    /// ever real - and carrying secrets for the same reason it does.
    #[error("the service doesn't recognise this note (service says: \"{reason}\")")]
    NoteUnknown {
        reason: String,
        new_secrets: Vec<String>,
    },

    /// The SERVICE confirmed a rotate, split or merge with `{"status":"OK"}`
    /// but returned no signature over the hash it was given. LUD-25 makes
    /// offline verification mandatory, so this is a non-conforming SERVICE -
    /// but the mutation LANDED. The note exists, at the hash the caller
    /// disclosed, and the WALLET-generated secret behind it is the only key to
    /// that value anywhere.
    ///
    /// So this is an error about the note's VERIFIABILITY, never about its
    /// existence, and it carries the secrets for the same reason
    /// [`Error::Ambiguous`] does: refusing without them would strand real money
    /// to make a point about conformance.
    ///
    /// Only ever raised when the policy requires signatures, which is the
    /// default.
    #[error("{message}")]
    Unverifiable {
        message: String,
        /// As [`Error::Ambiguous::new_secrets`], and more important here: the
        /// note is known to exist.
        new_secrets: Vec<String>,
    },

    /// The outcome is unknown: a timeout, a dropped connection, an unreadable
    /// response, or a 200 that did not confirm.
    #[error("{message}")]
    Ambiguous {
        message: String,
        /// Fresh WALLET-generated secrets whose hashes the uncertain request
        /// disclosed. If the request did land, these are the only copies of the
        /// notes the SERVICE minted - persist them before doing anything else.
        ///
        /// Order matches the operation's result shape: `[rotated]` for a
        /// rotate, `[split_off, change]` for a split, `[merged]` for a merge.
        new_secrets: Vec<String>,
    },
}

impl Error {
    pub fn ambiguous(message: impl Into<String>) -> Self {
        Error::Ambiguous {
            message: message.into(),
            new_secrets: Vec::new(),
        }
    }

    pub fn unverifiable(message: impl Into<String>) -> Self {
        Error::Unverifiable {
            message: message.into(),
            new_secrets: Vec::new(),
        }
    }

    /// Attach the secrets a mutation generated, so a lost answer cannot take
    /// them with it.
    pub fn with_secrets(self, secrets: Vec<String>) -> Self {
        match self {
            Error::Ambiguous { message, .. } => Error::Ambiguous {
                message,
                new_secrets: secrets,
            },
            // Not ambiguous at all, and the secrets matter more rather than
            // less: the mutation said OK, so the note is known to exist.
            Error::Unverifiable { message, .. } => Error::Unverifiable {
                message,
                new_secrets: secrets,
            },
            // A definitive refusal naming an input as spent or unknown is also
            // what a mutation the SERVICE ALREADY applied looks like, at a
            // SERVICE that answers a retry rather than replaying it. This crate
            // cannot tell those apart - at the wire they are the same answer -
            // so it hands back the secrets rather than a verdict.
            Error::NoteSpent { reason, .. } => Error::NoteSpent {
                reason,
                new_secrets: secrets,
            },
            Error::NoteUnknown { reason, .. } => Error::NoteUnknown {
                reason,
                new_secrets: secrets,
            },
            other => other,
        }
    }

    /// The fresh secrets carried out of an ambiguous mutation, if any.
    pub fn new_secrets(&self) -> &[String] {
        match self {
            Error::Ambiguous { new_secrets, .. }
            | Error::Unverifiable { new_secrets, .. }
            | Error::NoteSpent { new_secrets, .. }
            | Error::NoteUnknown { new_secrets, .. } => new_secrets,
            _ => &[],
        }
    }

    /// Whether the request could have been processed. The single most
    /// important question about any failure here.
    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Error::Ambiguous { .. })
    }

    /// Whether the SERVICE definitively refused. The operation did not happen.
    pub fn is_definitive(&self) -> bool {
        matches!(
            self,
            Error::ServiceRejected(_)
                | Error::NotePending
                | Error::NoteSpent { .. }
                | Error::NoteUnknown { .. }
                | Error::RequestRefused(_)
        )
    }
}

/// A SERVICE's wording for "this k1 is dead" varies by implementation and by
/// endpoint. An informational GET can afford to distinguish "Note already
/// spent." from "Unknown note.", while the mutating callback - an atomic,
/// possibly multi-k1 request - can only say something like "Invalid or already
/// spent k1.", since it cannot tell which case applies to which k1.
///
/// The reason must arrive here exactly as the SERVICE sent it, empty string
/// included. Substituting a friendly default first would be read back as
/// though the SERVICE had said it: "Unknown service error" matches the rule for
/// an unknown note, and would report one on no evidence at all.
pub fn classify_note_error(reason: &str) -> Error {
    let lowered = reason.to_ascii_lowercase();
    if lowered == "pending" {
        return Error::NotePending;
    }
    if lowered.contains("spent") {
        return Error::NoteSpent {
            reason: reason.to_string(),
            new_secrets: Vec::new(),
        };
    }
    if lowered.contains("unknown") || lowered.contains("not found") {
        return Error::NoteUnknown {
            reason: reason.to_string(),
            new_secrets: Vec::new(),
        };
    }
    Error::ServiceRejected(reason.to_string())
}

pub type Result<T> = std::result::Result<T, Error>;
