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

    /// The SERVICE reports the k1 as unambiguously already burned. It is
    /// authoritative here, so a holder may lock the note as spent.
    #[error("this note has already been spent (service says: \"{0}\")")]
    NoteSpent(String),

    /// The SERVICE does not recognise the k1 at all. Distinct from
    /// [`Error::NoteSpent`] because nothing here proves the holder's copy was
    /// ever real.
    #[error("the service doesn't recognise this note (service says: \"{0}\")")]
    NoteUnknown(String),

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

    /// Attach the secrets a mutation generated, so a lost answer cannot take
    /// them with it.
    pub fn with_secrets(self, secrets: Vec<String>) -> Self {
        match self {
            Error::Ambiguous { message, .. } => Error::Ambiguous {
                message,
                new_secrets: secrets,
            },
            other => other,
        }
    }

    /// The fresh secrets carried out of an ambiguous mutation, if any.
    pub fn new_secrets(&self) -> &[String] {
        match self {
            Error::Ambiguous { new_secrets, .. } => new_secrets,
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
                | Error::NoteSpent(_)
                | Error::NoteUnknown(_)
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
        return Error::NoteSpent(reason.to_string());
    }
    if lowered.contains("unknown") || lowered.contains("not found") {
        return Error::NoteUnknown(reason.to_string());
    }
    Error::ServiceRejected(reason.to_string())
}

pub type Result<T> = std::result::Result<T, Error>;
