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
//! - [`Error::Unverifiable`] - a MUTATION landed and the SERVICE returned no
//!   certificate for an output it was owed one for. The note exists; it just
//!   cannot be verified offline.
//!
//! Treating an ambiguous failure as a definitive one is how wallets lose
//! money: a rotate that times out after the SERVICE burned the input has
//! already minted the output, and the fresh secret the caller generated is the
//! only copy of it in existence.

use thiserror::Error;

/// The reason LUD-25 fixes for a `p1`/`p2` naming a note already outstanding
/// or burned.
pub const OUTPUT_IN_USE: &str = "already in use";

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
    /// while a note sits at the output it disclosed. That is why `new_secrets`
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
    /// but returned no `cs1` certificate for a `cp1` output, which is only
    /// worth naming by its key if it can be checked offline. The mutation
    /// LANDED. The note exists, at the key or hash the caller disclosed, and
    /// whatever stands behind it is the only key to that value anywhere.
    ///
    /// So this is an error about the note's VERIFIABILITY, never about its
    /// existence, and it carries the secrets for the same reason
    /// [`Error::Ambiguous`] does: refusing without them would strand real money
    /// to make a point about conformance. Empty for a mutation whose output
    /// the caller named, since this crate never saw the secret behind it.
    ///
    /// Raised for a `cp1` output whatever the policy says, and for a bearer
    /// output named by its hash only when
    /// [`crate::protocol::Policy::require_signatures`] asks for its
    /// certificate. The tolerant default admits a mint with no signer.
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

    /// Whether the SERVICE refused because an output names a note that is
    /// outstanding or was burned: a mint invoice's comment, or lnurl-mint's
    /// `Output already in use.` at the callback. Definitive, and nothing was
    /// burned, so name another output.
    ///
    /// LUD-25's exact `already in use` at the callback is ambiguous, since it
    /// also answers a spend of a burned note, and [`classify_note_error`]
    /// reads it as [`Error::NoteSpent`] so the fresh secrets stay attached;
    /// [`Error::is_already_in_use`] matches it in either form.
    pub fn is_output_in_use(&self) -> bool {
        match self {
            Error::ServiceRejected(reason) => reason.to_ascii_lowercase().contains(OUTPUT_IN_USE),
            _ => false,
        }
    }

    /// Whether the SERVICE answered `already in use` (LUD-25) in any form:
    /// either a note being spent was burned, or an output is somebody's
    /// already. A recovery scan counts it as a used index.
    pub fn is_already_in_use(&self) -> bool {
        match self {
            Error::ServiceRejected(reason) | Error::NoteSpent { reason, .. } => {
                reason.to_ascii_lowercase().contains(OUTPUT_IN_USE)
            }
            _ => false,
        }
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
/// LUD-25 fixes one wording (luds `92abbb3`): a burned note is answered exactly
/// `already in use`, at the informational GET and at the callback alike, and
/// a LUD-26 recovery scan counts that as a used index. Every caller of this
/// is asking about a note being spent, so that exact reason is
/// [`Error::NoteSpent`]. The same reason also refuses a `p1`/`p2` that is
/// already somebody's note, and from the wording alone the two are one: a
/// caller that named its own outputs and needs to know which it was looks its
/// inputs up. This crate's own rotate, split and merge mint to fresh secrets,
/// which nobody else holds, so for them it is the spent input. lnurl-mint's
/// older `Output already in use.` names the output, and stays a refusal
/// [`Error::is_output_in_use`] recognises.
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
    if lowered.contains("spent") || lowered.trim() == OUTPUT_IN_USE {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_in_use_is_read_in_either_wording() {
        for reason in ["already in use", "Output already in use."] {
            assert!(
                Error::ServiceRejected(reason.into()).is_output_in_use(),
                "{reason}"
            );
        }
        assert!(!Error::ServiceRejected("Unknown note.".into()).is_output_in_use());
    }

    /// LUD-25 answers a burned note exactly `already in use`: spent, wherever
    /// a note is being spent or looked up. lnurl-mint's older output wording
    /// stays an output refusal.
    #[test]
    fn already_in_use_is_a_spent_note_and_the_old_output_wording_is_not() {
        for reason in ["already in use", "Already in use", " already in use "] {
            let err = classify_note_error(reason);
            assert!(matches!(err, Error::NoteSpent { .. }), "{reason}: {err:?}");
            assert!(
                err.is_already_in_use() && !err.is_output_in_use(),
                "{reason}"
            );
        }
        let err = classify_note_error("Output already in use.");
        assert!(matches!(err, Error::ServiceRejected(_)), "{err:?}");
        assert!(err.is_output_in_use() && err.is_already_in_use());
        assert!(!classify_note_error("Unknown note.").is_already_in_use());
    }
}
