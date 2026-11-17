//! LUD-25 spends: what opens a note, and what its signatures sign.
//!
//! Every note is a BIP-341 taproot output key `Q`, written `cp1<Q>`, and a
//! mint stores, burns and certifies it by `hex(Q)`. A `k1` is a spend of one:
//!
//! ```text
//! ck1<Q || sig>   key path: a BIP-340 signature by Q
//! cw1<...>        script path: a leaf of Q's tree, its control block and the
//!                 witness that satisfies it
//! 64 hex          a bearer note's preimage, the short form of its cw1
//! ```
//!
//! Every signature signs the BIP-341 sighash of input 0 of one fixed,
//! never-broadcast transaction whose prevout is bound to the mint's domain,
//! so a spend one mint has seen cannot be replayed at another:
//!
//! ```text
//! nVersion 2, nLockTime as claimed
//! vin[0]   prevout (tagged_hash("LNURLcash/mint", domain), 0), nSequence as claimed
//! vout[0]  value 0, empty scriptPubKey
//! spent    (OP_1 <Q>, 0)
//! ```
//!
//! The transaction's shape never changes, so the sighash is built here field
//! by field rather than through a Bitcoin library: only the domain, `Q` and a
//! script path's time claim ever reach it. Spec vector 3 pins every
//! intermediate.
//!
//! A mint hands any leaf it cannot judge to Bitcoin Core's interpreter. This
//! crate has none, and wants none: offline, it evaluates the bearer hashlock
//! and reports any other script as unevaluated rather than guessing.
//!
//! Nothing here is secret apart from the secret key
//! [`taproot_tweak_secret_key`] takes: every other key, leaf and control
//! block is public, so none of it needs to be constant-time.

use secp256k1::{Keypair, Parity, Scalar, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::errors::{Error, Result};
use crate::recoverable::{
    decode_ck1, decode_cp1, decode_cw1, legacy_ck1_key, recover_note_ownership_pubkey, Cw1,
    DecodedCk1,
};
use crate::secrets::is_preimage;
use crate::urls::{from_bech32_lnurl, from_lud17, is_bech32_lnurl};

/// The one tapscript leaf version. A mint refuses any other: consensus lets
/// an unknown version succeed unconditionally.
pub const TAPLEAF_VERSION: u8 = 0xc0;
/// A key-path spend claims no time: locktime 0 and a final sequence.
pub const KEY_PATH_LOCKTIME: u32 = 0;
pub const KEY_PATH_SEQUENCE: u32 = 0xffff_ffff;

/// BIP-341's nothing-up-my-sleeve point. Nobody knows its discrete log, so a
/// note built on it has no key path: only its leaf can spend it.
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

// BIP-341 caps a control block's merkle path at 128 levels.
const MAX_MERKLE_DEPTH: usize = 128;
// BIP-342 keeps the 520-byte cap on every initial stack element.
const MAX_STACK_ELEMENT: usize = 520;

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_VALUE_MASK: u32 = 0xffff;
const SEQUENCE_GRANULARITY_SECONDS: i64 = 512;

// ---- hashes ----

/// BIP-340's tagged hash: `sha256(sha256(tag) || sha256(tag) || parts...)`.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(n as u32).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xff];
            out.extend_from_slice(&(n as u64).to_le_bytes());
            out
        }
    }
}

/// BIP-341's leaf hash: `tagged_hash("TapLeaf", version || compact_size(len) || script)`.
pub fn tapleaf_hash(script: &[u8], version: u8) -> [u8; 32] {
    tagged_hash(
        "TapLeaf",
        &[&[version], &compact_size(script.len()), script],
    )
}

/// BIP-341's branch hash, children in lexicographic order.
pub fn tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a <= b {
        tagged_hash("TapBranch", &[a, b])
    } else {
        tagged_hash("TapBranch", &[b, a])
    }
}

// ---- keys ----

/// Whether `x` is the x coordinate of a secp256k1 point. A `cp1` whose `Q`
/// is not can never be opened by any spend, so a mint must refuse one, and a
/// wallet must never name one as an output.
pub fn is_x_only_point(x: &[u8]) -> bool {
    <[u8; 32]>::try_from(x).is_ok_and(|x| XOnlyPublicKey::from_byte_array(x).is_ok())
}

/// A tweaked output key and its parity (0 even, 1 odd), which a control
/// block carries in its low bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaprootTweak {
    pub output_key: [u8; 32],
    pub parity: u8,
}

fn tweak_scalar(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> Option<Scalar> {
    // BIP-341 refuses t >= n rather than reducing it
    Scalar::from_be_bytes(tagged_hash("TapTweak", &[internal_key, merkle_root])).ok()
}

/// `Q = lift_x(P) + tagged_hash("TapTweak", P || merkle_root)·G`.
///
/// `None` when `P` is not a point, or the tweak lands on or above the curve
/// order (a ~2^-128 event BIP-341 also refuses).
pub fn taproot_tweak(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> Option<TaprootTweak> {
    let internal = XOnlyPublicKey::from_byte_array(*internal_key).ok()?;
    let tweak = tweak_scalar(internal_key, merkle_root)?;
    let (output, parity) = internal.add_tweak(&tweak).ok()?;
    Some(TaprootTweak {
        output_key: output.to_byte_array(),
        parity: match parity {
            Parity::Even => 0,
            Parity::Odd => 1,
        },
    })
}

/// The secret key that signs for [`taproot_tweak`]'s `Q`, from the internal
/// key's. A key-path spend of a note with a script tree signs with this.
/// Bearer material.
pub fn taproot_tweak_secret_key(secret_key: &[u8; 32], merkle_root: &[u8; 32]) -> Result<[u8; 32]> {
    let keypair = Keypair::from_secret_bytes(*secret_key).map_err(|_| {
        Error::Protocol("an internal secret key is a 32-byte scalar in [1, n)".into())
    })?;
    let unusable = || Error::Protocol("this tree does not tweak to a usable key".into());
    let tweak = tweak_scalar(&keypair.x_only_public_key().0.to_byte_array(), merkle_root)
        .ok_or_else(unusable)?;
    // negates an odd-y internal key first, as BIP-341's signer does
    let tweaked = keypair.add_xonly_tweak(&tweak).map_err(|_| unusable())?;
    Ok(tweaked.to_secret_bytes())
}

/// The `Q` a leaf and its control block commit to: fold the merkle path with
/// TapBranch, tweak the internal key, and check the parity bit. `None` for a
/// control block that is not `33 + 32m` bytes (m at most 128), an internal
/// key that is not a point, or the wrong parity - any of which commits to no
/// key at all.
pub fn output_key_of(script: &[u8], control_block: &[u8]) -> Option<[u8; 32]> {
    let len = control_block.len();
    if len < 33 || (len - 33) % 32 != 0 || (len - 33) / 32 > MAX_MERKLE_DEPTH {
        return None;
    }
    let mut node = tapleaf_hash(script, control_block[0] & 0xfe);
    for sibling in control_block[33..].chunks_exact(32) {
        node = tapbranch_hash(&node, sibling.try_into().ok()?);
    }
    let tweaked = taproot_tweak(control_block[1..33].try_into().ok()?, &node)?;
    (tweaked.parity == control_block[0] & 1).then_some(tweaked.output_key)
}

// ---- the bearer note ----
//
// NUMS internal key, one `OP_SHA256 <h> OP_EQUAL` leaf: spent by revealing
// the preimage, with no signature and so bound to no mint. Everything but the
// preimage follows from h, which is why its short forms work: a 64-hex k1 is
// the preimage, and 64 hex where a cp1 goes is h.

/// `OP_SHA256 <h> OP_EQUAL`, `a8 20 <h> 87`.
pub fn bearer_leaf(h: &[u8; 32]) -> [u8; 35] {
    let mut leaf = [0u8; 35];
    leaf[0] = 0xa8;
    leaf[1] = 0x20;
    leaf[2..34].copy_from_slice(h);
    leaf[34] = 0x87;
    leaf
}

/// The `h` inside a leaf, if the leaf is exactly a bearer hashlock.
fn bearer_hash_of_leaf(script: &[u8]) -> Option<[u8; 32]> {
    if script.len() == 35 && script[0] == 0xa8 && script[1] == 0x20 && script[34] == 0x87 {
        script[2..34].try_into().ok()
    } else {
        None
    }
}

/// A bearer note, everything about it but the preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BearerNote {
    pub output_key: [u8; 32],
    pub control_block: [u8; 33],
    pub leaf: [u8; 35],
}

/// The bearer note `h` names. `None` only if its tweak lands on or above the
/// curve order, which BIP-341 refuses and no hash is known to do.
pub fn bearer_note(h: &[u8; 32]) -> Option<BearerNote> {
    let leaf = bearer_leaf(h);
    let tweaked = taproot_tweak(&NUMS_H, &tapleaf_hash(&leaf, TAPLEAF_VERSION))?;
    let mut control_block = [0u8; 33];
    control_block[0] = TAPLEAF_VERSION | tweaked.parity;
    control_block[1..].copy_from_slice(&NUMS_H);
    Some(BearerNote {
        output_key: tweaked.output_key,
        control_block,
        leaf,
    })
}

/// A bearer note's full `cw1` for this preimage, claiming no time: the spend
/// its 64-hex short form stands for. `None` as for [`bearer_note`].
pub fn bearer_cw1(preimage: &[u8]) -> Option<Cw1> {
    let note = bearer_note(&Sha256::digest(preimage).into())?;
    Some(Cw1 {
        locktime: KEY_PATH_LOCKTIME,
        sequence: KEY_PATH_SEQUENCE,
        script: note.leaf.to_vec(),
        control_block: note.control_block.to_vec(),
        witness: vec![preimage.to_vec()],
    })
}

// ---- what a signature signs ----

/// The domain a spend at `value` is bound to: the host lowercased, A-label,
/// without port, userinfo or trailing dot. `value` may be a note or mint URL (https, http, a
/// LUD-17 scheme or a bech32 LNURL) or a bare host, with or without a port.
/// `None` when it names no host.
///
/// A note's domain is its own withdraw URL's host, so a caller holding a note
/// URL already has it.
pub fn spend_domain_of(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let expanded = if is_bech32_lnurl(trimmed) {
        from_bech32_lnurl(trimmed)?
    } else {
        from_lud17(trimmed)
    };
    // without a scheme, a bare "host:port" would parse as scheme "host"
    let candidate = if expanded.contains("://") {
        expanded
    } else {
        format!("https://{expanded}")
    };
    // The host, lowercased, in A-label form, without port, userinfo or
    // trailing dot (luds fd80cdd): the url crate does the IDNA step and
    // drops port and userinfo.
    let host = url::Url::parse(&candidate)
        .ok()?
        .host_str()?
        .to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host).to_string();
    (!host.is_empty()).then_some(host)
}

/// `tagged_hash("LNURLcash/mint", domain)`: the prevout txid that binds a
/// spend to one mint. `domain` is used as given, lowercased; pass a URL
/// through [`spend_domain_of`] first.
pub fn spend_prevout(domain: &str) -> [u8; 32] {
    tagged_hash("LNURLcash/mint", &[domain.to_ascii_lowercase().as_bytes()])
}

/// BIP-341's `SigMsg` for input 0 of the canonical spend transaction under
/// `SIGHASH_DEFAULT`, with BIP-342's extension when a leaf is given. Integers
/// little-endian, as BIP-341 has them.
pub fn spend_sig_msg(
    output_key: &[u8; 32],
    domain: &str,
    locktime: u32,
    sequence: u32,
    leaf_script: Option<&[u8]>,
) -> Vec<u8> {
    let mut script_pubkey = vec![0x51, 0x20];
    script_pubkey.extend_from_slice(output_key);
    let mut outpoint = spend_prevout(domain).to_vec();
    outpoint.extend_from_slice(&0u32.to_le_bytes());

    let mut msg = Vec::with_capacity(174 + 37);
    msg.push(0x00); // hash_type: SIGHASH_DEFAULT
    msg.extend_from_slice(&2u32.to_le_bytes()); // nVersion
    msg.extend_from_slice(&locktime.to_le_bytes());
    msg.extend_from_slice(&Sha256::digest(&outpoint)); // sha_prevouts: binds the mint
    msg.extend_from_slice(&Sha256::digest(0i64.to_le_bytes())); // sha_amounts
    msg.extend_from_slice(&Sha256::digest(
        [&[script_pubkey.len() as u8][..], &script_pubkey].concat(),
    )); // sha_scriptpubkeys: binds the note
    msg.extend_from_slice(&Sha256::digest(sequence.to_le_bytes())); // sha_sequences
    msg.extend_from_slice(&Sha256::digest([0u8; 9])); // sha_outputs: value 0, empty script
    msg.push(if leaf_script.is_some() { 0x02 } else { 0x00 }); // spend_type, no annex
    msg.extend_from_slice(&0u32.to_le_bytes()); // input_index
    if let Some(leaf) = leaf_script {
        msg.extend_from_slice(&tapleaf_hash(leaf, TAPLEAF_VERSION));
        msg.push(0x00); // key_version
        msg.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // no OP_CODESEPARATOR
    }
    msg
}

fn tap_sighash(sig_msg: &[u8]) -> [u8; 32] {
    // 0x00 is BIP-341's epoch byte
    tagged_hash("TapSighash", &[&[0x00], sig_msg])
}

/// What a `ck1`'s signature signs: the key-path sighash for `Q` at `domain`,
/// with locktime 0 and sequence `0xffffffff`. Nothing in it depends on value
/// or time, so a key has exactly one signature per mint.
pub fn key_path_sighash(output_key: &[u8; 32], domain: &str) -> [u8; 32] {
    tap_sighash(&spend_sig_msg(
        output_key,
        domain,
        KEY_PATH_LOCKTIME,
        KEY_PATH_SEQUENCE,
        None,
    ))
}

/// What a `SIGHASH_DEFAULT` signature inside a `cw1`'s leaf signs, for the
/// time the spend claims.
pub fn script_path_sighash(
    output_key: &[u8; 32],
    domain: &str,
    leaf_script: &[u8],
    locktime: u32,
    sequence: u32,
) -> [u8; 32] {
    tap_sighash(&spend_sig_msg(
        output_key,
        domain,
        locktime,
        sequence,
        Some(leaf_script),
    ))
}

// ---- naming a note ----

fn hex32(value: &str) -> Option<[u8; 32]> {
    if !is_preimage(value) {
        return None;
    }
    hex::decode(value.trim()).ok()?.try_into().ok()
}

/// The `Q` of whatever goes where a `cp1` goes (a mint comment, `p1`/`p2`,
/// `?p=`): a `cp1` whose key is a point, or a bearer note's 64-hex `h`.
pub fn decode_note(value: &str) -> Option<[u8; 32]> {
    match hex32(value) {
        Some(h) => bearer_note(&h).map(|note| note.output_key),
        None => decode_cp1(value),
    }
}

/// A `k1`, decoded. Nothing here checks a signature: that needs the note's
/// domain (see [`check_spend`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spend {
    /// A `ck1`: `Q` and a BIP-340 signature by it.
    KeyPath {
        output_key: [u8; 32],
        signature: [u8; 64],
    },
    /// A 65-byte recoverable-ECDSA `ck1` from before a `ck1` carried `Q`.
    /// Recovering the key is its only check, so it names whatever key its
    /// signature recovers to. Deprecated: rotate it.
    LegacyKeyPath { output_key: [u8; 32] },
    /// A `cw1`, or a 64-hex preimage, which is a bearer note's `cw1` in short.
    ScriptPath { output_key: [u8; 32], cw1: Cw1 },
}

impl Spend {
    /// The note this spend names.
    pub fn output_key(&self) -> [u8; 32] {
        match self {
            Spend::KeyPath { output_key, .. }
            | Spend::LegacyKeyPath { output_key }
            | Spend::ScriptPath { output_key, .. } => *output_key,
        }
    }

    /// The `h` of the bearer note this spend names, if it names one: the
    /// canonical hashlock leaf under the NUMS key, whatever its witness. What
    /// a certificate from a mint predating taproot signed instead of
    /// `hex(Q)`.
    pub fn bearer_hash(&self) -> Option<[u8; 32]> {
        let Spend::ScriptPath { output_key, cw1 } = self else {
            return None;
        };
        let h = bearer_hash_of_leaf(&cw1.script)?;
        (bearer_note(&h)?.output_key == *output_key).then_some(h)
    }
}

/// Decode what goes where a `k1` goes: a 64-hex preimage, a `ck1` or a
/// `cw1`. `None` for anything else, including a `ck1` whose `Q` is not a
/// point and a `cw1` whose control block commits to no key.
pub fn decode_spend(k1: &str) -> Option<Spend> {
    let value = k1.trim();
    if let Some(preimage) = hex32(value) {
        let cw1 = bearer_cw1(&preimage)?;
        return Some(Spend::ScriptPath {
            output_key: cw1.output_key()?,
            cw1,
        });
    }
    if let Some(decoded) = decode_ck1(value) {
        return match decoded {
            DecodedCk1::Current(payload) => {
                let output_key: [u8; 32] = payload[..32].try_into().ok()?;
                is_x_only_point(&output_key).then_some(Spend::KeyPath {
                    output_key,
                    signature: payload[32..].try_into().ok()?,
                })
            }
            DecodedCk1::Legacy(signature) => Some(Spend::LegacyKeyPath {
                output_key: legacy_ck1_key(&signature)?,
            }),
        };
    }
    let cw1 = decode_cw1(value)?;
    Some(Spend::ScriptPath {
        output_key: cw1.output_key()?,
        cw1,
    })
}

// ---- the rules a mint applies ----

// BIP-342's OP_SUCCESSx.
fn is_op_success(op: u8) -> bool {
    matches!(
        op,
        80 | 98 | 126..=129 | 131..=134 | 137 | 138 | 141 | 142 | 149..=153 | 187..=254
    )
}

/// Does this leaf use one of tapscript's upgrade hooks? `None` if not, or the
/// reason a mint refuses it: a leaf version other than `0xc0`, or an
/// `OP_SUCCESSx` opcode outside pushed data. Consensus accepts both
/// unconditionally, so either would be spendable by anyone who saw it.
///
/// `leaf_version` is the control block's first byte with its parity bit
/// cleared.
pub fn check_leaf(leaf_version: u8, script: &[u8]) -> Option<&'static str> {
    if leaf_version & 0xfe != TAPLEAF_VERSION {
        return Some("unknown tapleaf version");
    }
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        // pushed data is data, not an opcode; a truncated push ends the
        // walk, since Bitcoin Core fails such a script by itself
        let skip = match op {
            1..=75 => usize::from(op),
            0x4c => 1 + usize::from(*script.get(i)?),
            0x4d => {
                let len = script.get(i..i + 2)?;
                2 + usize::from(u16::from_le_bytes([len[0], len[1]]))
            }
            0x4e => {
                let len = script.get(i..i + 4)?;
                4usize.saturating_add(u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize)
            }
            op if is_op_success(op) => return Some("leaf uses a reserved OP_SUCCESS opcode"),
            _ => 0,
        };
        i = i.saturating_add(skip);
    }
    None
}

/// A script path's time claim against a mint's clock, in Unix seconds:
/// `None` if it is due, or why not. `locked_at` is when the mint credited the
/// note, where a relative lock starts counting.
///
/// A mint makes this check, not a wallet: a timelock a mint honours is that
/// mint asserting its own clock, a custodial policy and never a consensus
/// guarantee. It is here so a wallet can tell a holder when a note it holds
/// becomes spendable, and so the rule has one implementation.
pub fn check_time_claim(locktime: u32, sequence: u32, now: u64, locked_at: u64) -> Option<String> {
    if locktime != 0 {
        if locktime < LOCKTIME_THRESHOLD {
            return Some("block-height locktimes have no meaning without a chain".into());
        }
        if u64::from(locktime) > now {
            return Some(format!("locktime {locktime} is in the future"));
        }
    }
    if sequence & SEQUENCE_DISABLE_FLAG != 0 {
        return None;
    }
    if sequence & SEQUENCE_TYPE_FLAG == 0 {
        return Some("block-count relative locks have no meaning without a chain".into());
    }
    let required = i64::from(sequence & SEQUENCE_VALUE_MASK) * SEQUENCE_GRANULARITY_SECONDS;
    // signed, so a clock that reads earlier than the credit still counts as
    // nothing elapsed rather than wrapping round
    let elapsed = now as i64 - locked_at as i64;
    (elapsed < required).then(|| format!("relative lock of {required}s not yet satisfied"))
}

// ---- checking a spend offline ----

/// What [`check_spend`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendVerdict {
    /// The spend opens its note under LUD-25's current rules.
    Opens,
    /// It opens its note only under a deprecated `ck1` scheme: a signature
    /// over the fixed message `LNURLcash` (its sha256, or the raw bytes), or
    /// the 65-byte recoverable-ECDSA shape. Reference mints still accept
    /// these, so the note is spendable, but a holder should rotate it.
    OpensLegacy,
    /// A script path whose leaf passes the mint's leaf rules but whose script
    /// this crate does not evaluate: only the bearer hashlock is. The mint
    /// decides.
    Unevaluated,
    /// It does not open the note, and why.
    Fails(String),
}

impl SpendVerdict {
    /// Whether the spend is known to open its note, under any scheme a mint
    /// still accepts.
    pub fn opens(&self) -> bool {
        matches!(self, SpendVerdict::Opens | SpendVerdict::OpensLegacy)
    }
}

/// A spend's note and whether the spend opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendCheck {
    pub output_key: [u8; 32],
    pub verdict: SpendVerdict,
}

/// Does the spend in `k1` open its note at `domain`, as the mint would judge
/// it? `domain` is the mint's (a note URL, a mint URL or a bare host; see
/// [`spend_domain_of`]): a `ck1` signs for exactly one. `None` if `k1` is no
/// spend at all.
///
/// Time claims are left to the mint's clock, as LUD-25's offline
/// verification leaves them: read a `cw1`'s with [`decode_spend`] and
/// [`check_time_claim`].
pub fn check_spend(k1: &str, domain: &str) -> Option<SpendCheck> {
    let spend = decode_spend(k1)?;
    let output_key = spend.output_key();
    let verdict = match &spend {
        Spend::KeyPath {
            output_key,
            signature,
        } => {
            let mut payload = [0u8; 96];
            payload[..32].copy_from_slice(output_key);
            payload[32..].copy_from_slice(signature);
            match recover_note_ownership_pubkey(&payload, domain) {
                Some(owner) if !owner.legacy => SpendVerdict::Opens,
                Some(_) => SpendVerdict::OpensLegacy,
                // Deliberately unspecific, as a mint is: explaining a failed
                // signature only helps someone guess.
                None => SpendVerdict::Fails("the signature does not open this note here".into()),
            }
        }
        Spend::LegacyKeyPath { .. } => SpendVerdict::OpensLegacy,
        Spend::ScriptPath { cw1, .. } => script_path_verdict(cw1),
    };
    Some(SpendCheck {
        output_key,
        verdict,
    })
}

fn script_path_verdict(cw1: &Cw1) -> SpendVerdict {
    if let Some(reason) = check_leaf(cw1.control_block[0], &cw1.script) {
        return SpendVerdict::Fails(reason.into());
    }
    // A bearer leaf, under any internal key and at any depth, is exactly
    // what Bitcoin Core would decide about it: OP_SHA256 <h> OP_EQUAL leaves
    // one true element only for a lone witness item under the stack-element
    // cap that hashes to h.
    let Some(h) = bearer_hash_of_leaf(&cw1.script) else {
        return SpendVerdict::Unevaluated;
    };
    match cw1.witness.as_slice() {
        [preimage]
            if preimage.len() <= MAX_STACK_ELEMENT
                && Sha256::digest(preimage).as_slice() == h.as_slice() =>
        {
            SpendVerdict::Opens
        }
        _ => SpendVerdict::Fails("the witness does not satisfy the leaf".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_is_the_bare_lowercase_hostname() {
        for (value, domain) in [
            ("https://mint.example/w?k1=00", "mint.example"),
            ("https://Mint.Example/w", "mint.example"),
            ("http://127.0.0.1:8899/w", "127.0.0.1"),
            ("lnurlw://moneyer.dev/w?k1=00", "moneyer.dev"),
            ("lnurlw://localhost:3338/w", "localhost"),
            ("mint.example", "mint.example"),
            ("localhost:3338", "localhost"),
            ("  CASH.example.com  ", "cash.example.com"),
        ] {
            assert_eq!(spend_domain_of(value).as_deref(), Some(domain), "{value}");
        }
        for value in ["", "   ", "https://"] {
            assert_eq!(spend_domain_of(value), None, "{value:?}");
        }
        // a bech32 LNURL names its host too
        let lnurl = crate::urls::to_bech32_lnurl("https://mint.example/w").expect("encodes");
        assert_eq!(spend_domain_of(&lnurl).as_deref(), Some("mint.example"));
    }

    #[test]
    fn a_bearer_notes_short_form_is_its_full_cw1() {
        let preimage = [0x07; 32];
        let from_hex = decode_spend(&hex::encode(preimage)).expect("a spend");
        let cw1 = bearer_cw1(&preimage).expect("a cw1");
        let h: [u8; 32] = Sha256::digest(preimage).into();
        assert_eq!(from_hex.output_key(), cw1.output_key().expect("commits"));
        assert_eq!(from_hex.bearer_hash(), Some(h));
        assert_eq!(decode_note(&hex::encode(h)), Some(from_hex.output_key()));
        assert_eq!(
            check_spend(&hex::encode(preimage), "").map(|c| c.verdict),
            Some(SpendVerdict::Opens)
        );
    }

    #[test]
    fn a_wrong_preimage_does_not_open_a_bearer_leaf() {
        let mut cw1 = bearer_cw1(&[0x07; 32]).expect("a cw1");
        cw1.witness = vec![vec![0x08; 32]];
        assert!(matches!(script_path_verdict(&cw1), SpendVerdict::Fails(_)));
        cw1.witness = vec![vec![0x07; 32], vec![]];
        assert!(matches!(script_path_verdict(&cw1), SpendVerdict::Fails(_)));
        cw1.witness = vec![];
        assert!(matches!(script_path_verdict(&cw1), SpendVerdict::Fails(_)));
    }

    #[test]
    fn hostile_scripts_never_panic() {
        for script in [
            &[0x4e, 0xff, 0xff, 0xff, 0xff][..],
            &[0x4d, 0xff][..],
            &[0x4c][..],
            &[0x4b][..],
        ] {
            assert_eq!(check_leaf(TAPLEAF_VERSION, script), None, "{script:?}");
        }
        assert_eq!(output_key_of(&[], &[]), None);
        assert_eq!(output_key_of(&[], &[0xc0; 33 + 32 * 129]), None);
    }
}
