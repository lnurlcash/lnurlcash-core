//! LUD-25's bech32m strings, key-path notes, and LUD-26's seed tree they hang off.
//!
//! Every note is a taproot output key `Q` (see [`crate::spend`]). A key-path
//! note's `Q` is the holder's own key, used as is: the holder keeps `sk`,
//! discloses `cp1<Q>`, and spends the note with `ck1<Q || sig>`, a BIP-340
//! signature by `sk` over the key-path sighash for one mint's domain. The
//! SERVICE verifies the pair and finds the note by `Q`. It certifies every
//! note, key-path or bearer, with `cs1` over `hex(Q)`, whose human-readable
//! part also carries the signed amount using BOLT-11 amount rules, so a
//! recipient can check issuance offline (see [`crate::signature`]).
//!
//! The five strings:
//!
//! ```text
//! cp1<Q>                 a note, 32 bytes
//! ck1<Q || sig>          a key-path spend, 96 bytes
//! cw1<...>               a script-path spend, variable
//! cs<amount>1<sig>       a mint's certificate, 65 bytes
//! cx1<chain code || P>   a share's xpub, 65 bytes
//! ```
//!
//! The names and semantics follow the TypeScript kit, which follows
//! lnurl-wallet's `src/lib`.

use hmac::{Hmac, Mac};
use k256::schnorr::{Signature as SchnorrSignature, SigningKey, VerifyingKey};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Keypair, Message, PublicKey, Scalar, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::cash::{
    cash_node_public_key, derive_cash_child, derive_cash_child_pub, derive_cash_domain_node,
    derive_cash_root, derive_service_root, CashNode,
};
use crate::errors::{Error, Result};
use crate::long_bech32::{self, Bech32m};
use crate::secrets::is_preimage;
use crate::signature::lightning_signed_digest;
use crate::spend::{
    decode_spend, is_x_only_point, key_path_sighash, output_key_of, spend_domain_of, tagged_hash,
};

type HmacSha256 = Hmac<Sha256>;

// ---- bech32m ----
//
// `ck1`, `cw1`, `cs1` and `cx1` all run past BIP-173's 90 characters, which
// the draft deliberately does not adopt, and [`long_bech32`] enforces none.
// BIP-350's own rules do apply, as lnurl-mint applies them: one case
// throughout (all uppercase is the same string, mixed case is refused), a
// bech32m checksum rather than a bech32 one, and zero padding bits. Every
// type but `cw1` has a fixed payload length.

// No note URL gets near this; it only stops a hostile string costing work.
const MAX_BECH32_CHARS: usize = 8192;

fn encode_bytes(hrp: &str, bytes: &[u8]) -> String {
    long_bech32::encode::<Bech32m>(hrp, bytes).expect("a fixed, valid human-readable part")
}

/// Never panics: anything that is not this type is a `None`.
fn decode_bytes(hrp: &str, value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.len() > MAX_BECH32_CHARS {
        return None;
    }
    // a bech32 checksum, non-zero padding bits, or a whole spare group of
    // them, fail here
    long_bech32::decode::<Bech32m>(hrp, value)
}

fn decode_fixed<const N: usize>(hrp: &str, value: &str) -> Option<[u8; N]> {
    decode_bytes(hrp, value)?.try_into().ok()
}

/// A note's output key `Q`, 32-byte x-only, as a `cp1`. What a WALLET
/// discloses as an output, and what a SERVICE files the note under.
pub fn encode_cp1(output_key: &[u8; 32]) -> String {
    encode_bytes("cp", output_key)
}

/// `None` for anything but a `cp1` whose `Q` is the x coordinate of a curve
/// point. LUD-25 has a SERVICE refuse any other: no spend could ever open it,
/// so a note minted to one is value destroyed.
pub fn decode_cp1(value: &str) -> Option<[u8; 32]> {
    decode_fixed("cp", value).filter(|key: &[u8; 32]| is_x_only_point(key))
}

pub fn is_cp1(value: &str) -> bool {
    decode_cp1(value).is_some()
}

/// A key-path spend: the note's 32-byte output key followed by a 64-byte
/// BIP-340 signature, as a `ck1`. Whoever has it can spend the note.
pub fn encode_ck1(payload: &[u8; 96]) -> String {
    encode_bytes("ck", payload)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedCk1 {
    /// `Q || sig`. Which message `sig` signs is a question for
    /// [`recover_note_ownership_pubkey`], which needs the mint's domain.
    Current([u8; 96]),
    /// Pre-Schnorr recoverable-ECDSA bearer, accepted only so existing notes
    /// remain spendable long enough to rotate into the current format.
    Legacy([u8; 65]),
}

impl DecodedCk1 {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Current(payload) => payload,
            Self::Legacy(signature) => signature,
        }
    }
}

/// The payload's shape only. LUD-25 has a SERVICE refuse any `ck1` but the
/// 96-byte one; the 65-byte legacy shape is read here so a wallet can still
/// rotate a note it holds under one.
pub fn decode_ck1(value: &str) -> Option<DecodedCk1> {
    let bytes = decode_bytes("ck", value)?;
    match bytes.len() {
        96 => bytes.try_into().ok().map(DecodedCk1::Current),
        65 => bytes.try_into().ok().map(DecodedCk1::Legacy),
        _ => None,
    }
}

pub fn is_ck1(value: &str) -> bool {
    decode_ck1(value).is_some()
}

/// A script-path spend: a leaf script, its control block and the witness
/// items that satisfy it, with the time the spend claims. A bearer note's
/// full `cw1` is equivalent to its 64-hex preimage (see
/// [`crate::spend::bearer_cw1`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cw1 {
    /// The claimed `nLockTime`: 0, or a Unix time at least 500,000,000.
    pub locktime: u32,
    /// The claimed `nSequence`. `0xffffffff` claims nothing.
    pub sequence: u32,
    pub script: Vec<u8>,
    /// `(leaf version | parity) || internal key || merkle path`.
    pub control_block: Vec<u8>,
    /// Bottom of the stack first; the script and control block excluded.
    pub witness: Vec<Vec<u8>>,
}

impl Cw1 {
    /// The note this spend names, recomputed from its control block. `None`
    /// if the control block commits to no key.
    pub fn output_key(&self) -> Option<[u8; 32]> {
        output_key_of(&self.script, &self.control_block)
    }
}

/// `u32 locktime || u32 sequence || (u16 len || item)*` over the script, the
/// control block, then the witness items bottom of stack first; integers
/// big-endian. Refused only for an item too long for its 16-bit length.
pub fn encode_cw1(cw1: &Cw1) -> Result<String> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&cw1.locktime.to_be_bytes());
    payload.extend_from_slice(&cw1.sequence.to_be_bytes());
    for item in [&cw1.script, &cw1.control_block]
        .into_iter()
        .chain(cw1.witness.iter())
    {
        let len = u16::try_from(item.len())
            .map_err(|_| Error::Protocol("a cw1 item is at most 65535 bytes".into()))?;
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(item);
    }
    Ok(encode_bytes("cw", &payload))
}

/// `None` unless the length prefixes consume the payload exactly, a script
/// and a control block are both present, and the control block commits to a
/// key: LUD-25 has a SERVICE refuse anything else, so none of it names a
/// note.
pub fn decode_cw1(value: &str) -> Option<Cw1> {
    let payload = decode_bytes("cw", value)?;
    if payload.len() < 8 {
        return None;
    }
    let mut items = Vec::new();
    let mut at = 8;
    while at < payload.len() {
        let len = usize::from(u16::from_be_bytes(
            payload.get(at..at + 2)?.try_into().ok()?,
        ));
        at += 2;
        items.push(payload.get(at..at + len)?.to_vec());
        at += len;
    }
    if items.len() < 2 {
        return None;
    }
    let mut items = items.into_iter();
    let cw1 = Cw1 {
        locktime: u32::from_be_bytes(payload[..4].try_into().ok()?),
        sequence: u32::from_be_bytes(payload[4..8].try_into().ok()?),
        script: items.next()?,
        control_block: items.next()?,
        witness: items.collect(),
    };
    cw1.output_key().is_some().then_some(cw1)
}

pub fn is_cw1(value: &str) -> bool {
    decode_cw1(value).is_some()
}

/// A decoded current `cs1`: the amount committed in its human-readable part
/// and the mint's raw 65-byte recoverable signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cs1 {
    pub amount_msat: u64,
    pub signature: [u8; 65],
}

fn encode_amount_suffix(amount_msat: u64) -> String {
    for (suffix, unit) in [
        ("", 100_000_000_000u64),
        ("m", 100_000_000u64),
        ("u", 100_000u64),
        ("n", 100u64),
    ] {
        if amount_msat % unit == 0 {
            return format!("{}{suffix}", amount_msat / unit);
        }
    }
    // One pico-BTC unit is 0.1 msat. u128 keeps amount * 10 safe for every
    // u64 amount before it is rendered as decimal digits.
    format!("{}p", u128::from(amount_msat) * 10)
}

fn decode_amount_suffix(value: &str) -> Option<u64> {
    let (digits, unit) = match value.as_bytes().last().copied() {
        Some(b'm') => (&value[..value.len() - 1], 'm'),
        Some(b'u') => (&value[..value.len() - 1], 'u'),
        Some(b'n') => (&value[..value.len() - 1], 'n'),
        Some(b'p') => (&value[..value.len() - 1], 'p'),
        _ => (value, '\0'),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = digits.parse::<u128>().ok()?;
    let amount = match unit {
        '\0' => digits.checked_mul(100_000_000_000)?,
        'm' => digits.checked_mul(100_000_000)?,
        'u' => digits.checked_mul(100_000)?,
        'n' => digits.checked_mul(100)?,
        'p' if digits % 10 == 0 => digits / 10,
        'p' => return None,
        _ => unreachable!(),
    };
    amount.try_into().ok()
}

/// Legacy fixed-HRP certificate, retained for compatibility with notes made
/// before the amount moved into `cs1`. New code should use
/// [`encode_cs1_with_amount`].
pub fn encode_cs1(signature: &[u8; 65]) -> String {
    encode_bytes("cs", signature)
}

pub fn decode_cs1(value: &str) -> Option<[u8; 65]> {
    decode_fixed("cs", value)
}

pub fn is_cs1(value: &str) -> bool {
    decode_cs1(value).is_some()
}

/// A SERVICE's current issuance certificate. The HRP is `cs` followed by
/// the signed amount using BOLT-11's amount suffix rules; the payload is the
/// mint's 65-byte recoverable signature over that amount and the note key.
pub fn encode_cs1_with_amount(amount_msat: u64, signature: &[u8; 65]) -> String {
    encode_bytes(
        &format!("cs{}", encode_amount_suffix(amount_msat)),
        signature,
    )
}

/// `None` unless the payload is 65 bytes, `r || s || recovery-id`, with the
/// recovery id 0 to 3, as LUD-25 has a SERVICE refuse anything else.
pub fn decode_cs1_with_amount(value: &str) -> Option<Cs1> {
    let trimmed = value.trim();
    let separator = trimmed.rfind('1')?;
    let hrp = trimmed[..separator].to_ascii_lowercase();
    let amount_msat = decode_amount_suffix(hrp.strip_prefix("cs")?)?;
    let signature: [u8; 65] = decode_fixed(&hrp, trimmed)?;
    if signature[64] > 3 {
        return None;
    }
    Some(Cs1 {
        amount_msat,
        signature,
    })
}

pub fn is_cs1_with_amount(value: &str) -> bool {
    decode_cs1_with_amount(value).is_some()
}

/// The raw signature from either current or legacy `cs1` form.
pub fn decode_any_cs1(value: &str) -> Option<[u8; 65]> {
    decode_cs1_with_amount(value)
        .map(|cs1| cs1.signature)
        .or_else(|| decode_cs1(value))
}

pub fn is_any_cs1(value: &str) -> bool {
    decode_any_cs1(value).is_some()
}

/// A share's extended public key (LUD-26): its chain code and compressed
/// point, in BIP-32's order. Whoever holds one can derive every note key on
/// the share with [`derive_note_pubkey`], and link them all to each other,
/// but can spend none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cx1 {
    pub chain_code: [u8; 32],
    /// Compressed, `02` or `03` first.
    pub pubkey: [u8; 33],
}

impl Cx1 {
    /// `x(P)`: what a registration proof by this share verifies against.
    pub fn pubkey_x_only(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.pubkey[1..]);
        x
    }
}

/// `bech32m("cx", chainCode || P)`, 113 characters.
pub fn encode_cx1(cx1: &Cx1) -> String {
    let mut bytes = [0u8; 65];
    bytes[..32].copy_from_slice(&cx1.chain_code);
    bytes[32..].copy_from_slice(&cx1.pubkey);
    encode_bytes("cx", &bytes)
}

/// `None` unless the payload is 65 bytes and its last 33 a compressed curve
/// point. The superseded 64-byte shape is [`decode_legacy_cx1`]'s, and no
/// SERVICE registers one any more.
pub fn decode_cx1(value: &str) -> Option<Cx1> {
    let bytes: [u8; 65] = decode_fixed("cx", value)?;
    let mut chain_code = [0u8; 32];
    let mut pubkey = [0u8; 33];
    chain_code.copy_from_slice(&bytes[..32]);
    pubkey.copy_from_slice(&bytes[32..]);
    PublicKey::from_byte_array_compressed(pubkey).ok()?;
    Some(Cx1 { chain_code, pubkey })
}

pub fn is_cx1(value: &str) -> bool {
    decode_cx1(value).is_some()
}

// ---- LUD-26: notes below a SERVICE's root ----
//
//   S            = m/139'/d1/d2/d3/d4      see crate::cash::derive_service_root
//   S/a'/0/i     wallet: every note the wallet mints, rotates or merges into, and a split's p1
//   S/a'/1/i     change: a split's p2
//   S/a'/2/n'    share n, handed out as its cx1
//   S/a'/2/n'/i  note i of share n, picked and credited by the SERVICE
//
// Plain BIP-32 all the way down: a note's secret key is the private key at
// its path and its `Q` is `x(sk·G)`, so any BIP-32 library derives the same
// tree, and a SERVICE holding a share's `cx1` derives that share's notes
// with CKDpub alone. Accounts and shares are hardened, so no account's or
// share's keys can be derived from another's; note indices are not, and are
// below 2^31.

/// Every note the wallet mints, rotates or merges into, and a split's `p1`.
pub const CHAIN_WALLET: u32 = 0;
/// A split's change `p2`.
pub const CHAIN_CHANGE: u32 = 1;
/// The shares, each exported as a `cx1`.
pub const CHAIN_SHARE: u32 = 2;

const HARDENED: u32 = 0x8000_0000;

/// Where a note sits below a SERVICE's root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotePath {
    /// `S/account'/0/index`
    Wallet { account: u32, index: u32 },
    /// `S/account'/1/index`
    Change { account: u32, index: u32 },
    /// `S/account'/2/share'/index`. Only a SERVICE picks these indices; a
    /// wallet never names one as a resulting note itself.
    Share {
        account: u32,
        share: u32,
        index: u32,
    },
}

fn below_hardened(value: u32, what: &str) -> Result<u32> {
    if value >= HARDENED {
        return Err(Error::Protocol(format!("{what} {value} is not below 2^31")));
    }
    Ok(value)
}

impl NotePath {
    /// The BIP-32 indices below `S`, hardened ones included.
    pub fn indices(&self) -> Result<Vec<u32>> {
        let (account, middle, index) = match *self {
            Self::Wallet { account, index } => (account, vec![CHAIN_WALLET], index),
            Self::Change { account, index } => (account, vec![CHAIN_CHANGE], index),
            Self::Share {
                account,
                share,
                index,
            } => (
                account,
                vec![CHAIN_SHARE, below_hardened(share, "a share")? + HARDENED],
                index,
            ),
        };
        let mut out = vec![below_hardened(account, "an account")? + HARDENED];
        out.extend(middle);
        out.push(below_hardened(index, "a note index")?);
        Ok(out)
    }
}

/// A note's keys. Bearer material: the secret key spends the note.
#[derive(Clone, PartialEq, Eq)]
pub struct NoteKey {
    pub secret_key: [u8; 32],
    /// Compressed, so its `y` parity is visible: a BIP-340 signer negates
    /// the secret key when it is odd.
    pub pubkey: [u8; 33],
    /// `Q = x(pubkey)`, the note itself.
    pub output_key: [u8; 32],
}

impl std::fmt::Debug for NoteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoteKey")
            .field("secret_key", &"redacted")
            .field("output_key", &hex::encode(self.output_key))
            .finish()
    }
}

impl Drop for NoteKey {
    fn drop(&mut self) {
        self.secret_key.fill(0);
    }
}

/// The note at `path` below `service_root`
/// ([`crate::cash::derive_service_root`]).
pub fn derive_note_key(service_root: &CashNode, path: NotePath) -> Result<NoteKey> {
    let mut node = service_root.clone();
    for index in path.indices()? {
        node = derive_cash_child(&node, index)?;
    }
    let pubkey = cash_node_public_key(&node)?;
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&pubkey[1..]);
    Ok(NoteKey {
        secret_key: node.private_key,
        pubkey,
        output_key,
    })
}

/// `S/account'/2/share'`, the node behind a share's `cx1`. Bearer material
/// for every note on the share: hand out [`cash_node_to_cx1`] of it, and
/// sign its registration with its own key ([`crate::sign_address_proof`]).
pub fn derive_share_node(service_root: &CashNode, account: u32, share: u32) -> Result<CashNode> {
    let mut node = derive_cash_child(
        service_root,
        below_hardened(account, "an account")? + HARDENED,
    )?;
    node = derive_cash_child(&node, CHAIN_SHARE)?;
    derive_cash_child(&node, below_hardened(share, "a share")? + HARDENED)
}

/// A share node's `cx1`.
pub fn cash_node_to_cx1(node: &CashNode) -> Result<Cx1> {
    Ok(Cx1 {
        chain_code: node.chain_code,
        pubkey: cash_node_public_key(node)?,
    })
}

/// `Q` of note `index` on the share `cx1` exports: CKDpub, no private key
/// anywhere, which is what lets a SERVICE credit a registered share's next
/// note. A hardened index is refused, and an unusable one (~2^-127) is an
/// error: use the next.
pub fn derive_note_pubkey(cx1: &Cx1, index: u32) -> Result<[u8; 32]> {
    let (pubkey, _) = derive_cash_child_pub(&cx1.pubkey, &cx1.chain_code, index)?;
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&pubkey[1..]);
    Ok(output_key)
}

// ---- superseded: the per-note tweak ----
//
// Before LUD-26 (luds a6c4652), note keys were tweaked off one branch node,
// m/139'/d1/d2/d3/d4 over the host as stored (port included), and a `cx1`
// was the 64-byte `x(P) || chainCode`:
//
//   t    = tagged_hash("LNURLcash/derive", P || chainCode || ser32(purpose) || ser32(i))
//   pk_i = x(lift_x(P) + t*G)
//   sk_i = ((P has even y ? p : n - p) + t) mod n
//
// purpose 0 was the wallet's own notes, 1 a split's change and 2 the
// Lightning Address rail (luds 50d740a); before purposes (luds 6e865b1)
// there was no ser32(purpose) at all. Notes minted under either are still
// money, so a wallet derives them here to find and sweep them into LUD-26
// keys. Nothing new is ever derived or registered this way.

/// Purpose 0 of the superseded tweak: the wallet's own notes.
pub const LEGACY_PURPOSE_WALLET: u32 = 0;
/// Purpose 1 of the superseded tweak: a split's change.
pub const LEGACY_PURPOSE_CHANGE: u32 = 1;
/// Purpose 2 of the superseded tweak: Lightning Address auto-mint and
/// internal transfer.
pub const LEGACY_PURPOSE_LIGHTNING_ADDRESS: u32 = 2;

/// A superseded 64-byte `cx1`, `x(P) || chainCode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyCx1 {
    pub pubkey_x_only: [u8; 32],
    pub chain_code: [u8; 32],
}

pub fn encode_legacy_cx1(cx1: &LegacyCx1) -> String {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&cx1.pubkey_x_only);
    bytes[32..].copy_from_slice(&cx1.chain_code);
    encode_bytes("cx", &bytes)
}

pub fn decode_legacy_cx1(value: &str) -> Option<LegacyCx1> {
    let bytes: [u8; 64] = decode_fixed("cx", value)?;
    let mut pubkey_x_only = [0u8; 32];
    let mut chain_code = [0u8; 32];
    pubkey_x_only.copy_from_slice(&bytes[..32]);
    chain_code.copy_from_slice(&bytes[32..]);
    Some(LegacyCx1 {
        pubkey_x_only,
        chain_code,
    })
}

/// The node the superseded schemes tweaked their notes off: `m/139'/d1..d4`
/// for `host` exactly as the wallet stored it, port included. Bearer
/// material for every note it ever held there under them.
pub fn legacy_branch_node(root: &CashNode, host: &str) -> Result<CashNode> {
    derive_cash_domain_node(root, host)
}

/// The superseded watch-only half of a [`legacy_branch_node`].
pub fn legacy_cx1_of(node: &CashNode) -> Result<LegacyCx1> {
    let key = SecretKey::from_secret_bytes(node.private_key)
        .map_err(|_| Error::Protocol("cash node holds an invalid private key".into()))?;
    let (pubkey, _parity) = key.x_only_public_key();
    Ok(LegacyCx1 {
        pubkey_x_only: pubkey.to_byte_array(),
        chain_code: node.chain_code,
    })
}

const NOTE_DERIVE_TAG: &str = "LNURLcash/derive";

fn unusable(index: u32) -> Error {
    Error::Protocol(format!(
        "note index {index} is unusable on this branch - use the next index"
    ))
}

// `purpose` None is the pre-purpose scheme.
fn tweak_for(
    pubkey_x_only: &[u8; 32],
    chain_code: &[u8; 32],
    purpose: Option<u32>,
    index: u32,
) -> Result<Scalar> {
    let purpose = purpose.map(u32::to_be_bytes);
    let index_bytes = index.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![pubkey_x_only, chain_code];
    if let Some(purpose) = &purpose {
        parts.push(purpose);
    }
    parts.push(&index_bytes);
    let t = tagged_hash(NOTE_DERIVE_TAG, &parts);
    Scalar::from_be_bytes(reduce_mod_n(t)).map_err(|_| unusable(index))
}

// t mod n, as the spec required and lnurl-wallet did (lnurl-mint refused
// t >= n instead; at ~2^-128 the two never meet). libsecp256k1 only takes a
// tweak already below n, so k256 reduces it first.
fn reduce_mod_n(t: [u8; 32]) -> [u8; 32] {
    use k256::elliptic_curve::ops::Reduce;
    <k256::Scalar as Reduce<k256::FieldBytes>>::reduce(&t.into())
        .to_bytes()
        .into()
}

/// A note key under the superseded tweak, from the legacy `cx1` half alone.
/// `purpose` is `None` for the scheme before purposes existed.
pub fn legacy_derive_note_pubkey(
    cx1: &LegacyCx1,
    purpose: Option<u32>,
    index: u32,
) -> Result<[u8; 32]> {
    let branch = XOnlyPublicKey::from_byte_array(cx1.pubkey_x_only)
        .map_err(|_| Error::Protocol("a branch key is not an x-only secp256k1 point".into()))?;
    let tweak = tweak_for(&cx1.pubkey_x_only, &cx1.chain_code, purpose, index)?;
    // lift_x(P) + t*G, refusing the point at infinity
    let (note, _parity) = branch.add_tweak(&tweak).map_err(|_| unusable(index))?;
    Ok(note.to_byte_array())
}

/// The secret key behind [`legacy_derive_note_pubkey`], from a
/// [`legacy_branch_node`]. The branch key's own point may have odd y, and a
/// legacy `cx1` only carried x, which names the even-y point, so the key is
/// negated first; libsecp256k1's x-only keypair tweak does exactly that, and
/// refuses a zero result.
pub fn legacy_derive_note_secret_key(
    node: &CashNode,
    purpose: Option<u32>,
    index: u32,
) -> Result<[u8; 32]> {
    let branch = Keypair::from_secret_bytes(node.private_key).map_err(|_| {
        Error::Protocol("a branch private key is a 32-byte scalar in [1, n)".into())
    })?;
    let (branch_x, _parity) = branch.x_only_public_key();
    let tweak = tweak_for(&branch_x.to_byte_array(), &node.chain_code, purpose, index)?;
    let note = branch
        .add_xonly_tweak(&tweak)
        .map_err(|_| unusable(index))?;
    Ok(note.to_secret_bytes())
}

// ---- key-path spends ----
//
//   sig = BIP340.Sign(sk, key_path_sighash(Q, domain), aux_rand = 0^32)
//   ck1 = bech32m("ck", Q || sig)
//
// The sighash is BIP-341's for input 0 of the canonical spend transaction
// (see [`crate::spend`]), so a mint can hand the spend to an off-the-shelf
// taproot verifier, and a signature one mint has seen can never be replayed
// at another. Nothing in it depends on value or time, and the auxiliary input
// is fixed, so a key has exactly one `ck1` per mint and re-deriving the key
// on recovery reproduces it byte for byte.
//
// Three older schemes are read and never produced, since notes minted under
// them are still money and reference mints still accept them: Schnorr over
// sha256("LNURLcash") (2026-09-16, luds#6de59b2), Schnorr over the raw
// 9-byte "LNURLcash", and before that a 65-byte recoverable ECDSA signature
// with no key alongside it.

const LEGACY_OWNERSHIP_MESSAGE: &str = "LNURLcash";

fn legacy_ownership_digest() -> [u8; 32] {
    Sha256::digest(LEGACY_OWNERSHIP_MESSAGE.as_bytes()).into()
}

/// The 96-byte `Q || sig` key-path spend of the note `x(sk·G)` at `domain`:
/// the mint's domain, as a note URL, a mint URL or a bare host (see
/// [`spend_domain_of`]). Encode it with [`encode_ck1`] for the wire: that
/// string spends the note, so it is as secret as the key.
///
/// `Q` is the key as is, with no BIP-86 tweak. To spend a note whose `Q`
/// commits to a script tree by its key path, pass the tweaked key from
/// [`crate::spend::taproot_tweak_secret_key`].
pub fn sign_note_ownership(secret_key: &[u8; 32], domain: &str) -> Result<[u8; 96]> {
    let key = SigningKey::from_slice(secret_key)
        .map_err(|_| Error::Protocol("a note secret key is a 32-byte scalar in [1, n)".into()))?;
    let domain = spend_domain_of(domain).ok_or_else(|| {
        Error::Protocol("a ck1 is signed for a mint's domain, and that names none".into())
    })?;
    let output_key: [u8; 32] = key.verifying_key().to_bytes().into();
    let signature = key
        .sign_raw(&key_path_sighash(&output_key, &domain), &[0u8; 32])
        .map_err(|_| Error::Protocol("could not sign the key-path spend".into()))?;
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(&output_key);
    out[32..].copy_from_slice(signature.to_bytes().as_ref());
    Ok(out)
}

/// A verified `ck1` payload's note, and whether it was signed under a
/// deprecated scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteOwner {
    pub pubkey_x_only: [u8; 32],
    /// Signed over a fixed message rather than the key-path sighash, or the
    /// 65-byte recoverable shape. Still spendable at mints that accept it;
    /// a holder should rotate it into a current `ck1`.
    pub legacy: bool,
}

/// The key a pre-Schnorr 65-byte `ck1` recovers to. Recovering is its only
/// check: any signature recovers to some key.
pub(crate) fn legacy_ck1_key(signature: &[u8]) -> Option<[u8; 32]> {
    let signature: &[u8; 65] = signature.try_into().ok()?;
    let recovery = RecoveryId::try_from(i32::from(signature[64])).ok()?;
    let signature = RecoverableSignature::from_compact(&signature[..64], recovery).ok()?;
    let key = signature
        .recover_ecdsa(Message::from_digest(lightning_signed_digest(
            LEGACY_OWNERSHIP_MESSAGE,
        )))
        .ok()?;
    Some(key.x_only_public_key().0.to_byte_array())
}

/// Verify a `ck1` payload against the mint at `domain` (a note URL, a mint
/// URL or a bare host) and return its note. `None` for an invalid proof, one
/// signed for another mint, or the wrong length.
///
/// A 96-byte payload is checked against the key-path sighash for `domain`
/// first, then against the fixed messages older `ck1`s signed, which are
/// reported as `legacy`. A 65-byte one is the pre-Schnorr shape, recovered
/// rather than verified, and always legacy.
pub fn recover_note_ownership_pubkey(payload: &[u8], domain: &str) -> Option<NoteOwner> {
    if payload.len() == 65 {
        return legacy_ck1_key(payload).map(|pubkey_x_only| NoteOwner {
            pubkey_x_only,
            legacy: true,
        });
    }
    if payload.len() != 96 {
        return None;
    }
    let pubkey_x_only: [u8; 32] = payload[..32].try_into().ok()?;
    let key = VerifyingKey::from_slice(&pubkey_x_only).ok()?;
    let signature = SchnorrSignature::try_from(&payload[32..]).ok()?;
    let verifies = |message: &[u8]| key.verify_raw(message, &signature).is_ok();
    if spend_domain_of(domain)
        .is_some_and(|domain| verifies(&key_path_sighash(&pubkey_x_only, &domain)))
    {
        return Some(NoteOwner {
            pubkey_x_only,
            legacy: false,
        });
    }
    (verifies(&legacy_ownership_digest()) || verifies(LEGACY_OWNERSHIP_MESSAGE.as_bytes()))
        .then_some(NoteOwner {
            pubkey_x_only,
            legacy: true,
        })
}

// ---- a note's k1, any kind ----

/// The id a SERVICE files a note under: `hex(Q)`, for every kind of spend. A
/// 64-hex preimage names its bearer note's `Q`, a `ck1` carries `Q`, a `cw1`'s
/// control block commits to it, and a legacy 65-byte `ck1` recovers to it.
/// `None` for anything that is no spend.
///
/// This names the note; it does not say the spend opens it. A `ck1` states
/// its `Q` in plain sight, so anyone can write one for any note: whether it
/// opens the note needs the mint's domain (see [`crate::spend::check_spend`]).
/// Compare notes by this, never by the spend's string: one note has many
/// valid spends.
///
/// Before LUD-25 keyed every note by `Q`, a bearer note's id was its hash
/// `sha256(k1)`. That is now only its `cp1` short form, from
/// [`crate::secrets::hash_k1`].
pub fn note_id_of(k1: &str) -> Option<String> {
    decode_spend(k1).map(|spend| hex::encode(spend.output_key()))
}

/// What to look a note up by without disclosing it, for `?p=`: a bearer
/// note's hash `h` for a 64-hex preimage, since every mint that ever took a
/// hash lookup understands it, and `cp1<Q>` for any other spend. Pass it to
/// [`crate::note::build_note_info_url_by_hash`].
pub fn note_lookup_of(k1: &str) -> Option<String> {
    let value = k1.trim();
    if is_preimage(value) {
        return crate::secrets::hash_k1(&value.to_ascii_lowercase()).ok();
    }
    decode_spend(value).map(|spend| encode_cp1(&spend.output_key()))
}

// ---- a tree rooted in a Nostr key ----
//
// An extension, not LUD-25/26. A lightning address on a Nostr-native mint
// belongs to an npub, and a holder with no BIP-39 words (a hardware signer
// that keeps only its identity key, or a wallet that never made any) can
// still be paid to keys of its own:
//
//   seed = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
//
// then LUD-26's tree from that seed, unchanged. The identity key rebuilds
// every note on it, so whoever can restore that key can recover the notes,
// with or without the device that received them. A mint sees an ordinary
// `cx1` either way.

pub const NOSTR_CASH_SEED_LABEL: &str = "LNURLcash/nostr-seed";

/// Bearer material: the seed every note on the identity's tree grows from.
pub fn derive_nostr_cash_seed(secret_key: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret_key).expect("HMAC takes a key of any length");
    mac.update(NOSTR_CASH_SEED_LABEL.as_bytes());
    mac.finalize().into_bytes().into()
}

/// One mint's LUD-26 root `S` for a Nostr identity. Bearer material, like
/// any SERVICE root: hand out a share's `cx1`.
pub fn derive_nostr_service_root(secret_key: &[u8; 32], domain: &str) -> Result<CashNode> {
    let mut seed = derive_nostr_cash_seed(secret_key);
    let root = derive_cash_root(&seed);
    seed.fill(0);
    derive_service_root(&root?, domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cash::cash_node_to_hex;
    use crate::spend::bearer_cw1;
    use bech32::primitives::decode::CheckedHrpstring;
    use bech32::{Checksum, Fe32, Fe32IterExt, Hrp};

    const SEED: [u8; 32] = [0x42; 32];
    const DOMAIN: &str = "mint.example";

    fn words_of(value: &str) -> (Hrp, Vec<Fe32>) {
        let checked = CheckedHrpstring::new::<Bech32m>(value).expect("a valid string");
        (checked.hrp(), checked.fe32_iter().collect())
    }

    fn encode_words<Ck: Checksum>(hrp: &Hrp, words: Vec<Fe32>) -> String {
        words.into_iter().with_checksum::<Ck>(hrp).chars().collect()
    }

    fn samples() -> [(&'static str, String); 5] {
        let ownership = sign_note_ownership(&[0x11; 32], DOMAIN).expect("a valid key");
        let pubkey = recover_note_ownership_pubkey(&ownership, DOMAIN)
            .expect("verifies")
            .pubkey_x_only;
        [
            ("cp", encode_cp1(&pubkey)),
            ("ck", encode_ck1(&ownership)),
            (
                "cw",
                encode_cw1(&bearer_cw1(&[0x44; 32]).expect("a cw1")).expect("encodes"),
            ),
            ("cs", {
                let mut signature = [0x33; 65];
                signature[64] = 1;
                encode_cs1_with_amount(21_000, &signature)
            }),
            (
                "cx",
                encode_cx1(&Cx1 {
                    chain_code: [0x22; 32],
                    pubkey: PublicKey::from_secret_key(
                        &SecretKey::from_secret_bytes([0x11; 32]).expect("a key"),
                    )
                    .serialize(),
                }),
            ),
        ]
    }

    fn decodes(hrp: &str, value: &str) -> bool {
        match hrp {
            "cp" => is_cp1(value),
            "ck" => is_ck1(value),
            "cw" => is_cw1(value),
            "cs" => is_cs1_with_amount(value),
            "cx" => is_cx1(value),
            _ => unreachable!(),
        }
    }

    #[test]
    fn every_type_round_trips_and_runs_past_ninety_characters() {
        for (hrp, value) in samples() {
            assert!(decodes(hrp, &value), "{value}");
            if hrp != "cp" {
                assert!(value.len() > 90, "{hrp}: no limit to hide behind");
            }
        }
    }

    #[test]
    fn all_uppercase_is_the_same_string_and_mixed_case_is_not() {
        for (hrp, value) in samples() {
            assert!(decodes(hrp, &value.to_ascii_uppercase()), "{hrp}");
            let mut mixed = value.clone();
            mixed.replace_range(..3, &value[..3].to_ascii_uppercase());
            assert!(!decodes(hrp, &mixed), "{hrp}: mixed case");
        }
    }

    #[test]
    fn a_bech32_checksum_is_not_a_bech32m_one() {
        for (hrp, value) in samples() {
            let (prefix, words) = words_of(&value);
            let classic = encode_words::<long_bech32::Bech32>(&prefix, words);
            assert!(!decodes(hrp, &classic), "{hrp}");
        }
    }

    #[test]
    fn non_zero_padding_is_refused() {
        // Every payload here leaves spare bits in the last five-bit group,
        // which must be zero, except the 65-byte cs1 and cx1, which fill
        // their groups exactly.
        for (hrp, value) in samples() {
            if hrp == "cs" || hrp == "cx" {
                continue;
            }
            let (prefix, mut words) = words_of(&value);
            let last = words.len() - 1;
            assert_eq!(
                words[last].to_u8() & 1,
                0,
                "{hrp}: a valid string pads with zero"
            );
            words[last] = Fe32::try_from(words[last].to_u8() | 1).expect("five bits");
            let forged = encode_words::<Bech32m>(&prefix, words);
            assert!(!decodes(hrp, &forged), "{hrp}: padding");
        }
    }

    #[test]
    fn decoders_refuse_hostile_input_without_panicking() {
        let long = format!("cp1{}", "q".repeat(10_000));
        let long_cw = format!("cw1{}", "q".repeat(10_000));
        for value in [
            "",
            "1",
            "cp1",
            "cp1q",
            "cw1",
            "ck1\u{e9}\u{e9}\u{e9}",
            "\u{1f4b8}1qqqqqq",
            "cp1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            long.as_str(),
            long_cw.as_str(),
        ] {
            for hrp in ["cp", "ck", "cw", "cs", "cx"] {
                assert!(!decodes(hrp, value), "{hrp}: {value:?}");
            }
            assert_eq!(note_id_of(value), None);
            assert_eq!(note_lookup_of(value), None);
        }
        assert_eq!(recover_note_ownership_pubkey(&[], DOMAIN), None);
        assert_eq!(recover_note_ownership_pubkey(&[0xff; 96], DOMAIN), None);
    }

    #[test]
    fn tells_the_five_types_apart() {
        let samples = samples();
        for (hrp, value) in &samples {
            for (other, _) in &samples {
                assert_eq!(decodes(other, value), hrp == other, "{other} of {value}");
            }
        }
        let k1 = "11".repeat(32);
        for hrp in ["cp", "ck", "cw", "cs", "cx"] {
            assert!(!decodes(hrp, &k1), "a plain hex k1 is never a {hrp}1");
        }
    }

    #[test]
    fn a_cp1_off_the_curve_names_no_note() {
        // x = 5 is not the x coordinate of any point
        let mut x = [0u8; 32];
        x[31] = 5;
        let off_curve = encode_cp1(&x);
        assert_eq!(decode_cp1(&off_curve), None);
        assert!(!is_cp1(&off_curve));
    }

    #[test]
    fn a_ck1_opens_its_note_at_its_own_domain_only() {
        let payload = sign_note_ownership(&[0x11; 32], DOMAIN).expect("a valid key");
        let owner = recover_note_ownership_pubkey(&payload, DOMAIN).expect("verifies");
        assert!(!owner.legacy);
        // the same string at a URL on the same host, in any casing
        for same in [
            "https://MINT.example/w?k1=00",
            "lnurlw://mint.example:443/w",
        ] {
            assert_eq!(
                recover_note_ownership_pubkey(&payload, same),
                Some(owner),
                "{same}"
            );
        }
        for other in ["moneyer.dev", "mint.example.com", "", "https://"] {
            assert_eq!(
                recover_note_ownership_pubkey(&payload, other),
                None,
                "{other:?}"
            );
        }
        assert!(sign_note_ownership(&[0x11; 32], "").is_err());
    }

    #[test]
    fn a_truncated_or_corrupted_signature_is_not_the_note() {
        let signature = sign_note_ownership(&[0x11; 32], DOMAIN).expect("a valid key");
        let owner = recover_note_ownership_pubkey(&signature, DOMAIN);
        assert_eq!(
            recover_note_ownership_pubkey(&signature[..95], DOMAIN),
            None
        );
        let mut corrupted = signature;
        corrupted[10] ^= 0xff;
        assert_ne!(recover_note_ownership_pubkey(&corrupted, DOMAIN), owner);
    }

    #[test]
    fn one_key_reproduces_one_ck1_per_domain() {
        let a = sign_note_ownership(&[0x11; 32], DOMAIN).expect("a valid key");
        let b = sign_note_ownership(&[0x11; 32], DOMAIN).expect("a valid key");
        assert_eq!(a, b);
        assert_eq!(encode_ck1(&a), encode_ck1(&b));
        let elsewhere = sign_note_ownership(&[0x11; 32], "moneyer.dev").expect("a valid key");
        assert_eq!(a[..32], elsewhere[..32]);
        assert_ne!(a[32..], elsewhere[32..]);
    }

    #[test]
    fn a_legacy_ck1_stays_readable_for_rotation() {
        let secret = SecretKey::from_secret_bytes([0x11; 32]).expect("a valid key");
        let signature = RecoverableSignature::sign_ecdsa_recoverable(
            Message::from_digest(lightning_signed_digest(LEGACY_OWNERSHIP_MESSAGE)),
            &secret,
        );
        let (recovery, compact) = signature.serialize_compact();
        let mut payload = [0u8; 65];
        payload[..64].copy_from_slice(&compact);
        payload[64] = u8::from(recovery);
        let ck1 = encode_bytes("ck", &payload);
        let key = secret.x_only_public_key().0.to_byte_array();

        assert_eq!(decode_ck1(&ck1), Some(DecodedCk1::Legacy(payload)));
        assert!(is_ck1(&ck1));
        assert_eq!(note_id_of(&ck1), Some(hex::encode(key)));
        assert_eq!(
            recover_note_ownership_pubkey(&payload, DOMAIN),
            Some(NoteOwner {
                pubkey_x_only: key,
                legacy: true
            })
        );
    }

    #[test]
    fn a_fixed_message_ck1_stays_readable_for_rotation() {
        // Before every spend moved onto the sighash, a ck1 signed the fixed
        // message: its sha256 from 2026-09-16, and the raw 9 bytes before
        // that. sign_note_ownership never produces either, but a note held
        // under one must stay redeemable, at any domain, since neither names
        // one.
        let key = SigningKey::from_slice(&[0x22; 32]).expect("a valid key");
        let expected: [u8; 32] = key.verifying_key().to_bytes().into();
        for message in [
            legacy_ownership_digest().to_vec(),
            LEGACY_OWNERSHIP_MESSAGE.as_bytes().to_vec(),
        ] {
            let signature = key.sign_raw(&message, &[0u8; 32]).expect("signs");
            let mut payload = [0u8; 96];
            payload[..32].copy_from_slice(&expected);
            payload[32..].copy_from_slice(signature.to_bytes().as_ref());
            for domain in [DOMAIN, "moneyer.dev"] {
                assert_eq!(
                    recover_note_ownership_pubkey(&payload, domain),
                    Some(NoteOwner {
                        pubkey_x_only: expected,
                        legacy: true
                    })
                );
            }
        }
    }

    #[test]
    fn a_cw1_must_consume_its_payload_and_commit_to_a_key() {
        let cw1 = bearer_cw1(&[0x44; 32]).expect("a cw1");
        let encoded = encode_cw1(&cw1).expect("encodes");
        assert_eq!(decode_cw1(&encoded), Some(cw1.clone()));

        let mut no_control = cw1.clone();
        no_control.control_block = Vec::new();
        no_control.witness = Vec::new();
        assert_eq!(decode_cw1(&encode_cw1(&no_control).expect("encodes")), None);

        let mut wrong_parity = cw1.clone();
        wrong_parity.control_block[0] ^= 1;
        assert_eq!(
            decode_cw1(&encode_cw1(&wrong_parity).expect("encodes")),
            None
        );

        let mut too_long = cw1;
        too_long.witness = vec![vec![0; 65_536]];
        assert!(encode_cw1(&too_long).is_err());
    }

    #[test]
    fn signing_refuses_a_key_outside_the_curve_order() {
        assert!(sign_note_ownership(&[0; 32], DOMAIN).is_err());
        assert!(sign_note_ownership(&[0xff; 32], DOMAIN).is_err());
        let zero = CashNode {
            private_key: [0; 32],
            chain_code: [0; 32],
        };
        assert!(derive_note_key(
            &zero,
            NotePath::Wallet {
                account: 0,
                index: 0
            }
        )
        .is_err());
        assert!(legacy_derive_note_secret_key(&zero, Some(0), 0).is_err());
        // above the field prime, so not an x coordinate at all
        let off_curve = LegacyCx1 {
            pubkey_x_only: [0xff; 32],
            chain_code: [0; 32],
        };
        assert!(legacy_derive_note_pubkey(&off_curve, Some(0), 0).is_err());
    }

    #[test]
    fn a_cx1_is_refused_unless_its_key_is_a_compressed_point() {
        let mut bytes = [0u8; 65];
        bytes[32] = 0x02;
        bytes[33..].fill(0xff);
        assert_eq!(decode_cx1(&encode_bytes("cx", &bytes)), None);
        bytes[32] = 0x04;
        assert_eq!(decode_cx1(&encode_bytes("cx", &bytes)), None);
        // the superseded 64-byte shape is not a cx1, only a legacy one
        let legacy = encode_legacy_cx1(&LegacyCx1 {
            pubkey_x_only: [0x22; 32],
            chain_code: [0x33; 32],
        });
        assert_eq!(decode_cx1(&legacy), None);
        assert!(decode_legacy_cx1(&legacy).is_some());
    }

    #[test]
    fn the_service_root_hashes_the_domain_without_its_port() {
        let root = derive_cash_root(&SEED).expect("root");
        let service = derive_service_root(&root, "https://MINT.example:3338/w").expect("root S");
        let bare = derive_cash_domain_node(&root, "mint.example").expect("domain node");
        let as_stored = derive_cash_domain_node(&root, "mint.example:3338").expect("legacy node");
        assert_eq!(cash_node_to_hex(&service), cash_node_to_hex(&bare));
        assert_ne!(cash_node_to_hex(&service), cash_node_to_hex(&as_stored));
    }

    #[test]
    fn a_watcher_and_the_holder_agree_on_every_share_note() {
        let root = derive_cash_root(&SEED).expect("root");
        let service = derive_service_root(&root, DOMAIN).expect("root S");
        let cx1 =
            cash_node_to_cx1(&derive_share_node(&service, 0, 0).expect("share")).expect("cx1");
        for index in [0, 1, 0x7fff_ffff] {
            let pubkey = derive_note_pubkey(&cx1, index).expect("pubkey");
            let key = derive_note_key(
                &service,
                NotePath::Share {
                    account: 0,
                    share: 0,
                    index,
                },
            )
            .expect("note key");
            assert_eq!(key.output_key, pubkey, "{index}");
            let signature = sign_note_ownership(&key.secret_key, DOMAIN).expect("signs");
            assert_eq!(
                recover_note_ownership_pubkey(&signature, DOMAIN).map(|owner| owner.pubkey_x_only),
                Some(pubkey),
                "{index}"
            );
        }
        assert!(derive_note_pubkey(&cx1, 0x8000_0000).is_err());
    }

    #[test]
    fn chains_accounts_and_shares_never_share_a_key() {
        let root = derive_cash_root(&SEED).expect("root");
        let service = derive_service_root(&root, DOMAIN).expect("root S");
        let keys: Vec<[u8; 32]> = [
            NotePath::Wallet {
                account: 0,
                index: 0,
            },
            NotePath::Change {
                account: 0,
                index: 0,
            },
            NotePath::Wallet {
                account: 1,
                index: 0,
            },
            NotePath::Share {
                account: 0,
                share: 0,
                index: 0,
            },
            NotePath::Share {
                account: 0,
                share: 1,
                index: 0,
            },
        ]
        .into_iter()
        .map(|path| derive_note_key(&service, path).expect("key").output_key)
        .collect();
        for (i, a) in keys.iter().enumerate() {
            assert!(keys[i + 1..].iter().all(|b| a != b), "{i}");
        }
    }

    #[test]
    fn a_legacy_watcher_and_holder_agree_on_every_note_key() {
        let root = derive_cash_root(&SEED).expect("root");
        let node = legacy_branch_node(&root, "mint.example").expect("legacy node");
        let cx1 = legacy_cx1_of(&node).expect("legacy cx1");
        for purpose in [
            None,
            Some(LEGACY_PURPOSE_WALLET),
            Some(LEGACY_PURPOSE_LIGHTNING_ADDRESS),
        ] {
            for index in [0, 1, 0x8000_0000, u32::MAX] {
                let pubkey = legacy_derive_note_pubkey(&cx1, purpose, index).expect("pubkey");
                let secret = legacy_derive_note_secret_key(&node, purpose, index).expect("secret");
                let signature = sign_note_ownership(&secret, DOMAIN).expect("signs");
                assert_eq!(
                    recover_note_ownership_pubkey(&signature, DOMAIN)
                        .map(|owner| owner.pubkey_x_only),
                    Some(pubkey),
                    "{purpose:?}/{index}"
                );
            }
        }
        assert_ne!(
            legacy_derive_note_pubkey(&cx1, None, 0).expect("pre-purpose"),
            legacy_derive_note_pubkey(&cx1, Some(LEGACY_PURPOSE_WALLET), 0).expect("purpose 0")
        );
    }

    #[test]
    fn a_nostr_tree_is_lud26_from_its_seed() {
        let identity = [0x07; 32];
        let seed = derive_nostr_cash_seed(&identity);
        let expected = derive_service_root(&derive_cash_root(&seed).expect("root"), "moneyer.dev")
            .expect("service root");
        let root = derive_nostr_service_root(&identity, "moneyer.dev").expect("nostr root");
        assert_eq!(cash_node_to_hex(&root), cash_node_to_hex(&expected));
    }

    #[test]
    fn a_tweak_at_or_above_n_is_reduced_mod_n() {
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut above = N;
        above[31] += 5;
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(reduce_mod_n(N), [0u8; 32]);
        assert_eq!(reduce_mod_n(above), five);
        assert_eq!(reduce_mod_n(five), five);
        // 2^256 - 1 - n, what the all-ones hash reduces to
        let mut top = [0u8; 32];
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let d = 0xffu16.wrapping_sub(u16::from(N[i])).wrapping_sub(borrow);
            top[i] = d as u8;
            borrow = u16::from(d > 0xff);
        }
        assert_eq!(reduce_mod_n([0xff; 32]), top);
    }
}
