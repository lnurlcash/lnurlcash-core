# lnurlcash-core

LNURLcash ([LUD-25 draft](https://github.com/lnurl/luds/pull/301)) bearer
notes: the money-critical logic, in one place, with bindings for other
languages.

```toml
[dependencies]
lnurlcash-core = "0.2"
```

Early `0.x`, tracking a **draft** spec. Pin an exact version.

## Why a Rust core

The LNURLcash wire protocol is small enough to implement in an afternoon,
which is exactly the problem: the protocol is easy and the discipline is not.
Ambiguous mutations, melt semantics, who generates a replacement secret, which
end of a signature carries the recovery id — get any of those wrong and it
works perfectly until it costs somebody their money.

This crate exists so there is one audited implementation of that discipline,
and so the mobile bindings are a wrapper over it rather than a fifth
hand-written port drifting away from a draft spec.

## Layout

**`protocol`** has no I/O in it. Each operation is a `Request` — a URL to GET,
plus the fresh secrets that must survive if the answer is lost — paired with a
`parse_*` function for what comes back. A caller with its own HTTP stack needs
nothing else.

**`client`** (feature `client`) is a thin reqwest loop over exactly that. Off
by default: the core is pure, and a caller with its own stack should not
compile one it will not use.

**`ffi`** (feature `ffi`) exports the pure half through UniFFI, for Kotlin and
Swift. Deliberately no async across the boundary — see below.

## Usage

```rust
use lnurlcash_core::{protocol, verify_note_signature};

// no HTTP in the core: build, GET it yourself, parse
let request = protocol::note_info_request(note_url)?;
let body: serde_json::Value = your_http_get(&request.url)?;
let info = protocol::parse_note_info(&body, note_url, protocol::Policy::default())?;

println!("{} msat", info.max_withdrawable);
```

With the `client` feature:

```rust
use lnurlcash_core::client::{Client, NoteFate};

let client = Client::new();
let info = client.fetch_note_info(note_url).await?;
let fresh = client.rotate_note(&info.callback, &info.k1).await?;
```

## The four things that will cost you money

**1. Never let the service generate a replacement secret.** On rotate, split
and merge the *wallet* draws a fresh 32 bytes and discloses only
`sha256(secret)` as `p1`. A service-issued replacement has, structurally, been
seen by that service, so a "rotate" that accepts one closes no exposure at
all.

**2. A failed mutation is not a failure.** If a rotate times out, the service
may already have burned the input and minted the output, and the fresh secret
in your process is the only copy of that money.

```rust
match client.rotate_note(&callback, &k1).await {
    Ok(rotated) => { /* ... */ }
    Err(err) if err.is_ambiguous() => {
        save(err.new_secrets())?;                    // first. always.
        match client.probe_burned_note(&note_url).await {
            NoteFate::Live => {}      // nothing landed; the saved secrets are worthless
            NoteFate::Gone => {}      // the burn landed; the saved secrets ARE the note
            NoteFate::Unknown => {}   // no information - keep everything
        }
    }
    Err(err) => return Err(err),
}
```

`Error::RequestRefused` is the opposite and safe: nothing left the process.
`Error::is_ambiguous()` and `Error::is_definitive()` are the two questions
worth asking about any failure here.

A mutation whose answer the transport lost is re-sent rather than given up on.
LUD-25 requires a service to answer a byte-identical rotate, split or merge
with the success it already returned, so the retry usually completes the
operation and the caller never sees an error at all
(`ClientConfig::mutation_retries`, default 1). Never a melt, which carries
`pr`, is paid asynchronously and has no replay guarantee; and never a
definitive refusal, which is the service's considered answer.

**2b. A certificate proves issuance, not that your spend opens the note.**
A mint certifies every note with a `cs1` over its public key `Q` and the
amount. `Q` and the certificate are both public, so anyone can pair them with
a `ck1` whose signature opens nothing. `check_note` (and
`verify_note_signature`, its yes-or-no) needs the mint's domain for exactly
that reason: it checks the spend opens `Q` there as well as the certificate.
`check_note_url` reads everything off a certified note URL.

A `cp1` output is owed its `cs1` whatever the policy says: without it
`parse_mutation` raises `Error::Unverifiable`, which **carries the fresh
secrets**, because the mutation landed and the note is real. A bearer output
named by its hash is certified by a mint with a signer and may come back
uncertified from one without; `Policy { require_signatures: true, ..Policy::default() }`
refuses that. Hand `parse_mutation` the request's `outputs` so it knows which
kind it asked for.

`parse_note_info` refuses a `withdrawRequest` without a valid `mintPubkey`;
`Policy { require_mint_pubkey: false, ..Policy::default() }` admits a mint
that publishes none, knowing nothing it issues can then be checked offline.

**3. A melt's `OK` means "in flight", not "spent".** The service pays
asynchronously and only burns the note once the payment settles, restoring it
if the payment fails. A failed melt is never reported back through the
callback — only observed as the note becoming spendable again.
`Error::NotePending` means retry, never spent.

**4. Rotate the instant you claim a minted note.** The preimage that mints a
note is generated by the service, and if it serves LUD-21 `verify`, anyone who
saw the unpaid invoice can poll for it. First rotater wins.

## Bindings

```bash
cargo build --release --features ffi
cargo run --features bindgen --bin uniffi-bindgen -- \
  generate --library target/release/liblnurlcash_core.dylib \
  --language kotlin --out-dir bindings/kotlin
```

Swap `--language swift` for iOS.

Only the pure half crosses the boundary: request building, response parsing,
signature verification, note URLs, fee arithmetic. HTTP stays on the other
side, where a mobile app already has a stack it trusts and a concurrency model
it likes. Async over FFI is where these bindings usually turn painful, and
there is nothing to gain from it — the interesting part of LNURLcash is not the
GET, it is knowing what a response means and which secrets must survive a
failure. Both of those are pure functions.

[lnurlcash-kotlin](https://github.com/lnurlcash/lnurlcash-kotlin) wraps
the generated Kotlin in something idiomatic.

## Two things ports get wrong

Both are caught by the conformance vectors, and both are worth knowing if you
are porting this anywhere:

**The proportional fee term overflows.** `gross * ppm / 1_000_000` exceeds
`u64::MAX` at realistic amounts — 21M BTC is 2.1e15 msat, times 999_999 ppm is
about 2.1e21. It is computed split. A naive version passes every small test.

**Gross-up must be a binary search.** Estimate-then-walk is unbounded at a
99.9999% fee — roughly a million steps — so any guard on it returns a
non-minimal answer, and the *service* picks the fee.

## Every note is a taproot output key

LUD-25 (as of lnurl/luds `6e865b1`) makes every note a BIP-341 output key
`Q`, written `cp1<Q>`. A mint stores, burns and certifies it by `hex(Q)`, and
a spend opens it the way a taproot output is spent on chain:

```text
64 hex          a bearer note's preimage: the short form of its cw1
ck1<Q || sig>   key path: a BIP-340 signature by Q
cw1<...>        script path: a leaf, its control block, and its witness
```

A bearer note is the one-leaf hashlock `OP_SHA256 <h> OP_EQUAL` under
BIP-341's NUMS key, so it has no key path. Everything but the preimage follows
from `h`, which is why the bearer wire looks as it always did: 64 hex where a
`k1` goes is the preimage, and 64 hex where a `cp1` goes is `h`. Only its id
moved, from `sha256(k1)` to `hex(Q)`. `note_id_of(k1)` gives it for any spend.

Every signature signs the BIP-341 sighash of one canonical, never-broadcast
transaction whose prevout is `tagged_hash("LNURLcash/mint", domain)`, so a
spend one mint has seen can never be replayed at another. `domain` is the
mint's lowercase hostname, no scheme, no port: `spend_domain_of(note_url)`.
The transaction's shape never changes, so the sighash is built field by field
in `spend` with no Bitcoin library, graded against every intermediate of spec
vector 3.

`check_spend(k1, domain)` says whether a spend opens its note as a mint would
judge it: `Opens`, `OpensLegacy` (a `ck1` under a deprecated scheme mints
still accept: rotate it), `Unevaluated` (a script this crate does not run;
only the bearer hashlock is evaluated) or `Fails`. Time claims are the mint's
clock to judge; `check_time_claim` and `check_leaf` are the mint's rules, for
telling a holder what a mint will do.

## Seed-recoverable notes

LUD-25 specifies one seed derivation, and this crate implements it:

```
cashHashingKey   = m/139'/0
(d1, d2, d3, d4) = HMAC-SHA256(cashHashingKey, host)[0..16] as 4 uint32
domainNode       = m/139'/d1/d2/d3/d4
```

`d1..d4` are used **exactly as they fall**. BIP-32 reads any index `>= 2^31`
as hardened, so which of the four levels are hardened is decided by the mint's
own host name. Masking the top bit, or hardening all four, derives a different
tree and restores nothing, silently.

Bearer notes are not derived from the seed. The wallet draws plain
randomness, so a bearer note is only as recoverable as the wallet's backup of
its preimage. Seed recovery is what key-path notes are for: their keys hang
off this same domain node (see below).

`derive_cash_domain_node` is its own step because it is the unit a signer is
provisioned with. Whoever holds it can derive every note key held at that
mint: provisioning material, one mint's subtree, not the wallet.

`secrets::derive_note_root` / `derive_note_secret` are the pre-spec HMAC
scheme this project shipped before the draft had one. Not deprecated, because
notes minted under it are still money; just not what to mint under.

**The counter is half the backup.** A SERVICE must answer a lookup for a
burned note exactly as it answers one for a note it never issued, and a rotate
burns the index below, so a wallet that has rotated more than its gap limit
cannot find its own position by scanning. The per-host counter is not secret
(an index reveals nothing without the root), so back it up, and merge it
upwards only.

## Key-path notes

A key-path note's `Q` is the holder's own key, used as is with no BIP-86
tweak. The wallet keeps `sk`, and the mint only ever sees `cp1<Q>`. To spend
the note you hand over `ck1<Q || sig>`, a BIP-340 signature by `sk` over the
key-path sighash for that mint's domain, with an all-zero auxiliary input: one
key has exactly one `ck1` per mint, and seed recovery reproduces it byte for
byte. The mint's certificate, `cs1`, carries the amount in its human-readable
part and the mint's signature over its domain, that amount and `hex(Q)`.

Keys are plain BIP-32 below each mint's root (LUD-26):

```text
S            = m/139'/d1/d2/d3/d4    LUD-05's steps over the domain, no port
S/a'/0/i     wallet: every note you mint, rotate or merge into, and a split's p1
S/a'/1/i     change: a split's p2
S/a'/2/n'    share n, handed out as its cx1 (an xpub)
S/a'/2/n'/i  note i of share n, picked and credited by the mint
```

```rust
use lnurlcash_core::cash::{derive_cash_root, derive_service_root};
use lnurlcash_core::recoverable::*;
use lnurlcash_core::check_note;

let root = derive_service_root(&derive_cash_root(&seed)?, "mint.example")?;
let key = derive_note_key(&root, NotePath::Wallet { account: 0, index: i })?;
let cp1 = encode_cp1(&key.output_key); // what the mint sees
let ck1 = encode_ck1(&sign_note_ownership(&key.secret_key, note_url)?); // spends it at this mint only

let cs1 = encode_cs1_with_amount(amount_msat, &mint_signature);
let check = check_note(&ck1, note_url, amount_msat, &cs1, &mint_pubkey); // offline
assert!(check.is_some_and(|check| check.is_verified()));

// a share, for a Lightning Address: hand out its cx1, never the node
let share = derive_share_node(&root, 0, n)?;
let cx1 = encode_cx1(&cash_node_to_cx1(&share)?);
let q = derive_note_pubkey(&decode_cx1(&cx1).unwrap(), i)?; // what the mint credits, by CKDpub
```

A `cp1` whose key is not a curve point is refused everywhere: no spend could
ever open it, so a note minted to one is value destroyed. To spend a note
whose `Q` commits to a script tree by its key path, sign with
`spend::taproot_tweak_secret_key`.

Certificates travel as `c` (and `c2` for a split's change) in withdraw
responses and the informational GET, and a certified note URL carries
`&c=<cs1>`. Reading still accepts the legacy `sig`, `sig2` and `&sig=`; only
`c`, `c2` and `&c=` are written. A current `cs1` is `r || s || recovery-id`
with the recovery id 0 to 3. `check_note` and `check_note_certificate` still
read the certificates older mints issued, and say so: over `hex(Q)` without
the domain (`CertifiedOver::LegacyOutputKey`), or over a bearer note's `h`
before notes were keyed by `Q` (`CertifiedOver::LegacyHash`). The fixed-HRP
`encode_cs1`/`decode_cs1` remain for notes certified before the
amount-bearing form; `decode_any_cs1` accepts either.

A share's own key proves a Lightning Address registration:
`sign_address_proof(&share.private_key, action, domain, username, cx1)` returns
the raw 64-byte BIP-340 proof over
`sha256("LNURLcash:register:<domain>:<username>:<cx1>")`,
`sha256("LNURLcash:update:<domain>:<username>:<new cx1>")` (by the key on file;
a PUT also carries a register proof by the new share) or
`sha256("LNURLcash:unregister:<domain>:<username>")`. `domain` is the
SERVICE's hostname, so a proof one SERVICE saw cannot be replayed at another,
and the username is lowercased. `verify_address_proof` is the SERVICE's side:
it checks against `x(P)` of the signer's `cx1`.

`internal_transfer_request` pays a Lightning Address at the note's own mint
with the whole note, sent to the address's payRequest callback, and refuses
before anything is sent unless the address's `withdrawLink` is on the note's
domain. `parse_mint_fee` reads LUD-26's address fee, the third `Mint fees`
value, into `MintFee::address_fee_msat`.

The wire takes every kind. Any spend goes anywhere a k1 does. An output goes
as `p1`/`p2`, a `cp1` or a bearer note's hash alike, and the
`*_request_with_hash` builders refuse, before anything is sent, one that names
no note. `mint_invoice_request_with_hash` sends it as the comment, and
`build_note_info_url_by_hash` as `?p=`. `note_lookup_of(k1)` is what to look a
note up by without disclosing it. The decoders also read the three older
`ck1` shapes, so existing notes stay spendable: Schnorr over the fixed message
`LNURLcash` (its sha256, or the raw bytes) and the 65-byte recoverable ECDSA
`ck1` before that. Rotate those notes into a current `ck1` rather than issuing
new legacy values.

Three things worth knowing:

- **Accounts and shares are hardened, note indices are not.** An index is
  below 2^31; a share's `cx1` lets whoever holds it list every note on that
  share, and nothing else. Use a fresh share per party, and rotate what
  arrives on one into a wallet note.
- **The root hashes the domain, not the host as stored.** `localhost:3338`
  and `localhost` are the same mint, the same `S`, and the same signatures.
- **Only the mint picks a share's indices.** A wallet never names a share key
  as a resulting note itself.

`derive_nostr_service_root(secret_key, domain)` roots the same tree in a Nostr
identity key for a holder with no BIP-39 words:
`HMAC-SHA256(key = secret key, msg = "LNURLcash/nostr-seed")`, then LUD-26
from that seed. That one is an extension, not LUD-26; a mint sees an ordinary
`cx1` either way.

### Notes from before LUD-26

Until luds `a6c4652` a note key was a tweak of one branch node,
`tagged_hash("LNURLcash/derive", P || chaincode || ser32(purpose) ||
ser32(i))` (or without `ser32(purpose)` before luds `50d740a`), on
`m/139'/d1/d2/d3/d4` over the host as stored, and a `cx1` was the 64-byte
`x(P) || chaincode`. None of those keys is on the LUD-26 tree, so a wallet
upgrading from 0.2 must scan them too and rotate what it finds into LUD-26
keys: `legacy_branch_node`, `legacy_cx1_of`, `legacy_derive_note_pubkey` and
`legacy_derive_note_secret_key` (`purpose` `None` for the pre-purpose scheme,
or one of the `LEGACY_PURPOSE_*` constants) derive them. Nothing derives or
registers new keys that way. A Lightning Address registered with an old `cx1`
has to be registered again with a share's.

## Amounts

Integers in milli-satoshis, everywhere, with no exceptions.

## Conformance

Tested against
[lnurlcash-conformance](https://github.com/lnurlcash/lnurlcash-conformance):
language-neutral vectors plus a mock mint that can be told to drop a connection
mid-mutation, sign in the wrong byte order, lie about a note's value, or never
settle a melt.

```bash
cargo test --features client       # needs node and the conformance repo alongside
```

## Reference implementations

Both by dni, both MIT:
[lnurl-mint](https://github.com/dni/lnurl-mint) (the service) and
[lnurl-wallet](https://github.com/dni/lnurl-wallet) (the wallet).

The wider ecosystem — wallets, mints, hardware and the sibling ports — is
indexed in [awesome-lnurlcash](https://github.com/lnurlcash/awesome-lnurlcash).

## License

MIT.
