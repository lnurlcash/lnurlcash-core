# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

### Seed-recoverable note secrets, and the private lookup a restore needs

- `cash`: LUD-25's `m/139'` scheme. `derive_cash_root`,
  `derive_cash_domain_node`, `derive_cash_secret`, `cash_secret_at`,
  `cash_domain_indices`, `cash_node_to_hex`/`from_hex`, `derive_cash_child`
  and `CashSecretSource`. `d1..d4` are raw uint32 used exactly as they fall,
  hardened only where they land at or above 2^31; masking the top bit or
  hardening all four derives a different tree from every conforming wallet.
- `secrets::derive_note_root` / `derive_note_secret`: the pre-spec HMAC
  scheme, so notes minted under it stay findable. Not what to mint under.
- `note::build_note_info_url_by_hash` and `protocol::parse_note_info_by_hash`,
  with `Client::fetch_note_info_by_hash` behind the `client` feature: LUD-25's
  `?h=` informational GET. A restore walk queries a whole gap window of
  indices the wallet has not minted into yet, so asking by secret publishes
  exactly the secrets it is about to mint under.
- `NoteInfoByHash` is its own type rather than `WithdrawRequestInfo`: that
  type's `k1` is the bearer secret, and a conforming SERVICE has nothing to
  echo when the request never named one.
- Graded against `lnurlcash-conformance` 0.7.0's `cash-derivation.json` and
  `derivation.json`, including BIP-32's own published test vector 1.
- New dependency: `hmac`. `secp256k1` was already here, so the unhardened
  levels cost nothing extra.

First release. A Rust implementation of LNURLcash, following the protocol layer
of dni's [lnurl-wallet](https://github.com/dni/lnurl-wallet) and checked against
the shared
[conformance vectors](https://github.com/TheCryptoDonkey/lnurlcash-conformance)
and the adversarial mock mint.

### Design notes

**Offline verification is mandatory, and this crate insists on it.** LUD-25
stopped treating a note signature as optional: a SERVICE MUST publish
`mintPubkey` and MUST sign every note a rotate, split or merge mints. So
`parse_note_info` refuses a `withdrawRequest` publishing no `mintPubkey`, or
one that is not a 33-byte compressed secp256k1 key, and `parse_mutation`
raises `Error::Unverifiable` when a SERVICE confirms a mutation without
signing it. `Policy { require_signatures: false }` opts out for a SERVICE that
predates the requirement.

That error carries the fresh secrets, and the reason matters: `status` was OK,
so the mutation LANDED. The note exists at the hash the wallet disclosed and
that secret is the only key to it, so enforcing the spec must never be the
thing that strands the money.

**A spent-or-unknown refusal from a mutation carries its secrets too.** At a
SERVICE that has not implemented the replay rule below, a retried rotate,
split or merge is answered as an already-spent input - so that refusal is also
what a mutation the SERVICE ALREADY applied looks like. The crate cannot tell
those apart at the wire, so `Error::NoteSpent` and `Error::NoteUnknown` are
struct variants carrying `new_secrets`, and `Error::new_secrets()` reads them
off any of the four families that carry them.

**A mutation whose answer was lost is re-sent, and usually completes.** LUD-25
gained a "Retrying a mutation" section: a SERVICE MUST answer a byte-identical
rotate, split or merge with the success it already returned, signature and all,
rather than with the already-spent refusal its burned inputs would earn. That
closes the sharpest edge in the protocol - every mutation is a GET, HTTP treats
GET as idempotent, and stacks retry a dropped one - so `Client` re-sends and
the retry becomes invisible.

`ClientConfig::mutation_retries` defaults to 1. The safety rules are the whole
of it: never a melt, which carries `pr`, is paid asynchronously and has no
replay guarantee; never a definitive refusal, which is the SERVICE's considered
answer; and the `Request` is cloned rather than rebuilt, because the replay is
matched on the k1 set, `h`, `h2` and `amount` - a regenerated secret would make
the retry a different mutation, and a second real burn.

**Minting is comment-bound, and the payment preimage is only settlement proof.**
The draft keyed a fresh note by the invoice's payment preimage until 31 August
2026, when that fallback was removed outright: a preimage propagates to every
node that forwarded the payment, routinely before the payer has finished
processing it, so a note keyed by one is a note all of them can spend. A WALLET
now chooses the secret itself, before any invoice exists, and hands the SERVICE
only `sha256(secret)` in a mandatory LUD-12 `comment`; a minting `payRequest`
must advertise `commentAllowed >= 64` or it cannot mint at all. `mint_invoice_request` returns the secret
on `Request::new_secrets` - persist it before paying, because the SERVICE holds
nothing that could reconstruct it.

**The mint address carries the node stats under their wire names.** lnurl-mint
advertises `nodeCapacity` in msat, so `node_capacity_msat` is a rename and has
to be mapped rather than passed through — the TypeScript sibling shipped that
rename unmapped and read `undefined` for every mint.



**The core has no I/O.** `protocol` describes each operation as a `Request` — a
URL, and the fresh secrets that must survive a lost answer — paired with a
`parse_*` function. The `client` feature is a thin loop over exactly that, and
the `ffi` surface excludes it entirely.

**Nothing async crosses the FFI boundary.** Only the pure half is exported to
Kotlin and Swift. A mobile app keeps its own HTTP stack and concurrency model,
and the bindings stay boring.

**The proportional fee term is computed split**, as
`(g / 1e6) * ppm + ((g % 1e6) * ppm) / 1e6`. A direct multiply overflows
`u64::MAX` at realistic amounts: 21M BTC is 2.1e15 msat, and at 999_999 ppm the
product is about 2.1e21. A naive version passes every small test, which is why
the vectors include a large one.

**`gross_up_for_mint_fee` is a binary search**, not an estimate-then-walk. At a
99.9999% fee a one-msat walk is around a million steps, so any guard on it
returns a non-minimal answer — and the fee is chosen by the service, so that
input is reachable on purpose.

**A service's `reason` is carried through exactly as sent**, empty string
included. Substituting a friendly default before classification would be read
back as though the service had said it: "Unknown service error" matches the
rule for an unknown note, and would report one on no evidence at all.

**`is_bolt11_invoice` splits at the separator first.** Scanning left to right
is subtly wrong: an amountless invoice's bech32 separator IS a digit, so a
greedy digit scan swallows it and then finds no separator at all. The
equivalent regex in the TypeScript sibling gets away with it only because it
backtracks.
