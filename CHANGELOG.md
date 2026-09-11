# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

### LUD-25 Part 2: notes keyed by a public key

`recoverable` implements Part 2, with the TypeScript kit's names and
semantics.

- The four bech32m strings: `cp1` (a note's x-only key), `ck1` (the 65-byte
  ownership signature that spends it), `cs1` (the mint's certificate) and
  `cx1` (a watch-only branch). Fixed lengths, no 90-character limit, strict per
  BIP-350: mixed case, a bech32 checksum, the wrong prefix or length and
  non-zero padding are all refused. Decoders return `None` and never panic.
- `derive_note_pubkey` (watch-only, from a `cx1`) and `derive_note_secret_key`:
  the BIP-341-style tweak, through libsecp256k1's own x-only tweak functions.
  `i` is any u32. A tweak at or above the curve order is an error, never
  reduced.
- `sign_note_ownership` / `recover_note_ownership_pubkey`, RFC6979 and low-S,
  and `note_ownership_digest`.
- `note_id_of` and `note_lookup_of`: the id a mint files either kind of note
  under, and what to look one up by without disclosing it.
- `derive_cash_address_node` and `cash_node_to_cx1`: the reference wallet's
  `m/139'/1'/d1..d4` branch, not the draft text's `m/139'/d1..d4`.
- `derive_nostr_cash_seed` / `derive_nostr_address_node`: an extension, not
  LUD-25, rooting a branch in a Nostr identity key.
- `cash::derive_cash_master`, the BIP-32 master on its own.

The wire takes both kinds. A `ck1` goes anywhere a k1 does, including
`resolve_note_input`, `note_signature_message` and `verify_note_signature`,
which also takes a `cs1` as the signature. A `cp1` output goes as `p1`/`p2` in
the `*_request_with_hash` builders, where a hash keeps `h`/`h2`; as the comment
alone in `mint_invoice_request_with_hash`; and as `p` in
`build_note_info_url_by_hash`. `verify_note_signature_hash` and the `*_for_hash`
message and digest helpers check a certificate by key or hash, for a caller
that holds the id but not the k1.

`parse_note_info` checks the echoed k1 by note id rather than as a string.
One note has more than one valid `ck1` (anyone can flip one to its high-S
twin), so a SERVICE echoing a different `ck1` that recovers to the same key has
named the same note; one recovering to any other key is still refused, and a k1
with no id still has to match exactly. All the kits compare the echo this way,
as the note it names.

All of it crosses the FFI, along with `derive_cash_child` and the three
`*_request_with_hash` builders, which were not exported before and which a
Part 2 output needs.

`note_signature_message`, `note_signature_digest` and `verify_note_signature`
now want a k1 that is 32 bytes of hex or a `ck1`, as the TypeScript kit does.
Hex of any other length used to be hashed and signed over.

Graded against `lnurlcash-conformance` 0.9.0's `part2.json` and
`nostr-seed.json`: every field of every branch, note and certificate,
including each `ck1` recovered to its note key and each `cs1` to the mint's.

### Three more fields off a mint address

`parse_mint_address` reads `nodeUris`, `sunsetDate` and `outstandingNotesMsat`,
which the reference mint publishes and this dropped. All three cross the FFI on
`FfiMintAddress` too.

- `node_uris` — every address the SERVICE's node announces. `node_uri` is the
  first of them; a node behind Tor as well as clearnet has more. `None` rather
  than an empty vector when there are none.
- `sunset_date` — the day the SERVICE plans to close, ISO-8601. Validated as a
  real calendar day (leap years included) and dropped otherwise: the one thing
  a WALLET does with this is show it to a holder, and a wrong date is worse
  than no date.
- `outstanding_notes_msat` — what the SERVICE says it owes. Zero and absent
  stay distinct.

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

**`settle_note`'s best-effort rotate covers a refusal, never an uncertainty.**
Settling reads what an output is really worth, which puts `k1` on the wire, so
a rotate follows to replace the exposed secret. That rotate is allowed to fail:
a SERVICE that refuses it has burned nothing, and keeping the exposed `k1` beats
failing the whole settle. It is allowed to fail for that reason and no other -
`Error::RequestRefused`, `Error::ServiceRejected` and `Error::NotePending`, and
nothing else. Every other variant either carries fresh secrets or admits the
mutation may have applied, and returning the old `k1` there hands back a secret
the SERVICE has burned while dropping the only copy of the note it just minted.
The arms are named rather than defaulted to, so a variant added to the taxonomy
later surfaces instead of silently joining the swallowed set.

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
