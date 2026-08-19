# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

First release. A Rust implementation of LNURLcash, following the protocol layer
of dni's [lnurl-wallet](https://github.com/dni/lnurl-wallet) and checked against
the shared
[conformance vectors](https://github.com/TheCryptoDonkey/lnurlcash-conformance)
and the adversarial mock mint.

### Design notes

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
