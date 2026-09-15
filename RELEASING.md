# Releasing lnurlcash-core

Crates.io versions are permanent. The release workflow validates the exact tag
before the protected publish job can use a registry token.

## One-time setup

1. Sign in to crates.io with the GitHub account that will initially own the
   crate and create a narrowly scoped API token.
2. In this repository, create a `crates-io` GitHub environment. Restrict its
   deployment branches and tags to `v*.*.*`, then add the token as the
   environment secret `CARGO_REGISTRY_TOKEN`.
3. After the first publish, add the other maintainers or an appropriate GitHub
   team as crate owners. Do not put a personal registry token in repository
   secrets or a local release script.

## Rehearsal

Run the `release` workflow manually from `main` with the intended tag. The tag
is prospective and must not exist yet. This runs the full conformance suite and
`cargo publish --locked --dry-run` without entering the publishing environment
or reading its secret.

## Release

1. Set the version in `Cargo.toml`, update `Cargo.lock`, and date the matching
   changelog entry.
2. Merge only after CI and the local package dry-run pass.
3. Create and push the exact version tag, for example `v0.1.0`.
4. The tag runs the same validation and then enters the protected `crates-io`
   environment. Once approved, it runs `cargo publish --locked`.
5. Verify the version and repository link on crates.io before creating the
   matching GitHub release.

Never reuse or move a published version tag.
