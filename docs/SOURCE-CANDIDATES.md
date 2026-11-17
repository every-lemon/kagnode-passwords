# Authenticated source candidates (draft tooling)

This Rust tool prepares and verifies **local source/data candidates**. It never publishes a release, installs a service, activates networking, changes a vault or qualifies a native application. Existing product versions and all prior tags/assets remain unchanged. The internal tool crate is nonpublishable and its0.0.0 development version is not a product release.

## Commands and trust contract

From a clean independent checkout, with a real `.git/` directory (linked worktrees and alternate object stores are refused in v1):

```sh
cargo build --locked --manifest-path tools/release/Cargo.toml
release_tool=/absolute/path/to/kagnode-passwords-release-candidate
"$release_tool" inventory /absolute/path/to/source
"$release_tool" prepare /absolute/path/to/source /external/candidates/unsigned /external/trust/public.pem
"$release_tool" sign /absolute/path/to/source /external/candidates/unsigned /external/candidates/signed /external/trust/public.pem /external/identity/private.pem
"$release_tool" verify /absolute/path/to/source /external/candidates/signed /external/trust/public.pem
```

The public-key argument is mandatory and must come independently from outside the source/candidate directories. Key paths are absolute/canonical with no symlink aliases; the trust file and its parent must be caller/root controlled and not shared writable. A key bundled next to a signature cannot establish trust. Signing requires the matching caller-owned external Ed25519 identity, mode0600/0400, never generates one and never copies it to an artifact. The fixed OpenSSL engine reads private identity bytes over stdin; identity paths/material are not logged. Do not use these example paths as a command to create a production key. No production trust decision or key rotation is part of this draft.

Keep `TMPDIR` and `CARGO_TARGET_DIR` on an appropriate development disk. The tool uses private temporary files for bounded public Git/signature inputs; key bytes are held in a zeroizing buffer, not written to its temporary/output files. This is best-effort process hygiene, not a claim of protection from root, the engine itself or all physical memory attacks.

## Candidate format

`release-manifest.json` uses strict schema **`kagnode-source-candidate-v1`**, channel`candidate`, payload_kind`source-data` and an explicit unqualified/no-install/no-publication marker. It contains the exact committed source/tree, existing5.0.x source version, commit timestamp, independently supplied public-key DER fingerprint and one bounded archive declaration. The compatibility repository identity remains `every-lemon/kagnode-passwords`; canonical `source_repository` is `every-lemon/kagnode-passwords`. Package, service, command and storage identities are unchanged.

The only supported payload is a normalized USTAR/gzip **source** archive: sorted complete tracked regular files, fixed epoch/uid/gid/mode, approved source allowlist and no links, untracked data, private runtime files, metadata escapes or duplicate members. Normalized archive bytes must equal a fresh reconstruction of the exact committed source. There is deliberately no arbitrary archive extraction path. Binary/Debian/RPM/application-engine candidates, arbitrary downloaded roots and the older multi-format unsigned manifest schema are **not supported or silently upgraded**.

An unsigned candidate contains that archive, manifest andSHA256SUMS. Signing creates a new separate directory with the unchanged source archive/manifest plus detached64-byte Ed25519 signature, informational public key and regenerated sums. Never write over an existing output. Verification first authenticates the manifest against external trust; only then checks canonical source/archive bytes and sums. Supplied files are never installed or executed.

## Bounds and race checks

Inputs are limited to2048tracked files,8MiB per source file,64MiB total source/archive,64KiB manifest/inventory/config and1024bytes per key. Unknown/duplicate JSON fields, wrong products/versions/source hashes, unsafe paths, nonregular/multiply linked files, symlink source parents and candidate directories are refused. Dirty/index-vs-HEAD inputs and changed HEAD/file bytes fail closed. Source files are checked against immutable captured Git objects rather than later mutable HEAD resolution. Git config includes, external filters/hooks/config overrides and replacement objects are not trusted. The pinned checkout action’s exact `gc.auto=0` setting is supported; nonzero automatic-GC settings remain refused. Source and input/output/identity/trust locations remain separate; output parent must be caller-owned and not group/world writable.

On failure, an incomplete fresh output can remain for inspection. It is not a verified release: signing/verification rerun every source, signature, file and checksum check. Do not label a directory trusted because it exists or has a checksum file.

## Tests and current limits

Rust tests use only ephemeral synthetic keys and independent local source fixtures. Coverage includes deterministic repeated source/signature bytes, explicit external trust, wrong/missing/forged signatures, authentication-before-archive, malicious signed traversal/link/duplicate tar streams, dirty/racing inputs, commit changes, inventory mismatch, unsafe Git config/replace refs, unsafe links, size/count bounds, identity permissions/separation and no output overwrite. New tooling CI runs fmt, Clippy, tests and source inventory on Rust1.88/stable; no real key is uploaded and no publish job is added here.

This does not establish application-manager trust bootstrap, stable packaging/native installation, existing data upgrade/rollback, HA, production authentication or native hardware qualification. Those require independent review and disposable lifecycle checks before any actual release. The existing product runtime, encryption and all UI remain untouched.

## Existing tag publisher is intentionally fail-closed

The previous packaging job still exercises its historical source/data formats for ordinary PRs. A tag publication now additionally requires an explicit reviewed `KAGNODE_PASSWORDS_RELEASE_PUBLIC_KEY_PEM` repository variable and a strict authenticated candidate. No key is generated in CI. Existing unsigned seven-asset releases are historical and are not retroactively claimed signed. The current legacy packaging artifact does not satisfy the new signature gate, so a new tag fails instead of silently publishing unsigned packages.

The new candidate format is unqualified/source-only and cannot authorize a stable application publication. A future reviewed qualified release workflow must produce authenticated supported artifacts and establish the real installer/manager trust policy; do not bypass this guard or relabel source-only candidates stable. No product version, release/tag or live vault is changed by this draft. Native `packaging/build-deb.sh` and its enable/restart behaviour were not qualified or modified here.
