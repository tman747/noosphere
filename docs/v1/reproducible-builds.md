# Reproducible release candidates and external builder assurance

Status: **PREPRODUCTION / EXTERNAL_BLOCKED.** This tooling does not change
`protocol/release/promotion-blockers.json`, claim-registry states, or any gate verdict.

## Candidate builds

`tools/gates/generate_release.py` builds one native target with the exact Rust and Go
versions in `protocol/release/repro-toolchains-v1.json`. Cargo and Go dependencies are
acquired before the build (`go mod download all` runs from the `go/` module so the SBOM
module graph is present and the committed `go.sum` locks that complete graph), then the
build executes with locked/read-only dependency
resolution and network access disabled through Cargo/Go settings. The deterministic
environment binds `SOURCE_DATE_EPOCH` to the source commit timestamp, fixes locale and
timezone, remaps source paths, disables incremental/debug/build-VCS variance, and performs
no post-build normalization. The timestamp is build metadata; it is not elapsed public
time and cannot satisfy any duration gate.

Each candidate bundle contains binaries, exact SHA-256 checksums, a CycloneDX SBOM,
SLSA-v1/in-toto provenance, build details, and an unsigned attestation request. GitHub
Actions publishes bundles for Windows x86_64, Linux x86_64, and native Linux aarch64.
All jobs are controlled by one repository identity, so those artifacts are explicitly
`SMOKE_ONLY`, have promotion effect `NONE`, remain `EXTERNAL_BLOCKED`, and are classified
`public-candidate-smoke-not-independent-reproduction`.

The Windows job uses `vswhere` plus the Windows Kits registry to discover installation
roots, requires the exact locked Visual Studio component, MSVC tools version, Windows SDK
component, and SDK version, then exports explicit `NOOS_MSVC_*` and `NOOS_WINDOWS_SDK_*`
values. Release generation accepts no implicit BuildTools path or version alias. Local or
external Windows builders may use different canonical installation roots by supplying the
same four explicit variables; mismatched versions or incomplete roots fail closed. The
canonical paths, versions, and SHA-256 hashes of `cl.exe`, `link.exe`, and `rc.exe` are
recorded alongside the pinned `rust-lld` path/hash in build details, bundle manifests,
and in-toto provenance.

Local example (the frozen policy is currently unsigned, so only smoke mode is allowed):

```text
python tools/gates/generate_release.py --target windows-x86_64 --out release/candidates/windows-x86_64 --revision <40-hex-commit> --builder-profile local-builder --smoke
```

## External attestations

Two externally controlled builders must each rebuild all three targets. Each builder
creates one canonical `noos/repro-build-attestation/v1` payload per target and a separate
`noos/detached-ed25519-signature/v1` file. Production trust records are supplied out of
band from external operators using `trusted-repro-builders-template.json` as the shape.
The verifier requires distinct signing keys, operators, control-plane identities, host
identities, and pinned toolchain installations. Multiple jobs under one CI identity do
not qualify. An automated job may run a build; automation is not represented as an
independent human or substituted for the external signing authority.

The signature file name replaces `.attestation.json` with `.signature.json` and signs
the UTF-8 payload serialized as sorted-key compact JSON plus one LF. It contains:

```json
{"schema":"noos/detached-ed25519-signature/v1","algorithm":"ed25519","key_id":"<registered-key-id>","payload_sha256":"<sha256-of-canonical-payload>","signature_base64":"<detached-signature>"}
```

Verification is read-only:

```text
python tools/gates/repro_build.py verify-attestations --attestations <directory> --trusted-builders <external-trust.json> --revision <40-hex-commit> --out <report.json>
```

Even a qualifying report does not mark G4 or G5 passed. It is an input to the separate,
append-only promotion process. Current external inputs still required are the signed
repro policy, two external trust records and detached signature sets, native builds for
all targets from both operators, production identity/genesis inputs, and all other
blockers already recorded in the promotion ledger.
