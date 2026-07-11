// Package braidref is the independent Go implementation of the
// MindChain/NOOSPHERE Braid base-consensus surface: canonical block
// headers and bodies, the block-hash and proposal-commitment laws, Ground
// tickets, the Pulse v1 retarget, the fork-choice tuple, Witness Ring
// membership, finality votes and aggregate certificates, slashing
// evidence, and the epoch-randomness beacon.
//
// INDEPENDENCE ATTESTATION (plan §8.5): this package was authored
// exclusively from the frozen documents — protocol/spec/schema-tables/
// header-body.md, protocol/spec/pulse-exp2-v1.md, protocol/schemas/
// witness-v1.md, protocol/spec/schema-tables/da.md, protocol/spec/
// constants-v1.toml, protocol/spec/crypto-domains-v1.csv — and the frozen
// conformance vectors in protocol/vectors/{braid,ground,witness}/. It
// shares no generated codec, no Rust FFI, no consensus library, no
// verifier core, and no copied oracle with the crates/noos-* references,
// whose sources were never read. The exp2_q64 Pulse table is recomputed at
// package init from the spec's generator law with exact integer arithmetic
// and pinned to the frozen BLAKE3 constant. External dependencies are the
// standard cryptographic libraries lukechampine.com/blake3 (v1.4.1) and
// github.com/consensys/gnark-crypto (v0.19.0, BLS12-381 pairing and
// hash-to-curve) only.
package braidref
