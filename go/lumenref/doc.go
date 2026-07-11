// Package lumenref is the independent Go implementation of the Lumen v1
// public-state surface of the MindChain/NOOSPHERE L1: the canonical codec
// object shapes, identity derivations, and the depth-256 sparse Merkle tree.
//
// INDEPENDENCE ATTESTATION (plan §8.5): this package was authored
// exclusively from the frozen documents — protocol/schemas/lumen-v1.md,
// protocol/spec/schema-tables/lumen-objects.md, protocol/spec/
// crypto-domains-v1.csv, protocol/spec/constants-v1.toml — and the frozen
// conformance vectors in protocol/vectors/lumen/ and protocol/vectors/codec/.
// It shares no generated codec, no Rust FFI, no consensus library, no
// verifier core, and no copied oracle with crates/noos-lumen, whose sources
// were never read. The only external dependency is the standard BLAKE3
// library lukechampine.com/blake3 (pinned v1.4.1).
package lumenref
