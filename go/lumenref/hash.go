package lumenref

import "lukechampine.com/blake3"

// DomainHash is the NOOSPHERE hash law: BLAKE3-256 over the registered
// context string followed by the parts (lumen-v1.md: "All hashes are
// BLAKE3-256 over context_string || parts... with a registered context").
func DomainHash(ctx string, parts ...[]byte) [32]byte {
	h := blake3.New(32, nil)
	h.Write([]byte(ctx))
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// KeyedDomainHash is the keyed BLAKE3-256 law (crypto-domains-v1.csv kind
// BLAKE3_KEYED): BLAKE3 keyed with key over context_string || parts.
func KeyedDomainHash(key [32]byte, ctx string, parts ...[]byte) [32]byte {
	h := blake3.New(32, key[:])
	h.Write([]byte(ctx))
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
