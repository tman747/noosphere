// Adversarial sample: old Ascent domain-tagged hash input.
// The scanner must flag the ascent.* domain usage.
fn txid(body: &[u8]) -> Hash32 {
    hash_domain("ascent.tx", body)
}
fn sighash(body: &[u8]) -> Hash32 {
    hash_domain("ascent.sighash", body)
}
