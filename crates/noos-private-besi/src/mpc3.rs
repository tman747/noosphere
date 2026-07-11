//! M-3PC-MALICIOUS local contract: a deterministic, integer-only replicated-secret-sharing
//! three-party protocol over Z/2^64 with an active-security multiplication check.
//!
//! Construction. Values are additively shared into three components; party `i` holds the pair
//! `(x_i, x_{i+1})` (replicated sharing, honest majority, at most one active corruption). All
//! share arithmetic runs in Z/2^128 (SPDZ2k-style: k = 64 result bits, s = 64 statistical bits);
//! the semantic result is the low 64 bits. Multiplication uses the standard replicated product
//! with a zero-sharing mask, followed by a triple-sacrifice check under a post-commit odd
//! Fiat-Shamir challenge `r`: for the verified product t = r*z - h - e*g - d*f - e*d with
//! e = r*x - f, d = y - g, an additive error (dz on z, dh on h) leaves t = r*dz - dh. Because `r`
//! is odd and unknown when the error is injected, any error touching the low 64 result bits
//! survives the check with probability at most 2^-64 over `r` (it requires v2(r*dz - dh) >= 128
//! while v2(dz or dh) < 64). Openings are robust: every additive component is held by two
//! parties, so a lie about a broadcast share conflicts with an honest holder and aborts with the
//! exact share index. Aborts carry only indices and classes, never share or plaintext material.
//!
//! Non-claims: this is a local research harness. It is not the audited MP-SPDZ backend, has no
//! frozen container/toolchain or preprocessing ceremony, and does not execute the full frozen
//! transformer relation; the M-3PC-MALICIOUS registry row keeps those external prerequisites.

pub const MPC3_DOMAIN: &[u8] = b"NOOS/BESI/MPC3-MALICIOUS/V1";

/// Injected adversarial behavior for exactly one actively corrupted party.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Cheat {
    /// The party adds `delta` to its multiplication output share (consistently, so replication
    /// stays intact and only the sacrifice check can catch it). `aux` targets the auxiliary
    /// triple of the same logical multiplication instead of the main product.
    MulOutput {
        party: usize,
        mul: u32,
        aux: bool,
        delta: u128,
    },
    /// The party sends a different reshare message than the value it keeps, breaking replication.
    ReshareEquivocation { party: usize, mul: u32, delta: u128 },
    /// The party lies about its broadcast component during an opening.
    OpenLie {
        party: usize,
        open: u32,
        delta: u128,
    },
    /// The dealer hands the party an inconsistent replicated copy of an input component.
    InputTamper {
        party: usize,
        input: u32,
        delta: u128,
    },
}

/// Typed abort classes. Deliberately free of share or plaintext material: an abort identifies
/// what failed and where, never a secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbortClass {
    InputInconsistency { input: u32 },
    ShareEquivocation { share_index: u8 },
    SacrificeFailed { mul: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Abort {
    pub class: AbortClass,
}

/// Deterministic expandable tape (stand-in for the preprocessing/correlated-randomness ceremony).
struct Tape {
    reader: blake3::OutputReader,
}

impl Tape {
    fn new(seed: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(seed);
        hasher.update(MPC3_DOMAIN);
        Self {
            reader: hasher.finalize_xof(),
        }
    }
    fn next_u128(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.reader.fill(&mut buf);
        u128::from_le_bytes(buf)
    }
}

/// One replicated-shared ring element: `parts[i]` is party i's held pair (x_i, x_{i+1}).
#[derive(Clone, Debug)]
pub struct Shared {
    parts: [[u128; 2]; 3],
}

impl Shared {
    fn add(&self, other: &Shared) -> Shared {
        let mut parts = [[0u128; 2]; 3];
        for i in 0..3 {
            parts[i][0] = self.parts[i][0].wrapping_add(other.parts[i][0]);
            parts[i][1] = self.parts[i][1].wrapping_add(other.parts[i][1]);
        }
        Shared { parts }
    }
    fn sub(&self, other: &Shared) -> Shared {
        let mut parts = [[0u128; 2]; 3];
        for i in 0..3 {
            parts[i][0] = self.parts[i][0].wrapping_sub(other.parts[i][0]);
            parts[i][1] = self.parts[i][1].wrapping_sub(other.parts[i][1]);
        }
        Shared { parts }
    }
    fn scale(&self, c: u128) -> Shared {
        let mut parts = [[0u128; 2]; 3];
        for i in 0..3 {
            parts[i][0] = self.parts[i][0].wrapping_mul(c);
            parts[i][1] = self.parts[i][1].wrapping_mul(c);
        }
        Shared { parts }
    }
    /// Adds a public constant to component 0 (held by party 0 as `a` and party 2 as `b`).
    fn add_const(&self, c: u128) -> Shared {
        let mut parts = self.parts;
        parts[0][0] = parts[0][0].wrapping_add(c);
        parts[2][1] = parts[2][1].wrapping_add(c);
        Shared { parts }
    }
}

pub struct Session {
    tape: Tape,
    transcript: blake3::Hasher,
    cheats: Vec<Cheat>,
    inputs_shared: u32,
    muls: u32,
    opens: u32,
}

impl Session {
    #[must_use]
    pub fn new(seed: &[u8; 32], cheats: Vec<Cheat>) -> Self {
        let mut transcript = blake3::Hasher::new();
        transcript.update(MPC3_DOMAIN);
        transcript.update(seed);
        Self {
            tape: Tape::new(seed),
            transcript,
            cheats,
            inputs_shared: 0,
            muls: 0,
            opens: 0,
        }
    }

    /// Shares `x` (semantic low 64 bits) into a fresh replicated sharing and runs the pairwise
    /// input-consistency cross-check every party performs on its replicated copies.
    pub fn share_input(&mut self, x: u64) -> Result<Shared, Abort> {
        let index = self.inputs_shared;
        self.inputs_shared = self.inputs_shared.saturating_add(1);
        let c0 = self.tape.next_u128();
        let c1 = self.tape.next_u128();
        let c2 = u128::from(x).wrapping_sub(c0).wrapping_sub(c1);
        let components = [c0, c1, c2];
        let mut parts = [[0u128; 2]; 3];
        for i in 0..3 {
            parts[i][0] = components[i];
            parts[i][1] = components[(i + 1) % 3];
        }
        for cheat in &self.cheats {
            if let Cheat::InputTamper {
                party,
                input,
                delta,
            } = cheat
            {
                if *input == index {
                    parts[*party][1] = parts[*party][1].wrapping_add(*delta);
                }
            }
        }
        let shared = Shared { parts };
        // Every component is replicated on two parties; they cross-check their copies.
        for j in 0..3usize {
            let holder_a = shared.parts[j][0];
            let holder_b = shared.parts[(j + 2) % 3][1];
            if holder_a != holder_b {
                return Err(Abort {
                    class: AbortClass::InputInconsistency { input: index },
                });
            }
        }
        Ok(shared)
    }

    /// Robust opening: each additive component is broadcast by both of its holders; a mismatch
    /// aborts with the exact component index. Returns the reconstructed ring element.
    pub fn open(&mut self, x: &Shared) -> Result<u128, Abort> {
        let open_index = self.opens;
        self.opens = self.opens.saturating_add(1);
        let mut value: u128 = 0;
        for j in 0..3usize {
            let mut from_owner = x.parts[j][0];
            for cheat in &self.cheats {
                if let Cheat::OpenLie { party, open, delta } = cheat {
                    if *party == j && *open == open_index {
                        from_owner = from_owner.wrapping_add(*delta);
                    }
                }
            }
            let from_neighbor = x.parts[(j + 2) % 3][1];
            if from_owner != from_neighbor {
                return Err(Abort {
                    class: AbortClass::ShareEquivocation {
                        share_index: j as u8,
                    },
                });
            }
            value = value.wrapping_add(from_owner);
            self.transcript.update(&from_owner.to_le_bytes());
        }
        Ok(value)
    }

    /// Raw replicated multiplication with zero-sharing mask and reshare. `logical` and `aux`
    /// route cheat injection; the result is unchecked until the sacrifice runs.
    fn mul_raw(&mut self, x: &Shared, y: &Shared, logical: u32, aux: bool) -> Shared {
        let a0 = self.tape.next_u128();
        let a1 = self.tape.next_u128();
        let a2 = 0u128.wrapping_sub(a0).wrapping_sub(a1);
        let alpha = [a0, a1, a2];
        let mut kept = [0u128; 3];
        let mut sent = [0u128; 3];
        for i in 0..3 {
            let t = x.parts[i][0]
                .wrapping_mul(y.parts[i][0])
                .wrapping_add(x.parts[i][0].wrapping_mul(y.parts[i][1]))
                .wrapping_add(x.parts[i][1].wrapping_mul(y.parts[i][0]))
                .wrapping_add(alpha[i]);
            kept[i] = t;
            sent[i] = t;
            for cheat in &self.cheats {
                match cheat {
                    Cheat::MulOutput {
                        party,
                        mul,
                        aux: cheat_aux,
                        delta,
                    } if *party == i && *mul == logical && *cheat_aux == aux => {
                        kept[i] = kept[i].wrapping_add(*delta);
                        sent[i] = sent[i].wrapping_add(*delta);
                    }
                    Cheat::ReshareEquivocation { party, mul, delta }
                        if *party == i && *mul == logical && !aux =>
                    {
                        sent[i] = sent[i].wrapping_add(*delta);
                    }
                    _ => {}
                }
            }
        }
        // Party i keeps t_i and receives t_{i+1} from party i+1.
        let mut parts = [[0u128; 2]; 3];
        for i in 0..3 {
            parts[i][0] = kept[i];
            parts[i][1] = sent[(i + 1) % 3];
        }
        Shared { parts }
    }

    /// Post-commit odd Fiat-Shamir challenge bound to the transcript and the mul counter.
    fn challenge(&mut self, logical: u32) -> u128 {
        let mut hasher = self.transcript.clone();
        hasher.update(b"SACRIFICE-CHALLENGE");
        hasher.update(&logical.to_le_bytes());
        let mut buf = [0u8; 16];
        hasher.finalize_xof().fill(&mut buf);
        u128::from_le_bytes(buf) | 1
    }

    /// Actively checked multiplication: computes z = x*y, then sacrifices an auxiliary triple
    /// (f, g, h) under the challenge `r`. Any additive error on z or h that touches the low 64
    /// result bits fails the check except with probability <= 2^-64 over `r`.
    pub fn mul_checked(&mut self, x: &Shared, y: &Shared) -> Result<Shared, Abort> {
        let logical = self.muls;
        self.muls = self.muls.saturating_add(1);
        let z = self.mul_raw(x, y, logical, false);
        // Auxiliary triple from the correlated-randomness tape.
        let f_val = self.tape.next_u128();
        let g_val = self.tape.next_u128();
        let f = self.share_ring(f_val);
        let g = self.share_ring(g_val);
        let h = self.mul_raw(&f, &g, logical, true);
        // Commit the (possibly corrupted) product shares before drawing the challenge.
        for shared in [&z, &h] {
            for part in &shared.parts {
                self.transcript.update(&part[0].to_le_bytes());
            }
        }
        let r = self.challenge(logical);
        let e = self.open(&x.scale(r).sub(&f))?;
        let d = self.open(&y.sub(&g))?;
        let combination = z
            .scale(r)
            .sub(&h)
            .sub(&g.scale(e))
            .sub(&f.scale(d))
            .add_const(0u128.wrapping_sub(e.wrapping_mul(d)));
        let t = self.open(&combination)?;
        if t != 0 {
            return Err(Abort {
                class: AbortClass::SacrificeFailed { mul: logical },
            });
        }
        Ok(z)
    }

    /// Shares a full ring element from the tape (no input-consistency round: tape material is
    /// consistent by the correlated-randomness assumption; corruption is modeled via `Cheat`).
    fn share_ring(&mut self, x: u128) -> Shared {
        let c0 = self.tape.next_u128();
        let c1 = self.tape.next_u128();
        let c2 = x.wrapping_sub(c0).wrapping_sub(c1);
        let components = [c0, c1, c2];
        let mut parts = [[0u128; 2]; 3];
        for i in 0..3 {
            parts[i][0] = components[i];
            parts[i][1] = components[(i + 1) % 3];
        }
        Shared { parts }
    }

    #[must_use]
    pub fn add(&self, x: &Shared, y: &Shared) -> Shared {
        x.add(y)
    }

    /// Opens the semantic 64-bit result.
    pub fn open_result(&mut self, x: &Shared) -> Result<u64, Abort> {
        Ok(self.open(x)? as u64)
    }
}

/// Deterministic malicious-checked inner product over Z/2^64: the reference relation for the
/// local contract and its falsifiers.
pub fn inner_product(
    seed: &[u8; 32],
    xs: &[u64],
    ys: &[u64],
    cheats: Vec<Cheat>,
) -> Result<u64, Abort> {
    let mut session = Session::new(seed, cheats);
    let mut acc: Option<Shared> = None;
    for (x, y) in xs.iter().zip(ys) {
        let sx = session.share_input(*x)?;
        let sy = session.share_input(*y)?;
        let product = session.mul_checked(&sx, &sy)?;
        acc = Some(match acc {
            Some(a) => session.add(&a, &product),
            None => product,
        });
    }
    match acc {
        Some(a) => session.open_result(&a),
        None => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const SEED: [u8; 32] = [13u8; 32];
    const XS: [u64; 4] = [3, u64::MAX, 12_345_678_901_234_567, 42];
    const YS: [u64; 4] = [7, 2, u64::MAX - 5, 999_999_937];

    fn plaintext_inner(xs: &[u64], ys: &[u64]) -> u64 {
        xs.iter()
            .zip(ys)
            .fold(0u64, |acc, (x, y)| acc.wrapping_add(x.wrapping_mul(*y)))
    }

    #[test]
    fn honest_run_matches_plaintext_and_is_deterministic() {
        let expected = plaintext_inner(&XS, &YS);
        let a = inner_product(&SEED, &XS, &YS, Vec::new()).unwrap();
        let b = inner_product(&SEED, &XS, &YS, Vec::new()).unwrap();
        assert_eq!(a, expected);
        assert_eq!(a, b);
        // A second seed changes shares/challenges but never the result.
        let c = inner_product(&[99u8; 32], &XS, &YS, Vec::new()).unwrap();
        assert_eq!(c, expected);
    }

    #[test]
    fn falsifier_each_cheating_party_hits_sacrifice_abort_with_exact_index() {
        for party in 0..3usize {
            let cheat = Cheat::MulOutput {
                party,
                mul: 1,
                aux: false,
                delta: 3,
            };
            assert_eq!(
                inner_product(&SEED, &XS, &YS, vec![cheat]),
                Err(Abort {
                    class: AbortClass::SacrificeFailed { mul: 1 }
                }),
                "party {party} additive error must abort at the cheated multiplication"
            );
        }
    }

    #[test]
    fn falsifier_auxiliary_triple_corruption_is_caught() {
        let cheat = Cheat::MulOutput {
            party: 2,
            mul: 0,
            aux: true,
            delta: 1,
        };
        assert_eq!(
            inner_product(&SEED, &XS, &YS, vec![cheat]),
            Err(Abort {
                class: AbortClass::SacrificeFailed { mul: 0 }
            })
        );
    }

    #[test]
    fn falsifier_matched_top_bit_corruption_is_caught_by_the_extended_ring() {
        // Over a bare Z/2^64 sacrifice, adding 2^63 to BOTH z and h passes: t = (r-1)*2^63 = 0
        // mod 2^64 because r-1 is even. The 128-bit check keeps 64 statistical bits, so the same
        // attack leaves t = (r-1)*2^63 != 0 mod 2^128 and aborts.
        let delta = 1u128 << 63;
        let cheats = vec![
            Cheat::MulOutput {
                party: 0,
                mul: 2,
                aux: false,
                delta,
            },
            Cheat::MulOutput {
                party: 0,
                mul: 2,
                aux: true,
                delta,
            },
        ];
        assert_eq!(
            inner_product(&SEED, &XS, &YS, cheats),
            Err(Abort {
                class: AbortClass::SacrificeFailed { mul: 2 }
            })
        );
    }

    #[test]
    fn falsifier_open_lie_is_share_equivocation_with_exact_component() {
        for party in 0..3usize {
            let cheat = Cheat::OpenLie {
                party,
                open: 0,
                delta: 5,
            };
            assert_eq!(
                inner_product(&SEED, &XS, &YS, vec![cheat]),
                Err(Abort {
                    class: AbortClass::ShareEquivocation {
                        share_index: party as u8
                    }
                })
            );
        }
    }

    #[test]
    fn falsifier_reshare_equivocation_breaks_replication_and_aborts() {
        let cheat = Cheat::ReshareEquivocation {
            party: 1,
            mul: 0,
            delta: 9,
        };
        let result = inner_product(&SEED, &XS, &YS, vec![cheat]);
        // The receiving neighbor's copy conflicts with the sender's kept share at the first
        // opening that touches it: component 1 equivocation.
        assert_eq!(
            result,
            Err(Abort {
                class: AbortClass::ShareEquivocation { share_index: 1 }
            })
        );
    }

    #[test]
    fn falsifier_input_inconsistency_aborts_with_exact_input() {
        let cheat = Cheat::InputTamper {
            party: 0,
            input: 3,
            delta: 1,
        };
        assert_eq!(
            inner_product(&SEED, &XS, &YS, vec![cheat]),
            Err(Abort {
                class: AbortClass::InputInconsistency { input: 3 }
            })
        );
    }

    #[test]
    fn abort_carries_only_indices_never_share_material() {
        // Structural: every AbortClass payload is an index. The debug rendering of an abort from
        // a run over secret inputs must not depend on those inputs.
        let cheat = Cheat::OpenLie {
            party: 2,
            open: 1,
            delta: 7,
        };
        let a = inner_product(&SEED, &[11, 22], &[33, 44], vec![cheat.clone()]).unwrap_err();
        let b = inner_product(&SEED, &[55, 66], &[77, 88], vec![cheat]).unwrap_err();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}
