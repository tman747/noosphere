package braidref

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/mindchain/noosphere/go/lumenref"
)

// Pulse v1 retarget per protocol/spec/pulse-exp2-v1.md. The exp2_q64 table
// is recomputed at init from the spec's §2 generator law with exact integer
// arithmetic and pinned to the frozen BLAKE3 hash; the §3 evaluation and
// rounding-order law is implemented verbatim (same table, same bit order,
// same per-step floors, same short circuits).

const (
	pulseTargetSpacingSeconds = 6
	pulseHalfLifeSeconds      = 3600
	// exp2TableHashHex is the frozen BLAKE3-256 over the 64 entries
	// concatenated as u128 little-endian (pulse-exp2-v1.md §2).
	exp2TableHashHex = "15d783a23bcf9d9e20d1133bbc247a5c94a876705aed5281e73246f67c883999"
)

// exp2Table holds EXP2_Q64_TABLE_V1[k] = floor(2^(2^-(k+1)) * 2^64) for
// k = 0..63; every entry is a 65-bit integer in [2^64, 2^65).
var exp2Table [64]*big.Int

// tMax is 2^256 - 1.
var tMax = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

func init() {
	// Generator law (pulse-exp2-v1.md §2): work at P = 256 fractional
	// bits; s_1 = isqrt(2^(2P+1)); s_{j+1} = isqrt(s_j << P);
	// entry_{j-1} = s_j >> (P-64), with the truncation-unambiguity proof
	// (s >> (P-64)) == ((s+4) >> (P-64)) asserted at every step.
	const P = 256
	s := new(big.Int).Sqrt(new(big.Int).Lsh(big.NewInt(1), 2*P+1))
	four := big.NewInt(4)
	for j := 1; j <= 64; j++ {
		if j > 1 {
			s.Sqrt(new(big.Int).Lsh(s, P))
		}
		lo := new(big.Int).Rsh(s, P-64)
		hi := new(big.Int).Rsh(new(big.Int).Add(s, four), P-64)
		if lo.Cmp(hi) != 0 {
			panic("exp2 table: ambiguous truncation")
		}
		exp2Table[j-1] = lo
	}
	// Fixed-value checks (§2): entry_0 == isqrt(2^129), entry_63 == 2^64,
	// all entries in [2^64, 2^65) and strictly decreasing.
	one64 := new(big.Int).Lsh(big.NewInt(1), 64)
	one65 := new(big.Int).Lsh(big.NewInt(1), 65)
	if exp2Table[0].Cmp(new(big.Int).Sqrt(new(big.Int).Lsh(big.NewInt(1), 129))) != 0 {
		panic("exp2 table: entry 0")
	}
	if exp2Table[63].Cmp(one64) != 0 {
		panic("exp2 table: entry 63")
	}
	for k := range 64 {
		if exp2Table[k].Cmp(one64) < 0 || exp2Table[k].Cmp(one65) >= 0 {
			panic(fmt.Sprintf("exp2 table: entry %d out of range", k))
		}
		if k > 0 && exp2Table[k].Cmp(exp2Table[k-1]) >= 0 {
			panic(fmt.Sprintf("exp2 table: entry %d not decreasing", k))
		}
	}
	// Frozen table hash over u128-LE concatenation.
	buf := make([]byte, 0, 1024)
	var ent [16]byte
	for k := range 64 {
		lo := new(big.Int).And(exp2Table[k], new(big.Int).SetUint64(^uint64(0))).Uint64()
		hi := new(big.Int).Rsh(exp2Table[k], 64).Uint64()
		binary.LittleEndian.PutUint64(ent[:8], lo)
		binary.LittleEndian.PutUint64(ent[8:], hi)
		buf = append(buf, ent[:]...)
	}
	got := lumenref.DomainHash("", buf)
	want, _ := hex.DecodeString(exp2TableHashHex)
	if !equal32(got, want) {
		panic("exp2 table: hash mismatch against frozen constant")
	}
}

func equal32(a [32]byte, b []byte) bool {
	if len(b) != 32 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// PulseTargetV1 evaluates T_h = clamp(T_min, T_max,
// floor(T_a * 2^((t - t_a - 6*(h - h_a)) / 3600))) under the frozen §3
// rounding-order law.
//
// anchorTarget is T_a (contract: 1 <= T_a <= T_max); t is the parent
// block's median-time-past in integer seconds; (hA, tA) are the anchor
// height and median-time-past. Contract violations (h <= h_a, T_a out of
// range) are caller errors and panic rather than yielding a consensus
// verdict.
func PulseTargetV1(anchorTarget *big.Int, t, tA int64, h, hA uint64) *big.Int {
	if h <= hA {
		panic("pulse: h must exceed h_a")
	}
	if anchorTarget.Sign() < 1 || anchorTarget.Cmp(tMax) > 0 {
		panic("pulse: T_a out of range")
	}
	// 1. Exponent numerator, exact signed integer seconds.
	n := new(big.Int).SetInt64(t - tA)
	n.Sub(n, new(big.Int).Mul(big.NewInt(pulseTargetSpacingSeconds), new(big.Int).SetUint64(h-hA)))
	// 2. Euclidean division by 3600; f = floor(r * 2^64 / 3600).
	q, r := new(big.Int).DivMod(n, big.NewInt(pulseHalfLifeSeconds), new(big.Int))
	// big.Int.DivMod is Euclidean: 0 <= r < 3600.
	f := new(big.Int).Lsh(r, 64)
	f.Div(f, big.NewInt(pulseHalfLifeSeconds))
	// 3. Short circuits (exact equivalences, mandatory).
	if q.Cmp(big.NewInt(256)) >= 0 {
		return new(big.Int).Set(tMax)
	}
	if q.Cmp(big.NewInt(-257)) <= 0 {
		return big.NewInt(1)
	}
	// 4. Fractional walk, most-significant fractional bit first, flooring
	// at every step.
	acc := new(big.Int).Set(anchorTarget)
	for k := range 64 {
		if f.Bit(63-k) == 1 {
			acc.Mul(acc, exp2Table[k])
			acc.Rsh(acc, 64)
		}
	}
	// 5. Integer shift after the fractional walk.
	qi := q.Int64() // |q| <= 256 here
	if qi >= 0 {
		acc.Lsh(acc, uint(qi))
	} else {
		acc.Rsh(acc, uint(-qi))
	}
	// 6. Clamp into [1, 2^256 - 1].
	if acc.Sign() < 1 {
		return big.NewInt(1)
	}
	if acc.Cmp(tMax) > 0 {
		return new(big.Int).Set(tMax)
	}
	return acc
}

// U256FromLE converts a 32-byte little-endian unsigned integer.
func U256FromLE(b [32]byte) *big.Int {
	var be [32]byte
	for i := range b {
		be[31-i] = b[i]
	}
	return new(big.Int).SetBytes(be[:])
}

// U256ToLE converts to the canonical 32-byte little-endian form; v must be
// in [0, 2^256).
func U256ToLE(v *big.Int) [32]byte {
	var le [32]byte
	be := v.Bytes()
	for i, x := range be {
		le[len(be)-1-i] = x
	}
	return le
}
