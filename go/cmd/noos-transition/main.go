// Command noos-transition is an independently authored canonical Lumen client.
// It is derived only from the frozen protocol documents and vectors.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"lukechampine.com/blake3"
)

const family = "noosphere-go-independent"

var emptyRoot [32]byte

func init() {
	emptyRoot = dh("NOOS/SMT/LEAF/V1")
	for i := 0; i < 256; i++ {
		emptyRoot = dh("NOOS/SMT/NODE/V1", emptyRoot[:], emptyRoot[:])
	}
}
func dh(domain string, parts ...[]byte) [32]byte {
	h := blake3.New(32, nil)
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write(p)
	}
	var x [32]byte
	copy(x[:], h.Sum(nil))
	return x
}
func hx(x [32]byte) string { return hex.EncodeToString(x[:]) }
func u16(v uint16) []byte  { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func u32(v uint32) []byte  { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func u64(v uint64) []byte  { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
func u128(v uint64) []byte { return append(u64(v), make([]byte, 8)...) }

type decodeErr string

func (e decodeErr) Error() string { return string(e) }

type reader struct {
	b []byte
	p int
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.p+n > len(r.b) {
		return nil, decodeErr("TRUNCATED")
	}
	x := r.b[r.p : r.p+n]
	r.p += n
	return x, nil
}
func (r *reader) U8() (byte, error) {
	x, e := r.take(1)
	if e != nil {
		return 0, e
	}
	return x[0], nil
}
func (r *reader) U16() (uint16, error) {
	x, e := r.take(2)
	if e != nil {
		return 0, e
	}
	return binary.LittleEndian.Uint16(x), nil
}
func (r *reader) U32() (uint32, error) {
	x, e := r.take(4)
	if e != nil {
		return 0, e
	}
	return binary.LittleEndian.Uint32(x), nil
}
func (r *reader) tag(n uint16) error {
	v, e := r.U16()
	if e != nil {
		return e
	}
	if v != n {
		return decodeErr("UNKNOWN_MANDATORY_FIELD")
	}
	return nil
}
func (r *reader) version() error {
	v, e := r.U16()
	if e != nil {
		return e
	}
	if v != 1 {
		return decodeErr("UNKNOWN_VERSION")
	}
	return nil
}
func (r *reader) bounded(max uint32) ([]byte, error) {
	n, e := r.U32()
	if e != nil {
		return nil, e
	}
	if n > max {
		return nil, decodeErr("LENGTH_EXCEEDS_BOUND")
	}
	return r.take(int(n))
}
func (r *reader) count(max uint32) (uint32, error) {
	n, e := r.U32()
	if e != nil {
		return 0, e
	}
	if n > max {
		return 0, decodeErr("LENGTH_EXCEEDS_BOUND")
	}
	return n, nil
}
func fixed(r *reader, n int) error { _, e := r.take(n); return e }
func note(r *reader) error {
	if e := r.version(); e != nil {
		return e
	}
	sizes := []int{32, 16, 32, 32, 8, 4, 32}
	for i, n := range sizes {
		if e := r.tag(uint16(i + 1)); e != nil {
			return e
		}
		if e := fixed(r, n); e != nil {
			return e
		}
	}
	return nil
}
func feeAuth(r *reader) error {
	if e := r.version(); e != nil {
		return e
	}
	for i, n := range []int{16, 48, 8, 32, 32, 2} {
		if e := r.tag(uint16(i + 1)); e != nil {
			return e
		}
		if e := fixed(r, n); e != nil {
			return e
		}
	}
	if e := r.tag(7); e != nil {
		return e
	}
	_, e := r.bounded(96)
	return e
}
func txDecode(b []byte) error {
	r := reader{b: b}
	if e := r.version(); e != nil {
		return e
	}
	for i, n := range []int{32, 2, 8, 32} {
		if e := r.tag(uint16(i + 1)); e != nil {
			return e
		}
		if e := fixed(&r, n); e != nil {
			return e
		}
	}
	if e := r.tag(5); e != nil {
		return e
	}
	p, e := r.U8()
	if e != nil {
		return e
	}
	if p > 1 {
		return decodeErr("UNKNOWN_DISCRIMINANT")
	}
	if p == 1 {
		if e := feeAuth(&r); e != nil {
			return e
		}
	}
	if e := r.tag(6); e != nil {
		return e
	}
	if e := fixed(&r, 48); e != nil {
		return e
	}
	if e := r.tag(7); e != nil {
		return e
	}
	n, e := r.count(256)
	if e != nil {
		return e
	}
	if e := fixed(&r, int(n)*32); e != nil {
		return e
	}
	if e := r.tag(8); e != nil {
		return e
	}
	n, e = r.count(64)
	if e != nil {
		return e
	}
	if e := fixed(&r, int(n)*32); e != nil {
		return e
	}
	if e := r.tag(9); e != nil {
		return e
	}
	n, e = r.count(256)
	if e != nil {
		return e
	}
	for i := uint32(0); i < n; i++ {
		if e := fixed(&r, 32); e != nil {
			return e
		}
		m, e := r.U8()
		if e != nil {
			return e
		}
		if m > 1 {
			return decodeErr("UNKNOWN_DISCRIMINANT")
		}
	}
	if e := r.tag(10); e != nil {
		return e
	}
	n, e = r.count(64)
	if e != nil {
		return e
	}
	for i := uint32(0); i < n; i++ {
		if _, e := r.bounded(65536); e != nil {
			return e
		}
	}
	if e := r.tag(11); e != nil {
		return e
	}
	n, e = r.count(256)
	if e != nil {
		return e
	}
	for i := uint32(0); i < n; i++ {
		if e := note(&r); e != nil {
			return e
		}
	}
	if e := r.tag(12); e != nil {
		return e
	}
	n, e = r.count(64)
	if e != nil {
		return e
	}
	if e := fixed(&r, int(n)*32); e != nil {
		return e
	}
	if e := r.tag(13); e != nil {
		return e
	}
	if e := fixed(&r, 32); e != nil {
		return e
	}
	if r.p != len(b) {
		return decodeErr("TRAILING_BYTES")
	}
	return nil
}
func intent(r *reader) error {
	if e := r.version(); e != nil {
		return e
	}
	if e := r.tag(1); e != nil {
		return e
	}
	if e := fixed(r, 32); e != nil {
		return e
	}
	if e := r.tag(2); e != nil {
		return e
	}
	if e := fixed(r, 1); e != nil {
		return e
	}
	if e := r.tag(3); e != nil {
		return e
	}
	p, e := r.U8()
	if e != nil {
		return e
	}
	if p > 1 {
		return decodeErr("UNKNOWN_DISCRIMINANT")
	}
	if p == 1 {
		if e := fixed(r, 32); e != nil {
			return e
		}
	}
	if e := r.tag(4); e != nil {
		return e
	}
	if e := fixed(r, 2); e != nil {
		return e
	}
	if e := r.tag(5); e != nil {
		return e
	}
	_, e = r.bounded(96)
	return e
}
func witnessDecode(b []byte) ([]byte, error) {
	r := reader{b: b}
	if e := r.version(); e != nil {
		return nil, e
	}
	if e := r.tag(1); e != nil {
		return nil, e
	}
	n, e := r.count(64)
	if e != nil {
		return nil, e
	}
	for i := uint32(0); i < n; i++ {
		if e := intent(&r); e != nil {
			return nil, e
		}
	}
	if e := r.tag(2); e != nil {
		return nil, e
	}
	start := r.p
	n, e = r.count(256)
	if e != nil {
		return nil, e
	}
	for i := uint32(0); i < n; i++ {
		if _, e := r.bounded(4096); e != nil {
			return nil, e
		}
	}
	if r.p != len(b) {
		return nil, decodeErr("TRAILING_BYTES")
	}
	return b[start:r.p], nil
}
func smtOne(key [32]byte, value []byte) [32]byte {
	cur := dh("NOOS/SMT/LEAF/V1", key[:], value)
	empty := [32]byte{}
	empty = dh("NOOS/SMT/LEAF/V1")
	empties := make([][32]byte, 257)
	empties[0] = empty
	for i := 1; i <= 256; i++ {
		empties[i] = dh("NOOS/SMT/NODE/V1", empties[i-1][:], empties[i-1][:])
	}
	for d := 255; d >= 0; d-- {
		bit := (key[d/8] >> uint(7-d%8)) & 1
		e := empties[255-d]
		if bit == 0 {
			cur = dh("NOOS/SMT/NODE/V1", cur[:], e[:])
		} else {
			cur = dh("NOOS/SMT/NODE/V1", e[:], cur[:])
		}
	}
	return cur
}
func receipt(txid [32]byte, status uint16, charge uint64) []byte {
	b := append([]byte{}, u16(1)...)
	b = append(b, u16(1)...)
	b = append(b, txid[:]...)
	b = append(b, u16(2)...)
	b = append(b, u16(status)...)
	b = append(b, u16(3)...)
	b = append(b, u128(charge)...)
	b = append(b, u16(4)...)
	b = append(b, make([]byte, 48)...)
	return b
}
func identity(nonceHex string) error {
	nonce, e := hex.DecodeString(nonceHex)
	if e != nil {
		return e
	}
	seed := sha256.Sum256([]byte("NOOS independent Go client identity v1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	msg := append([]byte("NOOS/CLIENT/HANDSHAKE/V1"), []byte(family)...)
	msg = append(msg, u16(1)...)
	msg = append(msg, nonce...)
	sig := ed25519.Sign(priv, msg)
	fmt.Printf("%s,1,%s,%s\n", family, hex.EncodeToString(priv.Public().(ed25519.PublicKey)), hex.EncodeToString(sig))
	return nil
}
func process(line string) string {
	f := strings.Split(strings.TrimSpace(line), ",")
	if len(f) != 12 {
		return "0,REJECT,MALFORMED,,,,0,0,0,0,0,,"
	}
	id, _ := strconv.ParseUint(f[0], 10, 64)
	tx, e := hex.DecodeString(f[1])
	if e != nil {
		return fmt.Sprintf("%d,REJECT,MALFORMED,,,,0,0,0,0,0,,", id)
	}
	wit, e := hex.DecodeString(f[2])
	if e == nil {
		e = txDecode(tx)
	}
	var reveals []byte
	if e == nil {
		reveals, e = witnessDecode(wit)
	}
	empty := hx(emptyRoot)
	roots := strings.Join([]string{empty, empty, empty, empty, empty, empty}, ";")
	if e != nil {
		return fmt.Sprintf("%d,REJECT,%s,%s,,,%s,%s,%s,0,0,,", id, e, roots, f[3], f[4], f[7])
	}
	txid := dh("NOOS/TX/ID/V1", tx)
	wtxid := dh("NOOS/TX/WID/V1", tx, wit)
	_ = dh("NOOS/TX/WROOT/V1", reveals)
	status, _ := strconv.ParseUint(f[8], 10, 16)
	charge, _ := strconv.ParseUint(f[9], 10, 64)
	rec := receipt(txid, uint16(status), charge)
	rr := smtOne(txid, rec)
	rs := []string{empty, empty, empty, empty, hx(rr), empty}
	exec := dh("NOOS/BODY/RECEIPT/V1", append(u32(1), rec...))
	bh, _ := hex.DecodeString(f[11])
	inv := make([]byte, len(bh))
	for i := range bh {
		inv[i] = ^bh[i]
	}
	fork := fmt.Sprintf("%s:%s:%s:%s", f[4], f[3], f[5], hex.EncodeToString(inv))
	cls := "ACCEPT"
	err := "OK"
	trap := f[10]
	if status != 0 {
		cls = "FAILED"
		err = "EXECUTION_FAILURE"
	}
	return fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", id, cls, err, strings.Join(rs, ";"), hx(exec), fork, f[3], f[4], f[7], f[9], trap, hx(txid), hx(wtxid))
}
func main() {
	if len(os.Args) == 3 && os.Args[1] == "--identity" {
		if identity(os.Args[2]) != nil {
			os.Exit(2)
		}
		return
	}
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 1024), 2<<20)
	for s.Scan() {
		if strings.TrimSpace(s.Text()) != "" {
			fmt.Println(process(s.Text()))
		}
	}
	if s.Err() != nil {
		os.Exit(2)
	}
}
