// grainref-vec is the Go-side CLI shim for the Grain differential gate
// (tools/gates/differential_grain.py, plan §5.4). It is pure I/O plumbing
// over the independent go/grainref library.
//
// Line protocol (one request per line on stdin, one reply per line on
// stdout; empty byte strings are spelled "-"):
//
//	E <version> <meter_limit> <arena_limit> <subject_hex> <formula_hex>
//	  -> V <noun_hex> <charge>     (value outcome)
//	  -> T <trap_code> <charge>    (trap outcome; decode traps charge 0)
//	D <role: formula|subject> <hex>
//	  -> N <reencoded_hex>
//	  -> T <trap_code>
//
// The E runner order matches spec §14: version gate before decoding, then
// decode subject, decode formula, eval.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/mindchain/noosphere/go/grainref"
)

func parseHex(s string) ([]byte, error) {
	if s == "-" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

func hexOut(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			if e := handle(out, line); e != nil {
				fmt.Fprintf(os.Stderr, "grainref-vec: %v\n", e)
				out.Flush()
				os.Exit(2)
			}
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "grainref-vec: %v\n", err)
			os.Exit(2)
		}
	}
}

func handle(out *bufio.Writer, line string) error {
	fields := strings.Fields(line)
	switch fields[0] {
	case "E":
		if len(fields) != 6 {
			return fmt.Errorf("E wants 5 args, got %d", len(fields)-1)
		}
		version, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return err
		}
		meterLimit, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return err
		}
		arenaLimit, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return err
		}
		subjHex, err := parseHex(fields[4])
		if err != nil {
			return err
		}
		formHex, err := parseHex(fields[5])
		if err != nil {
			return err
		}
		m := grainref.NewMeter(meterLimit, arenaLimit)
		if uint32(version) != grainref.GrainVersion {
			_, tr := grainref.Eval(uint32(version), nil, nil, m)
			fmt.Fprintf(out, "T %d %d\n", tr, m.Spent())
			return nil
		}
		subj, tr := grainref.DecodeSubject(subjHex)
		if tr != grainref.TrapNone {
			fmt.Fprintf(out, "T %d 0\n", tr)
			return nil
		}
		form, tr := grainref.DecodeFormula(formHex)
		if tr != grainref.TrapNone {
			fmt.Fprintf(out, "T %d 0\n", tr)
			return nil
		}
		res, tr := grainref.Eval(uint32(version), subj, form, m)
		if tr != grainref.TrapNone {
			fmt.Fprintf(out, "T %d %d\n", tr, m.Spent())
			return nil
		}
		fmt.Fprintf(out, "V %s %d\n", hexOut(grainref.Encode(res)), m.Spent())
		return nil
	case "D":
		if len(fields) != 3 {
			return fmt.Errorf("D wants 2 args, got %d", len(fields)-1)
		}
		b, err := parseHex(fields[2])
		if err != nil {
			return err
		}
		var n *grainref.Noun
		var tr grainref.Trap
		switch fields[1] {
		case "formula":
			n, tr = grainref.DecodeFormula(b)
		case "subject":
			n, tr = grainref.DecodeSubject(b)
		default:
			return fmt.Errorf("unknown role %q", fields[1])
		}
		if tr != grainref.TrapNone {
			fmt.Fprintf(out, "T %d\n", tr)
			return nil
		}
		fmt.Fprintf(out, "N %s\n", hexOut(grainref.Encode(n)))
		return nil
	default:
		return fmt.Errorf("unknown command %q", fields[0])
	}
}
