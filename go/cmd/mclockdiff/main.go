// Command mclockdiff is the independent Go adapter for the M-CLOCK
// differential corpus. It intentionally calls braidref.Compare rather than
// sharing the Rust adapter's implementation.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/mindchain/noosphere/go/braidref"
)

const (
	tupleBytes = 80
	pairBytes  = tupleBytes * 2
)

func parse(input []byte) braidref.ForkTuple {
	var tuple braidref.ForkTuple
	tuple.FinalizedEpoch = binary.LittleEndian.Uint64(input[0:8])
	tuple.JustifiedEpoch = binary.LittleEndian.Uint64(input[8:16])
	copy(tuple.WorkLE[:], input[16:48])
	copy(tuple.BlockHash[:], input[48:80])
	return tuple
}

func run() error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	if len(input)%pairBytes != 0 {
		return fmt.Errorf("M-CLOCK corpus is not an exact tuple-pair sequence")
	}
	output := make([]byte, 0, len(input)/pairBytes)
	for offset := 0; offset < len(input); offset += pairBytes {
		left := parse(input[offset : offset+tupleBytes])
		right := parse(input[offset+tupleBytes : offset+pairBytes])
		switch comparison := braidref.Compare(left, right); {
		case comparison > 0:
			output = append(output, 'a')
		case comparison < 0:
			output = append(output, 'b')
		default:
			output = append(output, '=')
		}
	}
	_, err = os.Stdout.Write(output)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
