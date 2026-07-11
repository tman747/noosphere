// Command noos-verify is the CLI of the independent Go base client
// (plan §8.5): it runs the frozen conformance-vector corpus and verifies
// header chains.
//
// Subcommands:
//
//	noos-verify vectors [--root DIR]     run every understood vector file
//	noos-verify header-chain FILE        verify a JSON header chain
//	noos-verify version                  print version and library pins
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mindchain/noosphere/go/braidref"
	"github.com/mindchain/noosphere/go/conformance"
)

const version = "noos-verify 0.1.0 (independent Go base client, plan §8.5)"

const pins = `library pins (standard cryptographic libraries only):
  lukechampine.com/blake3            v1.4.1   BLAKE3-256 (domain hashes)
  github.com/consensys/gnark-crypto  v0.19.0  BLS12-381 pairing + hash-to-G2
independence: authored from frozen protocol/ documents and vectors only;
no generated codec, no Rust FFI, no consensus library, no verifier core,
no copied oracle; crates/noos-* sources never read.`

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "vectors":
		os.Exit(cmdVectors(os.Args[2:]))
	case "header-chain":
		os.Exit(cmdHeaderChain(os.Args[2:]))
	case "version":
		fmt.Println(version)
		fmt.Println(pins)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: noos-verify vectors [--root DIR] | header-chain FILE | version")
}

func cmdVectors(args []string) int {
	fs := flag.NewFlagSet("vectors", flag.ExitOnError)
	root := fs.String("root", "", "protocol/vectors directory (default: search upward from cwd)")
	_ = fs.Parse(args)
	dir := *root
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		dir, err = conformance.FindVectorRoot(wd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	files, err := conformance.VectorFiles(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	totalPass, totalFail, totalSkip, notUnderstood := 0, 0, 0, 0
	exit := 0
	for _, f := range files {
		rep, err := conformance.RunFile(f)
		if err != nil {
			fmt.Printf("ERROR %-58s %v\n", f, err)
			exit = 1
			continue
		}
		if rep == nil {
			notUnderstood++
			fmt.Printf("SKIP  %-58s (family outside base-client scope)\n", f)
			continue
		}
		pass, fail, skip := rep.Counts()
		totalPass += pass
		totalFail += fail
		totalSkip += skip
		status := "PASS"
		if fail > 0 {
			status = "FAIL"
			exit = 1
		}
		fmt.Printf("%s  %-58s pass=%-4d fail=%-4d skip=%d\n", status, rep.File, pass, fail, skip)
		for _, c := range rep.Cases {
			if c.Status == conformance.Fail {
				fmt.Printf("      FAIL %s: %s\n", c.Name, c.Detail)
			}
		}
	}
	fmt.Printf("\ntotal: pass=%d fail=%d skip=%d (skips are the recorded weft checker-semantics seam); %d file(s) outside scope\n",
		totalPass, totalFail, totalSkip, notUnderstood)
	return exit
}

// headerChainFile is the header-chain input: a chain id plus canonical
// header encodings in ascending height order.
type headerChainFile struct {
	ChainID string   `json:"chain_id"`
	Headers []string `json:"headers"`
}

func cmdHeaderChain(args []string) int {
	if len(args) != 1 {
		usage()
		return 2
	}
	blob, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var f headerChainFile
	if err := json.Unmarshal(blob, &f); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cid, err := hex.DecodeString(f.ChainID)
	if err != nil || len(cid) != 32 {
		fmt.Fprintln(os.Stderr, "chain_id must be 32 hex bytes")
		return 1
	}
	var chainID [32]byte
	copy(chainID[:], cid)
	var prev *braidref.BlockHeaderV1
	for i, hx := range f.Headers {
		raw, err := hex.DecodeString(hx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "header %d: bad hex: %v\n", i, err)
			return 1
		}
		h, err := braidref.DecodeHeader(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "header %d: decode: %v\n", i, err)
			return 1
		}
		if err := braidref.ValidateStructure(h, chainID); err != nil {
			fmt.Fprintf(os.Stderr, "header %d (height %d): %v\n", i, h.Height, err)
			return 1
		}
		if prev != nil {
			if err := braidref.ValidateChainLink(prev, h); err != nil {
				fmt.Fprintf(os.Stderr, "header %d: %v\n", i, err)
				return 1
			}
		}
		prev = h
	}
	last := prev
	if last == nil {
		fmt.Println("empty chain: nothing to verify")
		return 0
	}
	tip := last.BlockHash()
	fmt.Printf("header chain OK: %d headers, tip height %d, tip hash %s\n",
		len(f.Headers), last.Height, hex.EncodeToString(tip[:]))
	return 0
}
