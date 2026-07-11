package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mindchain/noosphere/go/braidref"
	"github.com/mindchain/noosphere/go/conformance"
)

// The vectors subcommand must fully pass against the frozen corpus.
func TestVectorsSubcommand(t *testing.T) {
	wd, _ := os.Getwd()
	root, err := conformance.FindVectorRoot(wd)
	if err != nil {
		t.Fatalf("vector root: %v", err)
	}
	if code := cmdVectors([]string{"--root", root}); code != 0 {
		t.Fatalf("vectors exit code %d", code)
	}
}

// header-chain accepts a well-linked chain and rejects a broken link.
func TestHeaderChainSubcommand(t *testing.T) {
	wd, _ := os.Getwd()
	root, err := conformance.FindVectorRoot(wd)
	if err != nil {
		t.Fatalf("vector root: %v", err)
	}
	// Take the frozen valid header as the base and derive two children.
	blob, err := os.ReadFile(filepath.Join(root, "braid", "braid-header-validation-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Cases []struct {
			Name    string `json:"name"`
			Bytes   string `json:"bytes"`
			ChainID string `json:"chain_id"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(blob, &vf); err != nil {
		t.Fatal(err)
	}
	var baseHex, chainID string
	for _, c := range vf.Cases {
		if c.Name == "valid-structure" {
			baseHex, chainID = c.Bytes, c.ChainID
		}
	}
	raw, _ := hex.DecodeString(baseHex)
	h0, err := braidref.DecodeHeader(raw)
	if err != nil {
		t.Fatalf("decode base header: %v", err)
	}
	h1 := *h0
	h1.Height = h0.Height + 1
	h1.Slot = h0.Slot + 1
	h1.ParentHash = h0.BlockHash()
	h2 := h1
	h2.Height = h1.Height + 1
	h2.Slot = h1.Slot + 2
	h2.ParentHash = h1.BlockHash()

	write := func(headers ...*braidref.BlockHeaderV1) string {
		f := headerChainFile{ChainID: chainID}
		for _, h := range headers {
			f.Headers = append(f.Headers, hex.EncodeToString(h.Encode()))
		}
		blob, _ := json.Marshal(f)
		p := filepath.Join(t.TempDir(), "chain.json")
		if err := os.WriteFile(p, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if code := cmdHeaderChain([]string{write(h0, &h1, &h2)}); code != 0 {
		t.Fatal("valid chain rejected")
	}
	broken := h2
	broken.ParentHash[0] ^= 1
	if code := cmdHeaderChain([]string{write(h0, &h1, &broken)}); code == 0 {
		t.Fatal("broken link accepted")
	}
}
