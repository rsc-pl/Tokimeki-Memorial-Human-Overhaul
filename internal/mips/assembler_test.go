package mips

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPythonAssemblerVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/python_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Source  string           `json:"source"`
		Origin  uint32           `json:"origin"`
		Symbols map[string]int64 `json:"symbols"`
		Hex     string           `json:"hex"`
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 200 {
		t.Fatal("too few reference vectors")
	}
	for i, tc := range vectors {
		got, err := Assemble(tc.Source, tc.Origin, tc.Symbols)
		if err != nil {
			t.Fatalf("vector %d: %v, source=%q", i, err, tc.Source)
		}
		expected, err := hex.DecodeString(tc.Hex)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("vector %d: MIPS bytes mismatch: got %x, want %x", i, got, expected)
		}
	}
}
func TestAssemblerRejectsInvalidCode(t *testing.T) {
	cases := []string{
		"badop t0, t1", "sll t0, t1, 32", "sll t0, t1, -1", "addiu t0, t1, 65536",
		"andi t0, t1, -1", "lui t0, 0x10000", "lw t0, 65536(t1)", "j 0x90000000",
		"j 0x80044441", "bne t0, t1, 0x80044441", "beqz t0, 0x80100000",
		"addu t0, t1", "nop garbage", "jr missing", "start: nop\nstart: nop", "jr not_a_reg", "lui t0, NOT_DEFINED",
	}
	for _, src := range cases {
		if _, err := Assemble(src, 0x8004443c, nil); err == nil {
			t.Errorf("accepted invalid source %q", src)
		}
	}
}
func TestAssemblerDoesNotMutateSymbols(t *testing.T) {
	syms := map[string]int64{"target": 0x80044000}
	x, err := Assemble("nop\nb: j target\nnop", 0x8004443c, syms)
	if err != nil {
		t.Fatal(err)
	}
	y, err := Assemble("nop\nb: j target\nnop", 0x8004443c, syms)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) || len(syms) != 1 {
		t.Fatal("symbols were mutated or compilation was not deterministic")
	}
}
func TestImmediateSignedBounds(t *testing.T) {
	for _, v := range []string{"-32768", "65535"} {
		if _, e := Assemble("addiu t0,t1,"+v, 0x8004443c, nil); e != nil {
			t.Fatal(e)
		}
	}
	for _, v := range []string{"-32769", "65536"} {
		if _, e := Assemble("addiu t0,t1,"+v, 0x8004443c, nil); e == nil {
			t.Fatal("unexpected acceptance " + v)
		}
	}
	if _, e := Assemble(strings.Repeat("nop\n", 3), 0xFFFFFFFC, nil); e == nil {
		t.Fatal("overflow accepted")
	}
}
