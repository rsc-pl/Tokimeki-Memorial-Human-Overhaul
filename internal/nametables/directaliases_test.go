package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func directFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	ex, ge := n10SyntheticABFixture(t)
	for _, tc := range []struct {
		raw   []byte
		pairs []AddressPair
		calls []struct {
			offset int
			word   uint32
		}
	}{
		{ex, verifiedFixedDirectEXE, fixedConsumerCallsEXE},
		{ge, verifiedFixedDirectGEKO, fixedConsumerCallsGEKO},
	} {
		for _, p := range tc.pairs {
			binary.LittleEndian.PutUint32(tc.raw[p.UpperOffset:], p.UpperWord)
			binary.LittleEndian.PutUint32(tc.raw[p.LowerOffset:], p.LowerWord)
		}
		for _, c := range tc.calls {
			binary.LittleEndian.PutUint32(tc.raw[c.offset:], c.word)
		}
	}
	for _, site := range inheritedFujisakiCode {
		binary.LittleEndian.PutUint32(ex[site.offset:], site.word)
	}
	// The EXE 0x3FFB8 conditional-branch delay-slot construction is deliberately
	// tested as a valid, guarded rewrite rather than arbitrary bit flipping.
	binary.LittleEndian.PutUint32(ex[0x3FFB8:], 0x15C00255)
	return ex, ge
}
func TestDirectFixedAliasesResearchCandidate(t *testing.T) {
	ex, ge := directFixture(t)
	ex0, ge0 := bytes.Clone(ex), bytes.Clone(ge)
	a, b, s, err := stageDirectFixedAliasesAfterIdentityProof(ex, ge)
	if err != nil {
		t.Fatal(err)
	}
	if !s.UnsafeToBoot || s.RuntimeApproved || s.Complete || s.EXEDirectRewrites != 3 || s.EXEInheritedRewrites != 1 || s.GEKODirectRewrites != 1 || len(s.UntouchedCases) != 2 {
		t.Fatalf("wrong safety status %+v", s)
	}
	if !bytes.Equal(ex, ex0) || !bytes.Equal(ge, ge0) {
		t.Fatal("modified input")
	}
	for _, tc := range []struct {
		old, now []byte
		pairs    []AddressPair
	}{{ex, a, verifiedFixedDirectEXE}, {ge, b, verifiedFixedDirectGEKO}} {
		allowed := map[int]bool{}
		for _, p := range tc.pairs {
			for j := 0; j < 4; j++ {
				allowed[p.UpperOffset+j] = true
				allowed[p.LowerOffset+j] = true
			}
		}
		if len(tc.pairs) == 3 { // two additional inherited Fujisaki instructions
			for j := 0; j < 4; j++ {
				allowed[0x3ff94+j] = true
				allowed[0x40068+j] = true
			}
		}
		diff := 0
		for i := range tc.old {
			if tc.old[i] != tc.now[i] {
				diff++
				if !allowed[i] {
					t.Fatalf("changed unrelated byte %#x", i)
				}
			}
		}
		if diff == 0 {
			t.Fatal("no alias addresses changed")
		}
	}
	// GEKO honorific-sensitive source at 0xF480 remains completely untouched.
	if !bytes.Equal(ge[0xF47C:0xF484], b[0xF47C:0xF484]) {
		t.Fatal("GEKO -san string source was aliased")
	}
	// The inherited site is now redirected, without changing its call.
	if binary.LittleEndian.Uint32(a[0x40064:]) != 0x0c02b838 || binary.LittleEndian.Uint32(a[0x40068:]) == 0x2484219c {
		t.Fatal("inherited source was not safely redirected")
	}
	if binary.LittleEndian.Uint32(a[0x3ffb4:]) != 0x3c048005 {
		t.Fatal("overwrote fall-through LUI")
	}
	if _, _, _, err := StageDirectFixedAliases(ex, ge); err == nil {
		t.Fatal("allowed unverified retail GEKO")
	}
}
func TestDirectFixedAliasesFailClosed(t *testing.T) {
	ex, ge := directFixture(t)
	tests := []struct {
		name    string
		corrupt func([]byte, []byte)
	}{
		{"source LUI", func(a, b []byte) { a[0x3FFE4] ^= 0x01 }},
		{"inherited branch", func(a, b []byte) { a[0x3ff98] ^= 1 }},
		{"inherited delay slot", func(a, b []byte) { a[0x3ff9c] ^= 1 }},
		{"inherited a0 producer", func(a, b []byte) { a[0x3ff94] ^= 1 }},
		{"inherited consumer", func(a, b []byte) { a[0x40068] ^= 1 }},
		{"GEKO source", func(a, b []byte) { b[0xF46C] ^= 1 }},
		{"EXE call", func(a, b []byte) { a[0x40098] ^= 1 }},
		{"GEKO call", func(a, b []byte) { b[0xF470] ^= 1 }},
		{"pool name identity", func(a, b []byte) { off := int(binary.LittleEndian.Uint32(a[PointerTable:]) - Base); a[off] = 0x41 }},
		{"pool pointer", func(a, b []byte) { a[PointerTable+4] ^= 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := bytes.Clone(ex), bytes.Clone(ge)
			tt.corrupt(a, b)
			beforeA, beforeB := bytes.Clone(a), bytes.Clone(b)
			outA, outB, _, err := stageDirectFixedAliasesAfterIdentityProof(a, b)
			if err == nil || outA != nil || outB != nil {
				t.Fatalf("fail-open %v", err)
			}
			if !bytes.Equal(a, beforeA) || !bytes.Equal(b, beforeB) {
				t.Fatal("partial write")
			}
		})
	}
}
