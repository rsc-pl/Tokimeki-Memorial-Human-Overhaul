package nametables

import (
	"encoding/binary"
	"testing"
)

func encodeWords(words ...uint32) []byte {
	b := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[i*4:], w)
	}
	return b
}
func TestDerivedGEKOReferences(t *testing.T) {
	const address = uint32(0x80144b1c)
	tests := []struct {
		name    string
		words   []uint32
		address uint32
		min     int
	}{
		{"direct", []uint32{0x3c058014, 0x24a54b1c}, address, 1},
		{"split low offset", []uint32{0x3c058014, 0x24a54b10, 0x24a5000c}, address, 1},
		{"register copy", []uint32{0x3c058014, 0x24a54b10, 0x00a03021, 0x24c6000c}, address, 1},
		{"read from aliased pointer", []uint32{0x3c058014, 0x24a54b10, 0x00a03021, 0x8cc6000c}, address, 1},
		{"store to aliased pointer", []uint32{0x3c058014, 0x24a54b10, 0x00a03021, 0xacc7000c}, address, 1},
		{"delay slot read", []uint32{0x3c058014, 0x24a54b10, 0x0c000123, 0x8ca6000c, 0x8ca6000c}, address, 1},
		{"clobber blocks old pointer", []uint32{0x3c058014, 0x24a54b10, 0x24050000, 0x24a5000c}, address, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := append(encodeWords(tc.words...), make([]byte, 16)...)
			refs, err := FindDerivedLiteralReferences(b, address, address+20, 32)
			if err != nil {
				t.Fatal(err)
			}
			if len(refs) < tc.min {
				t.Fatalf("expected >=%d matches, got %#v", tc.min, refs)
			}
		})
	}
}
func TestDerivedClobberAndBranch(t *testing.T) {
	const a = uint32(0x80144b1c)
	for _, words := range [][]uint32{
		{0x3c058014, 0x24a54b10, 0x24050000, 0x24a5000c},
		{0x3c058014, 0x10000000, 0, 0x24a54b1c},
	} {
		refs, err := FindDerivedLiteralReferences(encodeWords(words...), a, a+20, 32)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range refs {
			if v.Address == a {
				t.Fatalf("false positive past clobber/branch: %+v", v)
			}
		}
	}
}
func TestDerivedUnchangedInputAndFailures(t *testing.T) {
	b := encodeWords(0x3c058014, 0x24a54b1c)
	_, e := FindDerivedLiteralReferences(b, 0x80144b1c, 0x80144b30, 129)
	if e == nil {
		t.Fatal("accepted unreasonable window")
	}
	_, e = FindDerivedLiteralReferences(b[:3], 0x80144b1c, 0x80144b30, 32)
	if e == nil {
		t.Fatal("accepted truncated instruction")
	}
	_, e = FindDerivedLiteralReferences(b, 0x80144b1c, 0x80144b1c, 32)
	if e == nil {
		t.Fatal("accepted empty interval")
	}
}
