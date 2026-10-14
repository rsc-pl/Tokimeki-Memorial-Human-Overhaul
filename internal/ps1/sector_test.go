package ps1

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Independently frozen vector from DOCS-04 legacy_scripts/tokipatch/cd.py.
func TestEDCECCPythonParity(t *testing.T) {
	s := make([]byte, SectorSize)
	s[0] = 0
	for i := 1; i < 11; i++ {
		s[i] = 255
	}
	s[11] = 0
	copy(s[12:16], []byte{0, 2, 0, 2})
	copy(s[16:24], []byte{0, 0, 8, 0, 0, 0, 8, 0})
	for i := 0; i < DataSize; i++ {
		s[24+i] = byte(i*73 + 19)
	}
	if e := RegenerateForm1(s); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		a, b     int
		expected string
	}{
		{0x818, 0x81c, "62428fdd"},
		{0x81c, 0x82c, "e6c9e7ffdbd6e840de41ea7de9dd06cc"},
		{0x8c8, 0x8d8, "b6e69452e1ce5a6c070995f0bc880a1b"},
		{0x920, 0x930, "afe57fabda6c5a76b48eeb9af0a6efd7"},
	} {
		if got := hex.EncodeToString(s[tc.a:tc.b]); got != tc.expected {
			t.Fatalf("%x-%x: %s want %s", tc.a, tc.b, got, tc.expected)
		}
	}
	if e := VerifyForm1(s); e != nil {
		t.Fatal(e)
	}
	s[0x818] ^= 1
	if e := VerifyForm1(s); e == nil {
		t.Fatal("corrupt EDC passed")
	}
}
func TestTailChecksums(t *testing.T) {
	x := []byte{12, 13, 14, 0, 0, 0x12, 0x10}
	if e := FixTailChecksum(x); e != nil {
		t.Fatal(e)
	}
	if !TailChecksumValid(x) {
		t.Fatal("checksum invalid")
	}
	x[0]++
	if TailChecksumValid(x) {
		t.Fatal("expected checksum mismatch")
	}
}
func TestDataQuirk(t *testing.T) {
	s := make([]byte, SectorSize)
	s[0x10] = 1
	s[0x18] = 2
	x, _ := Data(s)
	if !bytes.Equal(x[:1], []byte{1}) {
		t.Fatal("quirk wrong")
	}
}
