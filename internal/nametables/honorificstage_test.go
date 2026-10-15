package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"tokimemo/internal/script"
)

func syntheticHonorificCandidate(t *testing.T) ([]byte, []byte, string) {
	t.Helper()
	ex, ge := directFixture(t)
	for i := ShortStart; i < ShortEnd; i++ {
		ex[i] = byte((i-ShortStart)*13 + 23)
	}
	binary.LittleEndian.PutUint32(ge[0xf47c:], 0x3c058014)
	binary.LittleEndian.PutUint32(ge[0xf480:], 0x24a54b24)
	binary.LittleEndian.PutUint32(ge[0xf484:], 0x0c02b83c)
	binary.LittleEndian.PutUint32(ge[0xf488:], 0x2484a190)
	copy(ge[0x12b24:], []byte{0x8a, 0xd9, 0x97, 0xd1, 0x82, 0xb3, 0x82, 0xf1, 0})
	return ex, ge, fmt.Sprintf("%x", sha256.Sum256(ex[ShortStart:ShortEnd]))
}
func TestHonorificResearchPreservesSuffixAndCopies(t *testing.T) {
	ex, ge, digest := syntheticHonorificCandidate(t)
	oldEXE, oldGEKO := bytes.Clone(ex), bytes.Clone(ge)
	n, g, r, err := stageHonorificAfterProof(ex, ge, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !r.UnsafeToBoot || r.Complete || r.RuntimeApproved || !r.UnknownIndirectConsumers || !r.OldCompactPoolReused || r.GEKOSites != 1 {
		t.Fatalf("unsafe success summary: %+v", r)
	}
	if !bytes.Equal(ex, oldEXE) || !bytes.Equal(ge, oldGEKO) {
		t.Fatal("mutated inputs")
	}
	encoded, err := (&script.PairEncoder{}).Encode("Tatebayashi-san")
	if err != nil {
		t.Fatal(err)
	}
	if r.BytesWithNUL != len(encoded)+1 || r.Destination != Base+ShortStart || !bytes.Equal(n[ShortStart:ShortStart+len(encoded)], encoded) || n[ShortStart+len(encoded)] != 0 {
		t.Fatal("honorific text truncated or missing")
	}
	if binary.LittleEndian.Uint32(g[0xf47c:]) != 0x3c05800b || binary.LittleEndian.Uint32(g[0xf480:]) != 0x24a53578 {
		t.Fatal("GEKO source pointer not redirected")
	}
	if binary.LittleEndian.Uint32(g[0xf484:]) != 0x0c02b83c {
		t.Fatal("GEKO call changed")
	}
	if !bytes.Equal(ge[0x12b24:0x12b30], g[0x12b24:0x12b30]) {
		t.Fatal("original GEKO literal overwritten")
	}
	for i := range ex {
		if ex[i] != n[i] && (i < ShortStart || i >= ShortStart+len(encoded)+1) {
			t.Fatalf("EXE unexpected diff %#x", i)
		}
	}
	for i := range ge {
		if ge[i] != g[i] && (i < 0xf47c || i >= 0xf484) {
			t.Fatalf("GEKO unexpected diff %#x", i)
		}
	}
}
func TestHonorificResearchFailClosed(t *testing.T) {
	checks := []struct {
		name   string
		mutate func([]byte, []byte)
	}{
		{"old pool", func(e, g []byte) { e[ShortStart] ^= 1 }},
		{"live old pointer", func(e, g []byte) { binary.LittleEndian.PutUint32(e[PointerTable:], Base+ShortStart) }},
		{"foreign old word pointer", func(e, g []byte) { binary.LittleEndian.PutUint32(e[0x100:], Base+ShortStart) }},
		{"GEKO old pointer", func(e, g []byte) { binary.LittleEndian.PutUint32(g[0x500:], Base+ShortStart) }},
		{"old GEKO san", func(e, g []byte) { g[0x12b24+7] ^= 1 }},
		{"GEKO LUI", func(e, g []byte) { g[0xf47c] ^= 1 }},
		{"GEKO source", func(e, g []byte) { g[0xf480] ^= 1 }},
		{"GEKO jal", func(e, g []byte) { g[0xf484] ^= 1 }},
		{"GEKO destination", func(e, g []byte) { g[0xf488] ^= 1 }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			e, g, h := syntheticHonorificCandidate(t)
			tc.mutate(e, g)
			saveE, saveG := bytes.Clone(e), bytes.Clone(g)
			a, b, _, err := stageHonorificAfterProof(e, g, h)
			if err == nil || a != nil || b != nil {
				t.Fatalf("accepted corruption: %v", err)
			}
			if !bytes.Equal(e, saveE) || !bytes.Equal(g, saveG) {
				t.Fatal("partial write")
			}
		})
	}
}
