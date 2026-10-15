package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
	"tokimemo/internal/script"
)

func adjacentTestFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	exe, geko := directFixture(t)
	copy(geko[gekoAdjacentNamesStart:gekoAdjacentNamesEnd], []byte{0x8a, 0xd9, 0x97, 0xd1, 0, 0, 0, 0, 0x8a, 0xd9, 0x97, 0xd1, 0x82, 0xb3, 0x82, 0xf1, 0, 0, 0, 0})
	for _, p := range []struct {
		off  int
		word uint32
	}{
		{0xf47c, 0x3c058014}, {0xf480, 0x24a54b24},
		{0xf484, 0x0c02b83c}, {0xf488, 0x2484a190},
	} {
		binary.LittleEndian.PutUint32(geko[p.off:], p.word)
	}
	_, combined, _, err := combinePartialAfterIdentityProof(exe, geko)
	if err != nil {
		t.Fatal(err)
	}
	return geko, combined
}

func TestGEKOAdjacentHonorificCandidate(t *testing.T) {
	orig, combined := adjacentTestFixture(t)
	saved := bytes.Clone(combined)
	result, detail, err := stageGEKOAdjacentAfterIdentityProof(orig, combined)
	if err != nil {
		t.Fatal(err)
	}
	if detail.OriginalSlotsBytes != 20 || detail.NewBytesWithNUL != 17 || detail.RemainingBytes != 3 ||
		!detail.HonorificPreserved || !detail.OrdinaryAliasUnchanged || !detail.UnknownIndirectConsumers || detail.DerivedSiteCandidates != 2 || detail.DerivedUnknownCandidates != 0 ||
		detail.Complete || detail.RuntimeApproved || !detail.UnsafeToBoot {
		t.Fatalf("unsafe summary: %+v", detail)
	}
	raw, err := (&script.PairEncoder{}).Encode("Tatebayashi-san")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result[gekoAdjacentNamesStart:gekoAdjacentNamesStart+len(raw)], raw) || result[gekoAdjacentNamesStart+len(raw)] != 0 {
		t.Fatal("incorrect string")
	}
	if binary.LittleEndian.Uint32(result[0xf480:]) != 0x24a54b1c {
		t.Fatalf("wrong target: %#x", binary.LittleEndian.Uint32(result[0xf480:]))
	}
	if !bytes.Equal(result[0xf468:0xf474], combined[0xf468:0xf474]) {
		t.Fatal("ordinary surname changed")
	}
	if !bytes.Equal(combined, saved) {
		t.Fatal("input mutated")
	}
	if _, _, err = StageGEKOAdjacentHonorificResearch(orig, combined); err == nil {
		t.Fatal("public entry accepted synthetic game bytes")
	}
}

func TestGEKOAdjacentFailClosed(t *testing.T) {
	failures := []struct {
		name  string
		alter func(o, c []byte)
	}{
		{"original literal", func(o, c []byte) { o[0x12b1c] ^= 1 }},
		{"staged literal", func(o, c []byte) { c[0x12b24] ^= 1 }},
		{"ordinary not relocated", func(o, c []byte) {
			binary.LittleEndian.PutUint32(c[0xf468:], 0x3c058014)
			binary.LittleEndian.PutUint32(c[0xf46c:], 0x24a54b1c)
		}},
		{"ordinary wrong target", func(o, c []byte) { binary.LittleEndian.PutUint32(c[0xf46c:], 0x24a50001) }},
		{"honorific high", func(o, c []byte) { c[0xf47c] ^= 1 }},
		{"honorific low", func(o, c []byte) { c[0xf480] ^= 1 }},
		{"honorific call", func(o, c []byte) { c[0xf484] ^= 1 }},
		{"honorific destination", func(o, c []byte) { c[0xf488] ^= 1 }},
		{"additional xref", func(o, c []byte) {
			binary.LittleEndian.PutUint32(o[0x500:], 0x3c058014)
			binary.LittleEndian.PutUint32(o[0x504:], 0x24a54b1c)
		}},
		{"aligned data pointer", func(o, c []byte) { binary.LittleEndian.PutUint32(o[0x500:], 0x80144b1c) }},
		{"computed source missed by old scanner", func(o, c []byte) {
			binary.LittleEndian.PutUint32(o[0x500:], 0x3c058014) // lui a1,8014
			binary.LittleEndian.PutUint32(o[0x504:], 0x24a54b10) // below source interval
			binary.LittleEndian.PutUint32(o[0x508:], 0x24a5000c) // enters first GEKO name
		}},
		{"original B destination", func(o, c []byte) { o[0xf488] ^= 1 }},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			o, c := adjacentTestFixture(t)
			tc.alter(o, c)
			before := bytes.Clone(c)
			out, _, err := stageGEKOAdjacentAfterIdentityProof(o, c)
			if err == nil || out != nil {
				t.Fatalf("accepted bad candidate: %v", err)
			}
			if !bytes.Equal(c, before) {
				t.Fatal("modified failed input")
			}
		})
	}
}
