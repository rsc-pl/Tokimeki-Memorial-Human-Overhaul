package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
	"tokimemo/internal/script"
)

const syntheticSuffixGap = 0x15000

func detachedTestFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	original, combined := adjacentTestFixture(t)
	// A synthetic interior zero run with a nonzero byte after it; no
	// real-overlay allocation or ownership may be inferred from this fixture.
	original[syntheticSuffixGap+0x100] = 0x41
	combined[syntheticSuffixGap+0x100] = 0x41
	return original, combined
}

func TestDetachedPreservesOriginalGEKOLiterals(t *testing.T) {
	original, combined := detachedTestFixture(t)
	input := bytes.Clone(combined)
	output, summary, err := stageGEKODetachedAfterIdentityProof(original, combined, syntheticSuffixGap, 24)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SafeToBoot || summary.RuntimeOwnershipProved || !summary.OriginalLiteralSlotsPreserved || !summary.OldOrdinaryCallerPreserved || summary.RAMAddress != gekoOverlayRAMBase+syntheticSuffixGap || summary.BytesWithNUL != 17 {
		t.Fatalf("unsafe or invalid %+v", summary)
	}
	if !bytes.Equal(original[gekoAdjacentNamesStart:gekoAdjacentNamesEnd], output[gekoAdjacentNamesStart:gekoAdjacentNamesEnd]) {
		t.Fatal("lost original GEKO strings")
	}
	if !bytes.Equal(combined[0xf468:0xf474], output[0xf468:0xf474]) {
		t.Fatal("changed ordinary caller")
	}
	raw, err := (&script.PairEncoder{}).Encode("Tatebayashi-san")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output[syntheticSuffixGap:syntheticSuffixGap+len(raw)], raw) || output[syntheticSuffixGap+len(raw)] != 0 {
		t.Fatal("wrong encoded source")
	}
	if binary.LittleEndian.Uint32(output[0xf480:]) == binary.LittleEndian.Uint32(combined[0xf480:]) {
		t.Fatal("honorific source not redirected")
	}
	if !bytes.Equal(input, combined) {
		t.Fatal("input modified")
	}
	if out, _, err := StageGEKODetachedSuffixResearch(original, combined, syntheticSuffixGap, 24); err == nil || out != nil {
		t.Fatal("public gate accepted synthetic GEKO")
	}
}

func TestDetachedRejectsUnsafePreconditions(t *testing.T) {
	cases := []struct {
		name      string
		alter     func([]byte, []byte)
		off, size int
	}{
		{"literal overlap", nil, gekoAdjacentNamesStart, 24},
		{"callsite overlap", nil, 0xf470, 24},
		{"unaligned offset", nil, syntheticSuffixGap + 1, 24},
		{"too small", nil, syntheticSuffixGap, 16},
		{"out of bounds", nil, 0x10000000, 24},
		{"occupied original", func(o, c []byte) { o[syntheticSuffixGap] = 1 }, syntheticSuffixGap, 24},
		{"occupied candidate", func(o, c []byte) { c[syntheticSuffixGap] = 1 }, syntheticSuffixGap, 24},
		{"direct word ref", func(o, c []byte) { binary.LittleEndian.PutUint32(o[0x500:], gekoOverlayRAMBase+syntheticSuffixGap) }, syntheticSuffixGap, 24},
		{"derived pointer", func(o, c []byte) {
			binary.LittleEndian.PutUint32(o[0x500:], 0x3c058014)
			binary.LittleEndian.PutUint32(o[0x504:], 0x24a57000)
		}, syntheticSuffixGap, 24},
		{"original GEKO caller", func(o, c []byte) { c[0xf480] ^= 1 }, syntheticSuffixGap, 24},
		{"trailing zero tail", func(o, c []byte) { o[syntheticSuffixGap+0x100] = 0; c[syntheticSuffixGap+0x100] = 0 }, syntheticSuffixGap, 24},
		{"slice inside trailing zero tail", nil, 0x20000, 24},
		{"direct JAL target", func(o, c []byte) {
			binary.LittleEndian.PutUint32(o[0x100:], encodeDirectJump(3, gekoOverlayRAMBase+syntheticSuffixGap))
		}, syntheticSuffixGap, 24},
		{"direct branch target", func(o, c []byte) {
			binary.LittleEndian.PutUint32(o[0x100:], encodeDirectBranch(4, 0x100, syntheticSuffixGap))
		}, syntheticSuffixGap, 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, c := detachedTestFixture(t)
			if tc.alter != nil {
				tc.alter(o, c)
			}
			prior := bytes.Clone(c)
			out, _, err := stageGEKODetachedAfterIdentityProof(o, c, tc.off, tc.size)
			if err == nil || out != nil {
				t.Fatalf("accepted %s: %v", tc.name, err)
			}
			if !bytes.Equal(c, prior) {
				t.Fatal("mutated source on error")
			}
		})
	}
}
