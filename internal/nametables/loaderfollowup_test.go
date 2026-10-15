package nametables

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestN10G38OriginalProvenanceDenial(t *testing.T) {
	exe := make([]byte, 667648)
	copy(exe, "PS-X EXE")
	odd := make([]byte, 196608)
	_, err := BuildN10LoaderFollowup(N10LoaderHeaderReport{}, strings.Repeat("0", 64), exe, odd, 38474)
	if err == nil {
		t.Fatal("unattested G37 accepted")
	}
	ref := N10LoaderHeaderReport{Status: "PSX_EXE_HEADER_AND_STATIC_MAIN_ANCHORS_ONLY_N10_DO_NOT_BOOT", OriginalSourceIdentityVerified: true, HeaderParsed: true, StaticDirectOverlayJALCount: 2, StaticOverlayAddressPairCount: 48}
	if err = CheckN10FollowupInputs(ref, strings.Repeat("0", 64), exe, odd, 38474); err == nil {
		t.Fatal("wrong EXE hash accepted")
	}
	if err = CheckN10FollowupInputs(ref, strings.Repeat("0", 64), exe, odd, 123); err == nil {
		t.Fatal("wrong extent accepted")
	}
}

func TestN10G38SyntheticMainAnchorsOddBinAndNoPatchApproval(t *testing.T) {
	exe := make([]byte, 667648)
	copy(exe, "PS-X EXE")
	odd := make([]byte, 196608)
	put := func(b []byte, off int, w uint32) { binary.LittleEndian.PutUint32(b[off:], w) }
	// Two direct JAL instructions to the hypothetical overlay image.
	put(exe, 0x900, 0x0c000000|((uint32(0x80140c04)>>2)&0x03ffffff))
	put(exe, 0x920, 0x0c000000|((uint32(0x80142a2c)>>2)&0x03ffffff))
	// Forty-eight exact adjacent LUI/addiu references in a 20-byte-stride run.
	for i := 0; i < 48; i++ {
		off := 0x2000 + i*20
		put(exe, off, 0x3c048013)
		put(exe, off+4, 0x24842000)
	}
	calls, pairs := scanMainOverlayAnchorOffsets(exe)
	if len(calls) != 2 || len(pairs) != 48 || pairs[1].FileOffset-pairs[0].FileOffset != 20 {
		t.Fatalf("bad synthetic sites %d/%d", len(calls), len(pairs))
	}
	// Synthetic O.BIN contains one A site and a separate C+64 site.
	put(odd, 0x200, 0x3c04800d)
	put(odd, 0x204, 0x2484a188)
	put(odd, 0x300, 0x3c04800d)
	put(odd, 0x304, 0x2484a1dc)
	put(odd, 0x400, 0x0c000000|((uint32(0x80132100)>>2)&0x03ffffff))
	r := N10LoaderHeaderReport{Status: "PSX_EXE_HEADER_AND_STATIC_MAIN_ANCHORS_ONLY_N10_DO_NOT_BOOT", OriginalSourceIdentityVerified: true, HeaderParsed: true, StaticDirectOverlayJALCount: 2, StaticOverlayAddressPairCount: 48, OriginalEXESHA256: strings.Repeat("0", 64), ISOExtentsOverlappingGap: []N10ISOGapOccupant{{Path: N10OddBinPath, LBA: 38474, Size: 196608, Sectors: 96}}}
	for _, c := range calls {
		r.StaticDirectOverlayJALExamples = append(r.StaticDirectOverlayJALExamples, c)
	}
	for i, c := range pairs {
		if i < 32 {
			r.StaticOverlayAddressPairExamples = append(r.StaticOverlayAddressPairExamples, c)
		}
	}
	out, err := buildN10LoaderFollowupVerified(r, strings.Repeat("f", 64), exe, odd, 38474)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.MainDirectOverlayJAL) != 2 || len(out.MainOverlayAddressPairs) != 48 || len(out.MainAddressPairRuns) != 1 || out.MainAddressPairRuns[0].Count != 48 || out.MainAddressPairRuns[0].Stride20Pairs != 47 {
		t.Fatalf("bad loader static clustering: %+v", out.MainAddressPairRuns)
	}
	if out.OddBINABCUniqueSites != 1 || out.OddBINCPlus64DirectSites != 1 || out.OddBINStaticSelfJALCount != 1 {
		t.Fatalf("odd BIN evidence unexpected: %+v", out)
	}
	if out.SafeToPatch || out.RuntimeLoaderVerified || out.BSSAndWritableMemoryVerified || out.FullControlFlowVerified {
		t.Fatal("static evidence promoted to safety approval")
	}
	// Mutate an instruction and require a strict recount mismatch.
	put(exe, 0x2004, 0x00000000)
	if _, err = buildN10LoaderFollowupVerified(r, strings.Repeat("f", 64), exe, odd, 38474); err == nil {
		t.Fatal("site count changed without failure")
	}
}
