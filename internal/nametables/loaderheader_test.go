package nametables

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestN10LoaderHeaderSynthetic(t *testing.T) {
	exe := make([]byte, 0x3000)
	copy(exe, "PS-X EXE")
	put := func(off int, x uint32) { binary.LittleEndian.PutUint32(exe[off:], x) }
	put(0x10, 0x80041000)
	put(0x18, 0x80041000)
	put(0x1c, 0x2800)
	put(0x28, 0x800ca100)
	put(0x2c, 0x200)
	// Call into overlay window and adjacent LUI/ADDIU overlay base construction.
	put(0x800, 0x0c000000|(0x80132020>>2&0x03ffffff))
	put(0x804, 0x3c048013)
	put(0x808, 0x24842000)
	r := inspectPSXHeaderAndAnchors(exe)
	if !r.Header.LegacyMainBaseAgrees || !r.Header.DeclaredTextFitsFile || !r.Header.ScratchABCInsideDeclaredBSS || r.Header.RendererTailInsideDeclaredText || r.StaticDirectOverlayJALCount != 1 || r.StaticOverlayAddressPairCount != 1 || r.SafeToPatch || r.RuntimeLoaderVerified || r.RuntimeBSSClearVerified || !r.HeaderParsed {
		t.Fatalf("unexpected evidence report %+v", r)
	}
	if r.Header.FileOffsetToRAMBase != "0x80040800" || r.Header.TextRangeIfHonored != "[0x80041000,0x80043800)" {
		t.Fatalf("wrong mapped text range %+v", r.Header)
	}
	// Offset 0x800 is the first text byte, not raw header data.
	put(0x10, 0x0c000000|(0x80132020>>2&0x03ffffff))
	r = inspectPSXHeaderAndAnchors(exe)
	if r.StaticDirectOverlayJALCount != 1 {
		t.Fatal("PS-X header treated as code")
	}
	put(0x18, 0x80040000)
	r = inspectPSXHeaderAndAnchors(exe)
	if r.Header.LegacyMainBaseAgrees {
		t.Fatal("mismatched legacy base accepted")
	}
	put(0x18, 0xfffffff0)
	put(0x1c, 0xffffffff)
	put(0x28, 0xfffffff0)
	put(0x2c, 0xffffffff)
	r = inspectPSXHeaderAndAnchors(exe)
	if r.Header.TextRangeIsWithin2MiBRAM || r.Header.BSSRangeIsWithin2MiBRAM || r.Header.DeclaredTextFitsFile {
		t.Fatal("wrapped addresses accepted")
	}
}
func TestN10LoaderRejectUnattestedInput(t *testing.T) {
	_, err := AnalyzeN10LoadHeader([]byte("PS-X EXE"), GeometryReport{}, "fake")
	if err == nil || !strings.Contains(err.Error(), "unreviewed") {
		t.Fatalf("missing provenance was accepted: %v", err)
	}
}
