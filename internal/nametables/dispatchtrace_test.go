package nametables

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestG40TraceBoundedStaticAndDecoder(t *testing.T) {
	exe := make([]byte, 667648)
	binary.LittleEndian.PutUint32(exe[233196:], 0x3C198012) // lui t9,8012
	binary.LittleEndian.PutUint32(exe[233200:], 0x8F393110) // lw t9,0x3110(t9)
	binary.LittleEndian.PutUint32(exe[233204:], 0x0320F809) // jalr ra,t9
	binary.LittleEndian.PutUint32(exe[233208:], 0x00000000)
	binary.LittleEndian.PutUint32(exe[233212:], 0x0C02719D) // JAL 8009C674
	report, err := n10TraceWindows(exe)
	if err != nil {
		t.Fatal(err)
	}
	if report.SafeToPatch || report.RuntimeLoaderVerified || report.BSSAndRAMOwnershipVerified {
		t.Fatal("static trace improperly approved patch")
	}
	if len(report.Windows) != 4 || report.SourceWindowBytes > 8192 {
		t.Fatalf("unbounded report %+v", report)
	}
	foundRead := false
	foundIndirect := false
	foundDirect := false
	for _, row := range report.Windows[0].Instructions {
		if row.FileOffset == 233200 && row.LexicalDecode == "lw $t9,12560($t9)" {
			foundRead = true
		}
		if row.FileOffset == 233204 && strings.HasPrefix(row.LexicalDecode, "jalr ") && row.ControlTarget == "indirect" {
			foundIndirect = true
		}
		if row.FileOffset == 233212 && row.ControlTarget == "0x8009C674" {
			foundDirect = true
		}
	}
	if !foundRead || !foundIndirect || !foundDirect {
		t.Fatalf("decode missing: read=%v indirect=%v direct=%v", foundRead, foundIndirect, foundDirect)
	}
}
func TestG40RejectsOtherOriginalEXEAndUnsafeReport(t *testing.T) {
	r := N10LoaderFollowupReport{Status: "G38_ORIGINAL_ODD_BIN_AND_MAIN_LOADER_ANCHORS_STATIC_ONLY_DO_NOT_BOOT", OriginalSourcesVerified: true, OwnerOriginalEXESHA256: N10OriginalEXESHA, MainOverlayAddressPairs: make([]N10RawWordWindow, 48), MainDirectOverlayJAL: make([]N10RawWordWindow, 2)}
	if _, err := BuildN10DispatchTrace(make([]byte, 667648), r, strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted forged original EXE")
	}
	r.SafeToPatch = true
	if _, err := BuildN10DispatchTrace(make([]byte, 667648), r, strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted patch approved report")
	}
}
func TestG40CorrectBranchSemantics(t *testing.T) {
	w := uint32(0x10000005) // b +5 instructions, target pc+24
	d, to := decodeN10Word(w, 0x80079400)
	if to != "0x80079418" || !strings.HasPrefix(d, "beq ") {
		t.Fatalf("bad branch: %s %s", d, to)
	}
	d, to = decodeN10Word(0x03E00008, 0x80079400)
	if to != "indirect" || d != "jr $ra" {
		t.Fatalf("bad JR: %s %s", d, to)
	}
}
