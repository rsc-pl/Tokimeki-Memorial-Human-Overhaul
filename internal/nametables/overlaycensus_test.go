package nametables

import (
	"encoding/binary"
	"testing"
)

func TestN10DiscCandidate(t *testing.T) {
	for _, c := range []struct {
		p         string
		dir, want bool
	}{{EXE, false, true}, {Geko, false, true}, {"OTHER.EXN", false, true}, {"CDROM/EXEDIR/AREA.EXE", false, true}, {"GEKO.EXN", true, false}, {"CDROM/DADIR/TR02.DA", false, false}, {"FOO.EXN.BAK", false, false}} {
		if got := N10DiscCodeCandidate(c.p, c.dir); got != c.want {
			t.Errorf("%q: %v want %v", c.p, got, c.want)
		}
	}
}
func TestN10OverlayCensusFindsAdditionalOverlaySites(t *testing.T) {
	raw := make([]byte, 128)
	binary.LittleEndian.PutUint32(raw[0:], 0x3c04800d)  // LUI a0,0x800d
	binary.LittleEndian.PutUint32(raw[4:], 0x2484a188)  // ADDIU a0,a0,-24184 => 0x800ca188
	binary.LittleEndian.PutUint32(raw[48:], 0x800ca190) // stored pointer to B
	s, e := ScanN10ExecutableSource("CDROM/EXEDIR/OTHER.EXN", raw)
	if e != nil {
		t.Fatal(e)
	}
	if s.DirectPairs < 1 || s.AlignedPointerWords != 1 || s.StaticCandidates < 2 {
		t.Fatalf("missed A/B: %+v", s)
	}
	s1, _ := ScanN10ExecutableSource(EXE, make([]byte, 4))
	s2, _ := ScanN10ExecutableSource(Geko, make([]byte, 4))
	d, e := BuildN10DiscCensus([]OverlaySourceCensus{s, s2, s1})
	if e != nil {
		t.Fatal(e)
	}
	if d.OtherSourcesWithCandidates != 1 || d.SafeToRelocate || d.CompleteDiscCodeCoverage {
		t.Fatalf("unsafe status: %+v", d)
	}
	if d.Sources[0].Path != Geko {
		t.Fatalf("not sorted: %+v", d.Sources)
	}
}
func TestN10OverlayCensusFailsClosed(t *testing.T) {
	if _, e := ScanN10ExecutableSource("BAD.EXN", make([]byte, 5)); e == nil {
		t.Fatal("unaligned accepted")
	}
	a := OverlaySourceCensus{Path: EXE}
	g := OverlaySourceCensus{Path: Geko}
	for _, sources := range [][]OverlaySourceCensus{{a}, {a, a, g}, {a, g, {Path: "A.TXT"}}} {
		if _, e := BuildN10DiscCensus(sources); e == nil {
			t.Fatalf("bad set accepted %+v", sources)
		}
	}
}
