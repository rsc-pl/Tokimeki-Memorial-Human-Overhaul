package nametables

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadG42OwnerEvidence(t *testing.T) (N10DispatchTraceReport, GeometryReport) {
	t.Helper()
	base := filepath.Join("..", "..", ".local", "go_toolchain", "reports")
	raw, e := os.ReadFile(filepath.Join(base, "G42_OWNER_G41_TRACE.json"))
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != N10OwnerG41TraceSHA {
		t.Fatal("G41 SHA mismatch")
	}
	geoRaw, e := os.ReadFile(filepath.Join(base, "G37_OWNER_G36_GEOMETRY.json"))
	if e != nil {
		t.Fatal(e)
	}
	var v N10DispatchTraceReport
	var g GeometryReport
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(geoRaw, &g); e != nil {
		t.Fatal(e)
	}
	return v, g
}
func TestG42Original24ISOExtentsAndNoRuntimeApproval(t *testing.T) {
	trace, geo := loadG42OwnerEvidence(t)
	r, e := ReviewN10OverlaySelectorG42(trace, geo)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.SelectorMatches) != 24 || len(r.EXNNotInThisSelector) != 2 || r.OwnerReportedG41FlowPresent || r.RuntimeIOVerified || r.RAMWriteOwnershipVerified || r.SafeToPatch {
		t.Fatalf("bad review status: %+v", r)
	}
	byLBA := map[int64]string{}
	for _, s := range r.SelectorMatches {
		byLBA[s.LBA] = s.Path
	}
	for lba, base := range map[int64]string{39530: "TT.EXN", 37994: "GEKO.EXN", 38378: "NAME_ENT.EXN", 39434: "TEL.EXN", 39050: "SHOUGATU.EXN"} {
		if !strings.HasSuffix(byLBA[lba], base) {
			t.Fatalf("incorrect LBA %d -> %s", lba, byLBA[lba])
		}
	}
}
func TestG42RejectsChangedOwnerWords(t *testing.T) {
	trace, geo := loadG42OwnerEvidence(t)
	for i := range trace.Windows {
		for j := range trace.Windows[i].Instructions {
			if trace.Windows[i].Instructions[j].FileOffset == 233016 {
				trace.Windows[i].Instructions[j].Word = "00000000"
				goto tampered
			}
		}
	}
	t.Fatal("anchor absent")
tampered:
	if _, e := ReviewN10OverlaySelectorG42(trace, geo); e == nil {
		t.Fatal("accepted corrupted original G41 opcode")
	}
}
func TestG42FailsClosedOnUnknownEXE(t *testing.T) {
	trace, geo := loadG42OwnerEvidence(t)
	r, e := ReviewN10OverlaySelectorG42(trace, geo)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = CaptureN10OverlayIOG42(make([]byte, 667648), r); e == nil {
		t.Fatal("accepted fake original EXE")
	}
}
