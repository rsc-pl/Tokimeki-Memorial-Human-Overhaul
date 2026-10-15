package nametables

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestN10GeometryModelAndStrictIdentity(t *testing.T) {
	exe := make([]byte, 0x4000)
	geko := make([]byte, 0x30000)
	// Synthesized MIPS JAL in both hypothesized image ranges.
	binary.LittleEndian.PutUint32(exe[0x10:], 0x0c000000|(uint32(0x80040880)>>2&0x03ffffff))
	binary.LittleEndian.PutUint32(geko[0x10:], 0x0c000000|(uint32(0x80132080)>>2&0x03ffffff))
	mk := func(p string, d []byte) OverlayContextSource {
		h := sha256.Sum256(d)
		return OverlayContextSource{Path: p, Size: len(d), SHA256: fmt.Sprintf("%x", h[:])}
	}
	ctx := OverlayContextReport{Status: "STATIC_MIPS_CONTEXT_REVIEW_ONLY_DO_NOT_BOOT", VerifiedAgainstFreshScan: true, UniqueSites: 211, Sources: []OverlayContextSource{mk(EXE, exe), mk(Geko, geko)}, Sites: []OverlayContextSite{}}
	in := []GeometryInput{{EXE, 321, exe}, {Geko, 654, geko}}
	// Test smaller controlled inventory after temporarily filling 25 known names
	// with unique valid SHA sources (the production acceptance requires all 27).
	for i := 0; i < 25; i++ {
		p := fmt.Sprintf("CDROM/EXEDIR/TEST%02d.EXN", i)
		d := make([]byte, 0x30000)
		ctx.Sources = append(ctx.Sources, mk(p, d))
		in = append(in, GeometryInput{p, int64(700 + i), d})
	}
	out, err := BuildN10OverlayGeometry(ctx, "context-sha", in)
	if err != nil {
		t.Fatal(err)
	}
	if out.FilesVerified != 27 || out.StaticSelfJALSites != 2 || out.SafeToPatch || out.RuntimeLoaderVerified || out.BSSRangeVerified || out.WritableRAMOwnershipVerified {
		t.Fatalf("unsafe classification %+v", out)
	}
	if out.MainFileImageRange != "[0x80040800,0x80044800)" || out.OverlayFileImageRange != "[0x80132000,0x80162000)" {
		t.Fatalf("wrong hypothesis %+v", out)
	}
	// Deliberate corrupt source must fail before publishing a report.
	in[1].Data = append([]byte(nil), geko...)
	in[1].Data[0] = 1
	if _, err := BuildN10OverlayGeometry(ctx, "context-sha", in); err == nil || !strings.Contains(err.Error(), "SHA mismatch") {
		t.Fatalf("corrupt input accepted: %v", err)
	}
	in[1].Data = geko
	in[1].Path = in[0].Path
	if _, err := BuildN10OverlayGeometry(ctx, "context-sha", in); err == nil {
		t.Fatal("duplicate source accepted")
	}
	in[1].Path = Geko
	ctx.RuntimeSafe = true
	if _, err := BuildN10OverlayGeometry(ctx, "context-sha", in); err == nil {
		t.Fatal("unsafe context status accepted")
	}
}
