package nametables

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func g44Owner(t *testing.T) N10DescriptorReviewG43 {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("..", "..", ".local", "go_toolchain", "reports", "G44_OWNER_G43_TRANSFER.json"))
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != N10OwnerG43TransferSHA {
		t.Fatal("G43 source SHA mismatch")
	}
	var r N10DescriptorReviewG43
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestG44OriginalSourceRoutingAnchors(t *testing.T) {
	r, e := ReviewN10RequestRouteG44(g44Owner(t))
	if e != nil {
		t.Fatal(e)
	}
	if !r.OwnerSourceVerified || r.RequestedOperation != 6 || r.Operation6EntryAddress != "0x800AF828" || r.SafeToPatch {
		t.Fatalf("bad source-derived table review %+v", r)
	}
}
func TestG44MutatedG43SourceRejected(t *testing.T) {
	for _, pc := range []uint32{0x80045424, 0x80045454, 0x8004545C, 0x80045498, 0x800454A0} {
		owner := g44Owner(t)
		hit := false
		for i := range owner.NewCodeWindows {
			for j := range owner.NewCodeWindows[i].Instructions {
				x := &owner.NewCodeWindows[i].Instructions[j]
				if n10FileToRAM+uint32(x.FileOffset) == pc {
					x.Word = "00000000"
					hit = true
				}
			}
		}
		if !hit {
			t.Fatalf("missing expected source %08X", pc)
		}
		if _, e := ReviewN10RequestRouteG44(owner); e == nil {
			t.Fatalf("accepted mutation at %08X", pc)
		}
	}
}
func TestG44SourceTableExtractionBoundedAndFailClosed(t *testing.T) {
	r, e := ReviewN10RequestRouteG44(g44Owner(t))
	if e != nil {
		t.Fatal(e)
	}
	fake := make([]byte, 667648)
	if _, e = CaptureN10RequestRouteG44(fake, r); e == nil {
		t.Fatal("accepted fake original EXE")
	}
	off := int(0x800AF828 - n10FileToRAM)
	binary.LittleEndian.PutUint32(fake[off:off+4], 0x80045494)
	got, e := captureG44Original(fake, r)
	if e != nil {
		t.Fatal(e)
	}
	if !got.Operation6IsCandidate45494 || !got.Operation6TargetInMainEXECode || !got.OriginalEXEVerified || len(got.Entries) != 28 || len(got.NewCodeWindows) != 4 || got.SafeToPatch || got.SectorTransferVerified || got.OverlayRAMBoundsVerified {
		t.Fatalf("invalid synthetic extraction %+v", got)
	}
	if got.Entries[6].TableAddress != "0x800AF828" {
		t.Fatal("bad op6 address")
	}
	total := 0
	for _, w := range got.NewCodeWindows {
		total += len(w.Instructions)
	}
	if total > 500 || total < 300 {
		t.Fatalf("unbounded or too-short capture %d", total)
	}
	binary.LittleEndian.PutUint32(fake[off:off+4], 0x60132000)
	bad, e := captureG44Original(fake, r)
	if e != nil {
		t.Fatal(e)
	}
	if bad.Operation6TargetInMainEXECode || bad.SafeToPatch {
		t.Fatal("unsafe target treated as executable or patch-ready")
	}
	if _, e = captureG44Original(fake, got); e == nil {
		t.Fatal("accepted repeated capture")
	}
}
