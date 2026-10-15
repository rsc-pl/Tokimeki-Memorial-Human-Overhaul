package nametables

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func g45RawOwnerReports(t *testing.T) ([]byte, []byte) {
	t.Helper()
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join("..", "..", ".local", "go_toolchain", "reports", name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	return read("G45_OWNER_G44_ROUTE.json"), read("G44_OWNER_G43_TRANSFER.json")
}
func TestG45OriginalOwnerQueueLayout(t *testing.T) {
	a, b := g45RawOwnerReports(t)
	if fmt.Sprintf("%x", sha256.Sum256(a)) != N10OwnerG44RouteSHA {
		t.Fatal("original G44 SHA mismatch")
	}
	r, e := ReviewN10QueueG45(a, b)
	if e != nil {
		t.Fatal(e)
	}
	if !r.G44SourceVerified || !r.G43QueueTailVerified || r.Queue.Capacity != 48 || r.Queue.RecordStride != 24 || r.Queue.QueueEndExclusive != "0x801255B0" || r.SafeToPatch || r.DeviceTransferVerified {
		t.Fatalf("bad derived queue: %+v", r)
	}
	fake := make([]byte, 667648)
	if _, e := CaptureN10QueueG45(fake, r); e == nil {
		t.Fatal("accepted synthetic EXE as original")
	}
	got, e := captureG45VerifiedEXE(fake, r)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.ExtraCodeWindows) != 3 || !got.OriginalEXEVerified || got.SafeToPatch {
		t.Fatalf("unsafe capture %+v", got)
	}
	n := 0
	for _, v := range got.ExtraCodeWindows {
		n += len(v.Instructions)
	}
	if n < 500 || n > 750 {
		t.Fatalf("unbounded instructions %d", n)
	}
	if _, e := captureG45VerifiedEXE(fake, got); e == nil {
		t.Fatal("accepted repeated capture")
	}
}
func TestG45RejectsTamperedEvidence(t *testing.T) {
	orig, prev := g45RawOwnerReports(t)
	for _, which := range []string{"status", "op6", "enqueue"} {
		var o N10RequestRouteReviewG44
		if e := json.Unmarshal(orig, &o); e != nil {
			t.Fatal(e)
		}
		switch which {
		case "status":
			o.Operation6BranchRuntimeVerified = true
		case "op6":
			o.Entries[6].WordLittleEndian = "0x800455B4"
		case "enqueue":
			found := false
			for i := range o.NewCodeWindows {
				for j := range o.NewCodeWindows[i].Instructions {
					if o.NewCodeWindows[i].Instructions[j].RAM == "0x800453C8" {
						o.NewCodeWindows[i].Instructions[j].Word = "00000000"
						found = true
					}
				}
			}
			if !found {
				t.Fatal("test source anchor missing")
			}
		}
		bad, e := json.Marshal(o)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ReviewN10QueueG45(bad, prev); e == nil {
			t.Fatalf("accepted mutated G44: %s", which)
		}
	}
	mut := append([]byte(nil), prev...)
	mut[len(mut)-3] = 'X'
	if _, e := ReviewN10QueueG45(orig, mut); e == nil {
		t.Fatal("accepted changed original G43")
	}
}
func TestG45BoundedReadWindows(t *testing.T) {
	specs := queueG45Windows()
	if len(specs) != 3 {
		t.Fatal("wrong window count")
	}
	for _, s := range specs {
		if s.start%4 != 0 || s.end%4 != 0 || s.end <= s.start || s.end-s.start > 2048 || s.start < 0x80041000 || s.end > 0x800E3800 {
			t.Fatalf("unsafe window %+v", s)
		}
	}
}
