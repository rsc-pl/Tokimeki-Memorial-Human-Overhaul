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

func readOwnerG42(t *testing.T) N10IOLoaderReview {
	t.Helper()
	path := filepath.Join("..", "..", ".local", "go_toolchain", "reports", "G43_OWNER_G42_IO.json")
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != N10OwnerG42IOSHA {
		t.Fatal("owner original G42 report SHA wrong")
	}
	var r N10IOLoaderReview
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestG43OriginalDescriptorAndNoApproval(t *testing.T) {
	r, e := ReviewN10DescriptorG43(readOwnerG42(t))
	if e != nil {
		t.Fatal(e)
	}
	if !r.SourceVerified || r.PackedDescriptor != "0x60132000" || r.PackedBytePattern != "00 20 13 60" || r.DescriptorStackOffset != 40 || r.RequestOperation != 6 || r.SafeToPatch || r.SectorTransferVerified || r.CalleeDescriptorInterpretationVerified || r.OverlayRAMBoundsVerified {
		t.Fatalf("wrong descriptor proof %+v", r)
	}
	if len(n10G43WindowSpecs()) != 4 {
		t.Fatal("bad number of scoped windows")
	}
}
func TestG43RejectsMutatedDelaySlotAndCallee(t *testing.T) {
	for _, pc := range []uint32{0x800462C4, 0x8004633C, 0x8004634C, 0x80046350} {
		owner := readOwnerG42(t)
		done := false
		for i := range owner.Windows {
			for j := range owner.Windows[i].Instructions {
				x := &owner.Windows[i].Instructions[j]
				if n10FileToRAM+uint32(x.FileOffset) == pc {
					x.Word = "00000000"
					done = true
					break
				}
			}
		}
		if !done {
			t.Fatalf("missing test source %08x", pc)
		}
		if _, e := ReviewN10DescriptorG43(owner); e == nil {
			t.Fatalf("accepted changed opcode %08x", pc)
		}
	}
}
func TestG43FailClosedFakeRetailImageAndBoundedWindows(t *testing.T) {
	r, e := ReviewN10DescriptorG43(readOwnerG42(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := CaptureN10DescriptorG43(make([]byte, 667648), r); e == nil {
		t.Fatal("accepted wrong EXE SHA")
	}
	fake := make([]byte, 667648)
	binary.LittleEndian.PutUint32(fake[int(0x80045414-n10FileToRAM):], 0x03E00008)
	got, e := captureG43Windows(fake, r)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, w := range got.NewCodeWindows {
		if len(w.Instructions) != (w.EndFileOffsetExclusive-w.StartFileOffset)/4 {
			t.Fatal("nonbounded captured window")
		}
		count += len(w.Instructions)
	}
	if count < 100 || count > 700 {
		t.Fatalf("bad bounded capture %d", count)
	}
	if got.SafeToPatch || got.OverlayRAMBoundsVerified {
		t.Fatal("static bytes approved patch")
	}
}
