package nametables

import (
	"encoding/binary"
	"strings"
	"testing"
)

func makeFlowG41Fixture(t *testing.T) N10DispatchTraceReport {
	t.Helper()
	exe := make([]byte, 667648)
	put := func(off int, w uint32) { binary.LittleEndian.PutUint32(exe[off:], w) }
	// Dispatcher reaches the G39 slot via a conditional branch and falls to the read.
	// Return must execute its delay slot, without traversing into subsequent data.
	put(232604, 0x10000002) // unconditional branch 232616
	put(232608, 0xAC253110) // delay slot store
	put(232612, 0x0C050301) // unreachable JAL-shaped data
	put(232616, 0x3C198012) // lui t9,8012
	put(232620, 0x8F393110) // lw t9,3110(t9)
	put(232624, 0x0320F809) // jalr ra,t9
	put(232628, 0)          // delay slot
	put(232632, 0x03E00008) // jr ra
	put(232636, 0)          // delay slot
	put(232640, 0x0C050301) // NOT reachable
	put(233148, 0x03E00008) // jr ra, isolate this seed
	put(233152, 0x00000000)
	put(233156, 0x0C050301) // NOT reachable
	put(233196, 0x3C198012)
	put(233200, 0x8F393110)
	put(233204, 0x0320F809)
	// callee entry points always return immediately
	for _, ram := range []uint32{0x8009C674, 0x8009C210, 0x800AF1A0} {
		off := int(ram - n10FileToRAM)
		put(off, 0x03E00008)
		put(off+4, 0)
		put(off+8, 0x0C050301) // unexecuted after return
	}
	r, err := n10TraceWindows(exe)
	if err != nil {
		t.Fatal(err)
	}
	r.OriginalSourceVerified = true
	r.OriginalEXESHA256 = N10OriginalEXESHA
	return r
}
func TestG41FlowDelaySlotsStopAtJRAndUnconditionalBranch(t *testing.T) {
	r := makeFlowG41Fixture(t)
	flow, err := n10TraceFlow(r)
	if err != nil {
		t.Fatal(err)
	}
	if flow.SafeToPatch || flow.RuntimeLoaderVerified || flow.BSSOrHeapVerified || len(flow.Seeds) != 5 || !flow.PointerReadWordVerified {
		t.Fatalf("unsafe %+v", flow)
	}
	for _, seed := range flow.Seeds {
		if seed.WorklistLimitHit {
			t.Fatalf("unbounded %s", seed.Label)
		}
		for _, call := range seed.DirectCalls {
			if call.FileOffset == 232612 || call.FileOffset == 232640 || call.FileOffset == 233156 {
				t.Fatalf("followed code after branch/return: %+v", call)
			}
		}
	}
	if len(flow.SyntacticT9IndirectWithin64Bytes) != 1 || flow.SyntacticT9IndirectWithin64Bytes[0].FileOffset != 233204 {
		t.Fatalf("lost indirect syntax %+v", flow.SyntacticT9IndirectWithin64Bytes)
	}
	if flow.Seeds[0].ReachableWords != 8 || flow.Seeds[0].ReachedPointerRead {
		t.Fatalf("unexpected dispatch reachability %+v", flow.Seeds[0])
	}
	if flow.Seeds[2].ReachableWords != 2 {
		t.Fatalf("ret returned into data: %+v", flow.Seeds[2])
	}
}
func TestG41FlowRejectsFakeOrIncompleteReport(t *testing.T) {
	r := makeFlowG41Fixture(t)
	r.SafeToPatch = true
	if _, err := n10TraceFlow(r); err == nil {
		t.Fatal("accepted approved patch")
	}
	r = makeFlowG41Fixture(t)
	r.Windows[0].Instructions[0].Word = "FFFFFFFF"
	if _, err := n10TraceFlow(r); err == nil {
		t.Fatal("accepted tampered word")
	}
	r = makeFlowG41Fixture(t)
	r.Windows[0].Instructions[0].FileOffset++
	if _, err := n10TraceFlow(r); err == nil {
		t.Fatal("accepted missing instruction")
	}
	r = makeFlowG41Fixture(t)
	r.DispatcherPointerSlot = "0x00000000"
	if _, err := n10TraceFlow(r); err == nil {
		t.Fatal("accepted pointer mismatch")
	}
	if !strings.HasPrefix(r.Status, "G40_") {
		t.Fatal("unexpected G40 compatibility")
	}
}
