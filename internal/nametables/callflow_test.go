package nametables

import (
	"encoding/binary"
	"testing"
)

func TestDirectA0CallUseAndDelaySlot(t *testing.T) {
	b := make([]byte, 192)
	put := func(at int, w uint32) { binary.LittleEndian.PutUint32(b[at:], w) }
	// Recorded pattern: LUI a0; ...; ADDIU a0; JAL; non-clobber delay slot.
	put(0, 0x3c04800d)
	put(4, 0x00000000)
	put(8, 0x2484a19c)
	put(12, 0x0c02b83c)
	put(16, 0xac39627c)
	// A0 overwritten before call, must never be classified as a direct arg.
	put(32, 0x3c04800d)
	put(36, 0x2484a19c)
	put(40, 0x24040002)
	put(44, 0x0c02b83c)
	// A0 modified in JAL delay slot, must never be classified.
	put(64, 0x3c04800d)
	put(68, 0x2484a19c)
	put(72, 0x0c02b83c)
	put(76, 0x24040001)
	// Branch before call invalidates straight-line inference.
	put(96, 0x3c04800d)
	put(100, 0x2484a19c)
	put(104, 0x10000002)
	put(108, 0x00000000)
	put(112, 0x0c02b83c)
	// Materialization in another register is not an A0 call argument.
	put(128, 0x3c06800d)
	put(132, 0x24c6a19c)
	put(136, 0x0c02b83c)
	refs, e := FindRAMReferences(b, 0x800ca180, 0x800ca1c0)
	if e != nil {
		t.Fatal(e)
	}
	out := AnnotateDirectCalls(b, refs)
	if len(out) != 5 {
		t.Fatalf("expected five refs, got %d: %+v", len(out), out)
	}
	if out[0].DirectCall == nil || out[0].DirectCall.Target != 0x800ae0f0 || out[0].DirectCall.Offset != 12 {
		t.Fatalf("missing proof %+v", out[0])
	}
	for i := 1; i < 5; i++ {
		if out[i].DirectCall != nil {
			t.Fatalf("unsafe inference at %d: %+v", i, out[i])
		}
	}
	groups := SummarizeDirectCalls(out)
	if len(groups) != 2 || groups[0].Count+groups[1].Count != 5 {
		t.Fatalf("bad grouping %+v", groups)
	}
}

func TestDirectCallTargetA0ReadOnlyWindow(t *testing.T) {
	b := make([]byte, 128)
	binary.LittleEndian.PutUint32(b[0:], 0x3c04800d)
	binary.LittleEndian.PutUint32(b[4:], 0x2484a188)
	// 35+ bytes after construction: refuse distant JAL association.
	binary.LittleEndian.PutUint32(b[44:], 0x0c02b83c)
	x, e := FindRAMReferences(b, 0x800ca180, 0x800ca1c0)
	if e != nil || len(x) != 1 {
		t.Fatalf("bad xrefs: %v %+v", e, x)
	}
	if AnnotateDirectCalls(b, x)[0].DirectCall != nil {
		t.Fatal("accepted distant call")
	}
}

func TestCallArgumentMaterializedInJALDelaySlot(t *testing.T) {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint32(b[0:], 0x3c04800d)  // lui a0
	binary.LittleEndian.PutUint32(b[4:], 0x3c058014)  // lui a1
	binary.LittleEndian.PutUint32(b[8:], 0x24a547c4)  // addiu a1
	binary.LittleEndian.PutUint32(b[12:], 0x0c02b83c) // jal strcpy
	binary.LittleEndian.PutUint32(b[16:], 0x2484a19c) // addiu a0 in JAL delay slot
	binary.LittleEndian.PutUint32(b[20:], 0x0c01fb61) // a different call
	binary.LittleEndian.PutUint32(b[24:], 0x240440bc) // A0 overwritten in its delay slot
	refs, e := FindRAMReferences(b, 0x800ca180, 0x800ca1c0)
	if e != nil || len(refs) != 1 {
		t.Fatalf("unexpected refs %v %+v", e, refs)
	}
	refs = AnnotateDirectCalls(b, refs)
	call := refs[0].DirectCall
	if call == nil || call.Target != 0x800ae0f0 || call.Role != "delay-slot-a0" || call.BytesAfterUse != -4 {
		t.Fatalf("wrong callsite evidence: %+v", call)
	}
}

func TestBranchDelaySlotA0TakenPath(t *testing.T) {
	b := make([]byte, 112)
	put := func(at int, w uint32) { binary.LittleEndian.PutUint32(b[at:], w) }
	// Real GEKO structure: BNE, slot ADDIU a0, fallthrough overwrites a0,
	// but taken branch retains a0 and calls copy thunk 0x800AE0F0.
	put(0, 0x3c04800d)
	put(4, 0x1580000d) // bne $t4,$zero,+13 -> 0x3c
	put(8, 0x2484a19c)
	put(12, 0x3c04800d) // fallthrough redefines a0; intentionally ignored
	put(60, 0x3c058014)
	put(64, 0x0c02b83c) // jal copy thunk
	put(68, 0x24a54834) // only a1 in call delay slot
	x, e := FindRAMReferences(b, 0x800ca180, 0x800ca1c0)
	if e != nil || len(x) < 1 {
		t.Fatalf("missing xrefs %v %+v", e, x)
	}
	x = AnnotateDirectCalls(b, x)
	call := x[0].DirectCall
	if call == nil || call.Target != 0x800ae0f0 || call.Role != "branch-delay-slot-a0" {
		t.Fatalf("missing taken branch evidence: %+v", x[0])
	}
	// A branch target is an instruction that modifies a0; refuse inference.
	put(60, 0x240400ff)
	x = AnnotateDirectCalls(b, x)
	if x[0].DirectCall != nil {
		t.Fatalf("accepted overwritten a0: %+v", x[0])
	}
}
