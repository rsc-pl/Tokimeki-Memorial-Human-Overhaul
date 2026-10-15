package nametables

import (
	"encoding/binary"
	"testing"
)

func encodeDirectJump(op uint32, target uint32) uint32 { return op<<26 | ((target >> 2) & 0x03ffffff) }
func encodeDirectBranch(op uint32, fromOffset, targetOffset int) uint32 {
	return op<<26 | uint32(uint16(int16((targetOffset-(fromOffset+4))/4)))
}
func TestGEKODirectControlTargets(t *testing.T) {
	b := make([]byte, 0x16000)
	at := 0x100
	target := uint32(gekoOverlayRAMBase + 0x15000)
	binary.LittleEndian.PutUint32(b[at:], encodeDirectJump(3, target))
	binary.LittleEndian.PutUint32(b[at+4:], encodeDirectBranch(4, at+4, 0x15004))
	hits := FindGEKODirectControlTargets(b, target, target+24)
	if len(hits) != 2 || hits[0].InstructionOffset != at || hits[0].Kind != "jump-or-call" || hits[1].TargetAddress != target+4 {
		t.Fatalf("bad targets: %+v", hits)
	}
	if h := FindGEKODirectControlTargets(b, target+0x100, target+0x200); len(h) != 0 {
		t.Fatalf("wrong range %+v", h)
	}
	if h := FindGEKODirectControlTargets(b, target, target); len(h) != 0 {
		t.Fatal("empty interval")
	}
}
