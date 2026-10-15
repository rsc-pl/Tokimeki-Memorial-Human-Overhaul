package nametables

import "encoding/binary"

// GEKOControlTarget is a possible direct MIPS control-flow reference into a
// candidate byte range. Scanning encoded data can give false positives; an
// empty list is NEVER proof of exclusive RAM or code/data ownership.
type GEKOControlTarget struct {
	InstructionOffset int    `json:"instruction_offset"`
	TargetAddress     uint32 `json:"target_address"`
	Kind              string `json:"kind"`
}

// FindGEKODirectControlTargets detects MIPS-I J/JAL and known conditional
// branches whose resolved destination falls within [start,end). It does NOT
// follow JR/JALR, computed branches, RAM-loaded pointers or runtime code.
func FindGEKODirectControlTargets(raw []byte, start, end uint32) []GEKOControlTarget {
	if start >= end || len(raw)%4 != 0 {
		return nil
	}
	var hits []GEKOControlTarget
	for at := 0; at+4 <= len(raw); at += 4 {
		ins := binary.LittleEndian.Uint32(raw[at:])
		op := ins >> 26
		pc := gekoOverlayRAMBase + uint32(at)
		var target uint32
		kind := ""
		switch {
		case op == 2 || op == 3:
			target = ((pc + 4) & 0xf0000000) | ((ins & 0x3ffffff) << 2)
			kind = "jump-or-call"
		case op == 1:
			rt := (ins >> 16) & 31
			if rt != 0 && rt != 1 && rt != 16 && rt != 17 {
				continue
			}
			target = pc + 4 + uint32(int32(int16(ins&0xffff))<<2)
			kind = "regimm-branch"
		case (op >= 4 && op <= 7) || (op >= 20 && op <= 23):
			target = pc + 4 + uint32(int32(int16(ins&0xffff))<<2)
			kind = "conditional-branch"
		default:
			continue
		}
		if target >= start && target < end {
			hits = append(hits, GEKOControlTarget{at, target, kind})
		}
	}
	return hits
}
