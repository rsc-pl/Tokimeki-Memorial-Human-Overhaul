package nametables

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// DirectCall is a conservative static candidate: the address is constructed
// in $a0 and a nearby JAL receives it via normal flow, a JAL delay slot or a
// single conditional-branch delay slot. This does NOT establish that the
// code executes or authorize any RAM relocation.
type DirectCall struct {
	Target        uint32 `json:"target"`
	Offset        int    `json:"offset"`
	BytesAfterUse int    `json:"bytes_after_use"`
	Role          string `json:"role"`
}

// AnnotateDirectCalls classifies previously found potential references. Only
// materializations into $a0 can qualify. Other types remain unclassified. The
// delay slot is accounted for because it executes before the call starts.
func AnnotateDirectCalls(code []byte, refs []Xref) []Xref {
	out := append([]Xref(nil), refs...)
	for i := range out {
		r := &out[i]
		r.DirectCall = nil // Reclassifying after source changes must never reuse stale evidence.
		if r.Kind != "address-construction" || r.Register != 4 {
			continue
		}
		// On MIPS I the JAL delay slot executes before control reaches the
		// callee. The effective $a0 may therefore be set *after* the JAL
		// instruction, exactly as the GEKO code does for strcpy. Checking
		// forward only would miss the bulk of real GEKO destinations.
		if r.UseOffset >= 4 {
			preceding := binary.LittleEndian.Uint32(code[r.UseOffset-4:])
			if preceding>>26 == 3 {
				r.DirectCall = &DirectCall{Target: 0x80000000 | ((preceding & 0x03ffffff) << 2), Offset: r.UseOffset - 4, BytesAfterUse: -4, Role: "delay-slot-a0"}
				continue
			}
			// Conditional branches also execute their delay slot. Follow the
			// *taken* branch for one bounded basic block. The fallthrough may
			// overwrite $a0 and is deliberately NOT inferred as the same use.
			if op := preceding >> 26; op == 4 || op == 5 || op == 6 || op == 7 {
				branchPC := r.UseOffset - 4
				dest := branchPC + 4 + int(int16(preceding&0xffff))*4
				if dest >= 0 && dest%4 == 0 && dest != r.UseOffset {
					if at, target, ok := nextA0JAL(code, dest, 24); ok {
						r.DirectCall = &DirectCall{Target: target, Offset: at, BytesAfterUse: at - r.UseOffset, Role: "branch-delay-slot-a0"}
						continue
					}
				}
			}
		}
		// A construction in the delay slot cannot be safely treated as the
		// beginning of an ordinary straight-line basic block.
		if r.UpperOffset >= 4 && isControlTransfer(binary.LittleEndian.Uint32(code[r.UpperOffset-4:])) {
			continue
		}
		if at, target, ok := nextA0JAL(code, r.UseOffset+4, 32); ok {
			r.DirectCall = &DirectCall{Target: target, Offset: at, BytesAfterUse: at - r.UseOffset, Role: "pre-call-a0"}
		}

	}
	return out
}

// nextA0JAL searches one straight-line basic block, without assuming data
// or instructions beyond the given bound are safe to cross. A JAL's own
// delay slot must not overwrite $a0 before the callee sees it.
func nextA0JAL(code []byte, start, maxForward int) (int, uint32, bool) {
	for at := start; at >= 0 && at <= start+maxForward && at+8 <= len(code); at += 4 {
		w := binary.LittleEndian.Uint32(code[at:])
		if w>>26 == 3 {
			slot := binary.LittleEndian.Uint32(code[at+4:])
			if writesGPR(slot, 4) || isControlTransfer(slot) {
				return 0, 0, false
			}
			return at, 0x80000000 | ((w & 0x03ffffff) << 2), true
		}
		if isControlTransfer(w) || writesGPR(w, 4) {
			return 0, 0, false
		}
	}
	return 0, 0, false
}

// SummarizeDirectCalls groups sites by buffer address and immediate JAL
// target. Uncategorized sites remain explicit, not silently discarded.
func SummarizeDirectCalls(refs []Xref) []CallGroup {
	counts := map[string]*CallGroup{}
	for _, r := range refs {
		addr := fmt.Sprintf("0x%08X", r.Address)
		target := "unclassified"
		if r.DirectCall != nil {
			target = fmt.Sprintf("0x%08X", r.DirectCall.Target)
		}
		key := addr + ":" + target
		g, ok := counts[key]
		if !ok {
			g = &CallGroup{Buffer: addr, Target: target}
			counts[key] = g
		}
		g.Count++
	}
	out := make([]CallGroup, 0, len(counts))
	for _, v := range counts {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Buffer != out[j].Buffer {
			return out[i].Buffer < out[j].Buffer
		}
		return out[i].Target < out[j].Target
	})
	return out
}

type CallGroup struct {
	Buffer string `json:"buffer"`
	Target string `json:"target"`
	Count  int    `json:"count"`
}
