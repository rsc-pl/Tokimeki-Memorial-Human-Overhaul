package nametables

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// PointerEscape is a statically inferred use of one of the old GEKO name
// literals as a call argument or as data being stored to memory. Such uses
// can outlive the immediate instruction sequence; they must not be ignored
// merely because no load/store *through* the pointer occurred locally.
// Neither a hit nor absence of hits proves runtime execution/coverage.
type PointerEscape struct {
	AnchorOffset int    `json:"anchor_offset"`
	UseOffset    int    `json:"use_offset"`
	Address      uint32 `json:"address"`
	Register     uint32 `json:"register"`
	Kind         string `json:"kind"`
	Reviewed     bool   `json:"reviewed"`
}

// FindGEKOPointerEscapes conservatively traces a single LUI provenance
// through simple additions and register copies, bounded by the first control
// transfer. MIPS-I delay slots execute before the call consumes its argument
// registers. No CFG, heap/pointer loads, dynamic JALR targets or overlay
// execution is inferred, so this function can only add reasons to HOLD.
func FindGEKOPointerEscapes(data []byte, first, last uint32, window int) ([]PointerEscape, error) {
	if len(data)%4 != 0 || first >= last || window < 2 || window > 128 {
		return nil, fmt.Errorf("invalid GEKO pointer escape input")
	}
	var out []PointerEscape
	seen := map[[4]uint64]bool{}
	emit := func(anchor, use int, addr, reg uint32, kind string) {
		if addr < first || addr >= last {
			return
		}
		k := [4]uint64{uint64(anchor), uint64(use), uint64(addr), uint64(reg)}
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, PointerEscape{AnchorOffset: anchor, UseOffset: use, Address: addr, Register: reg, Kind: kind})
	}
	// Update a register-state snapshot for the subset of MIPS I instructions
	// whose pointer-value semantics we have reviewed. Unknown writes kill
	// provenance; they never manufacture trusted pointer values.
	advance := func(in [32]trackedValue, w uint32) [32]trackedValue {
		regs := in
		op, rs, rt, rd := w>>26, (w>>21)&31, (w>>16)&31, (w>>11)&31
		var written uint32
		var v trackedValue
		ok := false
		switch {
		case (op == 9 || op == 13) && in[rs].valid:
			written, ok = rt, true
			v = trackedValue{valid: true, steps: in[rs].steps + 1, value: in[rs].value}
			if op == 9 {
				v.value += uint32(int32(int16(w & 0xffff)))
			} else {
				v.value |= w & 0xffff
			}
		case op == 0 && ((w&63) == 33 || (w&63) == 37) && (rs == 0 || rt == 0):
			src := rs
			if src == 0 {
				src = rt
			}
			if in[src].valid {
				written, ok = rd, true
				v = in[src]
				v.steps++
			}
		}
		for r := uint32(1); r < 32; r++ {
			if writesGPR(w, r) {
				regs[r] = trackedValue{}
			}
		}
		if ok && written != 0 {
			regs[written] = v
		}
		return regs
	}
	storeEscape := func(anchor, at int, regs [32]trackedValue, w uint32) {
		op, rt := w>>26, (w>>16)&31
		if isStoreInstruction(op) && regs[rt].valid {
			emit(anchor, at, regs[rt].value, rt, "stored-pointer")
		}
	}
	for anchor := 0; anchor+4 <= len(data); anchor += 4 {
		w := binary.LittleEndian.Uint32(data[anchor:])
		if w>>26 != 15 || (w>>21)&31 != 0 {
			continue
		}
		r := (w >> 16) & 31
		if r == 0 {
			continue
		}
		hi := uint32(w&0xffff) << 16
		if hi != first&0xffff0000 && hi != ((first+0x8000)&0xffff0000) {
			continue
		}
		var regs [32]trackedValue
		regs[r] = trackedValue{value: hi, valid: true}
		for step := 1; step <= window && anchor+4*step+4 <= len(data); step++ {
			at := anchor + step*4
			ins := binary.LittleEndian.Uint32(data[at:])
			storeEscape(anchor, at, regs, ins)
			if isControlTransfer(ins) {
				// Check stores and register writes in the delay slot before
				// inspecting the argument registers at call time.
				if at+8 <= len(data) && step < window {
					slot := binary.LittleEndian.Uint32(data[at+4:])
					storeEscape(anchor, at+4, regs, slot)
					regs = advance(regs, slot)
				}
				isCall := ins>>26 == 3 || (ins>>26 == 0 && ins&63 == 9)
				if isCall {
					for arg := uint32(4); arg <= 7; arg++ {
						if regs[arg].valid {
							emit(anchor, at, regs[arg].value, arg, "call-argument")
						}
					}
				}
				break
			}
			regs = advance(regs, ins)
			// Once all provenance is gone, continuing cannot recover its
			// origin via a different LUI; that will be another anchor.
			live := false
			for r := uint32(1); r < 32; r++ {
				if regs[r].valid {
					live = true
					break
				}
			}
			if !live {
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UseOffset != out[j].UseOffset {
			return out[i].UseOffset < out[j].UseOffset
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].AnchorOffset < out[j].AnchorOffset
	})
	for i := range out {
		h := &out[i]
		h.Reviewed = h.Kind == "call-argument" && h.Register == 5 &&
			((h.AnchorOffset == 0xf468 && h.UseOffset == 0xf470 && h.Address == 0x80144b1c) ||
				(h.AnchorOffset == 0xf47c && h.UseOffset == 0xf484 && h.Address == 0x80144b24))
	}
	return out, nil
}
