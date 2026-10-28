// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"encoding/binary"
	"fmt"
)

type AddressPair struct {
	UpperOffset int    `json:"upper_offset"`
	LowerOffset int    `json:"lower_offset"`
	UpperWord   uint32 `json:"upper_word"`
	LowerWord   uint32 `json:"lower_word"`
	OldAddress  uint32 `json:"old_address"`
	NewAddress  uint32 `json:"new_address"`
}
type PairRewriteResult struct {
	Sites int `json:"sites"`
	Words int `json:"words"`

	RuntimeValidated bool `json:"runtime_validated"`
}

func RewriteGuardedAddressPairs(source []byte, pairs []AddressPair) ([]byte, PairRewriteResult, error) {
	if len(pairs) == 0 {
		return nil, PairRewriteResult{}, fmt.Errorf("no MIPS address pairs provided")
	}
	used := map[int]bool{}
	for i, p := range pairs {
		if p.UpperOffset < 0 || p.LowerOffset < 0 || p.UpperOffset%4 != 0 || p.LowerOffset%4 != 0 ||
			p.LowerOffset <= p.UpperOffset || p.LowerOffset-p.UpperOffset > 64 || p.LowerOffset+4 > len(source) ||
			p.UpperOffset+4 > len(source) {
			return nil, PairRewriteResult{}, fmt.Errorf("site %d has invalid offsets", i)
		}
		if used[p.UpperOffset] || used[p.LowerOffset] {
			return nil, PairRewriteResult{}, fmt.Errorf("site %d shares instruction with another site", i)
		}
		used[p.UpperOffset], used[p.LowerOffset] = true, true
		hi := binary.LittleEndian.Uint32(source[p.UpperOffset:])
		lo := binary.LittleEndian.Uint32(source[p.LowerOffset:])
		if hi != p.UpperWord || lo != p.LowerWord {
			return nil, PairRewriteResult{}, fmt.Errorf("site %d original instruction mismatch", i)
		}

		if hi>>26 != 15 || hi>>21&31 != 0 {
			return nil, PairRewriteResult{}, fmt.Errorf("site %d is not LUI", i)
		}
		r := (hi >> 16) & 31
		op := lo >> 26
		if r == 0 || (op != 9 && op != 13) || (lo>>21)&31 != r || (lo>>16)&31 != r {
			return nil, PairRewriteResult{}, fmt.Errorf("site %d is not a compatible low-half operation", i)
		}
		old := hi & 0xffff << 16
		if op == 9 {
			old += uint32(int32(int16(lo & 0xffff)))
		} else {
			old |= lo & 0xffff
		}
		if old != p.OldAddress {
			return nil, PairRewriteResult{}, fmt.Errorf("site %d does not form claimed old address (%#x)", i, old)
		}

		for at := p.UpperOffset + 4; at < p.LowerOffset; at += 4 {
			w := binary.LittleEndian.Uint32(source[at:])
			if isControlTransfer(w) && !(at+4 == p.LowerOffset && ordinaryDelaySlotTransfer(w)) {
				return nil, PairRewriteResult{}, fmt.Errorf("site %d crosses control flow", i)
			}

			if writesGPR(w, r) {
				return nil, PairRewriteResult{}, fmt.Errorf("site %d clobbers LUI register", i)
			}
		}
	}
	out := append([]byte(nil), source...)
	for _, p := range pairs {
		upper := p.UpperWord & 0xffff0000
		lower := p.LowerWord & 0xffff0000
		if p.LowerWord>>26 == 9 {
			upper |= ((p.NewAddress + 0x8000) >> 16) & 0xffff
		} else {
			upper |= (p.NewAddress >> 16) & 0xffff
		}
		lower |= p.NewAddress & 0xffff
		binary.LittleEndian.PutUint32(out[p.UpperOffset:], upper)
		binary.LittleEndian.PutUint32(out[p.LowerOffset:], lower)
	}

	for _, p := range pairs {
		hi := binary.LittleEndian.Uint32(out[p.UpperOffset:])
		lo := binary.LittleEndian.Uint32(out[p.LowerOffset:])
		v := (hi & 0xffff) << 16
		if lo>>26 == 9 {
			v += uint32(int32(int16(lo & 0xffff)))
		} else {
			v |= lo & 0xffff
		}
		if v != p.NewAddress {
			return nil, PairRewriteResult{}, fmt.Errorf("rewritten address does not round-trip")
		}
	}
	return out, PairRewriteResult{Sites: len(pairs), Words: len(used)}, nil
}

func writesGPR(w uint32, r uint32) bool {
	op := w >> 26
	if op == 0 {
		fn := w & 63
		rd := (w >> 11) & 31
		switch fn {
		case 0, 2, 3, 4, 6, 7, 16, 18, 32, 33, 34, 35, 36, 37, 38, 39, 42, 43:
			return rd == r
		case 8, 9, 12, 13, 17, 19, 24, 25, 26, 27, 10, 11:
			return false
		default:
			return true
		}
	}
	rt := (w >> 16) & 31
	switch op {
	case 2, 3, 4, 5, 6, 7, 40, 41, 42, 43, 46, 47, 48, 56, 57, 58, 59, 60, 61, 62, 63:
		return false
	case 1:
		return false
	case 8, 9, 10, 11, 12, 13, 14, 15, 32, 33, 34, 35, 36, 37, 38:
		return rt == r
	default:
		return true
	}
}

func ordinaryDelaySlotTransfer(w uint32) bool {
	op := w >> 26
	if op >= 3 && op <= 7 {
		return true
	}
	if op == 1 {
		rt := (w >> 16) & 31
		return rt == 0 || rt == 1 || rt == 16 || rt == 17
	}
	return false
}
