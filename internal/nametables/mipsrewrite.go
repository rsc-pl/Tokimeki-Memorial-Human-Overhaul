package nametables

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// AddressPair is one EXPLICITLY REVIEWED MIPS R3000 LUI/addiu address load.
// File offsets and both original words must be taken from the original binary.
// This API deliberately does not discover or infer additional callers.
// In particular, a successfully rewritten set does NOT establish that all
// readers/writers of a buffer have been found.
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
	// Remains false: the operation does not prove call-site completeness,
	// safe RAM allocation, display width, or actual runtime behavior.
	RuntimeValidated bool `json:"runtime_validated"`
}

// RewriteGuardedAddressPairs patches only complete and explicitly verified
// LUI+ADDIU/ORI address materializations. It is transactional: any failure
// returns no output and never modifies the input. This low-level engineering
// primitive is NOT wired into build/native-build/name-stage.
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
		// Require LUI r,imm16; ADDIU r,r,imm16 or ORI r,r,imm16.
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
		// Check instructions between the halves. A control transfer immediately
		// before the lower half is allowed only when that lower instruction is
		// its ordinary MIPS I delay slot. It executes regardless of branch
		// direction. Never cross the transfer or accept a nested delay slot.
		for at := p.UpperOffset + 4; at < p.LowerOffset; at += 4 {
			w := binary.LittleEndian.Uint32(source[at:])
			if isControlTransfer(w) && !(at+4 == p.LowerOffset && ordinaryDelaySlotTransfer(w)) {
				return nil, PairRewriteResult{}, fmt.Errorf("site %d crosses control flow", i)
			}
			// A write to the LUI destination invalidates the address.
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
	// Defensive end-to-end round trip of patched address materializations.
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

// writesGPR recognizes integer register writes in the instruction families
// used here. Unknown opcodes fail closed, not silently assumed harmless.
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
		return false // regimm branches: handled by control-flow check
	case 8, 9, 10, 11, 12, 13, 14, 15, 32, 33, 34, 35, 36, 37, 38:
		return rt == r
	default:
		return true
	}
}

// MIPS I executes the slot after these control transfers unconditionally;
// R3000 has no branch-likely instructions. This does not permit crossing the
// transfer or infer any behavior beyond its one instruction delay slot.
func ordinaryDelaySlotTransfer(w uint32) bool {
	op := w >> 26
	if op >= 3 && op <= 7 {
		return true
	}
	if op == 1 { // REGIMM: only BLTZ/BGEZ and link variants.
		rt := (w >> 16) & 31
		return rt == 0 || rt == 1 || rt == 16 || rt == 17
	}
	return false // Indirect JR/JALR slots require additional provenance.
}

// KnownN10Copies is an *incomplete* reviewed list of address materializations
// from R04. It documents exact instruction words without including game data.
// Known EXE uses cover the specific surname-copy function observed in R07;
// other consumers still exist. Never feed only these sites to a live patch.
func KnownN10Copies(file string) []AddressPair {
	var sites []AddressPair
	switch file {
	case "SLPM_86.053":
		sites = []AddressPair{
			{UpperOffset: 0x44020, LowerOffset: 0x44028, UpperWord: 0x3c04800d, LowerWord: 0x2484a188, OldAddress: BufferA},
			{UpperOffset: 0x4402c, LowerOffset: 0x44038, UpperWord: 0x3c04800d, LowerWord: 0x2484a190, OldAddress: BufferB},
		}
	case "CDROM/EXEDIR/GEKO.EXN":
		sites = []AddressPair{
			{UpperOffset: 0xf464, LowerOffset: 0xf474, UpperWord: 0x3c04800d, LowerWord: 0x2484a188, OldAddress: BufferA},
			{UpperOffset: 0xf478, LowerOffset: 0xf488, UpperWord: 0x3c04800d, LowerWord: 0x2484a190, OldAddress: BufferB},
			{UpperOffset: 0xf4d0, LowerOffset: 0xf4dc, UpperWord: 0x3c04800d, LowerWord: 0x2484a19c, OldAddress: BufferC},
		}
	}
	return append([]AddressPair(nil), sites...)
}

// ApplyCandidateAddresses replaces the target addresses of a site list in a
// deterministic order. The caller must validate every intended target.
func ApplyCandidateAddresses(sites []AddressPair, addresses map[uint32]uint32) ([]AddressPair, error) {
	out := append([]AddressPair(nil), sites...)
	for i := range out {
		addr, ok := addresses[out[i].OldAddress]
		if !ok || addr == 0 {
			return nil, fmt.Errorf("no new destination for %#x", out[i].OldAddress)
		}
		out[i].NewAddress = addr
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpperOffset < out[j].UpperOffset })
	return out, nil
}

// VerifyKnownCopySites checks the complete, exact instruction bytes of every
// *currently documented* caller. The result is NOT a proof of exhaustive
// coverage or a permit to redirect buffers in a playable image.
func VerifyKnownCopySites(fileName string, original []byte) (int, error) {
	sites := KnownN10Copies(fileName)
	if len(sites) == 0 {
		return 0, fmt.Errorf("no reviewed N10 callsites for %q", fileName)
	}
	for i := range sites {
		sites[i].NewAddress = sites[i].OldAddress
	}
	tested, _, err := RewriteGuardedAddressPairs(original, sites)
	if err != nil {
		return 0, err
	}
	if len(tested) != len(original) {
		return 0, fmt.Errorf("verification changed length")
	}
	for i := range tested {
		if tested[i] != original[i] {
			return 0, fmt.Errorf("no-op verification changed byte %#x", i)
		}
	}
	return len(sites), nil
}
