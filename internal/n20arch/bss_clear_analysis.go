package n20arch

// Conservative read-only analysis of retail BIOS A0:28h bzero callers.
// It deliberately separates literal call arguments from pointers read from
// file-initialized (but potentially runtime-modified) overlay tables.
import "encoding/binary"

type n20BSSArgument struct {
	Value  uint32
	Source string // literal, file_initialized_pointer, or unresolved
}

func n20Sign16(x uint32) uint32 { return uint32(int32(int16(x & 0xffff))) }

// n20ConstArg traces the LAST writer to a register backwards. Encountering
// another call or control transfer is a barrier: caller-saved argument values
// are not assumed to survive it. File-backed loads are initial-state evidence
// ONLY, never asserted to be immutable at runtime.
func n20ConstArg(d []byte, base uint32, before int, reg uint32, steps int, currentCall int) n20BSSArgument {
	if reg == 0 {
		return n20BSSArgument{0, "literal"}
	}
	if steps <= 0 {
		return n20BSSArgument{Source: "unresolved"}
	}
	for j := before; j >= 0 && j >= before-4*steps; j -= 4 {
		if j+4 > len(d) {
			continue
		}
		if j == currentCall {
			continue
		} // Skip this JAL; its delay slot already ran.
		w := binary.LittleEndian.Uint32(d[j:])
		op, rs, rt, rd, fn := w>>26, (w>>21)&31, (w>>16)&31, (w>>11)&31, w&63
		// Barrier for other JAL/JALR, returns and conditional branches.
		if op == 3 || op == 2 || (op >= 4 && op <= 7) || op == 1 ||
			(op == 0 && (fn == 8 || fn == 9)) {
			return n20BSSArgument{Source: "unresolved"}
		}
		write := rt == reg && (op == 9 || op == 13 || op == 15 || op == 35 || op == 36 || op == 37 || op == 32 || op == 33 || op == 14 || op == 8 || op == 12)
		if op == 0 && rd == reg && (fn == 0 || fn == 2 || fn == 3 || fn == 4 || fn == 6 || fn == 7 || fn == 16 || fn == 18 || fn == 32 || fn == 33 || fn == 34 || fn == 35 || fn == 36 || fn == 37 || fn == 38 || fn == 39 || fn == 42 || fn == 43) {
			write = true // unsupported producers conservatively become unresolved
		}
		if !write {
			continue
		}
		prior := func(r uint32) n20BSSArgument { return n20ConstArg(d, base, j-4, r, steps-1, currentCall) }
		switch op {
		case 15:
			return n20BSSArgument{(w & 0xffff) << 16, "literal"}
		case 9, 13:
			v := prior(rs)
			if v.Source == "unresolved" {
				return v
			}
			if op == 9 {
				v.Value += n20Sign16(w)
			} else {
				v.Value |= w & 0xffff
			}
			return v
		case 35: // lw — read the initial value from an authenticated file region.
			p := prior(rs)
			if p.Source != "literal" {
				return n20BSSArgument{Source: "unresolved"}
			}
			addr := p.Value + n20Sign16(w)
			if addr < base || addr-base+4 > uint32(len(d)) || addr%4 != 0 {
				return n20BSSArgument{Source: "unresolved"}
			}
			return n20BSSArgument{binary.LittleEndian.Uint32(d[addr-base:]), "file_initialized_pointer"}
		case 0:
			if (fn == 33 || fn == 37) && (rs == 0 || rt == 0) {
				if rs == 0 {
					return prior(rt)
				}
				return prior(rs)
			}
		}
		return n20BSSArgument{Source: "unresolved"}
	}
	return n20BSSArgument{Source: "unresolved"}
}

// n20BSSClearArguments resolves arguments at the point the callee starts;
// JAL delay slots are executed and therefore inspected first.
func n20BSSClearArguments(d []byte, base uint32, callOff int) (n20BSSArgument, n20BSSArgument) {
	return n20ConstArg(d, base, callOff+4, 4, 24, callOff), n20ConstArg(d, base, callOff+4, 5, 24, callOff)
}

// Source-level resolutions for the four call sites the conservative resolver
// could not express. Every resolution is gated on authenticated instruction
// words at fixed PCs; if any anchor drifts the site stays unresolved. These
// do not upgrade runtime ownership: table-derived destinations remain
// file-initial-state only, because DMA/IRQ and indirect writes are not
// modelled.
const (
	n20TTTableBase = 0x80158A60
	n20TTTableEnd  = 0x80158AB8
)

type n20BSSTargetedResolution struct {
	A0         uint32
	A1         uint32
	RangeLo    uint32
	RangeHi    uint32
	Bounded    bool
	AddrSource string
	TableSlot  uint32
	Resolution string
}

func n20WordAt(d []byte, base, pc uint32) (uint32, bool) {
	if pc < base {
		return 0, false
	}
	o := int(pc - base)
	if o+4 > len(d) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(d[o:]), true
}

// n20AnchorsMatch requires every (pc,word) pair to equal the authenticated
// file word, so a targeted resolution cannot silently survive a byte change.
func n20AnchorsMatch(d []byte, base uint32, anchors [][2]uint32) bool {
	for _, an := range anchors {
		got, ok := n20WordAt(d, base, an[0])
		if !ok || got != an[1] {
			return false
		}
	}
	return true
}

// n20TargetedBSSClear resolves one of the four known dynamic bzero call sites
// from its surrounding decoded structure. It returns false for every other
// site, which keeps the generic conservative classification.
func n20TargetedBSSClear(d []byte, base uint32, callOff int) (n20BSSTargetedResolution, bool) {
	pc := base + uint32(callOff)
	switch pc {
	case 0x8006B148: // EXE: union of the 4-byte loop clears is [0x800E67CC,0x800E67EC)
		// slti t3,8 + addu a0,(a2<<2)+0x800E6280+0x54C + stop at 0x800E67EC.
		anchors := [][2]uint32{
			{0x8006B120, 0x29610008}, {0x8006B124, 0x10200011},
			{0x8006B12C, 0x00067080}, {0x8006B130, 0x3C18800E},
			{0x8006B134, 0x27186280}, {0x8006B138, 0x25D9054C},
			{0x8006B13C, 0x03382021}, {0x8006B148, 0x0C02B820},
			{0x8006B158, 0x25EF67EC}, {0x8006B164, 0x148FFFF7},
		}
		if !n20AnchorsMatch(d, base, anchors) {
			return n20BSSTargetedResolution{}, false
		}
		return n20BSSTargetedResolution{
			A0: 0x800E67CC, A1: 4, RangeLo: 0x800E67CC, RangeHi: 0x800E67EC,
			Bounded: true, AddrSource: "literal", Resolution: "loop_union_bounded_literal",
		}, true

	case 0x80136DF4: // TT: a0 <- 84(sp) <- v1 <- *(0x80158A6C)
		anchors := [][2]uint32{
			{0x80136C8C, 0x3C0F8016}, {0x80136C90, 0x8DE38A6C},
			{0x80136D3C, 0xAFA30054}, {0x80136DA8, 0xAFA30054},
			{0x80136DC0, 0xAFA30054}, {0x80136DF0, 0x8FA40054},
			{0x80136DF4, 0x0C02B820},
		}
		return n20TTTableResolution(d, base, anchors, 0x80158A6C, "stack_slot_table_pointer_84sp")

	case 0x80136E00: // TT: a0 <- 80(sp) <- t8 <- *(0x80158A70)
		anchors := [][2]uint32{
			{0x80136C74, 0x3C188016}, {0x80136C80, 0x8F188A70},
			{0x80136C9C, 0xAFB80050}, {0x80136DFC, 0x8FA40050},
			{0x80136E00, 0x0C02B820},
		}
		return n20TTTableResolution(d, base, anchors, 0x80158A70, "stack_slot_table_pointer_80sp")

	case 0x801452EC: // TT: a0 <- 64(sp) <- t8 <- *(0x80158A70)
		anchors := [][2]uint32{
			{0x80144D80, 0x3C188016}, {0x80144D88, 0x8F188A70},
			{0x80144DAC, 0xAFB80040}, {0x801452E8, 0x8FA40040},
			{0x801452EC, 0x0C02B820},
		}
		return n20TTTableResolution(d, base, anchors, 0x80158A70, "stack_slot_table_pointer_64sp")
	}
	return n20BSSTargetedResolution{}, false
}

func n20TTTableResolution(d []byte, base uint32, anchors [][2]uint32, slot uint32, how string) (n20BSSTargetedResolution, bool) {
	if !n20AnchorsMatch(d, base, anchors) {
		return n20BSSTargetedResolution{}, false
	}
	v, ok := n20WordAt(d, base, slot)
	if !ok || v < BootBSSStart || v+32 > BootBSSEnd {
		return n20BSSTargetedResolution{}, false
	}
	return n20BSSTargetedResolution{
		A0: v, A1: 32, RangeLo: v, RangeHi: v + 32,
		// Initial range only: the word is file-initialized and can change if
		// an unmodelled runtime writer/DMA exists.
		Bounded: false, AddrSource: "file_initialized_pointer", TableSlot: slot,
		Resolution: how + "_initial",
	}, true
}

// n20TTTableStaticWriters enumerates static stores whose effective address is
// in the 4-byte pointer entries [0x80158A60,0x80158AB8). Base registers are
// traced with the same conservative backward resolver used for bzero. A zero
// result means "no decoded static writer", not "immutable under DMA/IRQ".
func n20TTTableStaticWriters(d []byte, base uint32) []uint32 {
	var out []uint32
	for i := 0; i+4 <= len(d); i += 4 {
		w := binary.LittleEndian.Uint32(d[i:])
		op := w >> 26
		if op != 0x28 && op != 0x29 && op != 0x2A && op != 0x2B && op != 0x2E {
			continue
		}
		rs := (w >> 21) & 31
		c := n20ConstArg(d, base, i-4, rs, 24, -1)
		if c.Source != "literal" {
			continue
		}
		eff := c.Value + uint32(int32(int16(w&0xFFFF)))
		if eff >= n20TTTableBase && eff < n20TTTableEnd {
			out = append(out, base+uint32(i))
		}
	}
	return out
}
