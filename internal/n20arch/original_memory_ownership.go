package n20arch

// memory ownership: authenticate and classify original, literal memory accesses that could
// clobber the proposed overlay-local C10 executable window. Unlike the tail guard
// code-integrity hash, this is a PRE-EMISSION check of original game code/data.
// This deliberately cannot classify indirect CPU/DMA/IRQ writes and is NOT an
// ownership or runtime proof. No guest ROM/image is written by this analysis.
import (
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	OwnershipWindowStart uint32 = OverlayBase
	OwnershipWindowEnd   uint32 = OverlayEnd
)

type Access struct {
	PC      uint32 `json:"pc"`
	Address uint32 `json:"address"`
	Width   uint32 `json:"width"`
	Kind    string `json:"kind"`
}
type OverlayEvidence struct {
	Overlay         string   `json:"overlay"`
	Carrier         bool     `json:"carrier"`
	LiteralPointers int      `json:"literal_pointers"`
	DirectReads     int      `json:"direct_reads"`
	DirectWrites    int      `json:"direct_writes"`
	Examples        []Access `json:"examples,omitempty"`
}
type OwnershipBoundary struct {
	SafeToPatch              bool              `json:"safe_to_patch"`
	RuntimePass              bool              `json:"runtime_pass"`
	ProvenExclusiveOwnership bool              `json:"exclusive_ownership_proven"`
	ScanKind                 string            `json:"scan_kind"`
	EXEDirectReads           int               `json:"exe_direct_reads"`
	EXEDirectWrites          int               `json:"exe_direct_writes"`
	EXELiteralPointers       int               `json:"exe_literal_pointers"`
	Carriers                 int               `json:"carriers"`
	FallbackOverlays         int               `json:"fallback_overlays"`
	OverlayEvidence          []OverlayEvidence `json:"overlay_evidence"`
}

// memoryOwnershipBoundedLiteralAccesses traces constants only inside a small straight-line
// MIPS-I basic-block region. The old untyped 0x8016 scanner incorrectly called
// "lw t6, -... (t6); sb ..., 0(t6)" a direct C10 write: lw replaces the
// pointer register, so the final destination is UNKNOWN, not 0x80160000.
// In contrast LUI $at, 0x8016; SW ..., 0x04f0($at) is a genuine literal write.
// Unresolved registers are deliberately omitted, NOT reported as safe.
func memoryOwnershipBoundedLiteralAccesses(src []byte) (reads, writes []Access) {
	return memoryOwnershipBoundedLiteralAccessesAt(src, OverlaySlotBase, 0x24000)
}

func memoryOwnershipBoundedLiteralAccessesAt(src []byte, base uint32, capBytes int) (reads, writes []Access) {
	return memoryOwnershipBoundedLiteralAccessesInWindowAt(src, base, capBytes, OwnershipWindowStart, OwnershipWindowEnd)
}

// Parameterized only for the additional authenticated formatter bridge pre-C10 window.
// This remains a bounded literal scan, NOT evidence of runtime memory ownership.
func memoryOwnershipBoundedLiteralAccessesInWindowAt(src []byte, base uint32, capBytes int, from, to uint32) (reads, writes []Access) {
	limit := len(src)
	if limit > capBytes {
		limit = capBytes
	} // bounded code candidate; data may still be present
	if limit < 0 {
		return
	}
	seen := map[uint32]bool{}
	for off := 0; off+4 <= limit; off += 4 {
		w := binary.LittleEndian.Uint32(src[off:])
		if w>>26 != 15 || (w&0xffff != 0x8015 && w&0xffff != 0x8016) {
			continue
		}
		reg := int((w >> 16) & 31)
		if reg == 0 {
			continue
		}
		// The upper half is constant until an instruction changes the reg.
		val := uint32(w&0xffff) << 16
		stopAfterDelaySlot := false
		for pos := off + 4; pos+4 <= limit && pos <= off+36; pos += 4 {
			q := binary.LittleEndian.Uint32(src[pos:])
			op := q >> 26
			rs := int((q >> 21) & 31)
			rt := int((q >> 16) & 31)
			u := uint32(q & 0xffff)
			signed := int32(int16(q & 0xffff))
			// MIPS-I branches and jumps execute exactly one delay-slot
			// instruction. A literal store in that slot is real even when
			// the branch skips the following straight-line instructions.
			// Do not follow either successor after the delay slot.
			inDelaySlot := stopAfterDelaySlot
			isControlTransfer := op == 2 || op == 3 || (op >= 4 && op <= 7) || op == 1 || (op == 0 && (q&63 == 8 || q&63 == 9))
			if isControlTransfer {
				// JAL/JALR may replace the tracked link register before
				// the delay slot. Its former literal is no longer known.
				if (op == 3 && reg == 31) || (op == 0 && q&63 == 9 && int((q>>11)&31) == reg) || inDelaySlot {
					break
				}
				stopAfterDelaySlot = true
				continue
			}
			if rs == reg {
				width, kind := uint32(0), ""
				switch op {
				case 32, 36:
					width, kind = 1, "read"
				case 33, 37:
					width, kind = 2, "read"
				case 35, 34, 38:
					width, kind = 4, "read"
				case 40:
					width, kind = 1, "write"
				case 41:
					width, kind = 2, "write"
				case 43, 42, 46:
					width, kind = 4, "write"
				}
				if width != 0 {
					addr := uint32(int64(val) + int64(signed))
					if uint64(addr) < uint64(to) && uint64(addr)+uint64(width) > uint64(from) {
						pc := base + uint32(pos)
						k := pc << 1
						if kind == "write" {
							k++
						}
						if !seen[k] {
							hit := Access{PC: pc, Address: addr, Width: width, Kind: kind}
							if kind == "write" {
								writes = append(writes, hit)
							} else {
								reads = append(reads, hit)
							}
							seen[k] = true
						}
					}
				}
			}
			// Register replaced by a newly computed absolute value.
			if (op == 9 || op == 13) && rs == reg && rt == reg {
				if op == 9 {
					val = uint32(int64(val) + int64(signed))
				} else {
					val |= u
				}
				if inDelaySlot {
					break
				}
				continue
			}
			// A load replaces its target: it is a pointer dereference and
			// must never be misreported as literal-address access.
			if rt == reg && (op == 15 || op == 32 || op == 33 || op == 35 || op == 36 || op == 37 || op == 9 || op == 13 || op == 12 || op == 14 || op == 8 || op == 10 || op == 11) {
				break
			}
			if op == 0 { // any R-type write to rd kills known reg
				rd := int((q >> 11) & 31)
				// SLL (funct=0) is also a register write; NOP has
				// rd=0 and therefore cannot clobber a tracked register.
				if rd == reg && q&63 != 8 && q&63 != 9 {
					break
				}
			}
			if inDelaySlot {
				break
			}
		}
	}
	sort.Slice(reads, func(i, j int) bool { return reads[i].PC < reads[j].PC })
	sort.Slice(writes, func(i, j int) bool { return writes[i].PC < writes[j].PC })
	return
}

func memoryOwnershipEXELiteralAccess(exe []byte) (int, int, int, error) {
	if len(exe) != 667648 || sha(exe) != "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae" {
		return 0, 0, 0, fmt.Errorf("memory ownership original EXE authentication mismatch")
	}
	pointers := 0
	for i := 0; i+4 <= len(exe); i += 4 {
		v := binary.LittleEndian.Uint32(exe[i:])
		if v >= OwnershipWindowStart && v < OwnershipWindowEnd {
			pointers++
		}
	}
	reads, writes := memoryOwnershipBoundedLiteralAccessesAt(exe, 0x80040800, len(exe))
	return pointers, len(reads), len(writes), nil
}

func AuditOriginalC10Window(originals map[string][]byte, eligible []string) (OwnershipBoundary, error) {
	var out OwnershipBoundary
	out.ScanKind = "BOUNDED_LITERAL_MIPS_AND_DATA_POINTERS_NOT_INDIRECT_WRITES"
	if len(originals) != len(OverlaySHA) || len(eligible) != 22 {
		return out, fmt.Errorf("memory ownership requires original 26 and exactly 22 candidates")
	}
	carrier := map[string]bool{}
	for _, name := range eligible {
		if carrier[name] {
			return out, fmt.Errorf("memory ownership repeated carrier %s", name)
		}
		carrier[name] = true
	}
	names := make([]string, 0, len(OverlaySHA))
	for name := range OverlaySHA {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := originals[name]
		if len(b) != OverlayLoadSectors*2048 || sha(b) != OverlaySHA[name] {
			return out, fmt.Errorf("memory ownership refuses unknown original %s", name)
		}
		item := OverlayEvidence{Overlay: name, Carrier: carrier[name]}
		for i := 0; i+4 <= len(b); i += 4 {
			x := binary.LittleEndian.Uint32(b[i:])
			if x >= OwnershipWindowStart && x < OwnershipWindowEnd {
				item.LiteralPointers++
			}
		}
		reads, writes := memoryOwnershipBoundedLiteralAccesses(b)
		item.DirectReads = len(reads)
		item.DirectWrites = len(writes)
		item.Examples = append(item.Examples, writes...)
		item.Examples = append(item.Examples, reads...)
		if len(item.Examples) > 8 {
			item.Examples = item.Examples[:8]
		}
		if item.Carrier {
			out.Carriers++
			if item.LiteralPointers != 0 || item.DirectWrites != 0 || item.DirectReads != 0 {
				return out, fmt.Errorf("memory ownership C10 window already addressed by original %s: ptr=%d read=%d write=%d", name, item.LiteralPointers, item.DirectReads, item.DirectWrites)
			}
		} else {
			out.FallbackOverlays++
		}
		out.OverlayEvidence = append(out.OverlayEvidence, item)
	}
	if out.Carriers != 22 || out.FallbackOverlays != 4 {
		return out, fmt.Errorf("memory ownership carrier/fallback mismatch")
	}
	// Crucial: even zero bounded static references do not exclude indirect
	// stores or asynchronous changes. An empty list MUST NOT unlock a build.
	return out, nil
}

// PlanBoundedOwnershipOffline makes the source-backed memory audit an
// unavoidable precondition of the CURRENT full-English tail guard candidate. It
// emits exactly the same guest bytes as tail guard: this stage does not hide a
// speculative new callsite or a new executable placement.
type BoundedCandidate struct {
	GuardTailCandidate
	Boundary OwnershipBoundary
}

func PlanBoundedOwnershipOffline(exe []byte, originals map[string][]byte) (BoundedCandidate, error) {
	var empty BoundedCandidate
	tailGuardStage, err := PlanGuardTailIntegrityOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	audit, err := AuditOriginalC10Window(originals, tailGuardStage.Carriers)
	if err != nil {
		return empty, err
	}
	ep, er, ew, e := memoryOwnershipEXELiteralAccess(exe)
	if e != nil {
		return empty, e
	}
	audit.EXELiteralPointers = ep
	audit.EXEDirectReads = er
	audit.EXEDirectWrites = ew
	if ep != 0 || er != 0 || ew != 0 {
		return empty, fmt.Errorf("memory ownership original EXE directly refers to local C10: ptr=%d read=%d write=%d", ep, er, ew)
	}
	return BoundedCandidate{GuardTailCandidate: tailGuardStage, Boundary: audit}, nil
}
