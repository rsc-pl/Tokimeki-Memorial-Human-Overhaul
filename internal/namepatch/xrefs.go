package namepatch

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// Xref is a potential static address materialization or direct load/store.
// It is NOT evidence that the location executes, nor proof that all indirect
// users (register copies, pointers in data, DMA, overlays) have been found.
// UpperOffset and UseOffset are file offsets, not RAM addresses.
type Xref struct {
	UpperOffset int         `json:"upper_offset"`
	UseOffset   int         `json:"use_offset"`
	Address     uint32      `json:"address"`
	UpperWord   uint32      `json:"upper_word"`
	UseWord     uint32      `json:"use_word"`
	Kind        string      `json:"kind"`
	Register    uint32      `json:"register"`
	DirectCall  *DirectCall `json:"direct_call,omitempty"`
}

type XrefAudit struct {
	File                   string         `json:"file"`
	Size                   int            `json:"size"`
	References             []Xref         `json:"references"`
	CallGroups             []CallGroup    `json:"call_groups"`
	CountsByAddress        map[string]int `json:"counts_by_address"`
	ReviewedSitesMatched   int            `json:"reviewed_sites_matched"`
	ReviewedSitesRequired  int            `json:"reviewed_sites_required"`
	CompleteCallerCoverage bool           `json:"complete_caller_coverage"`
	SafeToRelocate         bool           `json:"safe_to_relocate"`
	Caveat                 string         `json:"caveat"`
}

// FindRAMReferences examines MIPS I instructions, searching for LUI followed
// by direct ADDIU/ORI or load/store addressing in a small straight-line window.
// It deliberately does NOT infer arbitrary indirect uses or interpret raw
// bytes as certainly executable. Its output is a review queue, not a patch list.
// The interval is [first, last), using the addresses observed in original EXE.
func FindRAMReferences(data []byte, first, last uint32) ([]Xref, error) {
	if len(data)%4 != 0 || first >= last {
		return nil, fmt.Errorf("invalid MIPS data or target range")
	}
	result := []Xref{}
	for pos := 0; pos+4 <= len(data); pos += 4 {
		hi := binary.LittleEndian.Uint32(data[pos:])
		if hi>>26 != 15 || (hi>>21)&31 != 0 {
			continue
		}
		reg := (hi >> 16) & 31
		if reg == 0 {
			continue
		}
		// HI immediates outside target's signed and unsigned 16-bit buckets
		// cannot produce a reference to the interval via a simple low half.
		h := uint32(hi&0xffff) << 16
		if h != first&0xffff0000 && h != ((first+0x8000)&0xffff0000) {
			continue
		}
		for at := pos + 4; at+4 <= len(data) && at <= pos+64; at += 4 {
			w := binary.LittleEndian.Uint32(data[at:])
			op := w >> 26
			rs := (w >> 21) & 31
			rt := (w >> 16) & 31
			kind := ""
			var addr uint32
			if rs == reg && rt == reg && (op == 9 || op == 13) {
				if op == 9 {
					addr = h + uint32(int32(int16(w&0xffff)))
				} else {
					addr = h | uint32(w&0xffff)
				}
				kind = "address-construction"
			} else if rs == reg && isMemoryInstruction(op) {
				addr = h + uint32(int32(int16(w&0xffff)))
				if isStoreInstruction(op) {
					kind = "memory-write"
				} else {
					kind = "memory-read"
				}
			}
			if kind != "" && addr >= first && addr < last {
				result = append(result, Xref{UpperOffset: pos, UseOffset: at, Address: addr, UpperWord: hi, UseWord: w, Kind: kind, Register: reg})
			}
			// Only a call/jump immediately before the following delay slot
			// is permitted; scanning may include that slot but never code
			// beyond it as if register lifetime were guaranteed.
			control := isControlTransfer(w)
			if control {
				if at+4 <= pos+64 && at+8 <= len(data) {
					slot := binary.LittleEndian.Uint32(data[at+4:])
					slotOp := slot >> 26
					slotRS := (slot >> 21) & 31
					slotRT := (slot >> 16) & 31
					sk := ""
					var sa uint32
					if slotRS == reg && slotRT == reg && (slotOp == 9 || slotOp == 13) {
						if slotOp == 9 {
							sa = h + uint32(int32(int16(slot&0xffff)))
						} else {
							sa = h | uint32(slot&0xffff)
						}
						sk = "address-construction"
					} else if slotRS == reg && isMemoryInstruction(slotOp) {
						sa = h + uint32(int32(int16(slot&0xffff)))
						if isStoreInstruction(slotOp) {
							sk = "memory-write"
						} else {
							sk = "memory-read"
						}
					}
					if sk != "" && sa >= first && sa < last {
						result = append(result, Xref{UpperOffset: pos, UseOffset: at + 4, Address: sa, UpperWord: hi, UseWord: slot, Kind: sk, Register: reg})
					}
				}
				break
			}
			// Any instruction that changes the register invalidates the
			// original LUI value, including the just-reported ADDIU/ORI.
			if writesGPR(w, reg) {
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].UpperOffset != result[j].UpperOffset {
			return result[i].UpperOffset < result[j].UpperOffset
		}
		return result[i].UseOffset < result[j].UseOffset
	})
	return result, nil
}

func isMemoryInstruction(op uint32) bool {
	switch op {
	case 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 46, 48, 49, 50, 51, 56, 57, 58, 59:
		return true
	}
	return false
}
func isStoreInstruction(op uint32) bool {
	switch op {
	case 40, 41, 42, 43, 46, 56, 57, 58, 59:
		return true
	}
	return false
}
func isControlTransfer(w uint32) bool {
	op := w >> 26
	if op == 1 || op == 2 || op == 3 || op == 4 || op == 5 || op == 6 || op == 7 {
		return true
	}
	return op == 0 && (w&63 == 8 || w&63 == 9)
}

// AuditXrefs never certifies coverage. It asserts only that the known
// independently reviewed original instruction pairs are present in the scan.
func AuditXrefs(file string, raw []byte) (XrefAudit, error) {
	refs, e := FindRAMReferences(raw, 0x800ca180, 0x800ca1c0)
	if e == nil {
		refs = AnnotateDirectCalls(raw, refs)
	}
	if e != nil {
		return XrefAudit{}, e
	}
	known := KnownN10Copies(file)
	if len(known) == 0 {
		return XrefAudit{}, fmt.Errorf("unsupported file %q", file)
	}
	found := 0
	for _, pair := range known {
		match := false
		for _, r := range refs {
			if r.UpperOffset == pair.UpperOffset && r.UseOffset == pair.LowerOffset && r.Address == pair.OldAddress && r.UpperWord == pair.UpperWord && r.UseWord == pair.LowerWord {
				match = true
				break
			}
		}
		if !match {
			return XrefAudit{}, fmt.Errorf("reviewed site missing from scan %s at %#x/%#x", file, pair.UpperOffset, pair.LowerOffset)
		}
		found++
	}
	counts := map[string]int{}
	for _, r := range refs {
		counts[fmt.Sprintf("0x%08X", r.Address)]++
	}
	return XrefAudit{File: file, Size: len(raw), References: refs, CallGroups: SummarizeDirectCalls(refs), CountsByAddress: counts, ReviewedSitesMatched: found, ReviewedSitesRequired: len(known), CompleteCallerCoverage: false, SafeToRelocate: false, Caveat: "Static MIPS candidates; indirect references, overlay aliasing, pointer data, buffer capacity and liveness unresolved. Not approval to patch."}, nil
}
