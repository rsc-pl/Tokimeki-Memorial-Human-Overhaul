package nametables

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// ProvenanceHit is a *static candidate*, not an executed reference. The
// scanner follows MIPS-I simple register moves and arithmetic within a bounded
// basic-block window; it does not resolve indirect calls, loaded pointer
// values, DMA, self-modifying code or both sides of a branch.
type ProvenanceHit struct {
	AnchorOffset int    `json:"anchor_offset"`
	UseOffset    int    `json:"use_offset"`
	Address      uint32 `json:"address"`
	Action       string `json:"action"`
	ViaRegister  uint32 `json:"via_register"`
	DerivedSteps int    `json:"derived_steps"`
}

type LiteralProvenanceReport struct {
	ZeroRunCandidates      []GEKOZeroRun   `json:"zero_run_candidates,omitempty"`
	Status                 string          `json:"status"`
	RangeStart             uint32          `json:"range_start"`
	RangeEnd               uint32          `json:"range_end"`
	Hits                   []ProvenanceHit `json:"hits"`
	PointerEscapes         []PointerEscape `json:"pointer_escapes"`
	ReviewedEscapes        int             `json:"reviewed_escapes"`
	UnreviewedEscapes      int             `json:"unreviewed_escapes"`
	DirectKnown            int             `json:"direct_known"`
	AdditionalCandidates   int             `json:"additional_candidates"`
	WindowInstructions     int             `json:"window_instructions"`
	CallerCoverageComplete bool            `json:"caller_coverage_complete"`
	SafeToOverwrite        bool            `json:"safe_to_overwrite"`
	Limitations            []string        `json:"limitations"`
}

type trackedValue struct {
	value uint32
	steps int
	valid bool
}

// FindDerivedLiteralReferences conservatively detects references assembled from
// LUI + multiple ADDIU/ORI instructions, copied through ADDU/OR with $zero,
// or dereferenced with a load/store. It only traces contiguous instructions,
// stopping after a control-flow delay slot. A reported hit may be dead code or
// data and an absent hit does NOT prove an absent indirect reader.
func FindDerivedLiteralReferences(data []byte, first, last uint32, maxInstructions int) ([]ProvenanceHit, error) {
	if len(data)%4 != 0 || first >= last || maxInstructions < 2 || maxInstructions > 128 {
		return nil, fmt.Errorf("invalid literal provenance input")
	}
	hits := make([]ProvenanceHit, 0)
	seen := map[[3]uint64]bool{}
	add := func(anchor, off int, addr uint32, action string, reg uint32, steps int) {
		k := [3]uint64{uint64(anchor), uint64(off), uint64(addr)}
		if seen[k] {
			return
		}
		seen[k] = true
		hits = append(hits, ProvenanceHit{AnchorOffset: anchor, UseOffset: off, Address: addr, Action: action, ViaRegister: reg, DerivedSteps: steps})
	}
	for anchor := 0; anchor+4 <= len(data); anchor += 4 {
		w := binary.LittleEndian.Uint32(data[anchor:])
		if w>>26 != 15 || (w>>21)&31 != 0 {
			continue
		}
		dest := (w >> 16) & 31
		if dest == 0 {
			continue
		}
		// Only anchor highs which may reach the target via the immediate encoding.
		hi := uint32(w&0xffff) << 16
		if hi != first&0xffff0000 && hi != ((first+0x8000)&0xffff0000) {
			continue
		}
		var regs [32]trackedValue
		regs[dest] = trackedValue{value: hi, valid: true}
		for step := 1; step <= maxInstructions && anchor+4*step+4 <= len(data); step++ {
			off := anchor + 4*step
			ins := binary.LittleEndian.Uint32(data[off:])
			op := ins >> 26
			rs := (ins >> 21) & 31
			rt := (ins >> 16) & 31
			rd := (ins >> 11) & 31
			imm := uint32(ins & 0xffff)
			signed := uint32(int32(int16(imm)))
			// Reads observe the OLD registers. Writes commit only afterward, including
			// when source and destination are the same register.
			old := regs
			var target uint32
			var action string
			var reg uint32
			var steps int
			if isMemoryInstruction(op) && old[rs].valid {
				target = old[rs].value + signed
				if isStoreInstruction(op) {
					action = "memory-write"
				} else {
					action = "memory-read"
				}
				reg = rs
				steps = old[rs].steps + 1
			}
			updates := map[uint32]trackedValue{}
			invalidate := map[uint32]bool{}
			newval := trackedValue{}
			if (op == 9 || op == 13) && old[rs].valid { // ADDIU / ORI
				newval = trackedValue{valid: true, steps: old[rs].steps + 1}
				if op == 9 {
					newval.value = old[rs].value + signed
				} else {
					newval.value = old[rs].value | imm
				}
				updates[rt] = newval
			} else if op == 0 && (ins&63 == 33 || ins&63 == 37) && (rs == 0 || rt == 0) { // ADDU/OR move
				source := rs
				if source == 0 {
					source = rt
				}
				if old[source].valid {
					newval = trackedValue{valid: true, value: old[source].value, steps: old[source].steps + 1}
					updates[rd] = newval
				}
			} else if op == 15 { // LUI overwrites a register; original provenance ends.
				invalidate[rt] = true
			}
			// Any unrecognized register write kills an old provenance, even if the
			// following instruction could happen to reconstruct the same numerical value.
			for r := uint32(1); r < 32; r++ {
				if writesGPR(ins, r) {
					invalidate[r] = true
				}
			}
			for r := range invalidate {
				regs[r] = trackedValue{}
			}
			for r, v := range updates {
				if r != 0 {
					regs[r] = v
				}
			}
			if action != "" && target >= first && target < last {
				add(anchor, off, target, action, reg, steps)
			}
			if newval.valid && newval.value >= first && newval.value < last {
				// Merely forming an address does not mean the memory was used.
				if op == 9 || op == 13 {
					action = "address-construction"
					reg = rt
				} else {
					action = "register-alias"
					reg = rd
				}
				add(anchor, off, newval.value, action, reg, newval.steps)
			}
			if isControlTransfer(ins) {
				// Permit only the ordinary delay-slot instruction, then stop. This
				// intentionally over-approximates the slot as reachable on both paths.
				if step < maxInstructions && off+8 <= len(data) {
					slot := binary.LittleEndian.Uint32(data[off+4:])
					sop := slot >> 26
					srs := (slot >> 21) & 31
					srt := (slot >> 16) & 31
					if isMemoryInstruction(sop) && regs[srs].valid {
						a := regs[srs].value + uint32(int32(int16(slot&0xffff)))
						if a >= first && a < last {
							kind := "memory-read"
							if isStoreInstruction(sop) {
								kind = "memory-write"
							}
							add(anchor, off+4, a, kind, srs, regs[srs].steps+1)
						}
					}
					if (sop == 9 || sop == 13) && regs[srs].valid && srs == srt {
						a := regs[srs].value
						if sop == 9 {
							a += uint32(int32(int16(slot & 0xffff)))
						} else {
							a |= slot & 0xffff
						}
						if a >= first && a < last {
							add(anchor, off+4, a, "address-construction", srt, regs[srs].steps+1)
						}
					}
				}
				break
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].UseOffset != hits[j].UseOffset {
			return hits[i].UseOffset < hits[j].UseOffset
		}
		return hits[i].AnchorOffset < hits[j].AnchorOffset
	})
	return hits, nil
}

// AuditGEKOLiteralProvenance is deliberately never an overwrite approval. It
// requires caller review for EVERY hit other than the two known direct sources.
func AuditGEKOLiteralProvenance(geko []byte) (LiteralProvenanceReport, error) {
	const first uint32 = 0x80144b1c
	const end uint32 = 0x80144b30
	hits, err := FindDerivedLiteralReferences(geko, first, end, 32)
	if err != nil {
		return LiteralProvenanceReport{}, err
	}
	direct := 0
	for _, h := range hits {
		if h.Action == "address-construction" && ((h.AnchorOffset == 0xf468 && h.UseOffset == 0xf46c && h.Address == first) || (h.AnchorOffset == 0xf47c && h.UseOffset == 0xf480 && h.Address == 0x80144b24)) {
			direct++
		}
	}
	additional := len(hits) - direct
	escapes, err := FindGEKOPointerEscapes(geko, first, end, 32)
	if err != nil {
		return LiteralProvenanceReport{}, err
	}
	reviewedEscapes := 0
	for _, h := range escapes {
		if h.Reviewed {
			reviewedEscapes++
		}
	}
	return LiteralProvenanceReport{ZeroRunCandidates: CandidateGEKOZeroRuns(geko, 17, 30), Status: "STATIC_PROVENANCE_CANDIDATES_NOT_GAMEPLAY_PROOF", RangeStart: first, RangeEnd: end, Hits: hits, PointerEscapes: escapes, ReviewedEscapes: reviewedEscapes, UnreviewedEscapes: len(escapes) - reviewedEscapes, DirectKnown: direct, AdditionalCandidates: additional, WindowInstructions: 32, CallerCoverageComplete: false, SafeToOverwrite: false, Limitations: []string{
		"No control-flow graph or whole-program pointer escape proof; code/data classification is unresolved",
		"Argument escapes and stored pointers are static candidates only; the two reviewed call arguments are not evidence of exhaustive coverage",
		"Indirect pointers loaded from RAM, overlay transitions and runtime string writes remain unknown",
		"All candidates require human instruction review; zero additional hits is not authorization to overwrite",
		"Zero-byte run candidates are only byte patterns; their code/data or runtime ownership is UNKNOWN",
		"Huge zero regions adjacent to a short nonzero file trailer are excluded, even when an interior slice is selected",
		"Known static direct MIPS jump/branch targets into a candidate also exclude it; indirect or computed control flow remains unknown",
		"No N10 research binary may be booted on this evidence alone",
	}}, nil
}
