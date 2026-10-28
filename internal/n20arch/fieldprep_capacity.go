package n20arch

// Exact name-capacity audit for the N6-FP fieldprep slots.
//
// The shim may write at most seven output bytes including the NUL terminator
// into each 8-byte working slot. The guest romanizer pads an odd-length ASCII
// result with one high-bit space, so a romanization of n bytes occupies
// n + (n%2) bytes before the NUL, and the gate is n <= 6.
//
// This file re-decodes the authenticated NAME_ENT.EXN keyboard grid (the real
// selectable kana input set) and enumerates every 1-, 2- and 3-kana name with
// repetition, using the same host RomanizeKana primitive the shim's guest core
// was built from. It reports exact coverage, not a sample. It also re-decodes
// the EXE slot geometry so a retail drift fails the test.

import (
	"fmt"
	"sort"

	pn "tokimemo/internal/playername"
)

const (
	// FieldPrepMaxRomanBytes is the longest ASCII romanization that can be
	// stored: six bytes, whether even (6+NUL=7) or odd (5+pad+NUL=7).
	FieldPrepMaxRomanBytes = 6
	// FieldPrepSlotStride is the authenticated distance between the family
	// and given working slots; the next blocked field is another 8 bytes on.
	FieldPrepSlotStride = 8
)

// FieldPrepCapacityExample is a deterministic sample of a name at a boundary.
type FieldPrepCapacityExample struct {
	Kana       string `json:"kana"`
	Roman      string `json:"roman"`
	RomanBytes int    `json:"roman_bytes"`
	WireBytes  int    `json:"wire_bytes_including_nul"`
	Accepted   bool   `json:"accepted"`
}

// FieldPrepCapacityCount is one kana-length bucket.
type FieldPrepCapacityCount struct {
	KanaCount   int `json:"kana_count"`
	Entries     int `json:"entries"`
	Accepted    int `json:"accepted"`
	Unromanized int `json:"unromanizable"`
	TooLong     int `json:"romanized_but_too_long"`
}

// FieldPrepCapacityAudit is the exact grid-derived capacity result.
//
// The three-kana counts are deliberately split into four independent
// limitations so prose cannot merge them:
//
//	(a) packed romanizer coverage: Triples.Unromanized;
//	(b) 8-byte working slots and the romanLen<=6 gate: Triples.TooLong;
//	(c) high-bit odd-length padding: TriplesPaddingBytes and
//	    TriplesPaddingRejected (entries that would fit only if the pad were
//	    dropped, but still would not cover every valid three-kana name);
//	(d) renderer consumption: p/m/F read the two working fields; P/G do not.
//
// A field that only reports "283140 too long" hides the fact that 269748 of
// those are padding-only and that 13176 + 216 remain too long even without a
// pad. The added fields keep those causes separate.
type FieldPrepCapacityAudit struct {
	KeyboardRows        int                        `json:"keyboard_rows"`
	KeyboardCells       int                        `json:"keyboard_cells"`
	UniqueKana          int                        `json:"unique_kana"`
	Singles             FieldPrepCapacityCount     `json:"singles"`
	Pairs               FieldPrepCapacityCount     `json:"pairs"`
	Triples             FieldPrepCapacityCount     `json:"triples"`
	TooLongByRomanBytes map[int]int                `json:"too_long_by_roman_bytes"`
	Examples            []FieldPrepCapacityExample `json:"examples"`
	MaxRomanBytes       int                        `json:"max_roman_bytes"`
	MaxWireBytes        int                        `json:"max_wire_bytes_before_nul"`
	SlotBytes           int                        `json:"slot_bytes_including_nul"`
	SlotStride          int                        `json:"slot_stride"`
	WorkingFamily       uint32                     `json:"working_family"`
	WorkingGiven        uint32                     `json:"working_given"`
	BlockedNext         uint32                     `json:"blocked_next_field"`

	// Attribution and exact future byte budget for three-kana names.
	TriplesRomanizable       int  `json:"triples_romanizable"`
	TriplesOddRoman          int  `json:"triples_odd_roman"`
	TriplesEvenRoman         int  `json:"triples_even_roman"`
	TriplesPaddingBytes      int  `json:"triples_padding_bytes"`
	TriplesPaddingRejected   int  `json:"triples_rejected_by_padding_only"`
	MaxTripleRomanBytes      int  `json:"max_triple_roman_bytes"`
	RequiredExactSlotBytes   int  `json:"required_exact_slot_bytes"`
	RequiredPaddedSlotBytes  int  `json:"required_padded_slot_bytes"`
	AlignedRequiredSlotBytes int  `json:"aligned_required_slot_bytes"`
	CurrentSlotCoversAll     bool `json:"current_slot_covers_all_romanizable"`

	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// FieldPrepWireBytes returns the bytes written before the NUL, including the
// guest romanizer's odd-length high-bit-space pad.
func FieldPrepWireBytes(romanLen int) int {
	return romanLen + romanLen%2
}

// FieldPrepAcceptedRomanLen reports whether a romanization fits the slot.
func FieldPrepAcceptedRomanLen(romanLen int) bool {
	return FieldPrepWireBytes(romanLen)+1 <= OLFieldPrepSlotBytes
}

// AuditFieldPrepCapacity re-decodes NAME_ENT.EXN and the retail EXE anchors.
func AuditFieldPrepCapacity(nameEnt, exe []byte) (FieldPrepCapacityAudit, error) {
	var a FieldPrepCapacityAudit
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return a, fmt.Errorf("unrecognised original EXE")
	}
	if len(nameEnt) != 196608 || sha(nameEnt) != OverlaySHA["NAME_ENT.EXN"] {
		return a, fmt.Errorf("NAME_ENT.EXN is not the authenticated original")
	}
	// Slot geometry: family/given are 8 B apart and the next blocked field is
	// another 8 B on. The renderer reads NUL-terminated strings, not lengths.
	for _, an := range []struct {
		pc   uint32
		want uint32
		name string
	}{
		{0x800847D4, 0x2484A16C, "fieldprep working family base"},
		{0x800847E8, 0x2484A174, "fieldprep working given base"},
		{0x80081408, 0x26D6A16C, "renderer family setup"},
		{0x800818E8, 0x24E7A174, "renderer given argument"},
		{0x800818D4, 0x24010046, "renderer F token"},
	} {
		if got := wordAt(exe, an.pc); got != an.want {
			return a, fmt.Errorf("%s drifted at %08x: %08x", an.name, an.pc, got)
		}
	}
	if OLFieldPrepWorkGiv-OLFieldPrepWorkFam != FieldPrepSlotStride ||
		OLFieldPrepBlockedFam-OLFieldPrepWorkGiv != FieldPrepSlotStride {
		return a, fmt.Errorf("working-slot stride drifted")
	}
	a.WorkingFamily = OLFieldPrepWorkFam
	a.WorkingGiven = OLFieldPrepWorkGiv
	a.BlockedNext = OLFieldPrepBlockedFam
	a.SlotBytes = OLFieldPrepSlotBytes
	a.SlotStride = FieldPrepSlotStride
	a.MaxRomanBytes = FieldPrepMaxRomanBytes
	a.MaxWireBytes = FieldPrepMaxRomanBytes
	a.TooLongByRomanBytes = map[int]int{}

	rows, err := pn.ParseNameEntryKeyboardRows(nameEnt)
	if err != nil {
		return a, err
	}
	a.KeyboardRows = len(rows)
	seen := map[string]bool{}
	for _, r := range rows {
		for _, c := range r.Cells {
			seen[c.Kana] = true
		}
		a.KeyboardCells++
	}
	kana := make([]string, 0, len(seen))
	for k := range seen {
		kana = append(kana, k)
	}
	sort.Strings(kana)
	a.UniqueKana = len(kana)

	var triRomanizable, triOdd, triEven, triPadding, triPaddingRejected, maxTriRoman int
	for n := 1; n <= 3; n++ {
		c := &a.Singles
		switch n {
		case 2:
			c = &a.Pairs
		case 3:
			c = &a.Triples
		}
		c.KanaCount = n
		cur := make([]string, n)
		var rec func(idx int)
		rec = func(idx int) {
			if idx == n {
				c.Entries++
				name := ""
				for _, s := range cur {
					name += s
				}
				roman, err := pn.RomanizeKana(name)
				if err != nil {
					c.Unromanized++
					return
				}
				if n == 3 {
					triRomanizable++
					if len(roman)%2 == 1 {
						triOdd++
						triPadding++ // one high-bit space per odd-length result
					} else {
						triEven++
					}
					if len(roman) > maxTriRoman {
						maxTriRoman = len(roman)
					}
					// Removing the pad would fit the current 8-byte slot only
					// when romanLen+NUL<=8. This is a subset of TooLong, never
					// a claim that dropping the pad covers every valid name.
					if !FieldPrepAcceptedRomanLen(len(roman)) && len(roman)+1 <= OLFieldPrepSlotBytes {
						triPaddingRejected++
					}
				}
				if FieldPrepAcceptedRomanLen(len(roman)) {
					c.Accepted++
				} else {
					c.TooLong++
					if n == 3 {
						a.TooLongByRomanBytes[len(roman)]++
					}
				}
				return
			}
			for _, k := range kana {
				cur[idx] = k
				rec(idx + 1)
			}
		}
		rec(0)
	}

	for _, e := range []struct {
		kana string
		note string
	}{
		{"しおり", "accepted three-kana boundary"},
		{"しし", "accepted two-kana boundary"},
		{"あしし", "seven-byte romanization fails after input pad"},
		{"かしし", "eight-byte romanization fails"},
		{"ししし", "nine-byte romanization fails"},
		{"つづき", "seven-byte romanization used by the shim test"},
		{"ぁ", "standalone small kana cannot romanize"},
		{"っ", "standalone sokuon cannot romanize"},
		{"ー", "standalone long-vowel mark cannot romanize"},
	} {
		var ex FieldPrepCapacityExample
		ex.Kana = e.kana
		if ex.Roman, err = pn.RomanizeKana(e.kana); err != nil {
			ex.Accepted = false
			ex.RomanBytes = -1
		} else {
			ex.RomanBytes = len(ex.Roman)
			ex.WireBytes = FieldPrepWireBytes(len(ex.Roman)) + 1
			ex.Accepted = FieldPrepAcceptedRomanLen(len(ex.Roman))
		}
		a.Examples = append(a.Examples, ex)
	}

	a.TriplesRomanizable = triRomanizable
	a.TriplesOddRoman = triOdd
	a.TriplesEvenRoman = triEven
	a.TriplesPaddingBytes = triPadding
	a.TriplesPaddingRejected = triPaddingRejected
	a.MaxTripleRomanBytes = maxTriRoman
	a.RequiredExactSlotBytes = maxTriRoman + 1
	a.RequiredPaddedSlotBytes = maxTriRoman + maxTriRoman%2 + 1
	a.AlignedRequiredSlotBytes = (a.RequiredPaddedSlotBytes + 3) &^ 3
	a.CurrentSlotCoversAll = a.RequiredPaddedSlotBytes <= a.SlotBytes

	a.Verdict = "exact_grid_limit_seven_wire_bytes"
	a.Reason = fmt.Sprintf("authenticated NAME_ENT grid has %d rows/%d unique kana; accepted=%d/%d one-kana, %d/%d two-kana and %d/%d three-kana entries; three-kana attribution: %d/%d accepted, %d unromanizable (packed-romanizer coverage), %d too long (7B=%d, 8B=%d, 9B=%d); odd-length pad adds one wire byte, so %d entries are rejected by padding only; max roman %d bytes needs %d exact or %d padded bytes including NUL, above the current %d-byte slot", a.KeyboardRows, a.UniqueKana, a.Singles.Accepted, a.Singles.Entries, a.Pairs.Accepted, a.Pairs.Entries, a.Triples.Accepted, a.Triples.Entries, a.Triples.Accepted, a.Triples.Entries, a.Triples.Unromanized, a.Triples.TooLong, a.TooLongByRomanBytes[7], a.TooLongByRomanBytes[8], a.TooLongByRomanBytes[9], a.TriplesPaddingRejected, a.MaxTripleRomanBytes, a.RequiredExactSlotBytes, a.RequiredPaddedSlotBytes, a.SlotBytes)
	return a, nil
}

// FieldPrepCapacityReportFor exposes the audit to the evidence generator
// without duplicating any number.
func FieldPrepCapacityReportFor(a FieldPrepCapacityAudit) map[string]any {
	return map[string]any{
		"grid_rows": a.KeyboardRows, "grid_cells": a.KeyboardCells,
		"unique_kana": a.UniqueKana, "singles": a.Singles, "pairs": a.Pairs,
		"triples": a.Triples, "too_long_by_roman_bytes": a.TooLongByRomanBytes,
		"examples": a.Examples, "max_roman_bytes": a.MaxRomanBytes,
		"max_wire_bytes": a.MaxWireBytes, "slot_bytes": a.SlotBytes,
		"slot_stride":         a.SlotStride,
		"triples_romanizable": a.TriplesRomanizable, "triples_odd_roman": a.TriplesOddRoman,
		"triples_even_roman": a.TriplesEvenRoman, "triples_padding_bytes": a.TriplesPaddingBytes,
		"triples_rejected_by_padding_only":    a.TriplesPaddingRejected,
		"max_triple_roman_bytes":              a.MaxTripleRomanBytes,
		"required_exact_slot_bytes":           a.RequiredExactSlotBytes,
		"required_padded_slot_bytes":          a.RequiredPaddedSlotBytes,
		"aligned_required_slot_bytes":         a.AlignedRequiredSlotBytes,
		"current_slot_covers_all_romanizable": a.CurrentSlotCoversAll,
		"verdict":                             a.Verdict, "reason": a.Reason,
	}
}

// The capacity audit is intentionally cheap enough to run in tests (four
// million short names), but the evidence generator should not enumerate twice.
// Callers may cache the value; no global mutable state is used here.
