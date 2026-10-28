package namepatch

// glyph-layout validation: read-only audit of the EXACT pair-glyph data produced by N10's
// integrated offline transaction. A pair glyph consumes one script cell,
// irrespective of the number of Latin letters (one or two) it represents.
// The historical {G}=10-cell validator reservation is an estimate, NOT a
// measured game dialogue-box/VRAM limit. This report never authorizes boot.

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/script"
)

const n10GValidatorCells = 10 // script.tokenCells['G']; validator assumption, not measured UI

type N10PresentationEntry struct {
	Group         string `json:"group"`
	Index         int    `json:"index"`
	Address       uint32 `json:"address"`
	Text          string `json:"text"`
	PairCells     int    `json:"pair_cells"`
	BytesWithNUL  int    `json:"bytes_with_nul"`
	WithinGBudget bool   `json:"within_g_validator_budget"`
}

type N10PresentationReport struct {
	Entries           []N10PresentationEntry `json:"entries"`
	ShortMaxCells     int                    `json:"short_max_cells"`
	FullMaxCells      int                    `json:"full_max_cells"`
	GEKOMaxCells      int                    `json:"geko_max_cells"`
	GBudgetCells      int                    `json:"g_validator_budget_cells"`
	MaxLineCells      int                    `json:"max_script_line_cells"`
	UnknownPixelWidth bool                   `json:"unknown_pixel_width"`
	RuntimeVerified   bool                   `json:"runtime_verified"`
	SafeToPatch       bool                   `json:"safe_to_patch"`
}

// AuditN10Presentation checks the encoded data, not merely the source names.
// It is independent of the N10 byte-diff audit and catches wrong table
// pointers, truncated strings, invalid pair-font encodings, and G2 mismatches.
// The source names must come from a revision-pinned N10OfflineTransaction.
func AuditN10Presentation(staged map[string][]byte, short, full []string, g2Policy string) (N10PresentationReport, error) {
	bad := func(format string, args ...any) (N10PresentationReport, error) {
		return N10PresentationReport{}, fmt.Errorf("N10 presentation glyph-layout validation: "+format, args...)
	}
	exe := staged[EXE]
	geko := staged["GEKO.EXN"]
	if len(exe) < PointerTable+Entries*4 || len(geko) <= 0xf484 || len(short) != Entries || len(full) != Entries {
		return bad("missing staged data / wrong entry count")
	}
	if g2Policy != N10GEKOBare && g2Policy != N10GEKOSan {
		return bad("unresolved GEKO G2 policy")
	}
	report := N10PresentationReport{GBudgetCells: n10GValidatorCells, MaxLineCells: script.MaxCells, UnknownPixelWidth: true, Entries: make([]N10PresentationEntry, 0, Entries*2+1)}
	check := func(group string, index int, addr uint32, name string) (N10PresentationEntry, error) {
		if addr < Base || name == "" {
			return N10PresentationEntry{}, fmt.Errorf("%s[%d] invalid pointer or name", group, index)
		}
		off := int(addr - Base)
		encoder := &script.PairEncoder{}
		raw, err := encoder.Encode(name)
		if err != nil {
			return N10PresentationEntry{}, fmt.Errorf("%s[%d] pair encoding: %w", group, index, err)
		}
		if len(raw)%2 != 0 || off < 0 || off+len(raw)+1 > len(exe) {
			return N10PresentationEntry{}, fmt.Errorf("%s[%d] encoded data outside staged EXE", group, index)
		}
		if !bytes.Equal(exe[off:off+len(raw)], raw) || exe[off+len(raw)] != 0 {
			return N10PresentationEntry{}, fmt.Errorf("%s[%d] bad stored pair bytes or missing NUL at %#x", group, index, addr)
		}
		cells := len(raw) / 2
		return N10PresentationEntry{Group: group, Index: index, Address: addr, Text: name, PairCells: cells, BytesWithNUL: len(raw) + 1, WithinGBudget: cells <= n10GValidatorCells}, nil
	}
	for i := 0; i < Entries; i++ {
		p := binary.LittleEndian.Uint32(exe[PointerTable+4*i:])
		if p < 0x8004ba78 || p >= 0x8004bafc {
			return bad("short pointer %d outside renderer tail: %#x", i, p)
		}
		entry, e := check("short", i, p, short[i])
		if e != nil {
			return bad("%v", e)
		}
		if entry.PairCells > report.ShortMaxCells {
			report.ShortMaxCells = entry.PairCells
		}
		report.Entries = append(report.Entries, entry)
	}
	for i := 0; i < Entries; i++ {
		p := binary.LittleEndian.Uint32(exe[N10FullPoolSplit+4*i:])
		if (p < Base+N10FullPoolStart || p >= Base+N10FullPoolSplit) && (p < Base+N10FullTableEnd || p >= Base+N10FullFragment2End) {
			return bad("full pointer %d outside split fragments: %#x", i, p)
		}
		entry, e := check("full", i, p, full[i])
		if e != nil {
			return bad("%v", e)
		}
		if entry.PairCells > report.FullMaxCells {
			report.FullMaxCells = entry.PairCells
		}
		report.Entries = append(report.Entries, entry)
	}
	hi := binary.LittleEndian.Uint32(geko[0xf47c:])
	lo := binary.LittleEndian.Uint32(geko[0xf480:])
	if (hi>>26) != 15 || (lo>>26) != 9 || ((hi>>16)&31) != ((lo>>21)&31) || ((hi>>16)&31) != ((lo>>16)&31) {
		return bad("GEKO G2 instruction pair no longer LUI/ADDIU")
	}
	p := uint32(int64(uint32(hi&0xffff)<<16) + int64(int16(lo&0xffff)))
	expected := binary.LittleEndian.Uint32(exe[PointerTable+11*4:])
	g2 := short[11]
	if g2Policy == N10GEKOSan {
		expected = N10Phase2G2
		g2 += "-san"
	}
	if p != expected {
		return bad("GEKO G2 pointer %#x, expected %#x", p, expected)
	}
	entry, e := check("geko_g2", 0, p, g2)
	if e != nil {
		return bad("%v", e)
	}
	report.GEKOMaxCells = entry.PairCells
	report.Entries = append(report.Entries, entry)
	return report, nil
}
