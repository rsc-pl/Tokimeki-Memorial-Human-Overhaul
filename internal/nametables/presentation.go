// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/script"
)

const nameGValidatorCells = 10

type NamePresentationEntry struct {
	Group         string `json:"group"`
	Index         int    `json:"index"`
	Address       uint32 `json:"address"`
	Text          string `json:"text"`
	PairCells     int    `json:"pair_cells"`
	BytesWithNUL  int    `json:"bytes_with_nul"`
	WithinGBudget bool   `json:"within_g_validator_budget"`
}
type NamePresentationReport struct {
	Entries           []NamePresentationEntry `json:"entries"`
	ShortMaxCells     int                     `json:"short_max_cells"`
	FullMaxCells      int                     `json:"full_max_cells"`
	GEKOMaxCells      int                     `json:"geko_max_cells"`
	GBudgetCells      int                     `json:"g_validator_budget_cells"`
	MaxLineCells      int                     `json:"max_script_line_cells"`
	UnknownPixelWidth bool                    `json:"unknown_pixel_width"`
	RuntimeVerified   bool                    `json:"runtime_verified"`
	SafeToPatch       bool                    `json:"safe_to_patch"`
}

func AuditNamePresentation(staged map[string][]byte, short, full []string, g2Policy string) (NamePresentationReport, error) {
	bad := func(format string, args ...any) (NamePresentationReport, error) {
		return NamePresentationReport{}, fmt.Errorf("Name presentation presentation audit: "+format, args...)
	}
	exe := staged[EXE]
	geko := staged["GEKO.EXN"]
	if len(exe) < PointerTable+Entries*4 || len(geko) <= 0xf484 || len(short) != Entries || len(full) != Entries {
		return bad("missing staged data / wrong entry count")
	}
	if g2Policy != NameGEKOBare && g2Policy != NameGEKOSan {
		return bad("unresolved GEKO G2 policy")
	}
	report := NamePresentationReport{GBudgetCells: nameGValidatorCells, MaxLineCells: script.MaxCells, UnknownPixelWidth: true, Entries: make([]NamePresentationEntry, 0, Entries*2+1)}
	check := func(group string, index int, addr uint32, name string) (NamePresentationEntry, error) {
		if addr < Base || name == "" {
			return NamePresentationEntry{}, fmt.Errorf("%s[%d] invalid pointer or name", group, index)
		}
		off := int(addr - Base)
		encoder := &script.PairEncoder{}
		raw, err := encoder.Encode(name)
		if err != nil {
			return NamePresentationEntry{}, fmt.Errorf("%s[%d] pair encoding: %w", group, index, err)
		}
		if len(raw)%2 != 0 || off < 0 || off+len(raw)+1 > len(exe) {
			return NamePresentationEntry{}, fmt.Errorf("%s[%d] encoded data outside staged EXE", group, index)
		}
		if !bytes.Equal(exe[off:off+len(raw)], raw) || exe[off+len(raw)] != 0 {
			return NamePresentationEntry{}, fmt.Errorf("%s[%d] bad stored pair bytes or missing NUL at %#x", group, index, addr)
		}
		cells := len(raw) / 2
		return NamePresentationEntry{Group: group, Index: index, Address: addr, Text: name, PairCells: cells, BytesWithNUL: len(raw) + 1, WithinGBudget: cells <= nameGValidatorCells}, nil
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
		p := binary.LittleEndian.Uint32(exe[NameFullPoolSplit+4*i:])
		if (p < Base+NameFullPoolStart || p >= Base+NameFullPoolSplit) && (p < Base+NameFullTableEnd || p >= Base+NameFullFragment2End) {
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
	if g2Policy == NameGEKOSan {
		expected = NamePhase2G2
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
