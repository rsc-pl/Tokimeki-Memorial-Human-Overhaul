// Package namepatch contains read-only capacity auditing and guarded, explicit
// table relocation primitives. It intentionally does not choose executable
// free space: unused-looking bytes do not prove unused runtime memory.
package namepatch

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"tokimemo/internal/script"
)

const (
	EXE          = "SLPM_86.053"
	Geko         = "CDROM/EXEDIR/GEKO.EXN"
	Base         = uint32(0x80040800)
	ShortStart   = 0x72D78
	ShortEnd     = 0x72DF4
	PointerTable = 0x72DF4
	Entries      = 16
	// The existing compiled English renderer counts ordinary pair glyph letters
	// as one display cell, not one Shift-JIS character.
	CurrentGCells         = 10
	IntendedLongestGCells = 12
)

// CapacityEntry is an observed N10 constraint, not an instruction to patch.
type CapacityEntry struct {
	File     string `json:"file"`
	Offset   int    `json:"offset"`
	Japanese string `json:"japanese"`
	Current  string `json:"current"`
	Intended string `json:"intended"`
	Slot     int    `json:"slot"`
	Encoded  int    `json:"encoded_bytes"`
	Required int    `json:"required_bytes"`
	Deficit  int    `json:"deficit_bytes"`
}

// ReadCapacityReport validates every byte count against the actual Go pair
// encoder, including odd-length padding and a NUL byte. It never writes JSON.
func ReadCapacityReport(r io.Reader) ([]CapacityEntry, error) {
	reader := csv.NewReader(r)
	reader.Comma = '\t'
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("empty report")
	}
	want := []string{"file", "offset", "line", "jp", "current", "surname", "slot_bytes", "surname_bytes", "required_bytes", "status"}
	if len(records[0]) != len(want) {
		return nil, fmt.Errorf("unexpected report header")
	}
	for i := range want {
		if records[0][i] != want[i] {
			return nil, fmt.Errorf("unexpected column %d %q", i, records[0][i])
		}
	}
	entries := make([]CapacityEntry, 0, len(records)-1)
	seen := map[string]bool{}
	for i, rec := range records[1:] {
		where := fmt.Sprintf("report row %d", i+2)
		if len(rec) != len(want) || rec[2] != "1" || rec[9] != "NEEDS_TECHNICAL_CHANGE" {
			return nil, fmt.Errorf("%s: wrong shape", where)
		}
		off, err := strconv.ParseInt(rec[1], 0, 64)
		if err != nil || off < 0 {
			return nil, fmt.Errorf("%s: bad offset", where)
		}
		slot, err := strconv.Atoi(rec[6])
		if err != nil || slot < 1 {
			return nil, fmt.Errorf("%s: invalid slot", where)
		}
		encoded, err := strconv.Atoi(rec[7])
		if err != nil {
			return nil, fmt.Errorf("%s: invalid encoded length", where)
		}
		required, err := strconv.Atoi(rec[8])
		if err != nil {
			return nil, fmt.Errorf("%s: invalid required length", where)
		}
		file := strings.TrimPrefix(rec[0], "translation/")
		if file != "character_names.json" && file != "event_words.json" {
			return nil, fmt.Errorf("%s: unknown file", where)
		}
		key := file + rec[1]
		if seen[key] {
			return nil, fmt.Errorf("%s: duplicate entry", where)
		}
		seen[key] = true
		raw, e := (&script.PairEncoder{}).Encode(rec[5])
		if e != nil {
			return nil, fmt.Errorf("%s: %w", where, e)
		}
		if encoded != len(raw) || required != len(raw)+1 || slot >= required {
			return nil, fmt.Errorf("%s: encoded size mismatch: %d+NUL vs slot %d", where, len(raw), slot)
		}
		entries = append(entries, CapacityEntry{file, int(off), rec[3], rec[4], rec[5], slot, len(raw), len(raw) + 1, len(raw) + 1 - slot})
	}
	return entries, nil
}

// ShortNamesRequired counts all 16 runtime strings, including NUL terminators;
// callers must supply them in index order, not merely the 10 blocked entries.
func ShortNamesRequired(names []string) (int, error) {
	if len(names) != Entries {
		return 0, fmt.Errorf("expected %d runtime names, got %d", Entries, len(names))
	}
	total := 0
	for i, name := range names {
		if name == "" || strings.ContainsAny(name, "\x00\n{}") {
			return 0, fmt.Errorf("short name %d invalid", i)
		}
		encoded, e := (&script.PairEncoder{}).Encode(name)
		if e != nil {
			return 0, fmt.Errorf("short name %d: %w", i, e)
		}
		total += len(encoded) + 1
	}
	return total, nil
}

// GCellPressure reports where a 12-cell {G} would cross an existing limit.
// Callers may use it for per-record diagnostics, never to rewrite dialogue.
func GCellPressure(text string, current []int, max int) (bool, bool) {
	if !strings.Contains(text, "{G}") {
		return false, false
	}
	after := strings.Count(text, "{G}") * (IntendedLongestGCells - CurrentGCells)
	for _, width := range current {
		if width <= max && width+after > max {
			return true, true
		}
	}
	return true, false
}

// GPressure summarizes potential added display cells in a dialogue block when
// {G} grows from the current runtime name budget to a longer surname. It is
// diagnostic only: actual RAM buffer size and scene-level glyph placement are
// not inferable from the JSON records alone.
func GPressure(text string, widths []int, limit int) (tokens int, overflow bool) {
	lines := strings.Split(strings.ReplaceAll(text, "{q}", "\n"), "\n")
	for i, line := range lines {
		n := strings.Count(line, "{G}")
		tokens += n
		if n > 0 && i < len(widths) && widths[i]+n*(IntendedLongestGCells-CurrentGCells) > limit {
			overflow = true
		}
	}
	return tokens, overflow
}
