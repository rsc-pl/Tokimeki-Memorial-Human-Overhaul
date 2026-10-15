package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tokimemo/internal/nametables"
	"tokimemo/internal/ps1"
	"tokimemo/internal/script"
)

// cmdNameTables audits current translation inputs and optionally an original
// game disc. It never edits either. Reports do not contain translated text.
func cmdNameTables(root string, args []string) error {
	fs := flag.NewFlagSet("name-tables", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	request := fs.String("request", "", "N10 SURNAME_CAPACITY.tsv from the translation handoff (read-only)")
	characterNames := fs.String("character-names", "", "optional read-only character_names.json reference (default: live checkout)")
	game := fs.String("game", "", "optional original CUE to examine actual table pointers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-tables [--request SURNAME_CAPACITY.tsv] [--character-names character_names.json] [--game GAME.cue]")
	}
	namesPath := filepath.Join(root, "translation", "character_names.json")
	if *characterNames != "" {
		namesPath = *characterNames
	}
	data, err := os.ReadFile(namesPath)
	if err != nil {
		return err
	}
	var names struct {
		Dialogue []struct {
			File  string `json:"file"`
			Lines []struct {
				Offset string `json:"offset"`
				Text   string `json:"text"`
			} `json:"lines"`
		} `json:"dialogue"`
	}
	if err = json.Unmarshal(data, &names); err != nil {
		return err
	}
	current := make([]string, nametables.Entries)
	for _, b := range names.Dialogue {
		if b.File != nametables.EXE {
			continue
		}
		for _, line := range b.Lines {
			var off int
			if _, e := fmt.Sscanf(line.Offset, "0x%x", &off); e != nil {
				continue
			}
			if off >= nametables.ShortStart && off < nametables.ShortEnd && (off-nametables.ShortStart)%4 == 0 {
				// Offsets are variable width; consult the actual N10 known entry offsets.
				for i, v := range shortNameOffsets {
					if off == v {
						current[i] = line.Text
					}
				}
			}
		}
	}
	for i, n := range current {
		if n == "" {
			return fmt.Errorf("short name index %d missing in %s", i, namesPath)
		}
	}
	used, err := nametables.ShortNamesRequired(current)
	if err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "Short-name runtime pool: %d / %d encoded bytes (including 16 NULs)\n", used, nametables.ShortEnd-nametables.ShortStart)
	fmt.Fprintln(commandOutput, "16 runtime entries, indirect pointer table at SLPM_86.053:0x72DF4; expansion beyond source pool requires proven alternate storage")
	if *request != "" {
		f, err := os.Open(*request)
		if err != nil {
			return err
		}
		defer f.Close()
		entries, err := nametables.ReadCapacityReport(f)
		if err != nil {
			return err
		}
		blocked, needed := 0, 0
		proposed := append([]string(nil), current...)
		for _, r := range entries {
			if r.File == "character_names.json" {
				for i, off := range shortNameOffsets {
					if off == r.Offset {
						proposed[i] = r.Intended
					}
				}
			}
			// Already applied by a newer translation checkout? Skip it rather than
			// implying a current blocker or overwriting its text.
			if r.File == "character_names.json" {
				for i, off := range shortNameOffsets {
					if off == r.Offset && current[i] == r.Intended {
						goto already
					}
				}
			}
			blocked++
			needed += r.Deficit
		already:
		}
		total, err := nametables.ShortNamesRequired(proposed)
		if err != nil {
			return err
		}
		fmt.Fprintf(commandOutput, "N10 report: %d entries, %d not already resolved in live compact table, sum of independent slot deficits %d bytes\n", len(entries), blocked, needed)
		fmt.Fprintf(commandOutput, "Proposed shared short-name pool: %d / %d bytes; EXCESS %d bytes\n", total, nametables.ShortEnd-nametables.ShortStart, max(0, total-(nametables.ShortEnd-nametables.ShortStart)))
		if total > nametables.ShortEnd-nametables.ShortStart {
			fmt.Fprintln(commandOutput, "BLOCKED: relocated verified storage required; individual slot padding cannot solve shared-pool overflow")
		}
	}
	// Inspect the exact live dialogue corpus, not the N10 reference snapshot.
	// Widening {G} could invalidate formerly valid 28-cell lines; report sites.
	jsonPaths, err := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if err != nil {
		return err
	}
	gTokens, gRisk, malformed := 0, 0, 0
	for _, path := range jsonPaths {
		docData, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var doc struct {
			Dialogue []struct {
				MaxCells int `json:"max_cells"`
				Lines    []struct {
					Offset string `json:"offset"`
					Text   string `json:"text"`
				} `json:"lines"`
			} `json:"dialogue"`
		}
		if e = json.Unmarshal(docData, &doc); e != nil {
			return fmt.Errorf("%s: %w", path, e)
		}
		for _, block := range doc.Dialogue {
			limit := block.MaxCells
			if limit == 0 {
				limit = script.MaxCells
			}
			for _, line := range block.Lines {
				if !strings.Contains(line.Text, "{G}") {
					continue
				}
				_, widths, e := script.EncodeEnglish(line.Text, &script.PairEncoder{})
				if e != nil {
					malformed++
					continue
				}
				n, risk := nametables.GPressure(line.Text, widths, limit)
				gTokens += n
				if risk {
					gRisk++
					fmt.Fprintf(commandOutput, "{G} prospective width risk: %s:%s\n", filepath.Base(path), line.Offset)
				}
			}
		}
	}
	fmt.Fprintf(commandOutput, "Current corpus: %d {G} tokens; %d dialogue records potentially beyond line width after +2 cells per expansion; %d failed diagnostic encodes\n", gTokens, gRisk, malformed)
	fmt.Fprintf(commandOutput, "Dynamic {G}: legacy budget %d cells, prospective longest surname %d cells; renderer/buffer and scene QA required\n", nametables.CurrentGCells, nametables.IntendedLongestGCells)

	if *game != "" {
		cue, err := cueChoice(root, *game)
		if err != nil {
			return err
		}
		tracks, err := parseCue(cue)
		if err != nil {
			return err
		}
		f, iso, err := openDiscISO(tracks.Data, tracks.Sectors)
		if err != nil {
			return err
		}
		defer f.Close()
		entry, ok := iso.Entries[nametables.EXE]
		if !ok {
			return errors.New("SLPM_86.053 not found")
		}
		var buf bytes.Buffer
		if err := ps1.ReadFileTo(f, tracks.Sectors, entry.LBA, entry.Size, &buf); err != nil {
			return err
		}
		exe := buf.Bytes()
		if nametables.PointerTable+nametables.Entries*4 > len(exe) {
			return errors.New("disc executable does not contain short-name table")
		}
		idx := script.NewWordIndex(exe)
		valid, unexpectedCode := 0, 0
		for i := 0; i < nametables.Entries; i++ {
			p := binary.LittleEndian.Uint32(exe[nametables.PointerTable+i*4:])
			if p < nametables.Base {
				continue
			}
			off := int(p - nametables.Base)
			if off < nametables.ShortStart || off >= nametables.ShortEnd {
				continue
			}
			if bytes.IndexByte(exe[off:nametables.ShortEnd], 0) < 0 {
				continue
			}
			valid++
			unexpectedCode += len(idx.CodeReferences(nametables.Base, uint32(off), 8))
		}
		fmt.Fprintf(commandOutput, "Original-disc static pointer audit: %d/%d table pointers inside the expected pool; code references discovered: %d\n", valid, nametables.Entries, unexpectedCode)
		fmt.Fprintln(commandOutput, "STATIC ONLY: no binary modification; GEKO callers, destination lifetime, RAM copies and DuckStation scenes not yet verified")
	}
	return nil
}

var shortNameOffsets = [...]int{0x72D78, 0x72D80, 0x72D88, 0x72D90, 0x72D98, 0x72DA0, 0x72DA8, 0x72DB0, 0x72DB4, 0x72DBC, 0x72DC4, 0x72DCC, 0x72DD4, 0x72DDC, 0x72DE4, 0x72DEC}
