package main

// Read-only audit of dialogue slot capacity. This tool deliberately does not
// attempt to extend game files, change pointers, or rewrite translated strings.
import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"

	"tokimemo/internal/patchplan"
	"tokimemo/internal/script"
)

type dialogueBudgetRow struct {
	Offset  int
	Slot    int
	Encoded int // includes the terminating NUL
	Excess  int
}

type dialogueBudgetResult struct {
	Rows  []dialogueBudgetRow
	Stats script.PlanStats
	Err   error
}

// All original-byte/terminator checks and relocation decisions stay delegated
// to the exact same native planner used by native-plan-parity. Per-line values
// are supplementary diagnostics, NOT an alternative packing algorithm.
func auditDialogueBudget(original []byte, block script.DialogueBlock) (dialogueBudgetResult, error) {
	var out dialogueBudgetResult
	pairs := &script.PairEncoder{}
	for _, line := range block.Lines {
		if line.Text == "" {
			continue
		}
		raw, err := script.EncodeOriginal(line.Original)
		if err != nil {
			return out, fmt.Errorf("%s @ %#x: %w", block.File, line.Offset, err)
		}
		end := line.Offset + len(raw)
		if line.Offset < 0 || end < line.Offset || end >= len(original) ||
			!bytes.Equal(original[line.Offset:end], raw) || original[end] != 0 {
			return out, fmt.Errorf("%s @ %#x: original bytes or terminator mismatch", block.File, line.Offset)
		}
		cap := len(raw) + 1
		for (line.Offset+cap)%4 != 0 && line.Offset+cap < len(original) && original[line.Offset+cap] == 0 {
			cap++
		}
		en, _, err := script.EncodeEnglish(line.Text, pairs)
		if err != nil {
			return out, fmt.Errorf("%s @ %#x: English encoding: %w", block.File, line.Offset, err)
		}
		required := len(en) + 1
		out.Rows = append(out.Rows, dialogueBudgetRow{Offset: line.Offset, Slot: cap, Encoded: required, Excess: required - cap})
	}
	scratch := append([]byte(nil), original...)
	out.Stats, out.Err = script.ApplyDialogue(original, scratch, block, &script.PairEncoder{})
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Excess != out.Rows[j].Excess {
			return out.Rows[i].Excess > out.Rows[j].Excess
		}
		if out.Rows[i].Encoded != out.Rows[j].Encoded {
			return out.Rows[i].Encoded > out.Rows[j].Encoded
		}
		return out.Rows[i].Offset < out.Rows[j].Offset
	})
	return out, nil
}

func cmdDialogueBudget(root string, args []string) error {
	fs := flag.NewFlagSet("dialogue-budget", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original game CUE (read-only)")
	translation := fs.String("translation", "translation/epilogue.json", "translation JSON to inspect")
	all := fs.Bool("all", false, "list every translated record (default: top 25 by excess over own slot)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo dialogue-budget [--game CUE] [--translation FILE.json] [--all]")
	}
	fpath := *translation
	if !filepath.IsAbs(fpath) {
		fpath = filepath.Join(root, fpath)
	}
	batch, err := patchplan.Load(root, []string{fpath})
	if err != nil {
		return err
	}
	if len(batch.Dialogue) == 0 {
		return fmt.Errorf("%s: no dialogue blocks", filepath.Base(fpath))
	}
	cue, err := cueChoice(root, *game)
	if err != nil {
		return err
	}
	track, err := parseCue(cue)
	if err != nil {
		return err
	}
	f, iso, err := openDiscISO(track.Data, track.Sectors)
	if err != nil {
		return err
	}
	defer f.Close()
	source := isoSource{iso}
	say("Source CUE", cue)
	say("Translation", fpath)
	failed := 0
	for i, block := range batch.Dialogue {
		data, err := source.ReadFile(block.File)
		if err != nil {
			return fmt.Errorf("%s: %w", block.File, err)
		}
		report, err := auditDialogueBudget(data, block)
		if err != nil {
			return err
		}
		fmt.Fprintf(commandOutput, "\nDialogue block %d: %s (%d translated records, shared-identical=%t)\n", i+1, block.File, len(report.Rows), block.ShareIdentical)
		fmt.Fprintf(commandOutput, "  Needed: %d bytes; available original slots: %d bytes", report.Stats.BytesNeeded, report.Stats.BytesAvailable)
		if report.Stats.BytesNeeded > report.Stats.BytesAvailable {
			fmt.Fprintf(commandOutput, "; MINIMUM DEFICIT: %d bytes", report.Stats.BytesNeeded-report.Stats.BytesAvailable)
		}
		fmt.Fprintln(commandOutput)
		if report.Err != nil {
			fmt.Fprintf(commandOutput, "  PACKING FAIL: %v\n", report.Err)
			printPackingDiagnostics(commandOutput, report.Stats)
			failed++
		} else {
			fmt.Fprintf(commandOutput, "  Packing: PASS (%d placements)\n", len(report.Stats.Placements))
		}
		n := len(report.Rows)
		if !*all && n > 25 {
			n = 25
		}
		fmt.Fprintf(commandOutput, "  offset   own_slot  encoded+NUL  over_own_slot\n")
		for _, row := range report.Rows[:n] {
			fmt.Fprintf(commandOutput, "  %#08x %9d %12d %+14d\n", row.Offset, row.Slot, row.Encoded, row.Excess)
		}
		if n < len(report.Rows) {
			fmt.Fprintf(commandOutput, "  (%d more records; use --all for every offset)\n", len(report.Rows)-n)
		}
	}
	fmt.Fprintln(commandOutput, "\nRead-only diagnostic. No Japanese/English text is printed. Own-slot excess is NOT the saving guaranteed by editing that record; packing can be fragmented or pinned.")
	if failed > 0 {
		return fmt.Errorf("%d dialogue block(s) did not pack; do not disable checks or edit translated text automatically", failed)
	}
	return nil
}
