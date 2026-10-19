package main

// Best-effort read-only explanation when the legacy Python build reports a
// dialogue slot packing failure. The Python error is authoritative for the
// production build; Go's reproduction is explicitly labeled independently.
import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"tokimemo/internal/patchplan"
	"tokimemo/internal/script"
)

var pythonPackingFailure = regexp.MustCompile(`(?i)([a-z0-9_\-]+\.json):\s*(CDROM/[A-Z0-9_./\-]+):\s*the English doesn't fit`)

// Capture a bounded tail, not a full build log that may be very large.
type buildErrorTail struct{ data []byte }

func (b *buildErrorTail) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	if len(b.data) > 65536 {
		b.data = append([]byte(nil), b.data[len(b.data)-65536:]...)
	}
	return len(p), nil
}

func printPackingDiagnostics(w io.Writer, stats script.PlanStats) {
	f := stats.Failure
	if f == nil {
		fmt.Fprintln(w, "  Diagnostics: no structured packing failure (may be validation error).")
		return
	}
	switch f.Reason {
	case "total_capacity":
		fmt.Fprintf(w, "  REASON: TOTAL_CAPACITY (%d bytes over original pool); relocation cannot solve this alone.\n", stats.BytesNeeded-stats.BytesAvailable)
	case "pinned_oversize":
		fmt.Fprintf(w, "  REASON: PINNED_OVERSIZE at %#x: %d encoded bytes, only %d contiguous bytes in fixed slot.\n", f.PinnedOffset, f.PinnedNeed, f.PinnedSlot)
	default:
		fmt.Fprintf(w, "  REASON: FRAGMENTATION_OR_PLACEMENT: %d bytes requested, %d bytes in original slots; two greedy placement strategies failed.\n", stats.BytesNeeded, stats.BytesAvailable)
		fmt.Fprintln(w, "  Note: neither failure proves the layout is mathematically impossible; a different safe algorithm may succeed.")
	}
	for _, a := range f.Attempts {
		fmt.Fprintf(w, "  %s: first unplaced at %#x, needs %d contiguous bytes; %d total bytes free in %d spans; largest span %d; %d placements so far.\n",
			a.Strategy, a.FirstUnplacedOffset, a.Requested, a.FreeTotal, a.FreeSpans, a.LargestContiguous, a.PlacedCount)
	}
}

func formatProblemRows(w io.Writer, rows []dialogueBudgetRow, limit int) {
	if limit > len(rows) {
		limit = len(rows)
	}
	over := 0
	for _, r := range rows {
		if r.Excess > 0 {
			over++
		}
	}
	fmt.Fprintf(w, "  Own-slot excess: %d/%d records (not automatically the cause of packing failure).\n", over, len(rows))
	if over == 0 {
		return
	}
	fmt.Fprintln(w, "  Highest own-slot excess (offset, own slot, encoded+NUL, delta):")
	shown := 0
	for _, r := range rows {
		if r.Excess <= 0 || shown >= limit {
			break
		}
		fmt.Fprintf(w, "    %#08x  %4d  %4d  %+d\n", r.Offset, r.Slot, r.Encoded, r.Excess)
		shown++
	}
	if over > shown {
		fmt.Fprintf(w, "  ... %d additional oversize records; use dialogue-budget --all.\n", over-shown)
	}
}

// Called only when the backend has already failed; never changes the original
// Python error, translations, ROM, or output tracks.
func explainPythonPackingError(root, cue, buildLog string, w io.Writer) {
	// The legacy patcher can print ANSI color around FAIL; the path and core
	// error remain adjacent. Never infer a failure from an unrelated message.
	cleaned := ansiCode.ReplaceAllString(buildLog, "")
	matches := pythonPackingFailure.FindAllStringSubmatch(cleaned, -1)
	if len(matches) == 0 {
		return
	}
	// Avoid repeating identical messages from rich TUI updates.
	seen := map[string]bool{}
	for _, m := range matches {
		name, file := filepath.Base(m[1]), strings.ToUpper(m[2])
		key := name + "|" + file
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(w, "\n=== AUTOMATIC DIALOGUE PACKING DIAGNOSTIC (read-only) ===\n")
		fmt.Fprintf(w, "  Translation: translation/%s | disc file: %s\n", name, file)
		if err := diagnosePythonFailedBlock(root, cue, name, file, w); err != nil {
			fmt.Fprintf(w, "  Independent Go diagnostic unavailable: %v\n", err)
			fmt.Fprintf(w, "  Inspect manually: ./tokimemo dialogue-budget --translation translation/%s --all\n", name)
		}
	}
}

var ansiCode = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func diagnosePythonFailedBlock(root, cue, name, file string, w io.Writer) error {
	translation := filepath.Join(root, "translation", name)
	batch, err := patchplan.Load(root, []string{translation})
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
	count := 0
	for _, block := range batch.Dialogue {
		if block.File != file {
			continue
		}
		count++
		original, err := source.ReadFile(block.File)
		if err != nil {
			return err
		}
		result, err := auditDialogueBudget(original, block)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "  Go replay: %d active lines; %d bytes encoded, %d bytes in original slots.\n", len(result.Rows), result.Stats.BytesNeeded, result.Stats.BytesAvailable)
		if result.Err == nil {
			fmt.Fprintln(w, "  Go replay: PASS — does NOT reproduce Python's failure. Possible Go/Python parity difference; investigate rather than editing text.")
		} else {
			fmt.Fprintf(w, "  Go replay: FAIL — %v\n", result.Err)
			printPackingDiagnostics(w, result.Stats)
			formatProblemRows(w, result.Rows, 12)
		}
	}
	if count == 0 {
		return fmt.Errorf("translated file has no matching dialogue block for %s", file)
	}
	return nil
}
