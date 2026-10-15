package main

// G42 original-disc targeted read-only sector-I/O routine collector.
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"tokimemo/internal/nametables"
)

func cmdNameOverlayIO(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-io", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original PS1 CUE; auto-selected when omitted")
	report := fs.String("report", "", "NEW private report JSON; no overwrite")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-io [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_io_G42.json]")
	}
	read := func(name, sha string, max int) ([]byte, error) {
		p, e := privateN10ReportPath(root, filepath.Join(root, ".local", "go_toolchain", "reports", name), true)
		if e != nil {
			return nil, e
		}
		buf, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		if len(buf) > max || fmt.Sprintf("%x", sha256.Sum256(buf)) != sha {
			return nil, fmt.Errorf("owner report %s SHA/size mismatch", name)
		}
		return buf, nil
	}
	raw, e := read("G42_OWNER_G41_TRACE.json", nametables.N10OwnerG41TraceSHA, 1<<20)
	if e != nil {
		return e
	}
	geomRaw, e := read("G37_OWNER_G36_GEOMETRY.json", ownerG36GeometrySHA, 1<<20)
	if e != nil {
		return e
	}
	var owner nametables.N10DispatchTraceReport
	var geo nametables.GeometryReport
	if e = json.Unmarshal(raw, &owner); e != nil {
		return e
	}
	if e = json.Unmarshal(geomRaw, &geo); e != nil {
		return e
	}
	review, e := nametables.ReviewN10OverlaySelectorG42(owner, geo)
	if e != nil {
		return e
	}
	cue, e := cueChoice(root, *game)
	if e != nil {
		return e
	}
	tracks, e := parseCue(cue)
	if e != nil {
		return e
	}
	f, iso, e := openDiscISO(tracks.Data, tracks.Sectors)
	if e != nil {
		return e
	}
	defer f.Close()
	exe, e := (isoSource{iso}).ReadFile(nametables.EXE)
	if e != nil {
		return e
	}
	review, e = nametables.CaptureN10OverlayIOG42(exe, review)
	if e != nil {
		return e
	}
	fmt.Fprintf(commandOutput, "G42: %d EXN LBA matches / %d other EXN paths in this selector; %d focused original EXE windows.\n", len(review.SelectorMatches), len(review.EXNNotInThisSelector), len(review.Windows))
	fmt.Fprintf(commandOutput, "Owner trace has G41 static_flow: %v. Original EXE source verified; IO implementation and RAM safety NOT verified. N10 DO_NOT_BOOT.\n", review.OwnerReportedG41FlowPresent)
	if *report == "" {
		fmt.Fprintln(commandOutput, "Use --report to save bounded original code windows.")
		return nil
	}
	dest, e := privateN10ReportPath(root, *report, false)
	if e != nil {
		return e
	}
	b, e := json.MarshalIndent(review, "", "  ")
	if e != nil {
		return e
	}
	if len(b) > 256<<10 {
		return errors.New("G42 report exceeds 256KiB bound")
	}
	out, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = out.Write(append(b, '\n')); e != nil {
		out.Close()
		os.Remove(dest)
		return e
	}
	if e = out.Close(); e != nil {
		os.Remove(dest)
		return e
	}
	fmt.Fprintln(commandOutput, "Saved private read-only original-disc report. ROM/CUE unchanged.")
	return nil
}
