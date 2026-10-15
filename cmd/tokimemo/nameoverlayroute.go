package main

// G44: only original EXE table/code bytes are read. No disc/RAM modification.
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

func cmdNameOverlayRoute(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-route", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original PS1 CUE; auto-detected if omitted")
	report := fs.String("report", "", "NEW private G44 report JSON; existing files are never overwritten")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-route [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_route_G44.json]")
	}
	path, e := privateN10ReportPath(root, filepath.Join(root, ".local", "go_toolchain", "reports", "G44_OWNER_G43_TRANSFER.json"), true)
	if e != nil {
		return e
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(raw) > 256<<10 || fmt.Sprintf("%x", sha256.Sum256(raw)) != nametables.N10OwnerG43TransferSHA {
		return errors.New("G43 owner source report SHA/size mismatch")
	}
	var owner nametables.N10DescriptorReviewG43
	if e = json.Unmarshal(raw, &owner); e != nil {
		return e
	}
	review, e := nametables.ReviewN10RequestRouteG44(owner)
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
	review, e = nametables.CaptureN10RequestRouteG44(exe, review)
	if e != nil {
		return e
	}
	fmt.Fprintf(commandOutput, "G44 verified operation-6 table target %s from original EXE; %d code windows. Not a DMA or RAM ownership proof. N10 HOLD.\n", review.Operation6Target, len(review.NewCodeWindows))
	if *report == "" {
		fmt.Fprintln(commandOutput, "Use --report to save original code windows.")
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
		return errors.New("G44 report >256KiB")
	}
	out, e := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
	fmt.Fprintln(commandOutput, "Saved private report; source game and translation untouched.")
	return nil
}
