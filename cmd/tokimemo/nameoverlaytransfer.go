package main

// G43: only original EXE code bytes are read. No disc/RAM modification.
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

func cmdNameOverlayTransfer(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-transfer", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original PS1 CUE; auto-detected if omitted")
	report := fs.String("report", "", "NEW private G43 report JSON; existing files are never overwritten")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-transfer [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_transfer_G43.json]")
	}
	path, e := privateN10ReportPath(root, filepath.Join(root, ".local", "go_toolchain", "reports", "G43_OWNER_G42_IO.json"), true)
	if e != nil {
		return e
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(raw) > 256<<10 || fmt.Sprintf("%x", sha256.Sum256(raw)) != nametables.N10OwnerG42IOSHA {
		return errors.New("G42 owner source report SHA/size mismatch")
	}
	var owner nametables.N10IOLoaderReview
	if e = json.Unmarshal(raw, &owner); e != nil {
		return e
	}
	review, e := nametables.ReviewN10DescriptorG43(owner)
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
	review, e = nametables.CaptureN10DescriptorG43(exe, review)
	if e != nil {
		return e
	}
	fmt.Fprintf(commandOutput, "G43 verified descriptor %s from original MIPS; %d code windows. Not a DMA or RAM ownership proof. N10 HOLD.\n", review.PackedDescriptor, len(review.NewCodeWindows))
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
		return errors.New("G43 report >256KiB")
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
