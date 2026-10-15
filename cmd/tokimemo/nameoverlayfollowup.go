package main

// Strict original-disc read-only check. G37 attested PS-X EXE+O.BIN extents;
// no N10 research result is ever used to patch the game or translations.
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

const ownerG37HeaderReportSHA = "83812e5d21a1cf50763b7c6348881d1386278475585a9a3dbdd4b626b5c8fe95"

func cmdNameOverlayFollowup(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-followup", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "owner original PS1 CUE; auto-discovers if empty")
	reportPath := fs.String("report", "", "NEW private read-only follow-up JSON; refuses overwrite")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-followup [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_followup_G38.json]")
	}
	ref, err := privateN10ReportPath(root, filepath.Join(root, ".local", "go_toolchain", "reports", "G38_OWNER_G37_LOADER.json"), true)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(ref)
	if err != nil {
		return err
	}
	if len(raw) > 128<<10 || fmt.Sprintf("%x", sha256.Sum256(raw)) != ownerG37HeaderReportSHA {
		return errors.New("owner G37 report SHA mismatch: cannot authenticate original disc")
	}
	var owner nametables.N10LoaderHeaderReport
	if err = json.Unmarshal(raw, &owner); err != nil {
		return err
	}
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
	exe, err := (isoSource{iso}).ReadFile(nametables.EXE)
	if err != nil {
		return err
	}
	odd, err := (isoSource{iso}).ReadFile(nametables.N10OddBinPath)
	if err != nil {
		return err
	}
	var oddLBA int64 = -1
	for _, e := range iso.Entries {
		if e.Path == nametables.N10OddBinPath && !e.IsDir && e.Size == 196608 {
			oddLBA = e.LBA
		}
	}
	analyzed, err := nametables.BuildN10LoaderFollowup(owner, ownerG37HeaderReportSHA, exe, odd, oddLBA)
	if err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "Original main EXE: %d JAL and %d constructed overlay-range addresses; %d structural address runs.\n", len(analyzed.MainDirectOverlayJAL), len(analyzed.MainOverlayAddressPairs), len(analyzed.MainAddressPairRuns))
	fmt.Fprintf(commandOutput, "Previously omitted O.BIN: LBA %d, SHA %s, A/B/C sites %d, C+64 sites %d, self-range JAL-like words %d.\n", analyzed.OddBINLBA, analyzed.OddBINSHA256, analyzed.OddBINABCUniqueSites, analyzed.OddBINCPlus64DirectSites, analyzed.OddBINStaticSelfJALCount)
	fmt.Fprintln(commandOutput, "STATIC ONLY: no demonstrated executable code in O.BIN, loader callflow, BSS clear or N10 patch approval.")
	if *reportPath == "" {
		fmt.Fprintln(commandOutput, "Pass --report to save the private instruction/context inventory.")
		return nil
	}
	dest, err := privateN10ReportPath(root, *reportPath, false)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(analyzed, "", "  ")
	if err != nil {
		return err
	}
	if len(out) > 4<<20 {
		return errors.New("follow-up report exceeds 4MiB safety limit")
	}
	fd, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = fd.Write(append(out, '\n')); err != nil {
		fd.Close()
		os.Remove(dest)
		return err
	}
	if err = fd.Close(); err != nil {
		os.Remove(dest)
		return err
	}
	fmt.Fprintln(commandOutput, "Saved private read-only G38 evidence. No game, translations or runtime modified.")
	return nil
}
