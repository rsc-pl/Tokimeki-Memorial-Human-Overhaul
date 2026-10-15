package main

// Strict read-only N10 disc geometry collector. Never writes ISO/CUE, patched
// EXE, translation or game RAM. A legacy memory-map convention is not proof
// of a running loader, overlay lifetime, BSS size or source-buffer ownership.

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"tokimemo/internal/nametables"
	"tokimemo/internal/ps1"
)

const ownerG34ContextSHA = "d9806092b8d4a2233b91ec14971bc16466f4368bf04bbef4de2c9e8fbf3f10b3"

func cmdNameOverlayGeometry(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-geometry", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "owner original PS1 CUE; auto-discovered if blank")
	report := fs.String("report", "", "NEW private JSON report path (will not overwrite)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-geometry [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_geometry_G36.json]")
	}
	ctxPath := filepath.Join(root, ".local", "go_toolchain", "reports", "G35_OWNER_G34_CONTEXT.json")
	name, err := privateN10ReportPath(root, ctxPath, true)
	if err != nil {
		return err
	}
	ctxBytes, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	if len(ctxBytes) > 8<<20 || fmt.Sprintf("%x", sha256.Sum256(ctxBytes)) != ownerG34ContextSHA {
		return errors.New("owner G34 context SHA-256 mismatch or oversized report; exact G35 reference required")
	}
	var ctx nametables.OverlayContextReport
	if err := json.Unmarshal(ctxBytes, &ctx); err != nil {
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
	var items []ps1.ISOEntry
	for _, entry := range iso.Entries {
		if !nametables.N10DiscCodeCandidate(entry.Path, entry.IsDir) {
			continue
		}
		if entry.Size <= 0 || entry.Size > 16<<20 {
			return fmt.Errorf("unscannable executable %s size %d", entry.Path, entry.Size)
		}
		items = append(items, entry)
	}
	if len(items) != 27 {
		return fmt.Errorf("unexpected original-disc executable count %d, expected 27", len(items))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	var files []nametables.GeometryInput
	for _, entry := range items {
		b, err := (isoSource{iso}).ReadFile(entry.Path)
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Path, err)
		}
		files = append(files, nametables.GeometryInput{Path: entry.Path, LBA: entry.LBA, Data: b})
	}
	geo, err := nametables.BuildN10OverlayGeometry(ctx, ownerG34ContextSHA, files)
	if err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "Original-disc SHA inventory: %d/27 verified; %d source bytes.\n", geo.FilesVerified, geo.TotalBytes)
	fmt.Fprintf(commandOutput, "LEGACY mapping HYPOTHESIS (not loader proof): EXE %s; overlay file %s.\n", geo.MainFileImageRange, geo.OverlayFileImageRange)
	fmt.Fprintf(commandOutput, "Self-range static JAL words: %d (NOT executed-call proof). BSS, runtime load, and RAM ownership remain unknown. N10 DO_NOT_BOOT.\n", geo.StaticSelfJALSites)
	if *report == "" {
		fmt.Fprintln(commandOutput, "Supply --report to save a new private bounded geometry report.")
		return nil
	}
	dest, err := privateN10ReportPath(root, *report, false)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(geo, "", "  ")
	if err != nil {
		return err
	}
	if len(out) > 2<<20 {
		return errors.New("geometry report exceeds 2MiB bound")
	}
	fd, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
	fmt.Fprintln(commandOutput, "Private read-only geometry report saved. No original source or translation changed.")
	return nil
}
