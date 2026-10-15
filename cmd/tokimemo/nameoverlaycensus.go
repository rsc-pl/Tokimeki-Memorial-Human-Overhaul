package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"tokimemo/internal/nametables"
	"tokimemo/internal/ps1"
)

// name-overlay-census is a READ-ONLY static source census of all .EXN/.EXE
// entries in the original ISO9660 image, not merely GEKO. No executable or
// original disc is ever modified and evidence does not approve N10 runtime.
func cmdNameOverlayCensus(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-census", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original CUE, auto-discovered if empty")
	report := fs.String("report", "", "new private JSON report inside .local/go_toolchain")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-census [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlays.json]")
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
	var entries []ps1.ISOEntry
	var total int64
	for _, item := range iso.Entries {
		if !nametables.N10DiscCodeCandidate(item.Path, item.IsDir) {
			continue
		}
		if item.Size <= 0 || item.Size > 16<<20 {
			return fmt.Errorf("unscannable executable %q size %d", item.Path, item.Size)
		}
		total += item.Size
		if total > 512<<20 {
			return errors.New("executable census exceeds 512MiB safety bound")
		}
		entries = append(entries, item)
	}
	if len(entries) > 2048 {
		return fmt.Errorf("unexpected executable file count %d", len(entries))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	// Retail verification prevents a patched CUE/ISO masquerading as original.
	expected := map[string]string{
		nametables.EXE:  "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae",
		nametables.Geko: "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad",
	}
	sources := make([]nametables.OverlaySourceCensus, 0, len(entries))
	for _, item := range entries {
		raw, err := (isoSource{iso}).ReadFile(item.Path)
		if err != nil {
			return fmt.Errorf("read executable %q: %w", item.Path, err)
		}
		if want, ok := expected[item.Path]; ok && fmt.Sprintf("%x", sha256.Sum256(raw)) != want {
			return fmt.Errorf("retail original %q SHA-256 mismatch", item.Path)
		}
		scan, err := nametables.ScanN10ExecutableSource(item.Path, raw)
		if err != nil {
			return err
		}
		sources = append(sources, scan)
	}
	outcome, e := nametables.BuildN10DiscCensus(sources)
	if e != nil {
		return e
	}
	fmt.Fprintf(commandOutput, "Original executable census: %d source files, %d bytes, %d files with static A/B/C candidates.\n", outcome.TotalFiles, outcome.TotalBytes, outcome.SourcesWithCandidates)
	fmt.Fprintf(commandOutput, "Other overlays beyond EXE and GEKO with candidates: %d. NOT patch-approved.\n", outcome.OtherSourcesWithCandidates)
	for _, s := range outcome.Sources {
		if s.StaticCandidates > 0 && s.Path != nametables.EXE && s.Path != nametables.Geko {
			fmt.Fprintf(commandOutput, "  %s: %d candidate sites (%d direct pairs, %d derived, %d pointer words)\n", s.Path, s.StaticCandidates, s.DirectPairs, s.DerivedCandidates, s.AlignedPointerWords)
		}
	}
	if *report == "" {
		fmt.Fprintln(commandOutput, "Use --report to retain the private per-file offsets for analysis.")
		return nil
	}
	base, e := filepath.EvalSymlinks(filepath.Join(root, ".local", "go_toolchain"))
	if e != nil {
		return e
	}
	dest, e := filepath.Abs(*report)
	if e != nil {
		return e
	}
	dir, e := filepath.EvalSymlinks(filepath.Dir(dest))
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(base, dir)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("report must remain inside private .local/go_toolchain")
	}
	data, e := json.MarshalIndent(outcome, "", "  ")
	if e != nil {
		return e
	}
	file, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = file.Write(append(data, '\n')); e != nil {
		file.Close()
		os.Remove(dest)
		return e
	}
	if e = file.Close(); e != nil {
		os.Remove(dest)
		return e
	}
	fmt.Fprintln(commandOutput, "Saved read-only private static census. Game and translations unchanged.")
	return nil
}
