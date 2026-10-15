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
)

// Read-only follow-up to the owner's G31 census. No MIPS instruction is
// modified, no N10 staged build is bootable or used by production builders.
func cmdNameOverlayContext(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-context", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original CUE; auto-discovered if empty")
	censusPath := fs.String("census", "", "existing original-disc G31 JSON; default private report")
	reportPath := fs.String("report", "", "NEW private bounded instruction context JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-context [--game ORIGINAL.cue] [--census .local/go_toolchain/reports/n10_all_executable_overlays_G31.json] [--report .local/go_toolchain/reports/n10_overlay_context_G34.json]")
	}
	if *censusPath == "" {
		*censusPath = filepath.Join(root, ".local", "go_toolchain", "reports", "n10_all_executable_overlays_G31.json")
	}
	input, err := privateN10ReportPath(root, *censusPath, true)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	if len(b) > 8<<20 {
		return errors.New("G31 census larger than safety limit")
	}
	var c nametables.OverlayDiscCensus
	if err = json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("invalid G31 census: %w", err)
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
	sources := make(map[string][]byte)
	paths := make([]string, 0)
	for _, item := range iso.Entries {
		if !nametables.N10DiscCodeCandidate(item.Path, item.IsDir) {
			continue
		}
		if item.Size <= 0 || item.Size > 16<<20 {
			return fmt.Errorf("bad executable size %s", item.Path)
		}
		paths = append(paths, item.Path)
	}
	if len(paths) > 2048 || len(paths) != c.TotalFiles {
		return fmt.Errorf("file count mismatch to G31 census: disc=%d census=%d", len(paths), c.TotalFiles)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, e := (isoSource{iso}).ReadFile(path)
		if e != nil {
			return fmt.Errorf("read %s: %w", path, e)
		}
		if len(raw) > 16<<20 {
			return fmt.Errorf("oversized source %s", path)
		}
		if path == nametables.EXE && fmt.Sprintf("%x", sha256.Sum256(raw)) != "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae" {
			return errors.New("original main EXE SHA-256 mismatch")
		}
		if path == nametables.Geko && fmt.Sprintf("%x", sha256.Sum256(raw)) != "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad" {
			return errors.New("original GEKO SHA-256 mismatch")
		}
		sources[path] = raw
	}
	report, err := nametables.BuildN10OverlayContext(c, b, sources)
	if err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "G31 verified against original sources: %d unique MIPS address constructions (%d in additional overlays). Research only.\n", report.UniqueSites, report.OtherOverlayUniqueSites)
	fmt.Fprintf(commandOutput, "Addresses: A=%d B=%d C=%d. No caller/lifetime proof or patch approval.\n", report.UniqueByAddress["0x800CA188"], report.UniqueByAddress["0x800CA190"], report.UniqueByAddress["0x800CA19C"])
	if *reportPath == "" {
		fmt.Fprintln(commandOutput, "Supply --report for a new private instruction-window report. No source files were changed.")
		return nil
	}
	dest, err := privateN10ReportPath(root, *reportPath, false)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 8<<20 {
		return errors.New("context report exceeds 8MiB safety bound")
	}
	o, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = o.Write(append(data, '\n')); err != nil {
		o.Close()
		os.Remove(dest)
		return err
	}
	if err = o.Close(); err != nil {
		os.Remove(dest)
		return err
	}
	fmt.Fprintln(commandOutput, "Saved read-only private MIPS word context report. No original game, translation or build changed.")
	return nil
}

func privateN10ReportPath(root, name string, existing bool) (string, error) {
	base, err := filepath.EvalSymlinks(filepath.Join(root, ".local", "go_toolchain"))
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(name) {
		name = filepath.Join(root, name)
	}
	p, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("report must be under the private .local/go_toolchain directory")
	}
	if filepath.Ext(p) != ".json" {
		return "", errors.New("report must be a .json file")
	}
	if existing {
		info, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("census report must be a regular non-symlink file")
		}
	}
	return p, nil
}
