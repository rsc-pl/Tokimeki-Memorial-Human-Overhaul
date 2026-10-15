package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tokimemo/internal/nametables"
)

// cmdNameCombineStage merges the separate G18/G24 guarded research-only MIPS
// modifications. It is NOT an image builder and must never publish to ROM or
// build directories. In particular it does not use the old compact pool for
// Tatebayashi-san, because lifetime/indirect references remain unproven.
func cmdNameCombineStage(root string, args []string) error {
	fs := flag.NewFlagSet("name-combine-stage", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original PS1 CUE; auto-detected by default")
	staged := fs.String("staged-exe", "", "private name-stage EXE with provenance JSON")
	out := fs.String("output-dir", "", "new directory inside .local/go_toolchain")
	includeSuffix := fs.Bool("adjacent-geko-suffix-research", false, "RESEARCH ONLY: use GEKO original adjacent 8+12 name slots for Tatebayashi-san (DO NOT BOOT)")
	detachedOffset := fs.String("detached-geko-suffix-offset", "", "RESEARCH ONLY: explicit 0x... file offset of a separate zero area; preserves originals (DO NOT BOOT)")
	detachedSize := fs.Int("detached-geko-suffix-size", 24, "size in bytes of detached zero region (17..4096)")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *includeSuffix && *detachedOffset != "" {
		return errors.New("choose only one GEKO suffix research variant")
	}
	if fs.NArg() != 0 || *staged == "" || *out == "" {
		return errors.New("usage: tokimemo name-combine-stage --staged-exe .local/go_toolchain/checkpoints/N10.EXE --output-dir .local/go_toolchain/checkpoints/N10_combined_research")
	}
	private, e := filepath.EvalSymlinks(filepath.Join(root, ".local", "go_toolchain"))
	if e != nil {
		return e
	}
	input, e := filepath.EvalSymlinks(*staged)
	if e != nil {
		return e
	}
	input, e = filepath.Abs(input)
	if e != nil {
		return e
	}
	checkIn, e := filepath.Rel(private, input)
	if e != nil || checkIn == "." || checkIn == ".." || strings.HasPrefix(checkIn, ".."+string(os.PathSeparator)) {
		return errors.New("candidate EXE must be inside .local/go_toolchain")
	}
	output, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	outputParent, e := filepath.EvalSymlinks(filepath.Dir(output))
	if e != nil {
		return e
	}
	checkOut, e := filepath.Rel(private, outputParent)
	if e != nil || checkOut == ".." || strings.HasPrefix(checkOut, ".."+string(os.PathSeparator)) {
		return errors.New("output must be in .local/go_toolchain")
	}
	if _, e := os.Lstat(output); e == nil {
		return fmt.Errorf("output exists: %s", output)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	source, e := os.ReadFile(input)
	if e != nil {
		return e
	}
	provenance, e := os.ReadFile(input + ".json")
	if e != nil {
		return fmt.Errorf("name-stage provenance missing: %w", e)
	}
	var state struct {
		Status                 string                      `json:"status"`
		CandidateHash          string                      `json:"candidate_sha256"`
		CompactEntries         int                         `json:"compact_entries"`
		CompleteCallerCoverage bool                        `json:"complete_caller_coverage"`
		Result                 nametables.RelocationResult `json:"relocation"`
	}
	if e = json.Unmarshal(provenance, &state); e != nil {
		return e
	}
	if state.Status != "EXPERIMENTAL_EXE_ONLY_NOT_BOOT_APPROVED" || state.CompactEntries != nametables.Entries || state.Result.NewBytes != 132 || state.CompleteCallerCoverage || state.CandidateHash != fmt.Sprintf("%x", sha256.Sum256(source)) {
		return errors.New("staged EXE provenance mismatch; refusing unverified source")
	}
	cue, e := cueChoice(root, *game)
	if e != nil {
		return e
	}
	tracks, e := parseCue(cue)
	if e != nil {
		return e
	}
	file, iso, e := openDiscISO(tracks.Data, tracks.Sectors)
	if e != nil {
		return e
	}
	defer file.Close()
	geko, e := (isoSource{iso}).ReadFile(nametables.Geko)
	if e != nil {
		return e
	}
	ex, ge, summary, e := nametables.CombinePartialN10Research(source, geko)
	if e != nil {
		return e
	}
	if *includeSuffix {
		candidate, suffix, err := nametables.StageGEKOAdjacentHonorificResearch(geko, ge)
		if err != nil {
			return fmt.Errorf("adjacent GEKO suffix candidate rejected: %w", err)
		}
		ge = candidate
		summary.GEKOSuffixOriginalUnchanged = false
		summary.GEKOAdjacentSuffix = &suffix
		summary.GEKOSHA256 = fmt.Sprintf("%x", sha256.Sum256(ge))
		summary.Status = "N10_COMBINED_PLUS_GEKO_SUFFIX_RESEARCH_NOT_BOOTABLE"
		summary.Remaining = []string{
			"Adjacent GEKO literal storage is only a candidate; computed/indirect readers of either original slot remain UNKNOWN",
			"A/B candidate runtime lifetime and writability through overlays remain UNPROVEN",
			"Indirect A/B readers/writers and all dynamic strcat suffix lengths remain UNKNOWN",
			"N10 long-name and {G} UI width/overflow not verified in gameplay",
			"N20 player-name transliteration remains a separate TODO",
			"NO tested game image or runtime approval: never boot candidate",
		}
	}
	if *detachedOffset != "" {
		offset, err := strconv.ParseInt(*detachedOffset, 0, 64)
		if err != nil || offset < 0 || offset > int64(len(geko)) {
			return errors.New("detached GEKO offset must be a valid file offset (e.g. 0x12340)")
		}
		candidate, suffix, err := nametables.StageGEKODetachedSuffixResearch(geko, ge, int(offset), *detachedSize)
		if err != nil {
			return fmt.Errorf("detached GEKO suffix research rejected: %w", err)
		}
		ge = candidate
		summary.GEKODetachedSuffix = &suffix
		summary.GEKOSHA256 = fmt.Sprintf("%x", sha256.Sum256(ge))
		summary.Status = "N10_COMBINED_DETACHED_GEKO_SUFFIX_RESEARCH_NOT_BOOTABLE"
		summary.Remaining = []string{
			"Both original GEKO literals and the ordinary source caller remain intact",
			"Zero bytes at detached destination do NOT prove ROM/overlay code-data or runtime ownership",
			"A/B buffer safety, indirect consumers and maximal dynamic appended text are UNPROVEN",
			"No gameplay/UI verification or isolated runtime approval; DO NOT BOOT",
		}
	}
	report, e := json.MarshalIndent(summary, "", "  ")
	if e != nil {
		return e
	}
	if e = os.Mkdir(output, 0700); e != nil {
		return e
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(output)
		}
	}()
	for _, data := range []struct {
		name    string
		content []byte
	}{
		{"DO_NOT_BOOT_SLPM_86.053", ex}, {"DO_NOT_BOOT_GEKO.EXN", ge}, {"DO_NOT_BOOT.json", append(report, '\n')},
	} {
		path := filepath.Join(output, data.name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err = f.Write(data.content); err != nil {
			_ = f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
	}
	committed = true
	fmt.Fprintf(commandOutput, "N10 G25 research merge: %d EXE + %d GEKO A/B sites, %d direct EXE + %d inherited Fujisaki + %d GEKO source sites.\n", summary.EXEABSites, summary.GEKOABSites, summary.EXEDirectSites, summary.EXEInheritedSites, summary.GEKODirectSites)
	if *includeSuffix {
		fmt.Fprintln(commandOutput, "GEKO adjacent suffix research staged: 17/20 bytes, 2 reviewed consumers, indirect aliases UNPROVEN.")
	}
	fmt.Fprintln(commandOutput, "NOT BOOTABLE: indirect consumers, A/B runtime ownership and dynamic suffix lengths NOT PROVEN.")
	fmt.Fprintln(commandOutput, "Research files only:", output)
	return nil
}
