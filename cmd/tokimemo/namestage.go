package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tokimemo/internal/nametables"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/ps1"
)

// cmdNameStage creates an EXE-only, NONBOOTABLE/UNVERIFIED engineering candidate
// in private .local space. It never changes the disc, translations, or native
// build path. The output is not a complete N10 fix: A/B/C and GEKO remain.
func cmdNameStage(root string, args []string) error {
	fs := flag.NewFlagSet("name-stage", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original two-track CUE")
	request := fs.String("request", "", "N10 SURNAME_CAPACITY.tsv (read-only)")
	output := fs.String("output", "", "private EXE-only engineering candidate; must not exist")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || *request == "" || *output == "" {
		return errors.New("usage: tokimemo name-stage --request N10.tsv --output .local/go_toolchain/checkpoints/n10_candidate.exe [--game ORIGINAL.cue]")
	}
	// Never let this research command publish a candidate into a public or ROM path.
	protected := filepath.Join(root, ".local", "go_toolchain")
	p, e := filepath.Abs(*output)
	if e != nil {
		return e
	}
	safeRoot, e := filepath.Abs(protected)
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(safeRoot, p)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("output must be inside private %s", safeRoot)
	}
	parent := filepath.Dir(p)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	// Don't follow symlink directories leading out of private storage.
	realParent, e := filepath.EvalSymlinks(parent)
	if e != nil {
		return e
	}
	realBase, e := filepath.EvalSymlinks(safeRoot)
	if e != nil {
		return e
	}
	check, e := filepath.Rel(realBase, realParent)
	if e != nil || check == ".." || strings.HasPrefix(check, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("output path escapes private root via symlink")
	}
	for _, candidate := range []string{p, p + ".json"} {
		if _, e := os.Lstat(candidate); e == nil {
			return fmt.Errorf("output already exists: %s", candidate)
		} else if !os.IsNotExist(e) {
			return e
		}
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
	// Read and verify original game executable identity prior to planning.
	if _, ok := iso.Entries[nametables.EXE]; !ok {
		return fmt.Errorf("disc is missing %s", nametables.EXE)
	}
	orig, e := (isoSource{iso}).ReadFile(nametables.EXE)
	if e != nil {
		return e
	}
	// This digest came from owner's original PlayStation the Best R04 capture.
	const ownerEXESHA = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	if fmt.Sprintf("%x", sha256.Sum256(orig)) != ownerEXESHA {
		return fmt.Errorf("original executable hash is not the verified N10 R04 image")
	}
	batch, e := patchplan.Load(root, nil)
	if e != nil {
		return e
	}
	result, files, e := patchplan.PlanBytes(isoSource{iso}, batch)
	if e != nil {
		return e
	}
	if !result.RendererInstalled {
		return errors.New("English pair renderer is not installed in planned EXE")
	}
	base, ok := files[nametables.EXE]
	if !ok {
		return errors.New("missing planned executable")
	}

	// The exact 16 index positions come from the current live translation,
	// not a historical handoff. Only entries in the compact block are used.
	current := make([]string, nametables.Entries)
	seen := make([]bool, nametables.Entries)
	for _, block := range batch.Dialogue {
		if block.File != nametables.EXE {
			continue
		}
		for _, line := range block.Lines {
			for i, off := range shortNameOffsets {
				if line.Offset == off {
					if seen[i] {
						return fmt.Errorf("duplicate live compact name at %#x", off)
					}
					current[i] = line.Text
					seen[i] = true
				}
			}
		}
	}
	desired := append([]string(nil), current...)
	for i, exists := range seen {
		if !exists {
			return fmt.Errorf("missing live compact name index %d", i)
		}
	}
	req, e := os.Open(*request)
	if e != nil {
		return e
	}
	defer req.Close()
	rows, e := nametables.ReadCapacityReport(req)
	if e != nil {
		return e
	}
	applied := 0
	for _, row := range rows {
		if row.File != "character_names.json" {
			continue
		}
		if row.Offset < nametables.ShortStart || row.Offset >= nametables.ShortEnd {
			continue
		}
		found := false
		for i, off := range shortNameOffsets {
			if row.Offset == off {
				if current[i] != row.Current && current[i] != row.Intended {
					return fmt.Errorf("current name differs from N10 expectation at %#x; review current checkout", off)
				}
				desired[i] = row.Intended
				applied++
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unexpected compact entry offset %#x", row.Offset)
		}
	}
	if applied == 0 {
		return errors.New("request contains no compact table replacements")
	}
	// G15: audit the documented runtime-copy instructions in the CURRENT
	// planned EXE and GEKO. This is a guarded, read-only preflight. It does not
	// redirect A/B/C and cannot prove that every caller has been found.
	verifiedEXE, e := nametables.VerifyKnownCopySites(nametables.EXE, base)
	if e != nil {
		return fmt.Errorf("N10 EXE name-copy preflight: %w", e)
	}
	origGEKO, e := (isoSource{iso}).ReadFile(nametables.Geko)
	if e != nil {
		return fmt.Errorf("N10 GEKO read: %w", e)
	}
	const ownerGEKOSHA = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
	if fmt.Sprintf("%x", sha256.Sum256(origGEKO)) != ownerGEKOSHA {
		return errors.New("N10 GEKO overlay is not the verified R04 image")
	}
	geko := origGEKO
	if planned, ok := files[nametables.Geko]; ok {
		geko = planned
	}
	verifiedGEKO, e := nametables.VerifyKnownCopySites(nametables.Geko, geko)
	if e != nil {
		return fmt.Errorf("N10 GEKO name-copy preflight: %w", e)
	}
	candidate, res, e := nametables.StageInRendererPool(base, current, desired)
	if e != nil {
		return e
	}
	if len(candidate) != len(orig) {
		return errors.New("staged executable size changed")
	}
	if ps1.TailChecksumValid(base) {
		if e := ps1.FixTailChecksum(candidate); e != nil {
			return e
		}
	}
	if bytes.Equal(candidate, base) {
		return errors.New("no changes generated")
	}
	fd, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = fd.Write(candidate); e != nil {
		fd.Close()
		os.Remove(p)
		return e
	}
	if e = fd.Sync(); e != nil {
		fd.Close()
		os.Remove(p)
		return e
	}
	if e = fd.Close(); e != nil {
		os.Remove(p)
		return e
	}
	report := struct {
		Status                 string                      `json:"status"`
		OriginalHash           string                      `json:"original_sha256"`
		PlannedHash            string                      `json:"planned_sha256"`
		CandidateHash          string                      `json:"candidate_sha256"`
		CompactEntries         int                         `json:"compact_entries"`
		Replacements           int                         `json:"request_replacements"`
		Result                 nametables.RelocationResult `json:"relocation"`
		RuntimeValidated       bool                        `json:"runtime_validated"`
		Blocks                 []string                    `json:"remaining_blockers"`
		VerifiedCopySites      map[string]int              `json:"verified_known_copy_sites"`
		CompleteCallerCoverage bool                        `json:"complete_caller_coverage"`
	}{"EXPERIMENTAL_EXE_ONLY_NOT_BOOT_APPROVED", ownerEXESHA, fmt.Sprintf("%x", sha256.Sum256(base)), fmt.Sprintf("%x", sha256.Sum256(candidate)), nametables.Entries, applied, res, false, []string{"RAM buffers A/B/C are not expanded", "four Fujisaki fixed literals remain", "GEKO-specific two strings remain", "{G} and scene UI widths not runtime verified"}, map[string]int{nametables.EXE: verifiedEXE, nametables.Geko: verifiedGEKO}, false}
	raw, _ := json.MarshalIndent(report, "", "  ")
	// Report is a sibling of the private candidate; avoid overwrites.
	reportFile := p + ".json"
	rf, e := os.OpenFile(reportFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		os.Remove(p)
		return e
	}
	if _, e = rf.Write(append(raw, '\n')); e != nil {
		rf.Close()
		os.Remove(reportFile)
		os.Remove(p)
		return e
	}
	if e = rf.Close(); e != nil {
		os.Remove(reportFile)
		os.Remove(p)
		return e
	}
	fmt.Fprintf(commandOutput, "N10 engineering candidate: %s\n16 pointers, %d/%d new encoded bytes; output SHA-256 %s\nNOT a bootable/approved fix. %d known copy sites verified; other RAM readers/writers unproven. Fujisaki, GEKO and UI remain on HOLD.\n", p, res.NewBytes, 180, report.CandidateHash, verifiedEXE+verifiedGEKO)
	return nil
}
