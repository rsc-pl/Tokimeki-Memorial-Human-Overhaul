package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"tokimemo/internal/patchplan"
	"tokimemo/internal/ps1"
)

type isoSource struct{ iso *ps1.ISO }

func (s isoSource) ReadFile(path string) ([]byte, error) {
	e, ok := s.iso.Entries[path]
	if !ok || e.IsDir {
		return nil, fmt.Errorf("missing game file %q", path)
	}
	// Read only files changed by translations; never stage whole-disc data.
	if e.Size > 128<<20 {
		return nil, fmt.Errorf("game file %q too large for memory planner", path)
	}
	var b bytes.Buffer
	if err := ps1.ReadFileTo(s.iso.Reader, s.iso.Sectors, e.LBA, e.Size, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// selectDefaultTranslations makes exclusions explicit, exact, and auditable.
// A missing or repeated exclusion fails closed rather than silently reporting
// a misleading full-corpus PASS. The input JSON files are never modified.
func selectDefaultTranslations(root string, discovered, excluded []string) ([]string, []string, error) {
	if len(excluded) == 0 {
		return discovered, nil, nil
	}
	translationDir, err := filepath.Abs(filepath.Join(root, "translation"))
	if err != nil {
		return nil, nil, err
	}
	selected := make(map[string]bool, len(discovered))
	for _, path := range discovered {
		abs, e := filepath.Abs(path)
		if e != nil {
			return nil, nil, e
		}
		selected[filepath.Clean(abs)] = true
	}
	excludedSet := map[string]bool{}
	report := []string{}
	for _, raw := range excluded {
		if raw == "" || strings.Contains(raw, "\\") {
			return nil, nil, fmt.Errorf("invalid exclusion %q", raw)
		}
		path := raw
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		abs, e := filepath.Abs(path)
		if e != nil {
			return nil, nil, e
		}
		abs = filepath.Clean(abs)
		rel, e := filepath.Rel(translationDir, abs)
		if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.Contains(rel, string(filepath.Separator)) {
			return nil, nil, fmt.Errorf("exclusion must name one translation/*.json file: %q", raw)
		}
		if !selected[abs] {
			return nil, nil, fmt.Errorf("excluded JSON not found in current translation corpus: %q", raw)
		}
		if excludedSet[abs] {
			return nil, nil, fmt.Errorf("duplicate exclusion: %q", raw)
		}
		excludedSet[abs] = true
		report = append(report, filepath.ToSlash(filepath.Join("translation", rel)))
	}
	out := make([]string, 0, len(discovered)-len(excludedSet))
	for _, path := range discovered {
		abs, e := filepath.Abs(path)
		if e != nil {
			return nil, nil, e
		}
		if !excludedSet[filepath.Clean(abs)] {
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		return nil, nil, errors.New("all translations excluded; no parity can be certified")
	}
	sort.Strings(report)
	return out, report, nil
}

func cmdNativePlan(root string, args []string) error {
	fs := flag.NewFlagSet("native-plan", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "game CUE (read-only)")
	compare := fs.Bool("compare-python", false, "compare complete file hashes with Python planner")
	summary := fs.Bool("summary", false, "print compact, non-text parity summary instead of per-file JSON")
	var translations, excludeTranslations strList
	fs.Var(&excludeTranslations, "exclude-translation", "exclude one translation/*.json from default all-corpus parity (repeatable, PARTIAL only)")
	fs.Var(&translations, "translation", "specific translation JSON (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *summary && !*compare {
		return errors.New("--summary requires --compare-python; no parity without reference")
	}
	if len(excludeTranslations) != 0 && (!*compare || len(translations) != 0) {
		return errors.New("--exclude-translation requires --compare-python and cannot be combined with --translation")
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo native-plan [--game CUE] [--compare-python] [--translation JSON] [--exclude-translation translation/FILE.json]")
	}
	explicit := *game
	if fs.NArg() == 1 {
		explicit = fs.Arg(0)
	}
	cue, err := cueChoice(root, explicit)
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
	// Keep disc identity checks consistent with the authenticated production disc reader.
	cnf, ok := iso.Entries["SYSTEM.CNF"]
	if !ok || cnf.IsDir {
		return errors.New("SYSTEM.CNF missing")
	}
	var cnfData bytes.Buffer
	if err = ps1.ReadFileTo(f, track.Sectors, cnf.LBA, cnf.Size, &cnfData); err != nil {
		return err
	}
	if !bytes.Contains(cnfData.Bytes(), []byte("cdrom:SLPM_86.053")) {
		return errors.New("unsupported disc: expected SLPM-86053 boot identifier")
	}
	paths := []string{}
	for _, p := range translations {
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		paths, err = filepath.Glob(filepath.Join(root, "translation", "*.json"))
		if err != nil {
			return err
		}
		sort.Strings(paths)
	}
	paths, excludedReport, err := selectDefaultTranslations(root, paths, excludeTranslations)
	if err != nil {
		return err
	}
	if len(excludedReport) > 0 {
		fmt.Fprintf(commandOutput, "PARTIAL PARITY REQUEST: %d selected JSON files; %d excluded\n", len(paths), len(excludedReport))
		for _, filename := range excludedReport {
			fmt.Fprintf(commandOutput, "EXCLUDED (not checked): %s\n", filename)
		}
	}
	// Hash originals, selected JSON and graphic source inputs *before* either
	// planner runs. The parity result is rejected if files are replaced or
	// mutated while the Python reference is executing.
	var discs, translationsBefore, imagesBefore []frozenInput
	if *compare {
		discs, err = freezeInputs(append([]string{cue}, track.Inputs...))
		if err != nil {
			return fmt.Errorf("snapshotting source game: %w", err)
		}
		translationsBefore, err = freezeInputs(paths)
		if err != nil {
			return fmt.Errorf("snapshotting translations: %w", err)
		}
	}
	batch, err := patchplan.Load(root, paths)
	if err != nil {
		return err
	}
	if *compare {
		imagesBefore, err = freezeInputs(graphicPaths(batch))
		if err != nil {
			return fmt.Errorf("snapshotting image inputs: %w", err)
		}
		for _, inputs := range [][]frozenInput{discs, translationsBefore, imagesBefore} {
			if err = verifyFrozen(inputs); err != nil {
				return err
			}
		}
	}
	got, err := patchplan.Plan(isoSource{iso}, batch)
	if err != nil {
		return err
	}
	if len(excludedReport) > 0 && len(got.Files) == 0 {
		return errors.New("partial parity selected no modified ISO files; refusing empty PASS")
	}
	if *compare {
		for _, inputs := range [][]frozenInput{discs, translationsBefore, imagesBefore} {
			if err = verifyFrozen(inputs); err != nil {
				return err
			}
		}
		reference := filepath.Join(root, "legacy_scripts", "tools", "fullplan_reference.py")
		python := os.Getenv("TOKIMEMO_PYTHON")
		if python == "" {
			python = "python3"
		}
		argv := []string{reference, "--track", track.Data}
		for _, p := range paths {
			argv = append(argv, "--translation", p)
		}
		c := exec.Command(python, argv...)
		c.Dir = root
		c.Env = pythonEnv(root)
		stderr := new(bytes.Buffer)
		c.Stderr = stderr
		data, e := c.Output()
		if e != nil {
			return fmt.Errorf("Python reference failed: %w: %s", e, stderr.String())
		}
		var want patchplan.Result
		if e = json.Unmarshal(data, &want); e != nil {
			return fmt.Errorf("Python returned invalid report: %w", e)
		}
		if !reflect.DeepEqual(patchplan.SortedFiles(got), patchplan.SortedFiles(want)) || got.RendererInstalled != want.RendererInstalled || got.Strings != want.Strings || got.Images != want.Images || got.Bytes != want.Bytes || got.Blocks != want.Blocks {
			return fmt.Errorf("Go and Python full-file plans differ; Go: %v; Python: %v", patchplan.SortedFiles(got), patchplan.SortedFiles(want))
		}
		// Verify once more *after* Python has read the same sources and
		// immediately before claiming parity. Inode/byte changes fail closed.
		for _, inputs := range [][]frozenInput{discs, translationsBefore, imagesBefore} {
			if err = verifyFrozen(inputs); err != nil {
				return err
			}
		}
		if len(excludedReport) != 0 {
			fmt.Fprintln(commandOutput, "PARTIAL selected-translations Go/Python bytes: PASS (SHA-256 of modified files for selected JSON only)")
			fmt.Fprintln(commandOutput, "NOT VERIFIED: excluded translations; full corpus build and parity remain unverified")
		} else {
			fmt.Fprintln(commandOutput, "Whole-file Go/Python bytes: PASS (SHA-256 of every modified file; inputs unchanged)")
		}
	}
	// Deterministic compact parity for TUI: no full JSON flood. Hash the
	// canonical ordered result, including each original/modified file SHA,
	// operations count and renderer flag. Neither private input text nor
	// absolute source paths are printed.
	if *summary {
		normalized := patchplan.SortedFiles(got)
		canonical, e := json.Marshal(struct {
			Files    []patchplan.FileResult `json:"files"`
			Renderer bool                   `json:"renderer_installed"`
			Strings  int                    `json:"strings"`
			Images   int                    `json:"images"`
			Bytes    int                    `json:"bytes"`
			Blocks   int                    `json:"blocks"`
		}{normalized, got.RendererInstalled, got.Strings, got.Images, got.Bytes, got.Blocks})
		if e != nil {
			return e
		}
		hash := sha256.Sum256(canonical)
		fmt.Fprintf(commandOutput, "Modified ISO files: %d\nRenderer plan: %t\nChanges: strings=%d images=%d binary=%d dialogue_blocks=%d\nPlan fingerprint SHA-256: %x\n", len(normalized), got.RendererInstalled, got.Strings, got.Images, got.Bytes, got.Blocks, hash)
		if len(excludedReport) != 0 {
			fmt.Fprintln(commandOutput, "PARITY SCOPE: PARTIAL selected JSON only; no full-corpus claim, no complete disc parity or game runtime evidence")
		} else {
			fmt.Fprintln(commandOutput, "PARITY SCOPE: individual planned ISO file bytes only; no complete disc parity, no game runtime evidence")
		}
		fmt.Fprintln(commandOutput, "Original CUE/BIN and translation inputs remain read-only")
		return nil
	}
	// Deterministic, machine-readable summary; no Japanese or English text.
	sort.Slice(got.Files, func(i, j int) bool { return got.Files[i].Path < got.Files[j].Path })
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(commandOutput, string(data))
	fmt.Fprintln(commandOutput, "Read-only: original BIN/CUE and translation resources unchanged; boot not tested")
	return nil
}
