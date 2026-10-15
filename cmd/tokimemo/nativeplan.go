package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"

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
func cmdNativePlan(root string, args []string) error {
	fs := flag.NewFlagSet("native-plan", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "game CUE (read-only)")
	compare := fs.Bool("compare-python", false, "compare complete file hashes with Python planner")
	var translations strList
	fs.Var(&translations, "translation", "specific translation JSON (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo native-plan [--game CUE] [--compare-python] [--translation JSON]")
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
	// Keep disc identity check consistent with the production Python backend.
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
	batch, err := patchplan.Load(root, paths)
	if err != nil {
		return err
	}
	got, err := patchplan.Plan(isoSource{iso}, batch)
	if err != nil {
		return err
	}
	if *compare {
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
		if !reflect.DeepEqual(patchplan.SortedFiles(got), patchplan.SortedFiles(want)) || got.RendererInstalled != want.RendererInstalled {
			return fmt.Errorf("Go and Python full-file plans differ; Go: %v; Python: %v", patchplan.SortedFiles(got), patchplan.SortedFiles(want))
		}
		fmt.Fprintln(commandOutput, "Whole-file Go/Python bytes: PASS (SHA-256 of every modified file)")
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
