package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tokimemo/internal/nametables"
)

// This is deliberately disconnected from build/native-build. It only accepts
// an already-prepared private, NONBOOTABLE name-stage EXE. The result is a
// private research-only EXE+GEKO pair; there is no game image publication.
func cmdNameFixedStage(root string, args []string) error {
	fs := flag.NewFlagSet("name-fixed-stage", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original PlayStation the Best game CUE")
	staged := fs.String("staged-exe", "", "private N10 name-stage EXE input")
	out := fs.String("output-dir", "", "new private output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *staged == "" || *out == "" {
		return errors.New("usage: tokimemo name-fixed-stage --staged-exe .local/go_toolchain/checkpoints/n10_candidate.exe --output-dir .local/go_toolchain/checkpoints/n10_fixed_research [--game original.cue]")
	}
	private := filepath.Join(root, ".local", "go_toolchain")
	privateReal, err := filepath.EvalSymlinks(private)
	if err != nil {
		return err
	}
	// Input must remain within the private toolchain; never read from or write
	// directly to a user game image or public repository paths.
	in, err := filepath.Abs(*staged)
	if err != nil {
		return err
	}
	inReal, err := filepath.EvalSymlinks(in)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(privateReal, inReal)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("staged EXE must be inside private .local/go_toolchain")
	}
	dest, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dest))
	if err != nil {
		return err
	}
	rel, err = filepath.Rel(privateReal, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("output parent must be inside private .local/go_toolchain")
	}
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("output already exists: %s", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	exe, err := os.ReadFile(inReal)
	if err != nil {
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
	geko, err := (isoSource{iso}).ReadFile(nametables.Geko)
	if err != nil {
		return err
	}
	newEXE, newGEKO, summary, err := nametables.StageDirectFixedAliases(exe, geko)
	if err != nil {
		return err
	}
	meta := struct {
		nametables.DirectAliasStage
		EXESHA  string `json:"exe_sha256"`
		GEKOSHA string `json:"geko_sha256"`
	}{summary, fmt.Sprintf("%x", sha256.Sum256(newEXE)), fmt.Sprintf("%x", sha256.Sum256(newGEKO))}
	report, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	// Directory is created only after validation. Failures remove only the new
	// research directory; no source or other project file is ever touched.
	if err := os.Mkdir(dest, 0700); err != nil {
		return err
	}
	good := false
	defer func() {
		if !good {
			os.RemoveAll(dest)
		}
	}()
	for _, item := range []struct {
		name string
		data []byte
	}{{"RESEARCH_ONLY_SLPM_86.053", newEXE}, {"RESEARCH_ONLY_GEKO.EXN", newGEKO}, {"UNSAFE_TO_BOOT.json", append(report, '\n')}} {
		p := filepath.Join(dest, item.name)
		if err := os.WriteFile(p, item.data, 0600); err != nil {
			return err
		}
	}
	good = true
	fmt.Fprintln(commandOutput, "N10 source aliases: EXE 3 direct + 1 guarded inherited path, GEKO 1 direct site rewritten in research copies.")
	fmt.Fprintln(commandOutput, "UNSAFE TO BOOT: all four EXE Fujisaki source sites staged; GEKO -san remains untouched, because verified writable storage and other constraints remain unresolved.")
	fmt.Fprintln(commandOutput, "Private output:", dest)
	return nil
}
