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

// name-geko-provenance is static, read-only and restricted to the original
// checked retail overlay. It does not certify complete references or patch
// anything; it exists to find newly derived/aliased address candidates missed
// by the earlier direct-pair scanner.
func cmdNameGEKOProvenance(root string, args []string) error {
	fs := flag.NewFlagSet("name-geko-provenance", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original CUE; auto-discovered if empty")
	report := fs.String("report", "", "new private JSON report under .local/go_toolchain")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-geko-provenance [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_geko_provenance.json]")
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
	raw, e := (isoSource{iso}).ReadFile(nametables.Geko)
	if e != nil {
		return e
	}
	const digest = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
		return errors.New("original GEKO revision mismatch; no scan performed")
	}
	result, e := nametables.AuditGEKOLiteralProvenance(raw)
	if e != nil {
		return e
	}
	fmt.Fprintf(commandOutput, "GEKO: %d candidate references (%d exact known, %d additional). Not patch-approved.\n", len(result.Hits), result.DirectKnown, result.AdditionalCandidates)
	fmt.Fprintf(commandOutput, "GEKO pointer escapes: %d reviewed calls, %d unreviewed candidates. No runtime approval.\n", result.ReviewedEscapes, result.UnreviewedEscapes)
	if *report == "" {
		fmt.Fprintln(commandOutput, "Supply --report to save private JSON with source offsets.")
		return nil
	}
	base, e := filepath.EvalSymlinks(filepath.Join(root, ".local", "go_toolchain"))
	if e != nil {
		return e
	}
	p, e := filepath.Abs(*report)
	if e != nil {
		return e
	}
	dir, e := filepath.EvalSymlinks(filepath.Dir(p))
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(base, dir)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("report must be inside existing private .local/go_toolchain")
	}
	data, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return e
	}
	output, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = output.Write(append(data, '\n')); e != nil {
		output.Close()
		os.Remove(p)
		return e
	}
	if e = output.Close(); e != nil {
		os.Remove(p)
		return e
	}
	fmt.Fprintln(commandOutput, "Private report saved; no BIN/CUE or translation files modified.")
	return nil
}
