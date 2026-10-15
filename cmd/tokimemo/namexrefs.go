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

// cmdNameXrefs is a read-only original-image census; it cannot apply any
// mutations to input files. Static candidates are never patch authorizations.
func cmdNameXrefs(root string, args []string) error {
	fs := flag.NewFlagSet("name-xrefs", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original two-track CUE (auto-discover if empty)")
	report := fs.String("report", "", "optional new JSON report in .local/go_toolchain/")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-xrefs [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/name-xrefs.json]")
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
	expected := map[string]string{
		nametables.EXE:  "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae",
		nametables.Geko: "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad",
	}
	result := struct {
		Status                 string                 `json:"status"`
		Sources                []nametables.XrefAudit `json:"sources"`
		CompleteCallerCoverage bool                   `json:"complete_caller_coverage"`
		SafeToPatch            bool                   `json:"safe_to_patch"`
	}{Status: "STATIC_REVIEW_ONLY_NOT_PATCH_APPROVED", Sources: []nametables.XrefAudit{}, CompleteCallerCoverage: false, SafeToPatch: false}
	for _, path := range []string{nametables.EXE, nametables.Geko} {
		raw, err := (isoSource{iso}).ReadFile(path)
		if err != nil {
			return err
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(raw))
		if digest != expected[path] {
			return fmt.Errorf("%s does not match verified original N10 revision", path)
		}
		audit, err := nametables.AuditXrefs(path, raw)
		if err != nil {
			return err
		}
		result.Sources = append(result.Sources, audit)
		fmt.Fprintf(commandOutput, "%s: %d static candidates; %d/%d reviewed sites matched; patch approval: NO\n", path, len(audit.References), audit.ReviewedSitesMatched, audit.ReviewedSitesRequired)
		for _, group := range audit.CallGroups {
			fmt.Fprintf(commandOutput, "  buffer %s -> %s : %d candidate sites\n", group.Buffer, group.Target, group.Count)
		}
		fmt.Fprintln(commandOutput, "  Direct JAL grouping accounts for MIPS delay slots; this is static evidence only.")
	}
	if *report == "" {
		fmt.Fprintln(commandOutput, "Use --report .local/go_toolchain/reports/n10_xrefs.json to retain all candidates.")
		return nil
	}
	private := filepath.Join(root, ".local", "go_toolchain")
	if e = os.MkdirAll(private, 0700); e != nil {
		return e
	}
	base, e := filepath.EvalSymlinks(private)
	if e != nil {
		return e
	}
	p, e := filepath.Abs(*report)
	if e != nil {
		return e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(p))
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(base, parent)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("report must be in existing private .local/go_toolchain directory")
	}
	data, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return e
	}
	out, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = out.Write(append(data, '\n')); e != nil {
		out.Close()
		os.Remove(p)
		return e
	}
	if e = out.Close(); e != nil {
		os.Remove(p)
		return e
	}
	fmt.Fprintf(commandOutput, "Saved private static census to %s\n", p)
	return nil
}
