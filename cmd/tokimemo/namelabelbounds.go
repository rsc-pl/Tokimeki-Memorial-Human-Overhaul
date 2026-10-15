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

// These addresses were recorded in the owner's actual R07 EXE_label_copy /
// EXE_label_append register traces. They describe observed sources ONLY; some
// may be transient RAM buffers and cannot be assumed immutable at runtime.
var r07LabelSources = []struct {
	address uint32
	role    string
}{
	{0x800B0000, "EXE_label_append_a1 (strcat source at entry)"},
	{0x800B0020, "EXE_label_copy_a1 (strcpy source at entry)"},
	{0x800AFB83, "EXE_label_builder_after_a1 (after call; not a proven append source)"},
	{0x800AFB8D, "EXE_label_builder_after_a1 (after call; not a proven append source)"},
}

type nameSourceFinding struct {
	Address                 string                    `json:"source_address"`
	Role                    string                    `json:"observed_role"`
	ReadableFromOriginalEXE bool                      `json:"readable_from_original_exe"`
	FileOffset              int                       `json:"original_exe_offset,omitempty"`
	BytesBeforeNUL          int                       `json:"original_exe_bytes_before_nul,omitempty"`
	LabelForLongestName     *nametables.LabelCapacity `json:"label_for_12_byte_surname,omitempty"`
	UnknownReason           string                    `json:"unknown_reason,omitempty"`
}

type nameLabelReport struct {
	Status                     string                          `json:"status"`
	OriginalEXESHA256          string                          `json:"original_exe_sha256"`
	Sources                    []nameSourceFinding             `json:"observed_r07_sources"`
	FixedLiteralSites          []nametables.FixedLiteral       `json:"six_original_fixed_literal_sites"`
	AliasCandidates            []nametables.LiteralAliasCensus `json:"six_fixed_literal_pointer_candidates"`
	ConfirmedRuntimeUpperBound bool                            `json:"confirmed_runtime_upper_bound"`
	SafeToPatch                bool                            `json:"safe_to_patch"`
	Notes                      []string                        `json:"notes"`
}

func reportNameLabelBounds(exe, geko []byte) (nameLabelReport, error) {
	const originalDigest = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	sum := fmt.Sprintf("%x", sha256.Sum256(exe))
	if sum != originalDigest {
		return nameLabelReport{}, fmt.Errorf("N10 label sources require the R04-verified original EXE")
	}
	sites, err := nametables.AuditFixedLiterals(exe, geko)
	if err != nil {
		return nameLabelReport{}, err
	}
	aliases, err := nametables.AuditLiteralAliases(exe, geko)
	if err != nil {
		return nameLabelReport{}, err
	}
	result := nameLabelReport{AliasCandidates: aliases, FixedLiteralSites: sites, Status: "STATIC_ORIGINAL_EXE_SOURCES_ONLY_NOT_RUNTIME_APPROVED", OriginalEXESHA256: sum, ConfirmedRuntimeUpperBound: false, SafeToPatch: false, Notes: []string{
		"R07 source addresses were observed at specific PC values; some sources may change in RAM during gameplay",
		"A 32-byte B region holds up to 12 name bytes plus a NUL and at most 19 suffix bytes for the longest N10 surname",
		"A static original-EXE string length never proves a dynamic strcat upper bound across all scenes",
		"The six literal sites may share existing compact surname storage only if all consumers and honorific-specific behavior are verified",
		"Exact 32-bit pointer words may be executable code or incidental data; zero hits does not exclude computed references",
		"No game image or translation JSON is modified",
	}}
	for _, source := range r07LabelSources {
		addr := source.address
		row := nameSourceFinding{Address: fmt.Sprintf("0x%08X", addr), Role: source.role}
		found, err := nametables.ResidentCStringLength(exe, addr, 128)
		if err != nil {
			row.UnknownReason = err.Error()
		} else {
			row.ReadableFromOriginalEXE = true
			row.FileOffset = found.FileOffset
			row.BytesBeforeNUL = found.BytesBeforeNUL
			footprint, e := nametables.CheckN10LongestLabelSuffix(found.BytesBeforeNUL)
			if e != nil {
				return nameLabelReport{}, e
			}
			if addr == 0x800B0000 {
				row.LabelForLongestName = &footprint
			}
		}
		result.Sources = append(result.Sources, row)
	}
	return result, nil
}

func cmdNameLabelBounds(root string, args []string) error {
	fs := flag.NewFlagSet("name-label-bounds", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original two-track CUE")
	report := fs.String("report", "", "optional private JSON output file")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-label-bounds [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_label_bounds.json]")
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
	raw, e := (isoSource{iso}).ReadFile(nametables.EXE)
	if e != nil {
		return e
	}
	const originalGEKO = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
	geko, e := (isoSource{iso}).ReadFile(nametables.Geko)
	if e != nil {
		return e
	}
	if fmt.Sprintf("%x", sha256.Sum256(geko)) != originalGEKO {
		return errors.New("N10 GEKO revision not verified by R04")
	}
	result, e := reportNameLabelBounds(raw, geko)
	if e != nil {
		return e
	}
	for _, r := range result.Sources {
		if !r.ReadableFromOriginalEXE {
			fmt.Fprintf(commandOutput, "%s: UNKNOWN (%s)\n", r.Address, r.UnknownReason)
		} else {
			if r.LabelForLongestName != nil {
				fmt.Fprintf(commandOutput, "%s (%s): original EXE offset %#x, static source=%d bytes, longest N10 B=%d/32; static snapshot fits=%v\n", r.Address, r.Role, r.FileOffset, r.BytesBeforeNUL, r.LabelForLongestName.RequiredWithNUL, r.LabelForLongestName.Fits)
			} else {
				fmt.Fprintf(commandOutput, "%s (%s): original EXE offset %#x, static source=%d bytes (not verified as append source)\n", r.Address, r.Role, r.FileOffset, r.BytesBeforeNUL)
			}
		}
	}
	for _, site := range result.FixedLiteralSites {
		fmt.Fprintf(commandOutput, "Fixed %s @%#x (%#x): original %d/%d bytes, direct candidate refs=%d; indirect UNKNOWN\n", site.File, site.OriginalOffset, site.RAMAddress, site.OriginalBytesBeforeNUL+1, site.SlotBytes, site.DirectAddressCandidates)
	}
	for _, a := range result.AliasCandidates {
		fmt.Fprintf(commandOutput, "Alias candidate %s @%#x: compact index %d, potential pointer words EXE=%d GEKO=%d, honorific-sensitive=%v; HOLD\n", a.File, a.OriginalOffset, a.SharedSurnameIndex, a.EXEWordCandidates, a.GEKOWordCandidates, a.HonorificSensitive)
	}
	fmt.Fprintln(commandOutput, "NOT RUNTIME APPROVED: observed pointers and original EXE do not prove dynamic source lifetimes or other strcat paths.")
	if *report == "" {
		return nil
	}
	private := filepath.Join(root, ".local", "go_toolchain")
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
		return errors.New("report must reside inside existing private .local/go_toolchain directory")
	}
	data, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return e
	}
	fd, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = fd.Write(append(data, '\n')); e != nil {
		fd.Close()
		os.Remove(p)
		return e
	}
	if e = fd.Close(); e != nil {
		os.Remove(p)
		return e
	}
	return nil
}
