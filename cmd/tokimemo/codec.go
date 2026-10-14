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

	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/script"
)

type codecRow struct {
	Kind     string `json:"kind"`
	Original string `json:"original"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
	Source   string `json:"-"`
	MaxCells int    `json:"-"`
}

func codecRows(root string) ([]codecRow, error) {
	paths, e := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if e != nil {
		return nil, e
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, errors.New("translation/*.json not found")
	}
	var rows []codecRow
	for _, path := range paths {
		content, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		var doc struct {
			Strings []struct {
				Original string `json:"original"`
				Text     string `json:"text"`
				Encoding string `json:"encoding"`
			} `json:"strings"`
			Dialogue []struct {
				MaxCells int `json:"max_cells"`
				Lines    []struct {
					Original string `json:"original"`
					Text     string `json:"text"`
				} `json:"lines"`
			} `json:"dialogue"`
		}
		if e := json.Unmarshal(content, &doc); e != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), e)
		}
		for i, item := range doc.Strings {
			enc := item.Encoding
			if enc == "" {
				enc = "pairs"
			}
			rows = append(rows, codecRow{Kind: "string", Original: item.Original, Text: item.Text, Encoding: enc, Source: fmt.Sprintf("%s:strings[%d]", filepath.Base(path), i)})
		}
		for i, block := range doc.Dialogue {
			maximum := block.MaxCells
			if maximum == 0 {
				maximum = script.MaxCells
			}
			for j, line := range block.Lines {
				// The production patcher skips empty English lines.
				if line.Text == "" {
					continue
				}
				rows = append(rows, codecRow{Kind: "dialogue", Original: line.Original, Text: line.Text, Source: fmt.Sprintf("%s:dialogue[%d].lines[%d]", filepath.Base(path), i, j), MaxCells: maximum})
			}
		}
	}
	return rows, nil
}

// A byte digest prevents the regression interface from reproducing a corpus of
// user translation strings as another package artifact.
func digest(data []byte) string { v := sha256.Sum256(data); return fmt.Sprintf("%x", v[:]) }

type codecResult struct {
	Original          string
	Target            string
	Widths            []int
	OriginalStructure string
	TargetStructure   string
}

func (r codecResult) asList() []any {
	return []any{r.Original, r.Target, r.Widths, r.OriginalStructure, r.TargetStructure}
}
func runGoCodec(row codecRow) codecResult {
	ret := codecResult{}
	original, e := script.EncodeOriginal(row.Original)
	if e != nil {
		ret.Original = "ERR"
	} else {
		ret.Original = digest(original)
	}
	var encoded []byte
	if row.Kind == "dialogue" || row.Encoding == "pairs" {
		encoded, ret.Widths, e = script.EncodeEnglish(row.Text, &script.PairEncoder{})
	} else if row.Encoding == "fullwidth" {
		encoded, e = script.EncodeFullwidth(row.Text)
	} else {
		e = fmt.Errorf("unknown encoding %q", row.Encoding)
	}
	if e != nil {
		ret.Target = "ERR"
		ret.Widths = nil
	} else {
		ret.Target = digest(encoded)
	}
	if row.Kind == "dialogue" {
		ret.OriginalStructure = script.Structure(row.Original)
		ret.TargetStructure = script.Structure(row.Text)
	}
	return ret
}
func cmdCodecCheck(root string, args []string) error {
	fs := flag.NewFlagSet("codec-check", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	compare := fs.Bool("compare-python", false, "compare every result against the legacy Python codec")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo codec-check [--compare-python]")
	}
	rows, e := codecRows(root)
	if e != nil {
		return e
	}
	var errorsFound, structural, widthErrors int
	var firstIssues []string
	ours := make([][]any, len(rows))
	for i, row := range rows {
		result := runGoCodec(row)
		ours[i] = result.asList()
		if result.Original == "ERR" || result.Target == "ERR" {
			errorsFound++
			if len(firstIssues) < 5 {
				firstIssues = append(firstIssues, row.Source+": encoding rejected")
			}
		}
		if row.Kind == "dialogue" {
			if result.OriginalStructure != result.TargetStructure {
				structural++
				if len(firstIssues) < 5 {
					firstIssues = append(firstIssues, row.Source+": dialogue structure differs")
				}
			}
			for _, w := range result.Widths {
				if w > row.MaxCells {
					widthErrors++
					if len(firstIssues) < 5 {
						firstIssues = append(firstIssues, row.Source+": too wide")
					}
				}
			}
		}
	}
	say("Codec audit", fmt.Sprintf("%d records (Go, read-only)", len(rows)))
	say("Encode errors", fmt.Sprintf("%d", errorsFound))
	say("Structure", fmt.Sprintf("%d mismatches", structural))
	say("Line widths", fmt.Sprintf("%d over the declared limit", widthErrors))
	for _, v := range firstIssues {
		fmt.Fprintln(commandOutput, "  "+v)
	}
	if *compare {
		payload, e := json.Marshal(rows)
		if e != nil {
			return e
		}
		python := os.Getenv("TOKIMEMO_PYTHON")
		if python == "" {
			python = "python3"
		}
		cmd := exec.Command(python, filepath.Join(root, "legacy_scripts", "tools", "codec_reference.py"))
		cmd.Dir = root
		cmd.Env = pythonEnv(root)
		cmd.Stdin = bytes.NewReader(payload)
		raw, e := cmd.CombinedOutput()
		if e != nil {
			return fmt.Errorf("Python codec oracle failed: %w: %s", e, strings.TrimSpace(string(raw)))
		}
		var theirs [][]any
		if e := json.Unmarshal(raw, &theirs); e != nil {
			return fmt.Errorf("invalid Python codec reference: %w", e)
		}
		if len(theirs) != len(ours) {
			return fmt.Errorf("Python codec reference returned %d records; expected %d", len(theirs), len(ours))
		}
		var mismatches int
		for i := range ours {
			// Normalize numeric widths: JSON decoder produces float64 for Python results.
			a, _ := json.Marshal(ours[i])
			b, _ := json.Marshal(theirs[i])
			if !reflect.DeepEqual(a, b) {
				mismatches++
				if mismatches <= 8 {
					fmt.Fprintf(commandOutput, "  PARITY DIFFERENCE %s (Go %s; Python %s)\n", rows[i].Source, a, b)
				}
			}
		}
		say("Python parity", fmt.Sprintf("%d/%d identical", len(rows)-mismatches, len(rows)))
		if mismatches > 0 {
			return fmt.Errorf("%d native Go/Python codec mismatches", mismatches)
		}
	}
	if errorsFound > 0 || structural > 0 || widthErrors > 0 {
		return fmt.Errorf("codec audit found %d encoding, %d structure, %d width issues", errorsFound, structural, widthErrors)
	}
	return nil
}
