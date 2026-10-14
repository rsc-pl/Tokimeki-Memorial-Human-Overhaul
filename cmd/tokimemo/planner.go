package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/script"
)

// The corpus probes deliberately use fake bytes and fake address tables. They
// test relocation *algorithms*, not positions/validity in a real game disc.
// No original disc data, translation strings, or simulated binaries are saved.
type plannerProbe struct {
	Name  string               `json:"name"`
	Data  string               `json:"data"`
	Block script.DialogueBlock `json:"block"`
}
type plannerProbeResult struct {
	OK         bool     `json:"ok"`
	SHA256     string   `json:"sha256,omitempty"`
	Placements [][2]int `json:"placements,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func gatherPlannerProbes(root string, perBlock int) ([]plannerProbe, error) {
	paths, e := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if e != nil {
		return nil, e
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, errors.New("translation corpus missing")
	}
	probes := []plannerProbe{}
	for _, path := range paths {
		raw, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		var doc struct {
			Dialogue []struct {
				Base           string `json:"base"`
				File           string `json:"file"`
				MaxCells       int    `json:"max_cells"`
				ShareIdentical bool   `json:"share_identical"`
				Lines          []struct {
					Offset   string `json:"offset"`
					Original string `json:"original"`
					Text     string `json:"text"`
				} `json:"lines"`
			} `json:"dialogue"`
		}
		if e = json.Unmarshal(raw, &doc); e != nil {
			return nil, fmt.Errorf("%s: %w", path, e)
		}
		for blockNum, block := range doc.Dialogue {
			active := []script.DialogueLine{}
			for _, line := range block.Lines {
				if line.Text != "" {
					active = append(active, script.DialogueLine{Original: line.Original, Text: line.Text})
				}
			}
			if len(active) == 0 {
				continue
			}
			// Deterministic sample from both ends of each logical dialogue block.
			if len(active) > perBlock {
				left := perBlock / 2
				active = append(append([]script.DialogueLine{}, active[:left]...), active[len(active)-(perBlock-left):]...)
			}
			source := make([]byte, 0x1000)
			const base uint32 = 0x80100000
			for i := range active {
				original, e := script.EncodeOriginal(active[i].Original)
				if e != nil {
					return nil, fmt.Errorf("%s dialogue %d: %w", filepath.Base(path), blockNum, e)
				}
				// Real planner may encounter adjacent slots; synthetic allocator places
				// the original strings contiguously, including zero compiler padding.
				off := len(source)
				cap := len(original) + 1
				for (off+cap)%4 != 0 {
					cap++
				}
				source = append(source, original...)
				source = append(source, make([]byte, cap-len(original))...)
				active[i].Offset = off
				binary.LittleEndian.PutUint32(source[0x100+4*i:], base+uint32(off))
			}
			source = append(source, []byte("G04_END")...)
			maxCells := block.MaxCells
			if maxCells == 0 {
				maxCells = script.MaxCells
			}
			probes = append(probes, plannerProbe{Name: fmt.Sprintf("%s:dialogue[%d]", filepath.Base(path), blockNum), Data: base64.StdEncoding.EncodeToString(source), Block: script.DialogueBlock{File: "SYNTHETIC.BIN", Source: "G04", Base: base, MaxCells: maxCells, ShareIdentical: block.ShareIdentical, Lines: active}})
		}
	}
	return probes, nil
}

func cmdPlannerCheck(root string, args []string) error {
	fs := flag.NewFlagSet("planner-check", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	compare := fs.Bool("compare-python", false, "compare hashes and placements against Python on synthetic corpus blocks")
	sample := fs.Int("sample", 24, "maximum dialogue lines sampled from each logical block (2-96)")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || *sample < 2 || *sample > 96 {
		return errors.New("usage: tokimemo planner-check [--compare-python] [--sample 2..96]")
	}
	cases, e := gatherPlannerProbes(root, *sample)
	if e != nil {
		return e
	}
	var matched, blocked int
	ours := make([]plannerProbeResult, len(cases))
	var lines int
	for i, c := range cases {
		data, _ := base64.StdEncoding.DecodeString(c.Data)
		pristine := append([]byte(nil), data...)
		stats, e := script.ApplyDialogue(pristine, data, c.Block, &script.PairEncoder{})
		lines += len(c.Block.Lines)
		if e != nil {
			ours[i] = plannerProbeResult{OK: false, Error: e.Error()}
			blocked++
			continue
		}
		placement := make([][2]int, 0, len(stats.Placements))
		for _, p := range stats.Placements {
			placement = append(placement, [2]int{p.Offset, p.At})
		}
		ours[i] = plannerProbeResult{OK: true, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Placements: placement}
		matched++
	}
	say("Synthetic blocks", fmt.Sprintf("%d (using %d dialogue records)", len(cases), lines))
	say("Go placement", fmt.Sprintf("%d placed, %d rejected by original-slot limits", matched, blocked))
	if !*compare {
		return nil
	}
	raw, e := json.Marshal(cases)
	if e != nil {
		return e
	}
	python := os.Getenv("TOKIMEMO_PYTHON")
	if python == "" {
		python = "python3"
	}
	command := exec.Command(python, filepath.Join(root, "legacy_scripts", "tools", "planner_reference.py"))
	command.Dir = root
	command.Env = pythonEnv(root)
	command.Stdin = bytes.NewReader(raw)
	output, e := command.CombinedOutput()
	if e != nil {
		return fmt.Errorf("Python planner oracle: %w: %s", e, strings.TrimSpace(string(output)))
	}
	var pythonResults []plannerProbeResult
	if e = json.Unmarshal(output, &pythonResults); e != nil {
		return fmt.Errorf("invalid oracle response: %w", e)
	}
	if len(pythonResults) != len(ours) {
		return fmt.Errorf("oracle returned %d/%d cases", len(pythonResults), len(ours))
	}
	bad := 0
	for i := range ours {
		a, b := ours[i], pythonResults[i]
		same := a.OK == b.OK
		if a.OK && b.OK {
			same = same && a.SHA256 == b.SHA256 && len(a.Placements) == len(b.Placements)
			if same {
				for j := range a.Placements {
					if a.Placements[j] != b.Placements[j] {
						same = false
						break
					}
				}
			}
		}
		if !same {
			bad++
			if bad <= 6 {
				fmt.Fprintf(commandOutput, "  DIFF %s Go={ok:%v sha:%s} Python={ok:%v sha:%s}\n", cases[i].Name, a.OK, a.SHA256, b.OK, b.SHA256)
			}
		}
	}
	say("Python parity", fmt.Sprintf("%d/%d identical outcomes, bytes and placements", len(cases)-bad, len(cases)))
	if bad > 0 {
		return fmt.Errorf("%d planner parity discrepancies", bad)
	}
	return nil
}
