package main

// G10: strict layout audit for operations that WRITE a complete PS1 disc.
// The ordinary CUE inspector remains permissive; the native writer only
// supports the two-independent-BINARY-file layout it can reproduce exactly.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	strictFile  = regexp.MustCompile(`(?i)^FILE\s+(?:"([^"]+)"|(\S+))\s+(\S+)$`)
	strictTrack = regexp.MustCompile(`(?i)^TRACK\s+(\d{2})\s+(\S+)$`)
	strictIndex = regexp.MustCompile(`(?i)^INDEX\s+(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$`)
)

type cueAudit struct {
	Tracks, InputFiles int
	DataSectors        int64
	AudioSectors       int64
	AudioPregapSectors int64
}

// rejectLinksBetween also rejects symlinks for the source CUE or any FILE
// component, rather than following them silently when copying the game.
func rejectLinksBetween(base, path string) error {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absBase, abs)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("CUE reference escapes source directory: %s", filepath.Base(path))
	}
	for p := abs; p != absBase; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("CUE reference crosses symlink: %s", filepath.Base(p))
		}
	}
	return nil
}

func auditCueForNative(path string) (cueAudit, error) {
	var result cueAudit
	path, err := filepath.Abs(path)
	if err != nil {
		return result, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	if !st.Mode().IsRegular() {
		return result, errors.New("CUE must be a regular, non-symlink file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	if len(data) > 1024*1024 || strings.ContainsRune(string(data), '\x00') {
		return result, errors.New("invalid CUE file")
	}
	dir := filepath.Dir(path)
	var currentFile string
	fileUsed := false
	haveTrack := false
	indexSeen := false
	indexZeroSeen := false
	seen := map[string]bool{}
	for lineNo, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		keyword := strings.ToUpper(fields[0])
		switch keyword {
		case "REM", "TITLE", "PERFORMER", "SONGWRITER", "CATALOG", "ISRC":
			// Metadata does not change sector addressing; preserved byte-for-byte.
		case "FILE":
			m := strictFile.FindStringSubmatch(line)
			if m == nil || !strings.EqualFold(m[3], "BINARY") {
				return result, fmt.Errorf("CUE line %d: only FILE ... BINARY is supported", lineNo+1)
			}
			if currentFile != "" && !fileUsed {
				return result, fmt.Errorf("CUE line %d: FILE without a track", lineNo+1)
			}
			if haveTrack && !indexSeen {
				return result, fmt.Errorf("CUE line %d: missing INDEX 01", lineNo+1)
			}
			name := m[1]
			if name == "" {
				name = m[2]
			}
			if name == "" || strings.Contains(name, "\\") || filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
				return result, fmt.Errorf("CUE line %d: unsafe FILE name", lineNo+1)
			}
			resolved := filepath.Clean(filepath.Join(dir, name))
			if err := rejectLinksBetween(dir, resolved); err != nil {
				return result, err
			}
			if seen[resolved] {
				return result, errors.New("multiple CUE FILE directives reference the same track")
			}
			seen[resolved] = true
			stat, err := os.Lstat(resolved)
			if err != nil {
				return result, err
			}
			if !stat.Mode().IsRegular() || stat.Size() == 0 || stat.Size()%2352 != 0 {
				return result, fmt.Errorf("invalid raw 2352-byte track: %s", filepath.Base(resolved))
			}
			result.InputFiles++
			if result.InputFiles == 1 {
				result.DataSectors = stat.Size() / 2352
			} else {
				result.AudioSectors = stat.Size() / 2352
			}
			currentFile, fileUsed, haveTrack, indexSeen, indexZeroSeen = resolved, false, false, false, false
		case "TRACK":
			m := strictTrack.FindStringSubmatch(line)
			if m == nil {
				return result, fmt.Errorf("CUE line %d: malformed TRACK", lineNo+1)
			}
			if currentFile == "" || fileUsed {
				return result, errors.New("native builder requires one separate FILE per track")
			}
			if haveTrack && !indexSeen {
				return result, errors.New("missing INDEX 01")
			}
			track, _ := strconv.Atoi(m[1])
			result.Tracks++
			if track != result.Tracks || result.Tracks > 2 {
				return result, errors.New("unsupported track number/order")
			}
			expected := "MODE2/2352"
			if track == 2 {
				expected = "AUDIO"
			}
			if !strings.EqualFold(m[2], expected) {
				return result, fmt.Errorf("track %d must be %s", track, expected)
			}
			fileUsed, haveTrack, indexSeen, indexZeroSeen = true, true, false, false
		case "FLAGS":
			// DCP is a copy-permitted subchannel flag in the owner's original CUE.
			// Preserve the line exactly in the copied CUE; do not infer sectors from it.
			if !haveTrack || len(fields) != 2 || !strings.EqualFold(fields[1], "DCP") || indexSeen {
				return result, fmt.Errorf("CUE line %d: unsupported track flag", lineNo+1)
			}
		case "INDEX":
			m := strictIndex.FindStringSubmatch(line)
			if m == nil || !haveTrack || indexSeen {
				return result, fmt.Errorf("CUE line %d: malformed or duplicate INDEX", lineNo+1)
			}
			// Each BINARY FILE starts at file offset zero. The original audio
			// FILE contains its own 150-frame INDEX 00 region; it is NOT a
			// separate generated pregap, and must be copied byte-for-byte.
			if m[1] == "00" && result.Tracks == 2 && !indexZeroSeen && m[2] == "00" && m[3] == "00" && m[4] == "00" {
				indexZeroSeen = true
				continue
			}
			if m[1] != "01" {
				return result, fmt.Errorf("CUE line %d: unsupported INDEX", lineNo+1)
			}
			zero := m[2] == "00" && m[3] == "00" && m[4] == "00"
			audio150 := result.Tracks == 2 && indexZeroSeen && m[2] == "00" && m[3] == "02" && m[4] == "00"
			if (!indexZeroSeen && !zero) || (indexZeroSeen && !audio150) {
				return result, fmt.Errorf("CUE line %d: unsupported INDEX 01 position", lineNo+1)
			}
			if audio150 {
				if result.AudioSectors <= 150 {
					return result, errors.New("audio FILE too small for INDEX 00 / INDEX 01 layout")
				}
				result.AudioPregapSectors = 150
			}
			indexSeen = true
		default:
			// PREGAP, POSTGAP, INDEX 00, and other layout directives must never be
			// ignored: they may shift the entire LBA map even when file hashes match.
			return result, fmt.Errorf("CUE line %d: unsupported layout directive %q", lineNo+1, keyword)
		}
	}
	if result.Tracks != 2 || result.InputFiles != 2 || !indexSeen {
		return result, errors.New("native writer requires exactly two independent tracks with INDEX 01")
	}
	return result, nil
}

func cmdCueAudit(root string, args []string) error {
	fs := flag.NewFlagSet("cue-audit", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "CUE to inspect, otherwise discover original game")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo cue-audit [--game CUE]")
	}
	cue, err := cueChoice(root, *game)
	if err != nil {
		return err
	}
	result, err := auditCueForNative(cue)
	if err != nil {
		return err
	}
	info, err := parseCue(cue)
	if err != nil {
		return err
	}
	if info.Tracks != result.Tracks || len(info.Inputs) != result.InputFiles || info.Sectors != result.DataSectors {
		return errors.New("CUE parser disagreement")
	}
	fmt.Fprintf(commandOutput, "CUE layout: PASS; tracks: %d; data sectors: %d; audio sectors: %d; audio INDEX 00 frames: %d; source: read-only\n", result.Tracks, result.DataSectors, result.AudioSectors, result.AudioPregapSectors)
	return nil
}
