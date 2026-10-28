package fullenglish

// Authenticated, read-only raw-disc N20 QA sector planner.
// This file creates ONLY in-memory sector deltas. There is intentionally no
// image-building command, no I/O writer, and no DuckStation execution path.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	n "tokimemo/internal/n20arch"
	"tokimemo/internal/ps1"
)

type cueInfo struct {
	CuePath string `json:"cue_path"`
	Track1  string `json:"track1"`
	Track2  string `json:"track2"`
}

var cueFile = regexp.MustCompile(`(?i)^\s*FILE\s+(?:"([^"]+)"|([^\s]+))\s+BINARY\s*$`)
var cueTrack = regexp.MustCompile(`(?i)^\s*TRACK\s+([0-9]{2})\s+(\S+)\s*$`)

func parseRetailCue(path string) (cueInfo, error) {
	var c cueInfo
	content, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	var current, data, audio string
	count, files := 0, 0
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r", ""), "\n") {
		if m := cueFile.FindStringSubmatch(line); m != nil {
			current = m[1]
			if current == "" {
				current = m[2]
			}
			if filepath.IsAbs(current) || filepath.Base(current) != current || current == "." || current == ".." || strings.ContainsAny(current, `/\\`) {
				return c, fmt.Errorf("unsafe CUE FILE reference %q", current)
			}
			files++
		} else if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FILE ") {
			return c, errors.New("unsupported CUE FILE line")
		}
		if m := cueTrack.FindStringSubmatch(line); m != nil {
			count++
			if m[1] == "01" && strings.EqualFold(m[2], "MODE2/2352") {
				data = current
			} else if m[1] == "02" && strings.EqualFold(m[2], "AUDIO") {
				audio = current
			} else {
				return c, errors.New("unexpected CUE TRACK layout")
			}
		}
	}
	if count != 2 || files != 2 || data == "" || audio == "" || strings.EqualFold(data, audio) {
		return c, errors.New("requires exactly two FILE and two TRACK entries, MODE2/2352 + separate AUDIO")
	}
	dir := filepath.Dir(path)
	c = cueInfo{CuePath: path, Track1: filepath.Join(dir, data), Track2: filepath.Join(dir, audio)}
	for _, name := range []string{c.Track1, c.Track2} {
		st, e := os.Stat(name)
		if e != nil {
			return cueInfo{}, fmt.Errorf("CUE file %q: %w", name, e)
		}
		if !st.Mode().IsRegular() {
			return cueInfo{}, fmt.Errorf("CUE target not regular file: %s", name)
		}
	}
	return c, nil
}

type sectorDelta struct {
	LBA    int64
	Before []byte
	After  []byte
	Files  []string
}
type sectorNote struct {
	LBA         int64    `json:"lba"`
	Files       []string `json:"files"`
	OriginalSHA string   `json:"original_sha256"`
	PlannedSHA  string   `json:"planned_sha256"`
	Mode2Form1  bool     `json:"mode2_form1_validated"`
}
type discReport struct {
	Schema                int          `json:"schema"`
	Verdict               string       `json:"verdict"`
	SafeToPatch           bool         `json:"safe_to_patch"`
	RuntimePass           bool         `json:"runtime_pass"`
	ImageBuilt            bool         `json:"image_built"`
	SourceCue             string       `json:"source_cue"`
	Track1                string       `json:"source_track1"`
	Track2                string       `json:"unchanged_external_audio_track2"`
	Sectors               int64        `json:"source_track1_sectors"`
	FilesAuthenticated    int          `json:"authenticated_disc_files"`
	EXESizeUnchanged      bool         `json:"exe_size_unchanged"`
	OverlaySizesUnchanged bool         `json:"overlay_sizes_unchanged"`
	MetadataChanges       int          `json:"metadata_changes"`
	AudioChanges          int          `json:"audio_changes"`
	PlannedChangedSectors int          `json:"planned_changed_sectors"`
	SectorNotes           []sectorNote `json:"sector_notes"`
	Warning               string       `json:"warning"`
}

// buildDiscDeltas does no writes. All extents must match their exact verified
// source images from the integrated planner. File sizes are unchanged, hence
// no ISO directory, LBA, CUE or audio-track metadata requires modification.
func buildDiscDeltas(track io.ReaderAt, sectors int64, iso *ps1.ISO, exe []byte, overlays map[string][]byte, plan n.N20IntegratedPlan) ([]sectorDelta, error) {
	if _, err := verify(plan, exe, overlays); err != nil {
		return nil, fmt.Errorf("integrated manifest/readback failed: %w", err)
	}
	if iso == nil || track == nil || sectors <= 16 {
		return nil, errors.New("no authenticated ISO reader")
	}
	type target struct {
		path         string
		old, updated []byte
	}
	targets := []target{{"SLPM_86.053", exe, plan.PatchedEXE}}
	names := make([]string, 0, len(overlays))
	for name := range overlays {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		targets = append(targets, target{"CDROM/EXEDIR/" + name, overlays[name], plan.PatchedOverlays[name]})
	}
	if len(targets) != 27 {
		return nil, fmt.Errorf("expected 27 authenticated file extents, got %d", len(targets))
	}
	// Fail closed if any authenticated file shares raw sectors with an
	// unrelated entry (including directories). This is a no-relocation plan.
	for _, target := range targets {
		entry, exists := iso.Entries[target.path]
		if !exists {
			return nil, fmt.Errorf("missing ISO entry %s", target.path)
		}
		count := (int64(len(target.old)) + ps1.DataSize - 1) / ps1.DataSize
		for _, other := range iso.Entries {
			if other.Path == target.path || ps1.IsExternalTrackAudio(other) {
				continue
			}
			otherCount := (other.Size + ps1.DataSize - 1) / ps1.DataSize
			if count > 0 && otherCount > 0 && entry.LBA < other.LBA+otherCount && other.LBA < entry.LBA+count {
				return nil, fmt.Errorf("unsafe shared ISO extent: %s and %s", target.path, other.Path)
			}
		}
	}
	taken := map[int64]string{}
	delta := map[int64]*sectorDelta{}
	for _, t := range targets {
		entry, ok := iso.Entries[t.path]
		if !ok || entry.IsDir || entry.Size != int64(len(t.old)) || entry.Size != int64(len(t.updated)) {
			return nil, fmt.Errorf("missing/incorrect disc extent %s (expected %d B)", t.path, len(t.old))
		}
		var extracted bytes.Buffer
		if e := ps1.ReadFileTo(track, sectors, entry.LBA, entry.Size, &extracted); e != nil {
			return nil, fmt.Errorf("read %s from ISO: %w", t.path, e)
		}
		if !bytes.Equal(extracted.Bytes(), t.old) {
			return nil, fmt.Errorf("disc %s differs from authenticated original", t.path)
		}
		count := (entry.Size + ps1.DataSize - 1) / ps1.DataSize
		for j := int64(0); j < count; j++ {
			lba := entry.LBA + j
			if previous, exists := taken[lba]; exists {
				return nil, fmt.Errorf("overlapping disc extents: %s and %s at LBA %d", previous, t.path, lba)
			}
			taken[lba] = t.path
			start := int(j * ps1.DataSize)
			end := start + ps1.DataSize
			if end > len(t.old) {
				end = len(t.old)
			}
			if bytes.Equal(t.old[start:end], t.updated[start:end]) {
				continue
			}
			original, e := ps1.ReadSectorAt(track, lba)
			if e != nil {
				return nil, e
			}
			if e = ps1.VerifyForm1(original); e != nil {
				return nil, fmt.Errorf("LBA %d %s: %w", lba, t.path, e)
			}
			body, e := ps1.Data(original)
			if e != nil {
				return nil, e
			}
			if !bytes.Equal(body[:end-start], t.old[start:end]) {
				return nil, fmt.Errorf("sector %d source user-data mismatch", lba)
			}
			updated := bytes.Clone(original)
			copy(updated[ps1.DataOffset:ps1.DataOffset+end-start], t.updated[start:end])
			if e = ps1.RegenerateForm1(updated); e != nil {
				return nil, e
			}
			if e = ps1.VerifyForm1(updated); e != nil {
				return nil, e
			}
			delta[lba] = &sectorDelta{LBA: lba, Before: original, After: updated, Files: []string{t.path}}
		}
	}
	out := make([]sectorDelta, 0, len(delta))
	for _, d := range delta {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LBA < out[j].LBA })
	return out, nil
}

func discPlan(cuePath string, exe []byte, original map[string][]byte, plan n.N20IntegratedPlan) (discReport, error) {
	var r discReport
	c, e := parseRetailCue(cuePath)
	if e != nil {
		return r, e
	}
	f, e := os.Open(c.Track1)
	if e != nil {
		return r, e
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil {
		return r, e
	}
	if stat.Size() <= 2352*400 || stat.Size()%ps1.SectorSize != 0 {
		return r, errors.New("Track1 geometry invalid")
	}
	sectors := stat.Size() / ps1.SectorSize
	iso, e := ps1.OpenISO(f, sectors)
	if e != nil {
		return r, e
	}
	changes, e := buildDiscDeltas(f, sectors, iso, exe, original, plan)
	if e != nil {
		return r, e
	}
	r = discReport{Schema: 1, Verdict: "DISC_PLAN_OFFLINE_ONLY", SafeToPatch: false, RuntimePass: false, ImageBuilt: false,
		SourceCue: c.CuePath, Track1: c.Track1, Track2: c.Track2, Sectors: sectors, FilesAuthenticated: 27,
		EXESizeUnchanged: true, OverlaySizesUnchanged: true, MetadataChanges: 0, AudioChanges: 0,
		PlannedChangedSectors: len(changes), Warning: "READ-ONLY plan. No modified disc built; no runtime QA authorized. Sector SHA values describe IN-MEMORY hypothetical output only."}
	for _, d := range changes {
		r.SectorNotes = append(r.SectorNotes, sectorNote{LBA: d.LBA, Files: d.Files, OriginalSHA: hash(d.Before), PlannedSHA: hash(d.After), Mode2Form1: true})
	}
	return r, nil
}
