package main

// Independent, read-only comparison of previously assembled CUE/BIN outputs.
// The report intentionally contains no game data or absolute private paths.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tokimemo/internal/config"
	"tokimemo/internal/ps1"
)

type parityFile struct {
	Role            string `json:"role"`
	Name            string `json:"name"`
	NativeSize      int64  `json:"native_size"`
	ReferenceSize   int64  `json:"reference_size"`
	NativeSHA256    string `json:"native_sha256,omitempty"`
	ReferenceSHA256 string `json:"reference_sha256,omitempty"`
	Match           bool   `json:"match"`
}
type parityReport struct {
	Schema              int          `json:"schema"`
	Status              string       `json:"status"`
	Files               []parityFile `json:"files"`
	OriginalChecked     bool         `json:"original_checked"`
	AudioUnchanged      bool         `json:"audio_unchanged,omitempty"`
	ChangedDataSectors  int64        `json:"changed_data_sectors,omitempty"`
	ChangedSectorChecks string       `json:"changed_sector_checks,omitempty"`
	Errors              []string     `json:"errors,omitempty"`
}

func (r *parityReport) reject(s string) { r.Errors = append(r.Errors, s); r.Status = "MISMATCH" }

// DiscParity hashes only CUE and referenced tracks. With original set it also
// verifies all changed Mode2/Form1 data sectors and unchanged audio tracks.
// No source image is opened for writing.
func DiscParity(native, reference, original string) (parityReport, error) {
	report := parityReport{Schema: 1, Status: "MATCH", Files: []parityFile{}}
	na, err := parseCue(native)
	if err != nil {
		return report, fmt.Errorf("native CUE: %w", err)
	}
	re, err := parseCue(reference)
	if err != nil {
		return report, fmt.Errorf("reference CUE: %w", err)
	}
	// Identical CUE bytes do not prove that the track indices and layout
	// correspond to the writer's LBA assumptions. Reject both-identically-bad
	// discs instead of incorrectly reporting MATCH.
	if _, e := auditCueForNative(native); e != nil {
		report.reject("unsafe native CUE layout: " + e.Error())
	}
	if _, e := auditCueForNative(reference); e != nil {
		report.reject("unsafe reference CUE layout: " + e.Error())
	}

	if len(na.Inputs) != len(re.Inputs) || na.Tracks != re.Tracks {
		report.reject("CUE track count differs")
	}
	nativeFiles := append([]string{native}, na.Inputs...)
	refFiles := append([]string{reference}, re.Inputs...)
	max := len(nativeFiles)
	if len(refFiles) > max {
		max = len(refFiles)
	}
	for i := 0; i < max; i++ {
		row := parityFile{Role: fmt.Sprintf("track-%d", i)}
		if i == 0 {
			row.Role = "cue"
		}
		if i >= len(nativeFiles) || i >= len(refFiles) {
			report.reject(fmt.Sprintf("missing file at index %d", i))
			report.Files = append(report.Files, row)
			continue
		}
		a, b := nativeFiles[i], refFiles[i]
		row.Name = filepath.Base(a)
		sa, e := os.Stat(a)
		if e != nil {
			return report, e
		}
		sb, e := os.Stat(b)
		if e != nil {
			return report, e
		}
		if !sa.Mode().IsRegular() || !sb.Mode().IsRegular() {
			return report, errors.New("disc contains nonregular track")
		}
		row.NativeSize, row.ReferenceSize = sa.Size(), sb.Size()
		row.NativeSHA256, e = shaFile(a)
		if e != nil {
			return report, e
		}
		row.ReferenceSHA256, e = shaFile(b)
		if e != nil {
			return report, e
		}
		row.Match = row.NativeSize == row.ReferenceSize && row.NativeSHA256 == row.ReferenceSHA256 && filepath.Base(a) == filepath.Base(b)
		if !row.Match {
			report.reject(fmt.Sprintf("different bytes or names in %s", row.Role))
		}
		report.Files = append(report.Files, row)
	}
	if original != "" {
		src, e := parseCue(original)
		if e != nil {
			return report, fmt.Errorf("original CUE: %w", e)
		}
		if _, layoutErr := auditCueForNative(original); layoutErr != nil {
			report.reject("unsafe original CUE layout: " + layoutErr.Error())
		}
		report.OriginalChecked = true
		report.AudioUnchanged = true
		if len(src.Inputs) != len(na.Inputs) || src.Tracks != na.Tracks {
			report.reject("original track structure differs")
			report.AudioUnchanged = false
		}
		if len(src.Inputs) == len(na.Inputs) {
			dataMatch := false
			for i := range src.Inputs {
				if src.Inputs[i] == src.Data && na.Inputs[i] == na.Data {
					dataMatch = true
					continue
				}
				sh, e := shaFile(src.Inputs[i])
				if e != nil {
					return report, e
				}
				nh, e := shaFile(na.Inputs[i])
				if e != nil {
					return report, e
				}
				if sh != nh {
					report.AudioUnchanged = false
					report.reject(fmt.Sprintf("non-data track %d changed from original", i+1))
				}
			}
			if !dataMatch {
				report.reject("original and native data-track positions differ")
			}
		}
		changed, e := verifyChangedSectors(src.Data, na.Data)
		report.ChangedDataSectors = changed
		if e != nil {
			report.ChangedSectorChecks = "FAIL"
			report.reject("changed data sectors: " + e.Error())
		} else {
			report.ChangedSectorChecks = "PASS"
		}
	}
	if report.Status != "MATCH" {
		return report, fmt.Errorf("disc comparison failed: %s", strings.Join(report.Errors, "; "))
	}
	return report, nil
}

func verifyChangedSectors(original, patched string) (int64, error) {
	a, e := os.Open(original)
	if e != nil {
		return 0, e
	}
	defer a.Close()
	b, e := os.Open(patched)
	if e != nil {
		return 0, e
	}
	defer b.Close()
	as, e := a.Stat()
	if e != nil {
		return 0, e
	}
	bs, e := b.Stat()
	if e != nil {
		return 0, e
	}
	if !as.Mode().IsRegular() || !bs.Mode().IsRegular() || as.Size() != bs.Size() || as.Size()%ps1.SectorSize != 0 {
		return 0, errors.New("data track size/type differs")
	}
	var old, new [ps1.SectorSize]byte
	var changed int64
	for lba := int64(0); lba < as.Size()/ps1.SectorSize; lba++ {
		if _, e = io.ReadFull(a, old[:]); e != nil {
			return changed, e
		}
		if _, e = io.ReadFull(b, new[:]); e != nil {
			return changed, e
		}
		if bytes.Equal(old[:], new[:]) {
			continue
		}
		changed++
		if !ps1.IsForm1(old[:]) {
			return changed, fmt.Errorf("LBA %d changed from unsupported sector format", lba)
		}
		if e = ps1.VerifyForm1(new[:]); e != nil {
			return changed, fmt.Errorf("LBA %d: %w", lba, e)
		}
		// Patcher may only change file payload and its resulting EDC/ECC;
		// sync, header, subheader and unaffected padding must be identical.
		if !bytes.Equal(old[:ps1.DataOffset], new[:ps1.DataOffset]) || !bytes.Equal(old[0x930:], new[0x930:]) {
			return changed, fmt.Errorf("LBA %d changed non-payload sector bytes", lba)
		}
	}
	return changed, nil
}

func rejectSymlinkAncestors(path string) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("parity report path crosses symlink: %s", p)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func writeParityReport(path string, report parityReport) error {
	if path == "" {
		return nil
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	if err := rejectSymlinkAncestors(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite parity report %s (%s)", path, info.Mode())
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(parent, ".tokimemo-parity-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), path); err != nil {
		return err
	}
	return nil
}

func cmdNativeVerify(root string, argv []string) error {
	fs := flag.NewFlagSet("native-verify", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	native := fs.String("native", "", "Go-built CUE")
	reference := fs.String("reference", "", "Python-built CUE")
	original := fs.String("original", "", "optional original source CUE for changed-sector and audio checks")
	report := fs.String("report", "", "write JSON report to a new private path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 0 || *native == "" || *reference == "" {
		return errors.New("usage: tokimemo native-verify --native GO.cue --reference PYTHON.cue [--original SOURCE.cue] [--report NEW.json]")
	}
	norm := func(s string) string {
		if s == "" {
			return s
		}
		if filepath.IsAbs(s) {
			return s
		}
		return filepath.Join(root, s)
	}
	n, r, o := norm(*native), norm(*reference), norm(*original)
	rp := norm(*report)
	if rp != "" {
		// Reports cannot be written into game, public or translation directories.
		if config.Within(root, rp) && !config.Within(filepath.Join(root, ".local", "go_toolchain", "reports"), rp) && !config.Within(filepath.Join(root, ".local", "build"), rp) {
			return errors.New("in-repository parity report must be inside .local/go_toolchain/reports/ or .local/build/")
		}
		for _, source := range []string{n, r, o} {
			if source != "" && config.Within(filepath.Dir(source), rp) && !config.Within(root, rp) {
				return errors.New("report cannot be written into external source disc directory")
			}
		}
	}
	result, err := DiscParity(n, r, o)
	if rp != "" {
		if writeErr := writeParityReport(rp, result); writeErr != nil {
			return writeErr
		}
	}
	fmt.Fprintf(commandOutput, "DISC PARITY: %s | files: %d | changed sectors checked: %d (%s) | audio unchanged: %t\n", result.Status, len(result.Files), result.ChangedDataSectors, result.ChangedSectorChecks, result.AudioUnchanged)
	if rp != "" {
		fmt.Fprintf(commandOutput, "Report: %s\n", rp)
	}
	return err
}
