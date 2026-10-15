package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tokimemo/internal/config"
	"tokimemo/internal/termui"
)

type buildIdentity struct {
	Path   string
	State  string
	Exists bool
}

func buildPaths(root string) (string, string, error) {
	cue, _, e := config.Discover(root, "", func(path string) error { _, e := parseCue(path); return e })
	if e != nil {
		return "", "", e
	}
	target, e := config.Output(root)
	if e != nil {
		return "", "", e
	}
	target, e = filepath.Abs(target)
	if e != nil {
		return "", "", e
	}
	if e = config.SafeOutput(root, cue, target); e != nil {
		return "", "", e
	}
	if e = guardOutputTracks(cue, target); e != nil {
		return "", "", e
	}
	return cue, target, nil
}
func diskSHA(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// auditCompletedBuild accepts only an exact prior tool output: its CUE must
// match the input, the audio track must be unchanged, and the patched track
// must be a distinct, same-sized regular file. Any unknown file is a conflict.
func auditCompletedBuild(cue, target string) (string, error) {
	info, e := parseCue(cue)
	if e != nil {
		return "", e
	}
	st, e := os.Lstat(target)
	if e != nil {
		return "", e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("existing output is not an ordinary directory")
	}
	inputs := append([]string{cue}, info.Inputs...)
	wanted := make(map[string]string)
	for _, p := range inputs {
		name := filepath.Base(p)
		if _, ok := wanted[name]; ok {
			return "", errors.New("duplicate input filename")
		}
		wanted[name] = p
	}
	names, e := os.ReadDir(target)
	if e != nil {
		return "", e
	}
	// Marker is generated exclusively by successful TUI builds; older production
	// builds have three exact files and no marker.
	if len(names) != len(wanted) && len(names) != len(wanted)+1 {
		return "", errors.New("output contains unknown/missing files; refusing overwrite")
	}
	for _, d := range names {
		if d.Name() == ".tokimemo-build.json" {
			continue
		}
		if _, ok := wanted[d.Name()]; !ok {
			return "", fmt.Errorf("unknown output file %q", d.Name())
		}
	}
	var fingerprint strings.Builder
	fmt.Fprintf(&fingerprint, "dir:%d:%d:%d\n", st.Size(), st.ModTime().UnixNano(), len(names))
	sourceChanged := false
	for _, src := range inputs {
		name := filepath.Base(src)
		p := filepath.Join(target, name)
		dst, e := os.Lstat(p)
		if e != nil {
			return "", e
		}
		orig, e := os.Stat(src)
		if e != nil {
			return "", e
		}
		if !dst.Mode().IsRegular() || dst.Mode()&os.ModeSymlink != 0 || os.SameFile(dst, orig) {
			return "", fmt.Errorf("unsafe output track %q", name)
		}
		if dst.Size() != orig.Size() {
			return "", fmt.Errorf("output %q has unexpected length", name)
		}
		a, e := diskSHA(src)
		if e != nil {
			return "", e
		}
		b, e := diskSHA(p)
		if e != nil {
			return "", e
		}
		if src == cue || src != info.Data {
			if a != b {
				return "", fmt.Errorf("output %q is not an unchanged CUE/audio track", name)
			}
		} else {
			sourceChanged = a != b
		}
		fmt.Fprintf(&fingerprint, "file:%s:%d:%d:%s\n", name, dst.Size(), dst.ModTime().UnixNano(), b)
	}
	if !sourceChanged {
		return "", errors.New("output data track is identical to source; not a confirmed prior patch")
	}
	marker := filepath.Join(target, ".tokimemo-build.json")
	if _, e := os.Lstat(marker); e == nil {
		m, e := os.Lstat(marker)
		if e != nil || !m.Mode().IsRegular() {
			return "", errors.New("invalid build marker")
		}
		b, e := os.ReadFile(marker)
		if e != nil {
			return "", e
		}
		var meta map[string]any
		if json.Unmarshal(b, &meta) != nil || meta["tool"] != "tokimemo-go-tui" {
			return "", errors.New("unrecognized build marker")
		}
		fmt.Fprintf(&fingerprint, "marker:%s\n", string(b))
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	sum := sha256.Sum256([]byte(fingerprint.String()))
	return hex.EncodeToString(sum[:]), nil
}
func inspectTUIBuild(root string) (termui.BuildTarget, error) {
	cue, target, e := buildPaths(root)
	if e != nil {
		return termui.BuildTarget{}, e
	}
	_, e = os.Lstat(target)
	if errors.Is(e, os.ErrNotExist) {
		return termui.BuildTarget{Path: target}, nil
	}
	if e != nil {
		return termui.BuildTarget{}, e
	}
	snap, e := auditCompletedBuild(cue, target)
	if e != nil {
		return termui.BuildTarget{}, fmt.Errorf("existing output is not a verified patch (%w); select an empty build folder", e)
	}
	return termui.BuildTarget{Path: target, Exists: true, Snapshot: snap}, nil
}

func buildTUI(root string, confirmed termui.BuildTarget, writer io.Writer) error {
	cue, target, e := buildPaths(root)
	if e != nil {
		return e
	}
	if target != confirmed.Path {
		return errors.New("output path changed since confirmation")
	}
	current, e := inspectTUIBuild(root)
	if e != nil {
		return e
	}
	if current.Exists != confirmed.Exists || current.Snapshot != confirmed.Snapshot {
		return errors.New("output changed since confirmation; previous build preserved")
	}
	parent := filepath.Dir(target)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return e
	}
	// Revalidate after creating parent; never follow symlink ancestors.
	if e = config.SafeOutput(root, cue, target); e != nil {
		return e
	}
	lock := filepath.Join(parent, "."+filepath.Base(target)+".build-lock")
	lf, e := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return fmt.Errorf("another build or stale build lock (remove only after checking): %w", e)
	}
	lf.Close()
	defer os.Remove(lock)
	stage, e := os.MkdirTemp(parent, ".tokimemo-build-stage-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	fmt.Fprintf(writer, "Output: %s\nStaging: %s\n", target, stage)
	prior := commandOutput
	commandOutput = writer
	// No --force: Python writes ONLY into its own fresh empty staging folder.
	e = cmdBuild(root, []string{"--game", cue, "--output", stage}, false)
	commandOutput = prior
	if e != nil {
		return fmt.Errorf("staged patch failed; previous build preserved: %w", e)
	}
	fmt.Fprintln(writer, "Checking CUE, track sizes, original audio and patched data...")
	if _, e = auditCompletedBuild(cue, stage); e != nil {
		return fmt.Errorf("staged result invalid; previous output preserved: %w", e)
	}
	stamp, _ := json.Marshal(map[string]any{"tool": "tokimemo-go-tui", "built_at": time.Now().UTC().Format(time.RFC3339), "cue": filepath.Base(cue)})
	if e = os.WriteFile(filepath.Join(stage, ".tokimemo-build.json"), append(stamp, '\n'), 0600); e != nil {
		return e
	}
	// Race check immediately before publication, still holding the exclusive lock.
	latest, e := inspectTUIBuild(root)
	if e != nil {
		return e
	}
	if latest.Exists != confirmed.Exists || latest.Snapshot != confirmed.Snapshot {
		return errors.New("output changed during build; keeping old image")
	}
	if !confirmed.Exists {
		if e = publishNativeDirectory(stage, target); e != nil {
			return e
		}
	} else {
		if e = replaceBuildDirectory(stage, target, confirmed.Snapshot, cue); e != nil {
			return e
		}
	}
	fmt.Fprintf(writer, "Verified output published: %s\nVerified CUE and audio retained. DuckStation runtime remains untested.\n", target)
	return nil
}
