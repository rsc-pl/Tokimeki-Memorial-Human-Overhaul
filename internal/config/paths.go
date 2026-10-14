// Package config manages private per-checkout paths. Translation inputs are never modified.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const DefaultCue = "Tokimeki Memorial - Forever with You (Japan) (PlayStation the Best).cue"
const FileName = ".local/go_toolchain/config.json"

type Settings struct {
	Version   int    `json:"version"`
	GameCue   string `json:"game_cue,omitempty"`
	OutputDir string `json:"output_dir,omitempty"`
}

func Path(root string) string { return filepath.Join(root, FileName) }
func Load(root string) (Settings, error) {
	b, e := os.ReadFile(Path(root))
	if errors.Is(e, os.ErrNotExist) {
		return Settings{Version: 1}, nil
	}
	if e != nil {
		return Settings{}, e
	}
	var s Settings
	if e = json.Unmarshal(b, &s); e != nil {
		return s, fmt.Errorf("invalid private config: %w", e)
	}
	if s.Version != 1 {
		return s, fmt.Errorf("unsupported private config version %d", s.Version)
	}
	return s, nil
}
func storePath(root, p string) string {
	p, _ = filepath.Abs(p)
	r, _ := filepath.Rel(root, p)
	if r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r) {
		return r
	}
	return p
}
func Absolute(root, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(root, p)
}
func Save(root string, s Settings) error {
	s.Version = 1
	if s.GameCue != "" {
		s.GameCue = storePath(root, Absolute(root, s.GameCue))
	}
	if s.OutputDir != "" {
		s.OutputDir = storePath(root, Absolute(root, s.OutputDir))
	}
	path := Path(root)
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	f, e := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}

// Discover uses the exact default CUE first, saved config second, and never guesses another edition.
// validate must verify the CUE and every referenced track before a path is accepted.
func Discover(root, explicit string, validate func(string) error) (string, string, error) {
	if explicit != "" {
		p, e := filepath.Abs(explicit)
		if e != nil {
			return "", "", e
		}
		if e = validate(p); e != nil {
			return "", "", fmt.Errorf("selected game image: %w", e)
		}
		return p, "explicit", nil
	}
	p := filepath.Join(root, ".local", "rom", DefaultCue)
	if validate(p) == nil {
		return p, "default .local/rom", nil
	}
	settings, e := Load(root)
	if e != nil {
		return "", "", e
	}
	if settings.GameCue != "" {
		p = Absolute(root, settings.GameCue)
		if validate(p) == nil {
			return p, "saved settings", nil
		}
	}
	return "", "", errors.New("no valid game CUE found; place it in .local/rom/, use --game PATH, or choose it in TUI Settings")
}
func SetGame(root, p string, validate func(string) error) error {
	absolute, e := filepath.Abs(p)
	if e != nil {
		return e
	}
	if e = validate(absolute); e != nil {
		return e
	}
	s, e := Load(root)
	if e != nil {
		return e
	}
	s.GameCue = absolute
	return Save(root, s)
}
func SetOutput(root, p string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("empty output path")
	}
	s, e := Load(root)
	if e != nil {
		return e
	}
	s.OutputDir = Absolute(root, p)
	return Save(root, s)
}
func Output(root string) (string, error) {
	s, e := Load(root)
	if e != nil {
		return "", e
	}
	if s.OutputDir != "" {
		return Absolute(root, s.OutputDir), nil
	}
	return filepath.Join(root, ".local", "build", "ps1-english"), nil
}
func Within(parent, child string) bool {
	parent, _ = filepath.Abs(parent)
	child, _ = filepath.Abs(child)
	rel, e := filepath.Rel(parent, child)
	return e == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
func SafeOutput(root, gameCue, output string) error {
	if output == "" {
		return errors.New("empty output directory")
	}
	in, _ := filepath.Abs(gameCue)
	out, _ := filepath.Abs(output)
	if in == out || Within(filepath.Dir(in), out) {
		return errors.New("output cannot be in the source CUE directory (source images are immutable)")
	}
	if Within(out, filepath.Dir(in)) {
		return errors.New("output cannot contain the source game directory")
	}
	if Within(filepath.Join(root, ".local", "rom"), out) {
		return errors.New("output cannot be inside .local/rom/")
	}
	if Within(out, root) || out == string(filepath.Separator) {
		return errors.New("output cannot contain the project")
	}
	// A symlink in the output tree could redirect writes into ROMs or other files.
	for p := out; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output path crosses symlink: %s", p)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
