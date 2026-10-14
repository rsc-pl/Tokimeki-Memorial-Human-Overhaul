package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubCue(p string) error {
	if _, e := os.Stat(p); e != nil {
		return e
	}
	if filepath.Ext(p) != ".cue" {
		return os.ErrInvalid
	}
	return nil
}
func touch(t *testing.T, p string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte("CUE"), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestDiscoveryAndPrivatePersistence(t *testing.T) {
	r := t.TempDir()
	saved := filepath.Join(r, "else", "a.cue")
	touch(t, saved)
	if e := SetGame(r, saved, stubCue); e != nil {
		t.Fatal(e)
	}
	s, e := Load(r)
	if e != nil || filepath.IsAbs(s.GameCue) {
		t.Fatalf("expected relative private path: %+v %v", s, e)
	}
	p, kind, e := Discover(r, "", stubCue)
	if e != nil || p != saved || kind != "saved settings" {
		t.Fatalf("%s %s %v", p, kind, e)
	}
	fallback := filepath.Join(r, ".local/rom", DefaultCue)
	touch(t, fallback)
	p, kind, e = Discover(r, "", stubCue)
	if e != nil || p != fallback || kind != "default .local/rom" {
		t.Fatalf("%s %s %v", p, kind, e)
	}
	if e = os.Remove(fallback); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(saved); e != nil {
		t.Fatal(e)
	}
	if _, _, e = Discover(r, "", stubCue); e == nil {
		t.Fatal("accepted invalid CUE")
	}
}
func TestSafeOutput(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, ".local", "rom", "a.cue")
	for _, p := range []string{filepath.Dir(src), filepath.Join(root, ".local/rom", "out"), root, filepath.Dir(root)} {
		if e := SafeOutput(root, src, p); e == nil {
			t.Errorf("accepted unsafe output %s", p)
		}
	}
	good := filepath.Join(root, ".local", "build", "ps1")
	if e := SafeOutput(root, src, good); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(root, ".local"), 0700); e != nil {
		t.Fatal(e)
	}
	lnk := filepath.Join(root, ".local", "shortcut")
	if e := os.Symlink("rom", lnk); e != nil {
		t.Fatal(e)
	}
	if e := SafeOutput(root, src, filepath.Join(lnk, "out")); e == nil || !strings.Contains(e.Error(), "symlink") {
		t.Fatalf("symlink accepted %v", e)
	}
}
