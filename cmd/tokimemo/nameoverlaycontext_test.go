package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateN10ReportPathKeepsReportsPrivate(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".local", "go_toolchain", "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "old.json")
	if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := privateN10ReportPath(root, p, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(root, "outside.json"), filepath.Join(root, ".local", "rom", "bad.json"), filepath.Join(dir, "../..", "outside.json"), filepath.Join(dir, "bad.txt")} {
		if _, err := privateN10ReportPath(root, name, false); err == nil {
			t.Errorf("unsafe path accepted: %s", name)
		}
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := privateN10ReportPath(root, link, true); err == nil {
		t.Fatal("symlink accepted")
	}
}
