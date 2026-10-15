package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildInputSnapshotDetectsChanges(t *testing.T) {
	root := t.TempDir()
	one := filepath.Join(root, "data.bin")
	if e := os.WriteFile(one, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	frozen, e := freezeInputs([]string{one, one})
	if e != nil || len(frozen) != 1 {
		t.Fatalf("bad snapshot %v %v", frozen, e)
	}
	if e = verifyFrozen(frozen); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(one, []byte("modified"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = verifyFrozen(frozen); e == nil || !strings.Contains(e.Error(), "changed") {
		t.Fatalf("did not detect changed bytes %v", e)
	}
	if e = os.Rename(one, filepath.Join(root, "previous.bin")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(one, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = verifyFrozen(frozen); e == nil {
		t.Fatal("failed to detect replaced inode")
	}
}
func TestBuildInputSnapshotMissingAndNonregular(t *testing.T) {
	dir := t.TempDir()
	if _, e := freezeInputs([]string{dir}); e == nil {
		t.Fatal("accepted directory")
	}
	p := filepath.Join(dir, "missing")
	if _, e := freezeInputs([]string{p}); e == nil {
		t.Fatal("accepted missing input")
	}
	if e := os.WriteFile(p, []byte("abc"), 0600); e != nil {
		t.Fatal(e)
	}
	snap, e := freezeInputs([]string{p})
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e = verifyFrozen(snap); e == nil {
		t.Fatal("failed to detect disappeared input")
	}
}
