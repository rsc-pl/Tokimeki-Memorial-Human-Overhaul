//go:build linux

package fullenglish

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyOutputAtomicPublication(t *testing.T) {
	parent := t.TempDir()
	stage := filepath.Join(parent, "stage")
	dest := filepath.Join(parent, "dest")
	for _, d := range []string{stage, dest} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for n, v := range map[string]string{"track01.bin": "patched", "track02.bin": "audio", "disc.cue": "cue"} {
		if err := os.WriteFile(filepath.Join(stage, n), []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	prior, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err = PublishIntoEmptyBuildDirectory(stage, dest); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("obsolete empty staging dir still exists: %v", err)
	}
	updated, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(prior, updated) {
		t.Fatal("expected atomic directory exchange")
	}
	for n, v := range map[string]string{"track01.bin": "patched", "track02.bin": "audio", "disc.cue": "cue"} {
		b, err := os.ReadFile(filepath.Join(dest, n))
		if err != nil || string(b) != v {
			t.Fatalf("%s: %q %v", n, b, err)
		}
	}
}

func TestEmptyOutputChangedFailsClosed(t *testing.T) {
	parent := t.TempDir()
	stage := filepath.Join(parent, "stage")
	dest := filepath.Join(parent, "dest")
	for _, d := range []string{stage, dest} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "disc.cue"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "owner.txt"), []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PublishIntoEmptyBuildDirectory(stage, dest); err == nil {
		t.Fatal("accepted nonempty owner output")
	}
	for name, want := range map[string]string{filepath.Join(stage, "disc.cue"): "new", filepath.Join(dest, "owner.txt"): "protected"} {
		b, err := os.ReadFile(name)
		if err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", name, b, err)
		}
	}
}

func TestEmptyOutputRejectsSymlink(t *testing.T) {
	parent := t.TempDir()
	stage := filepath.Join(parent, "stage")
	real := filepath.Join(parent, "real")
	dest := filepath.Join(parent, "link")
	for _, d := range []string{stage, real} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(real, dest); err != nil {
		t.Fatal(err)
	}
	if err := PublishIntoEmptyBuildDirectory(stage, dest); err == nil {
		t.Fatal("accepted symlink destination")
	}
	if st, err := os.Lstat(dest); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("removed symlink", err)
	}
}

func TestFailedRollbackOldOutputMustNotBeRemoved(t *testing.T) {
	parent := t.TempDir()
	stage := filepath.Join(parent, "stage")
	dest := filepath.Join(parent, "dest")
	for _, d := range []string{stage, dest} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Lstat(stage)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dest, "old.cue"), []byte("owner"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = swapBuildDirectoryEntries(stage, dest); err != nil {
		t.Skipf("rename exchange unavailable: %v", err)
	}
	// Model the ownership check used by cmdIntegratedEnglishBuild's deferred
	// cleanup: the old owner directory at the stage path has a different inode.
	after, err := os.Lstat(stage)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("swapped old output looks stage-owned")
	}
	b, err := os.ReadFile(filepath.Join(stage, "old.cue"))
	if err != nil || string(b) != "owner" {
		t.Fatalf("previous image lost: %q %v", b, err)
	}
}
