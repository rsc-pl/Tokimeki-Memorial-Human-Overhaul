package ps1

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestChangedSectorWritesPythonByteParity(t *testing.T) {
	source := syntheticTrack(t)
	dir := t.TempDir()
	goTrack := filepath.Join(dir, "go.bin")
	pythonTrack := filepath.Join(dir, "python.bin")
	for _, p := range []string{goTrack, pythonTrack} {
		if err := os.WriteFile(p, source, 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := make([]byte, 3900)
	copy(old, source[28*SectorSize+DataOffset:29*SectorSize-280])
	copy(old[2048:], source[29*SectorSize+DataOffset:29*SectorSize+DataOffset+1852])
	replacement := append([]byte(nil), old...)
	replacement[19] ^= 0x55
	replacement[3200] ^= 0xcc
	f, err := os.OpenFile(goTrack, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	count, err := WriteFileDiff(f, 90, 28, old, replacement)
	f.Close()
	if err != nil || count != 2 {
		t.Fatalf("Go writes %d: %v", count, err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	code := `import sys
from pathlib import Path
from tokipatch.cd import Track
with Track(Path(sys.argv[1]),writable=True) as tr:
 old=tr.read_file(28,3900)
 new=bytearray(old);new[19]^=0x55;new[3200]^=0xcc
 print(tr.write_file(28,old,new))`
	cmd := exec.Command(python, "-c", code, pythonTrack)
	repo, _ := filepath.Abs("../..")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "legacy_scripts"), "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Equal(bytes.TrimSpace(out), []byte("2")) {
		t.Fatalf("Python: %s %v", out, err)
	}
	a, _ := os.ReadFile(goTrack)
	b, _ := os.ReadFile(pythonTrack)
	if !bytes.Equal(a, b) {
		t.Fatal("changed-sector Go/Python disc bytes differ")
	}
	for _, n := range []int{28, 29} {
		if err := VerifyForm1(a[n*SectorSize : (n+1)*SectorSize]); err != nil {
			t.Fatal(err)
		}
	}
}
func TestDiffInvalidModePreflight(t *testing.T) {
	source := syntheticTrack(t)
	source[29*SectorSize+0xf] = 1
	fpath := filepath.Join(t.TempDir(), "track.bin")
	if err := os.WriteFile(fpath, source, 0600); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), source...)
	f, err := os.OpenFile(fpath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	replacement := make([]byte, 3000)
	replacement[0] = 1
	replacement[2100] = 2
	_, err = WriteFileDiff(f, 90, 28, make([]byte, 3000), replacement)
	f.Close()
	if err == nil {
		t.Fatal("invalid later sector accepted")
	}
	after, _ := os.ReadFile(fpath)
	if !bytes.Equal(after, before) {
		t.Fatal("failed preflight damaged copy")
	}
}
