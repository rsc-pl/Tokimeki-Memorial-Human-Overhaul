package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tokimemo/internal/ps1"
)

func isoTestRecord(name []byte, lba, size uint32, isDir bool) []byte {
	n := 33 + len(name)
	if len(name)%2 == 0 {
		n++
	}
	r := make([]byte, n)
	r[0] = byte(n)
	binary.LittleEndian.PutUint32(r[2:6], lba)
	binary.LittleEndian.PutUint32(r[10:14], size)
	binary.BigEndian.PutUint32(r[6:10], lba)
	binary.BigEndian.PutUint32(r[14:18], size)
	if isDir {
		r[25] = 2
	}
	r[28] = 1
	r[31] = 1
	r[32] = byte(len(name))
	copy(r[33:], name)
	return r
}
func fixtureCue(t *testing.T, dir string) (cue, track string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cue = filepath.Join(dir, "synthetic.cue")
	track = filepath.Join(dir, "synthetic.bin")
	sectors := make([]byte, 40*ps1.SectorSize)
	for i := 0; i < 40; i++ {
		s := make([]byte, ps1.SectorSize)
		s[0xf] = 2
		copy(s[0x10:0x18], []byte{0, 0, 8, 0, 0, 0, 8, 0})
		if i == 16 {
			d := s[0x18:]
			d[0] = 1
			copy(d[1:6], "CD001")
			d[6] = 1
			copy(d[40:72], "EXTRACT_PARITY")
			copy(d[156:], isoTestRecord([]byte{0}, 20, 2048, true))
		}
		if i == 20 {
			d := s[0x18:]
			recs := [][]byte{
				isoTestRecord([]byte{0}, 20, 2048, true),
				isoTestRecord([]byte{1}, 20, 2048, true),
				isoTestRecord([]byte("HELLO.TXT;1"), 25, 14, false),
				isoTestRecord([]byte("MOVIE.STR;1"), 26, 5, false),
			}
			pos := 0
			for _, r := range recs {
				copy(d[pos:], r)
				pos += len(r)
			}
		}
		if i == 25 {
			copy(s[0x18:], "hello from iso")
		}
		if i == 26 {
			copy(s[0x18:], "movie")
		}
		if err := ps1.RegenerateForm1(s); err != nil {
			t.Fatal(err)
		}
		copy(sectors[i*ps1.SectorSize:], s)
	}
	if err := os.WriteFile(track, sectors, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cue, []byte("FILE \"synthetic.bin\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return cue, track
}
func TestGoExtractionEqualsPython(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repo, "legacy_scripts/tools/extract.py")); err != nil {
		t.Skip("Python reference not installed")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python not installed")
	}
	d := t.TempDir()
	cue, track := fixtureCue(t, filepath.Join(d, "source"))
	goTarget := filepath.Join(d, "go")
	pyTarget := filepath.Join(d, "python")
	n, err := nativeExtract(track, 40, goTarget)
	if err != nil || n != 1 {
		t.Fatalf("native extracted %d: %v", n, err)
	}
	cmd := exec.Command(py, filepath.Join(repo, "legacy_scripts/tools/extract.py"), cue, pyTarget)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "legacy_scripts"), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Python extraction error: %s %v", output, err)
	}
	for _, file := range []string{"HELLO.TXT", "files.tsv"} {
		a, err := os.ReadFile(filepath.Join(goTarget, file))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(pyTarget, file))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("Go/Python mismatch: %s\nGo %q\nPython %q", file, a, b)
		}
	}
	if _, err := os.Stat(filepath.Join(goTarget, "MOVIE.STR")); !os.IsNotExist(err) {
		t.Fatal("STR must be skipped")
	}
	if _, err := nativeExtract(track, 40, goTarget); err == nil {
		t.Fatal("refused to preserve existing extraction")
	}
	// Negative test: directory entry into a non-existing sector must never create output.
	truncated := filepath.Join(d, "truncated.bin")
	raw, err := os.ReadFile(track)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truncated, raw[:22*ps1.SectorSize], 0600); err != nil {
		t.Fatal(err)
	}
	failDir := filepath.Join(d, "must-not-exist")
	if _, err := nativeExtract(truncated, 22, failDir); err == nil {
		t.Fatal("invalid track accepted")
	}
	if _, err := os.Stat(failDir); !os.IsNotExist(err) {
		t.Fatal("partial output exposed")
	}
}
func TestNativeImageCLI(t *testing.T) {
	root := t.TempDir()
	cue, _ := fixtureCue(t, filepath.Join(root, ".local", "rom"))
	info, err := parseCue(cue)
	if err != nil {
		t.Fatal(err)
	}
	if info.Sectors != 40 || info.Tracks != 1 {
		t.Fatal(info)
	}
	old := commandOutput
	var out bytes.Buffer
	commandOutput = &out
	defer func() { commandOutput = old }()
	if err := cmdFiles(root, []string{"--game", cue, "--prefix", "HELLO"}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "HELLO.TXT") || strings.Contains(got, "MOVIE.STR") {
		t.Fatalf("unexpected file inventory: %q", got)
	}
	out.Reset()
	if err := cmdSectorCheck(root, []string{"--game", cue, "--start", "16", "--count", "2"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "EDC/ECC failures") {
		t.Fatal("no verification summary")
	}
	out.Reset()
	target := filepath.Join(root, ".local", "build", "native-extract")
	if err := cmdExtract(root, []string{"--game", cue, "--output", target}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(target, "HELLO.TXT"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, []byte("hello from iso")) {
		t.Fatal(string(data))
	}
	// Never let a symlinked extraction parent redirect writes to the ROM folder.
	link := filepath.Join(root, ".local", "build", "redirect")
	if err := os.Symlink(filepath.Join(root, ".local", "rom"), link); err != nil {
		t.Fatal(err)
	}
	if err := cmdExtract(root, []string{"--game", cue, "--output", filepath.Join(link, "extract")}); err == nil {
		t.Fatal("symlinked extraction output was accepted")
	}
}

func fixtureCueWithAudioDescriptor(t *testing.T, dir string) (string, string) {
	t.Helper()
	cue, bin := fixtureCue(t, dir)
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	install := func(lba int, data []byte, quirky bool) {
		sector := make([]byte, ps1.SectorSize)
		sector[0xf] = 2
		copy(sector[0x10:0x18], []byte{0, 0, 8, 0, 0, 0, 8, 0})
		offset := ps1.DataOffset
		if quirky {
			offset = 0x10
		}
		copy(sector[offset:], data)
		// The /CDROM special sector deliberately has overlapping subheader.
		if err := ps1.RegenerateForm1(sector); err != nil {
			t.Fatal(err)
		}
		copy(raw[lba*ps1.SectorSize:(lba+1)*ps1.SectorSize], sector)
	}
	root := make([]byte, ps1.DataSize)
	at := 0
	for _, r := range [][]byte{
		isoTestRecord([]byte{0}, 20, ps1.DataSize, true),
		isoTestRecord([]byte{1}, 20, ps1.DataSize, true),
		isoTestRecord([]byte("HELLO.TXT;1"), 25, 14, false),
		isoTestRecord([]byte("MOVIE.STR;1"), 26, 5, false),
		isoTestRecord([]byte("CDROM"), 21, ps1.DataSize, true),
	} {
		copy(root[at:], r)
		at += len(r)
	}
	install(20, root, false)
	cdrom := make([]byte, ps1.DataSize)
	at = 0
	for _, r := range [][]byte{
		isoTestRecord([]byte{0}, 21, ps1.DataSize, true),
		isoTestRecord([]byte{1}, 20, ps1.DataSize, true),
		isoTestRecord([]byte("DADIR"), 22, ps1.DataSize, true),
	} {
		copy(cdrom[at:], r)
		at += len(r)
	}
	install(21, cdrom, true)
	dadir := make([]byte, ps1.DataSize)
	at = 0
	for _, r := range [][]byte{
		isoTestRecord([]byte{0}, 22, ps1.DataSize, true),
		isoTestRecord([]byte{1}, 21, ps1.DataSize, true),
		isoTestRecord([]byte("TR02.DA;1"), 9000, 2352*150, false),
	} {
		copy(dadir[at:], r)
		at += len(r)
	}
	install(22, dadir, false)
	if err := os.WriteFile(bin, raw, 0600); err != nil {
		t.Fatal(err)
	}
	audio := filepath.Join(dir, "audio.bin")
	if err := os.WriteFile(audio, bytes.Repeat([]byte{0x5a}, 150*ps1.SectorSize), 0600); err != nil {
		t.Fatal(err)
	}
	cueText := "FILE \"synthetic.bin\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\nFILE \"audio.bin\" BINARY\n  TRACK 02 AUDIO\n    FLAGS DCP\n    INDEX 00 00:00:00\n    INDEX 01 00:02:00\n"
	if err := os.WriteFile(cue, []byte(cueText), 0600); err != nil {
		t.Fatal(err)
	}
	return cue, bin
}

func TestAudioDescriptorNativeExtractionPythonParity(t *testing.T) {
	tmp := t.TempDir()
	cue, bin := fixtureCueWithAudioDescriptor(t, filepath.Join(tmp, "disc"))
	before, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	iso, err := ps1.OpenISO(f, 40)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	entry, found := iso.Entries["CDROM/DADIR/TR02.DA"]
	if !found || !ps1.IsExternalTrackAudio(entry) {
		t.Fatal("audio descriptor missing")
	}
	out := filepath.Join(tmp, "go")
	count, err := nativeExtract(bin, 40, out)
	if err != nil || count != 1 {
		t.Fatalf("native extraction count %d: %v", count, err)
	}
	if _, err := os.Stat(filepath.Join(out, "CDROM", "DADIR", "TR02.DA")); !os.IsNotExist(err) {
		t.Fatal("tried to extract external audio from Track 1")
	}
	if !bytes.Equal(before, mustRead(t, bin)) {
		t.Fatal("source image mutated")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python not available for parity test")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	reference := filepath.Join(tmp, "python")
	cmd := exec.Command(py, filepath.Join(repo, "legacy_scripts", "tools", "extract.py"), cue, reference)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "legacy_scripts"), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Python failed: %v: %s", err, output)
	}
	for _, file := range []string{"files.tsv", "HELLO.TXT"} {
		a, b := mustRead(t, filepath.Join(out, file)), mustRead(t, filepath.Join(reference, file))
		if !bytes.Equal(a, b) {
			t.Fatalf("different extracted %s, Go %q Python %q", file, a, b)
		}
	}
}
func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNameXrefsAudioDescriptorDoesNotBlockISO(t *testing.T) {
	dir := t.TempDir()
	cue, bin := fixtureCueWithAudioDescriptor(t, dir)
	data := mustRead(t, bin)
	// Add the expected EXE entry so name-xrefs reaches its mandatory
	// cryptographic revision check, rather than failing during ISO parsing.
	s := append([]byte(nil), data[20*ps1.SectorSize:21*ps1.SectorSize]...)
	records := s[ps1.DataOffset : ps1.DataOffset+ps1.DataSize]
	at := 0
	for at < len(records) && records[at] != 0 {
		at += int(records[at])
	}
	copy(records[at:], isoTestRecord([]byte("SLPM_86.053;1"), 27, 16, false))
	if err := ps1.RegenerateForm1(s); err != nil {
		t.Fatal(err)
	}
	copy(data[20*ps1.SectorSize:21*ps1.SectorSize], s)
	if err := os.WriteFile(bin, data, 0600); err != nil {
		t.Fatal(err)
	}
	err := cmdNameXrefs(dir, []string{"--game", cue})
	if err == nil || !strings.Contains(err.Error(), "does not match verified original N10 revision") {
		t.Fatalf("expected revision check after ISO traversal, got: %v", err)
	}
}
