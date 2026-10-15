package main

import (
	"bytes"
	"tokimemo/internal/ps1"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeNativeBuildFixture(t *testing.T) (string, string, string, []byte, []byte) {
	t.Helper()
	root := t.TempDir()
	rom := filepath.Join(root, ".local", "rom")
	cue, track := fixtureCue(t, rom)
	data, err := os.ReadFile(track)
	if err != nil {
		t.Fatal(err)
	}
	// Extend the ISO directory with the correct PlayStation boot marker.
	dir := data[20*ps1.SectorSize : (21)*ps1.SectorSize]
	index := ps1.DataOffset
	for dir[index] != 0 {
		index += int(dir[index])
	}
	copy(dir[index:], isoTestRecord([]byte("SYSTEM.CNF;1"), 27, 40, false))
	if err = ps1.RegenerateForm1(dir); err != nil {
		t.Fatal(err)
	}
	cnf := data[27*ps1.SectorSize : 28*ps1.SectorSize]
	copy(cnf[ps1.DataOffset:], "BOOT = cdrom:SLPM_86.053;1")
	if err = ps1.RegenerateForm1(cnf); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(track, data, 0600); err != nil {
		t.Fatal(err)
	}
	audio := bytes.Repeat([]byte{0x55}, 2352*2)
	if err = os.WriteFile(filepath.Join(rom, "audio.bin"), audio, 0600); err != nil {
		t.Fatal(err)
	}
	cueBytes := []byte("FILE \"synthetic.bin\" BINARY\n TRACK 01 MODE2/2352\n INDEX 01 00:00:00\nFILE \"audio.bin\" BINARY\n TRACK 02 AUDIO\n INDEX 01 00:00:00\n")
	if err = os.WriteFile(cue, cueBytes, 0600); err != nil {
		t.Fatal(err)
	}
	translation := filepath.Join(root, "translation")
	if err = os.MkdirAll(translation, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(translation, "one.json"), []byte(`{"bytes":[{"file":"HELLO.TXT","offset":"0x0","original":"68656c6c6f","replacement":"48454c4c4f"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(repo, "legacy_scripts"), filepath.Join(root, "legacy_scripts")); err != nil {
		t.Fatal(err)
	}
	return root, cue, track, data, audio
}
func TestNativeBuildFullDiscParityAndProtection(t *testing.T) {
	root, cue, track, original, audio := makeNativeBuildFixture(t)
	dest := filepath.Join(root, ".local", "build", "g07-disc")
	var log bytes.Buffer
	saved := commandOutput
	commandOutput = &log
	defer func() { commandOutput = saved }()
	if err := cmdNativeBuild(root, []string{"--game", cue, "--output", dest}); err == nil {
		t.Fatal("experimental gate missing")
	}
	if err := cmdNativeBuild(root, []string{"--experimental", "--compare-python", "--game", cue, "--output", dest}); err != nil {
		t.Fatalf("native full-disc compare failed: %v\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "Go/Python entire disc bytes: PASS") {
		t.Fatal(log.String())
	}
	if b, err := os.ReadFile(track); err != nil || !bytes.Equal(b, original) {
		t.Fatal("original BIN was modified")
	}
	outAudio, err := os.ReadFile(filepath.Join(dest, "audio.bin"))
	if err != nil || !bytes.Equal(outAudio, audio) {
		t.Fatal("audio track modified")
	}
	outCUE, err := os.ReadFile(filepath.Join(dest, filepath.Base(cue)))
	if err != nil || !bytes.Contains(outCUE, []byte("TRACK 02 AUDIO")) {
		t.Fatal("CUE not preserved")
	}
	if err = cmdNativeBuild(root, []string{"--experimental", "--game", cue, "--output", dest}); err == nil {
		t.Fatal("existing build dir should be rejected")
	}
}
func TestNativeBuildBadPatchLeavesNoOutput(t *testing.T) {
	root, cue, track, original, _ := makeNativeBuildFixture(t)
	bad := filepath.Join(root, "translation", "one.json")
	if err := os.WriteFile(bad, []byte(`{"bytes":[{"file":"HELLO.TXT","offset":"0x0","original":"0000000000","replacement":"48454c4c4f"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, ".local", "build", "should-not-exist")
	if err := cmdNativeBuild(root, []string{"--experimental", "--game", cue, "--output", dest}); err == nil {
		t.Fatal("bad source accepted")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("partial output published")
	}
	if raw, err := os.ReadFile(track); err != nil || !bytes.Equal(raw, original) {
		t.Fatal("original touched on error")
	}
}
