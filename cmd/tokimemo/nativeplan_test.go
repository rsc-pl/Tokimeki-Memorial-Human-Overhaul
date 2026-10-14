package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/ps1"
)

func isoRecord(name string, lba, size int, dir bool) []byte {
	n := []byte(name)
	length := 33 + len(n)
	if len(n)%2 == 0 {
		length++
	}
	rec := make([]byte, length)
	rec[0] = byte(length)
	binary.LittleEndian.PutUint32(rec[2:], uint32(lba))
	binary.BigEndian.PutUint32(rec[6:], uint32(lba))
	binary.LittleEndian.PutUint32(rec[10:], uint32(size))
	binary.BigEndian.PutUint32(rec[14:], uint32(size))
	if dir {
		rec[25] = 2
	}
	rec[28] = 1
	rec[31] = 1
	rec[32] = byte(len(n))
	copy(rec[33:], n)
	return rec
}
func TestNativePlanEndToEndSyntheticCue(t *testing.T) {
	root := t.TempDir()
	rom := filepath.Join(root, ".local", "rom")
	if err := os.MkdirAll(rom, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "translation"), 0700); err != nil {
		t.Fatal(err)
	}
	const sectors = 40
	raw := make([]byte, sectors*ps1.SectorSize)
	put := func(lba int, b []byte) {
		s := make([]byte, ps1.SectorSize)
		s[0x0f] = 2
		copy(s[0x10:0x18], []byte{0, 0, 8, 0, 0, 0, 8, 0})
		copy(s[ps1.DataOffset:], b)
		if err := ps1.RegenerateForm1(s); err != nil {
			t.Fatal(err)
		}
		copy(raw[lba*ps1.SectorSize:], s)
	}
	for lba := 0; lba < sectors; lba++ {
		put(lba, nil)
	}
	volume := make([]byte, 2048)
	volume[0] = 1
	copy(volume[1:6], "CD001")
	volume[6] = 1
	copy(volume[156:], isoRecord(string([]byte{0}), 20, 2048, true))
	put(16, volume)
	dir := make([]byte, 2048)
	n := 0
	for _, v := range [][]byte{isoRecord(string([]byte{0}), 20, 2048, true), isoRecord(string([]byte{1}), 20, 2048, true), isoRecord("SYSTEM.CNF;1", 21, 40, false), isoRecord("TEST.BIN;1", 22, 64, false)} {
		copy(dir[n:], v)
		n += len(v)
	}
	put(20, dir)
	cnf := make([]byte, 40)
	copy(cnf, []byte("BOOT = cdrom:SLPM_86.053;1"))
	put(21, cnf)
	file := make([]byte, 64)
	copy(file[12:], []byte{0xaa, 0xbb})
	put(22, file)
	cue := filepath.Join(rom, "test.cue")
	if err := os.WriteFile(cue, []byte("FILE \"disc.bin\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n"), 0600); err != nil {
		t.Fatal(err)
	}
	track := filepath.Join(rom, "disc.bin")
	if err := os.WriteFile(track, raw, 0600); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), raw...)
	doc := `{"bytes":[{"file":"TEST.BIN","offset":"0xc","original":"aabb","replacement":"ccdd"}]}`
	if err := os.WriteFile(filepath.Join(root, "translation", "one.json"), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	// Install only the reference script and Python modules required by this test.
	// This test runs in the checked-out tree via the repo root directory for the reference.
	repo, err := rootDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(repo, "legacy_scripts"), filepath.Join(root, "legacy_scripts")); err != nil {
		t.Fatal(err)
	}
	previous := commandOutput
	var output bytes.Buffer
	commandOutput = &output
	defer func() { commandOutput = previous }()
	if err := cmdNativePlan(root, []string{"--game", cue, "--compare-python"}); err != nil {
		t.Fatalf("native-plan: %v", err)
	}
	if !strings.Contains(output.String(), "Whole-file Go/Python bytes: PASS") || !strings.Contains(output.String(), "TEST.BIN") {
		t.Fatal(output.String())
	}
	final, err := os.ReadFile(track)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(final, original) {
		t.Fatal("native-plan modified source BIN")
	}
}
