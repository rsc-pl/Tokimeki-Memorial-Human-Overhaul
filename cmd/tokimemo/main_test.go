package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCueTwoTracks(t *testing.T) {
	d := t.TempDir()
	for _, file := range []string{"Track 01.bin", "Track 02.bin"} {
		f, err := os.Create(filepath.Join(d, file))
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Truncate(2352 * 3); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	cue := filepath.Join(d, "game.cue")
	text := "FILE \"Track 01.bin\" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\nFILE \"Track 02.bin\" BINARY\n  TRACK 02 AUDIO\n    INDEX 01 00:00:00\n"
	if err := os.WriteFile(cue, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
	r, err := parseCue(cue)
	if err != nil {
		t.Fatal(err)
	}
	if r.Sectors != 3 || r.Tracks != 2 || len(r.Inputs) != 2 || !strings.HasSuffix(r.Data, "Track 01.bin") {
		t.Fatalf("bad cue %+v", r)
	}
}
func TestCueRejectsMissingTrack(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "game.cue")
	_ = os.WriteFile(p, []byte("FILE \"missing.bin\" BINARY\nTRACK 01 MODE2/2352\n"), 0644)
	if _, e := parseCue(p); e == nil {
		t.Fatal("expected missing track error")
	}
}
func TestCueRejectsMisalignedData(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "game.cue")
	_ = os.WriteFile(filepath.Join(d, "bad.bin"), []byte("broken"), 0644)
	_ = os.WriteFile(p, []byte("FILE bad.bin BINARY\nTRACK 01 MODE2/2352\n"), 0644)
	if _, e := parseCue(p); e == nil {
		t.Fatal("expected sector alignment error")
	}
}
func TestRepositoryCorpus(t *testing.T) {
	wd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Dir(filepath.Dir(wd))
	n, e := validate(root)
	if e != nil {
		t.Fatal(e)
	}
	if n.Files == 0 || n.Lines == 0 || n.Strings == 0 || n.Images == 0 || n.Bytes == 0 {
		t.Fatalf("missing expected resource types %+v", n)
	}
}
func TestParseOffset(t *testing.T) {
	for _, v := range []any{"0x1ca8", float64(12)} {
		if _, e := getInt(v); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := getInt("xxx"); e == nil {
		t.Fatal("expected invalid offset")
	}
}
