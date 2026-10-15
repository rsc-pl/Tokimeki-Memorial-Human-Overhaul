package main

import (
	"tokimemo/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestRealCueDiscoveryAndOutputGuard(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".local", "rom")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	name := "Tokimeki Memorial - Forever with You (Japan) (PlayStation the Best)"
	track1 := filepath.Join(dir, name+" (Track 1).bin")
	track2 := filepath.Join(dir, name+" (Track 2).bin")
	for _, p := range []string{track1, track2} {
		if e := os.WriteFile(p, make([]byte, 2352*2), 0600); e != nil {
			t.Fatal(e)
		}
	}
	cue := filepath.Join(dir, config.DefaultCue)
	raw := "FILE \"" + filepath.Base(track1) + "\" BINARY\nTRACK 01 MODE2/2352\nINDEX 01 00:00:00\nFILE \"" + filepath.Base(track2) + "\" BINARY\nTRACK 02 AUDIO\nINDEX 01 00:00:00\n"
	if e := os.WriteFile(cue, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	if p, e := cueChoice(root, ""); e != nil || p != cue {
		t.Fatalf("auto CUE=%s %v", p, e)
	}
	output := filepath.Join(root, ".local", "build", "ps1-english")
	if e := config.SafeOutput(root, cue, output); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(output, 0700); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(output, filepath.Base(track1))
	if e := os.Symlink(track1, dest); e != nil {
		t.Fatal(e)
	}
	if e := guardOutputTracks(cue, output); e == nil {
		t.Fatal("allowed target symlink into original ROM")
	}
	if e := os.Remove(dest); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(track1, dest); e != nil {
		t.Fatal(e)
	}
	if e := guardOutputTracks(cue, output); e == nil {
		t.Fatal("allowed target hardlink to original ROM")
	}
	if e := os.Remove(dest); e != nil {
		t.Fatal(e)
	}
	if e := guardOutputTracks(cue, output); e != nil {
		t.Fatal(e)
	}
}
