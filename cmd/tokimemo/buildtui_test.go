package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tokimemo/internal/config"
)

func syntheticBuildOutput(t *testing.T) (string, string, string) {
	t.Helper()
	d := t.TempDir()
	src := filepath.Join(d, "source")
	dest := filepath.Join(d, "result")
	if e := os.MkdirAll(src, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(dest, 0700); e != nil {
		t.Fatal(e)
	}
	names := []string{"Track 1.bin", "Track 2.bin"}
	for i, name := range names {
		data := make([]byte, 2352*3)
		for k := range data {
			data[k] = byte(i + 1)
		}
		if e := os.WriteFile(filepath.Join(src, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	cueText := "FILE \"Track 1.bin\" BINARY\n TRACK 01 MODE2/2352\n INDEX 01 00:00:00\nFILE \"Track 2.bin\" BINARY\n TRACK 02 AUDIO\n INDEX 00 00:00:00\n INDEX 01 00:02:00\n"
	cue := filepath.Join(src, "game.cue")
	if e := os.WriteFile(cue, []byte(cueText), 0600); e != nil {
		t.Fatal(e)
	}
	for _, name := range append(names, "game.cue") {
		data, e := os.ReadFile(filepath.Join(src, name))
		if e != nil {
			t.Fatal(e)
		}
		if name == "Track 1.bin" {
			data[111] ^= 0xff
		}
		if e = os.WriteFile(filepath.Join(dest, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return cue, src, dest
}
func TestAuditOwnedPreviousBuild(t *testing.T) {
	cue, _, target := syntheticBuildOutput(t)
	snap, e := auditCompletedBuild(cue, target)
	if e != nil || snap == "" {
		t.Fatalf("expected verified old image: %v", e)
	}
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, p string)
	}{
		{"unknown file", func(t *testing.T, p string) { os.WriteFile(filepath.Join(p, "notes.txt"), []byte("mine"), 0600) }},
		{"bad audio", func(t *testing.T, p string) {
			f := filepath.Join(p, "Track 2.bin")
			data, _ := os.ReadFile(f)
			data[0] ^= 1
			os.WriteFile(f, data, 0600)
		}},
		{"symlink", func(t *testing.T, p string) {
			f := filepath.Join(p, "Track 1.bin")
			os.Remove(f)
			os.Symlink(filepath.Join(filepath.Dir(cue), "Track 1.bin"), f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyTo := filepath.Join(t.TempDir(), "candidate")
			os.Mkdir(copyTo, 0700)
			for _, n := range []string{"Track 1.bin", "Track 2.bin", "game.cue"} {
				data, _ := os.ReadFile(filepath.Join(target, n))
				os.WriteFile(filepath.Join(copyTo, n), data, 0600)
			}
			tc.change(t, copyTo)
			if _, e := auditCompletedBuild(cue, copyTo); e == nil {
				t.Fatal("must refuse untrusted output")
			}
		})
	}
}
func TestReplaceBuildPreservesAndPublishes(t *testing.T) {
	cue, _, old := syntheticBuildOutput(t)
	snap, e := auditCompletedBuild(cue, old)
	if e != nil {
		t.Fatal(e)
	}
	stage := filepath.Join(filepath.Dir(old), "stage")
	os.Mkdir(stage, 0700)
	for _, name := range []string{"Track 1.bin", "Track 2.bin", "game.cue"} {
		b, _ := os.ReadFile(filepath.Join(old, name))
		if name == "Track 1.bin" {
			b[200] ^= 1
		}
		os.WriteFile(filepath.Join(stage, name), b, 0600)
	}
	if e = replaceBuildDirectory(stage, old, "stale snapshot", cue); e == nil {
		t.Fatal("stale verification should rollback")
	}
	restored, e := auditCompletedBuild(cue, old)
	if e != nil || restored != snap {
		t.Fatalf("old image changed after rollback: %v", e)
	}
	if e = replaceBuildDirectory(stage, old, snap, cue); e != nil {
		if strings.Contains(e.Error(), "requires Linux") {
			t.Skip(e)
		}
		t.Fatal(e)
	}
	if _, e = os.Stat(stage); !os.IsNotExist(e) {
		t.Fatal("old output stage not removed")
	}
	latest, e := auditCompletedBuild(cue, old)
	if e != nil || latest == snap {
		t.Fatalf("new output not promoted: %v", e)
	}
}

// End-to-end TUI build transaction against a MOCK producer. No game data,
// Python patcher or real-disc behavior is claimed by this fixture.
func TestTUIBuildTransactionWithMockProducer(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, ".local", "rom")
	if e := os.MkdirAll(src, 0700); e != nil {
		t.Fatal(e)
	}
	cueName := config.DefaultCue
	base := strings.TrimSuffix(cueName, ".cue")
	files := []string{base + " (Track 1).bin", base + " (Track 2).bin"}
	contents := make([]byte, 2352*3)
	for _, name := range files {
		if e := os.WriteFile(filepath.Join(src, name), contents, 0600); e != nil {
			t.Fatal(e)
		}
	}
	cueText := "FILE \"" + files[0] + "\" BINARY\n TRACK 01 MODE2/2352\n INDEX 01 00:00:00\nFILE \"" + files[1] + "\" BINARY\n TRACK 02 AUDIO\n INDEX 00 00:00:00\n INDEX 01 00:02:00\n"
	if e := os.WriteFile(filepath.Join(src, cueName), []byte(cueText), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(root, "translation"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "translation", "sample.json"), []byte(`{"dialogue":[],"strings":[],"images":[],"bytes":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	fake := filepath.Join(root, "mock_python.sh")
	sh := `#!/bin/sh
set -eu
out="";prev=""
for v in "$@"; do if [ "$prev" = "-o" ]; then out="$v"; fi; prev="$v"; done
[ -n "$out" ]
echo 'Step 1/3: validated (MOCK)'
echo 'Step 2/3: copy (MOCK)'
cp "$TOKIMEMO_MOCK_SOURCE"/* "$out"/
echo 'Step 3/3: patch (MOCK)'
if [ "${TOKIMEMO_FAKE_FAIL:-}" = "1" ];then exit 9;fi
printf '\377' | dd of="$out/$TOKIMEMO_MOCK_DATA" bs=1 seek=10 conv=notrunc 2>/dev/null
`
	if e := os.WriteFile(fake, []byte(sh), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("TOKIMEMO_PYTHON", fake)
	t.Setenv("TOKIMEMO_MOCK_SOURCE", src)
	t.Setenv("TOKIMEMO_MOCK_DATA", files[0])
	target, e := inspectTUIBuild(root)
	if e != nil {
		t.Fatal(e)
	}
	if target.Exists {
		t.Fatal("initial output should be absent")
	}
	var log bytes.Buffer
	if e = buildTUI(root, target, &log); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(log.String(), "Step 2/3:") {
		t.Fatal("mock producer not streamed")
	}
	confirmed, e := inspectTUIBuild(root)
	if e != nil || !confirmed.Exists {
		t.Fatalf("expected valid published image: %v", e)
	}
	if e = buildTUI(root, target, io.Discard); e == nil {
		t.Fatal("stale no-clobber should fail")
	}
	t.Setenv("TOKIMEMO_FAKE_FAIL", "1")
	if e = buildTUI(root, confirmed, io.Discard); e == nil {
		t.Fatal("intentional mock failure should abort")
	}
	after, e := inspectTUIBuild(root)
	if e != nil || after.Snapshot != confirmed.Snapshot {
		t.Fatalf("old image not preserved after failure: %v", e)
	}
	t.Setenv("TOKIMEMO_FAKE_FAIL", "0")
	if e = buildTUI(root, confirmed, io.Discard); e != nil {
		t.Fatalf("replacement failed: %v", e)
	}
	if _, e = inspectTUIBuild(root); e != nil {
		t.Fatalf("replaced image invalid: %v", e)
	}
}
