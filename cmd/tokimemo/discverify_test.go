package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tokimemo/internal/ps1"
)

func testParityDiscs(t *testing.T) (root, original, native, reference string) {
	t.Helper()
	root, original, _, _, _ = makeNativeBuildFixture(t)
	a := filepath.Join(root, ".local", "build", "go")
	b := filepath.Join(root, ".local", "build", "reference")
	if err := cmdNativeBuild(root, []string{"--experimental", "--game", original, "--output", a}); err != nil {
		t.Fatal(err)
	}
	if err := cmdNativeBuild(root, []string{"--experimental", "--game", original, "--output", b}); err != nil {
		t.Fatal(err)
	}
	native = filepath.Join(a, filepath.Base(original))
	reference = filepath.Join(b, filepath.Base(original))
	return
}

func TestDiscParityFullImageAndOriginal(t *testing.T) {
	root, original, native, reference := testParityDiscs(t)
	r, e := DiscParity(native, reference, original)
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != "MATCH" || len(r.Files) != 3 || !r.AudioUnchanged || r.ChangedDataSectors < 1 || r.ChangedSectorChecks != "PASS" {
		t.Fatalf("unexpected parity: %+v", r)
	}
	report := filepath.Join(root, ".local", "go_toolchain", "reports", "parity.json")
	if e = cmdNativeVerify(root, []string{"--native", native, "--reference", reference, "--original", original, "--report", report}); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(report)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte(root)) {
		t.Fatal("report leaks absolute private filesystem path")
	}
	var parsed parityReport
	if e = json.Unmarshal(b, &parsed); e != nil || parsed.Status != "MATCH" {
		t.Fatalf("invalid report %v %+v", e, parsed)
	}
	if e = cmdNativeVerify(root, []string{"--native", native, "--reference", reference, "--original", original, "--report", report}); e == nil {
		t.Fatal("should refuse report overwrite")
	}
	if e = cmdNativeVerify(root, []string{"--native", native, "--reference", reference, "--report", filepath.Join(root, ".local", "go_toolchain", "config.json")}); e == nil {
		t.Fatal("should refuse personal configuration path")
	}
	if e = cmdNativeVerify(root, []string{"--native", native, "--reference", reference, "--report", filepath.Join(root, "translation", "bad.json")}); e == nil {
		t.Fatal("should refuse translation report")
	}
}

func TestDiscParityDetectsMismatchAndWritesFailReport(t *testing.T) {
	root, original, native, reference := testParityDiscs(t)
	refAudio := filepath.Join(filepath.Dir(reference), "audio.bin")
	if e := os.WriteFile(refAudio, []byte("modified audio"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := DiscParity(native, reference, original)
	if e == nil || r.Status != "MISMATCH" {
		t.Fatalf("modified reference audio not caught %+v: %v", r, e)
	}
	report := filepath.Join(root, ".local", "go_toolchain", "reports", "mismatch.json")
	if e = cmdNativeVerify(root, []string{"--native", native, "--reference", reference, "--original", original, "--report", report}); e == nil {
		t.Fatal("mismatch command returned success")
	}
	b, e := os.ReadFile(report)
	if e != nil || !strings.Contains(string(b), `"status": "MISMATCH"`) {
		t.Fatalf("missing mismatch JSON: %v %s", e, b)
	}
}

func TestDiscParityRejectsCorruptECCAndUnexpectedSectorHeader(t *testing.T) {
	_, original, native, reference := testParityDiscs(t)
	// Corrupt the same patched sector in both outputs: their hashes are still
	// equal, but the independent original-relative validation must detect it.
	data := filepath.Join(filepath.Dir(native), "synthetic.bin")
	b, e := os.ReadFile(data)
	if e != nil {
		t.Fatal(e)
	}
	index := 25 * ps1.SectorSize
	b[index+0x818] ^= 0xff
	if e = os.WriteFile(data, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(filepath.Dir(reference), "synthetic.bin"), b, 0600); e != nil {
		t.Fatal(e)
	}
	r, e := DiscParity(native, reference, original)
	if e == nil || r.ChangedSectorChecks != "FAIL" {
		t.Fatalf("corrupt checksum accepted: %+v %v", r, e)
	}
	b[index+0x818] ^= 0xff
	b[index+0x0f] ^= 0x01 // raw sector mode changed: forbidden
	if e = os.WriteFile(data, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(filepath.Dir(reference), "synthetic.bin"), b, 0600); e != nil {
		t.Fatal(e)
	}
	r, e = DiscParity(native, reference, original)
	if e == nil || r.ChangedSectorChecks != "FAIL" {
		t.Fatalf("corrupt mode accepted: %+v %v", r, e)
	}
}

func TestBuiltInParityReportPublished(t *testing.T) {
	root, original, _, _, _ := makeNativeBuildFixture(t)
	dest := filepath.Join(root, ".local", "build", "compared")
	if e := cmdNativeBuild(root, []string{"--experimental", "--compare-python", "--game", original, "--output", dest}); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dest, ".parity-report.json"))
	if e != nil {
		t.Fatal(e)
	}
	var report parityReport
	if e = json.Unmarshal(raw, &report); e != nil || report.Status != "MATCH" || !report.AudioUnchanged || report.ChangedSectorChecks != "PASS" {
		t.Fatalf("invalid published report %+v: %v", report, e)
	}
	if bytes.Contains(raw, []byte(root)) {
		t.Fatal("private original path in report")
	}
}

func TestDiscParityRejectsMatchingButUnsafeCueLayouts(t *testing.T) {
	_, original, native, reference := testParityDiscs(t)
	for _, cue := range []string{native, reference} {
		old, err := os.ReadFile(cue)
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Replace(old, []byte("INDEX 01 00:00:00"), []byte("INDEX 01 00:02:00"), 1)
		if bytes.Equal(old, changed) {
			t.Fatal("fixture missing index")
		}
		if err := os.WriteFile(cue, changed, 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := DiscParity(native, reference, original)
	if err == nil || got.Status != "MISMATCH" || !strings.Contains(strings.Join(got.Errors, ";"), "unsafe") {
		t.Fatalf("matching malformed CUE falsely considered valid: %+v, %v", got, err)
	}
}
