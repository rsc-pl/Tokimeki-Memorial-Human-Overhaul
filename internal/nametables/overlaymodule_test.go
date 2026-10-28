package nametables

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These candidate hashes come from the existing offline composer executed on
// authenticated retail overlays. The test performs an independent byte-for-
// byte comparison without importing or executing the reference composer.
func TestSpeakerCarrierExactOutput(t *testing.T) {
	source := os.Getenv("TOKIMEMO_AUTHENTIC_OVERLAY_DIR")
	if source == "" {
		t.Skip("requires explicit original-overlay directory")
	}
	ref := map[string]string{
		"CDROM/EXEDIR/ETC.EXN":      "f3319426d1936b639d9bb0d2410f56f89731face62ff6b4a1310d90b2f86d7b7",
		"CDROM/EXEDIR/NAME_ENT.EXN": "dba498368f4148f27da1d0cc78421ca5e6cf89933a342cbdc4fe94ffdb84759b",
		"CDROM/EXEDIR/TEL.EXN":      "de2c8142b57df1286b50a31eb4f6b33c4d87c6f71dac66089d147980d05134b6",
	}
	original := map[string][]byte{}
	read := func(path string) ([]byte, error) {
		id := strings.TrimPrefix(path, "CDROM/EXEDIR/")
		b, e := os.ReadFile(filepath.Join(source, id))
		if e == nil {
			original[path] = bytes.Clone(b)
		}
		return b, e
	}
	result, err := ComposeSpeakerCarriers(read)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != len(ref) {
		t.Fatalf("got %d carriers", len(result))
	}
	for path, digest := range ref {
		got, ok := result[path]
		if !ok {
			t.Fatalf("missing carrier %s", path)
		}
		s := sha256.Sum256(got)
		if fmt.Sprintf("%x", s) != digest {
			t.Errorf("%s: reference byte mismatch %x", path, s)
		}
		if bytes.Equal(got, original[path]) {
			t.Errorf("%s not patched", path)
		}
		if s := sha256.Sum256(original[path]); fmt.Sprintf("%x", s) != speakerCarriers[strings.TrimPrefix(path, "CDROM/EXEDIR/")].hash {
			t.Errorf("original input modified: %s", path)
		}
	}
	result["CDROM/EXEDIR/ETC.EXN"][0] ^= 1
	result2, err := ComposeSpeakerCarriers(read)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(result2["CDROM/EXEDIR/ETC.EXN"])
	if fmt.Sprintf("%x", s) != ref["CDROM/EXEDIR/ETC.EXN"] {
		t.Fatal("output aliases a prior candidate")
	}
	badReader := func(path string) ([]byte, error) {
		b, e := read(path)
		if e != nil {
			return nil, e
		}
		b = bytes.Clone(b)
		b[0] ^= 1
		return b, nil
	}
	if _, err := ComposeSpeakerCarriers(badReader); err == nil {
		t.Fatal("accepted corrupt source")
	}
	if _, err := ComposeSpeakerCarriers(nil); err == nil {
		t.Fatal("accepted absent source reader")
	}
	if _, err := ComposeSpeakerCarriers(func(path string) ([]byte, error) { return nil, os.ErrNotExist }); err == nil {
		t.Fatal("accepted missing source")
	}
}
func TestSpeakerModuleKnownDigests(t *testing.T) {
	if speakerHash(speakerGuardImage[:]) != speakerGuardDigest || speakerHash(speakerBodyImage[:]) != speakerBodyDigest {
		t.Fatal("frozen original module mismatch")
	}
}
