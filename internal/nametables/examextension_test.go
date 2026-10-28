package nametables

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFrozenExamCodeLayer(t *testing.T) {
	d := os.Getenv("TOKIMEMO_AUTHENTIC_OVERLAY_DIR")
	exePath := os.Getenv("TOKIMEMO_AUTHENTIC_RETAIL_EXE")
	if d == "" || exePath == "" {
		t.Skip("requires explicit original EXE and authenticated overlays")
	}
	originalExe, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	originalETC, err := os.ReadFile(filepath.Join(d, "ETC.EXN"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := ComposeSpeakerCarriers(func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(d, filepath.Base(p))) })
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := ComposeFrozenExamETC(originalExe, originalETC, base["CDROM/EXEDIR/ETC.EXN"])
	if err != nil {
		t.Fatal(err)
	}
	if got := speakerHash(candidate); got != examCombinedETCDigest {
		t.Fatalf("exam code byte mismatch: %s", got)
	}
	if bytes.Equal(candidate, base["CDROM/EXEDIR/ETC.EXN"]) {
		t.Fatal("exam module missing")
	}
	for _, k := range speakerCarriers["ETC.EXN"].calls {
		if !bytes.Equal(candidate[k:k+4], base["CDROM/EXEDIR/ETC.EXN"][k:k+4]) {
			t.Fatalf("lost speaker hook %#x", k)
		}
	}
	base["CDROM/EXEDIR/ETC.EXN"][0] ^= 1
	if _, err := ComposeFrozenExamETC(originalExe, originalETC, base["CDROM/EXEDIR/ETC.EXN"]); err == nil {
		t.Fatal("accepted corrupted layer")
	}
	if _, err := ComposeFrozenExamETC(originalExe, originalETC, originalETC); err == nil {
		t.Fatal("accepted retail without verified speaker base")
	}
	alteredEXE := bytes.Clone(originalExe)
	alteredEXE[0] ^= 1
	if _, err := ComposeFrozenExamETC(alteredEXE, originalETC, base["CDROM/EXEDIR/ETC.EXN"]); err == nil {
		t.Fatal("accepted unknown EXE")
	}
	if _, err := ComposeFrozenExamETC(nil, originalETC, base["CDROM/EXEDIR/ETC.EXN"]); err == nil {
		t.Fatal("accepted missing EXE")
	}
	if _, err := ComposeFrozenExamETC(originalExe, nil, base["CDROM/EXEDIR/ETC.EXN"]); err == nil {
		t.Fatal("accepted missing ETC")
	}
}
