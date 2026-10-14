package graphics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"os"
	"testing"
)

func TestRendererPythonGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/renderer_golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var oracle struct {
		Site       string `json:"site"`
		CodeSHA    string `json:"code_sha256"`
		CodeLength int    `json:"code_length"`
		Scratch    string `json:"scratch"`
		NarrowSHA  string `json:"narrow_sha256"`
	}
	if e = json.Unmarshal(raw, &oracle); e != nil {
		t.Fatal(e)
	}
	site, code, font, scratch, e := RendererBuild()
	if e != nil {
		t.Fatal(e)
	}
	a := sha256.Sum256(code)
	b := sha256.Sum256(font)
	if hex.EncodeToString(site) != oracle.Site || len(code) != oracle.CodeLength || hex.EncodeToString(a[:]) != oracle.CodeSHA || hex.EncodeToString(b[:]) != oracle.NarrowSHA || oracle.Scratch != "0x8004451c" || scratch != scratchGlyph {
		t.Fatalf("renderer build differs from Python assembler")
	}
}
func TestInstallRendererGuardAndAtomic(t *testing.T) {
	fake := make([]byte, 0xF000)
	for i := range fake {
		fake[i] = byte(i*33 + 29)
	}
	at, _ := region(fake, hookSite, len(originalSite))
	copy(at, originalSite)
	hook, _ := region(fake, hookSource, hookSize)
	font, _ := region(fake, narrowSource, narrowSize)
	guards := rendererGuards{crc32.ChecksumIEEE(hook), crc32.ChecksumIEEE(font)}
	original := append([]byte(nil), fake...)
	installed, e := installRenderer(fake, guards)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(original, fake) {
		t.Fatal("installer modified source executable")
	}
	if bytes.Equal(original, installed) {
		t.Fatal("renderer was not installed")
	}
	if _, e = installRenderer(installed, guards); e == nil {
		t.Fatal("second installation overwrote modified executable")
	}
	if _, e = InstallRenderer(fake); e == nil {
		t.Fatal("production guard incorrectly accepted synthetic EXE")
	}
}
