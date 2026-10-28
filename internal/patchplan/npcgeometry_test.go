package patchplan

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestFirstLineNPCGeometryAuthenticPreimages(t *testing.T) {
	path := os.Getenv("TOKIMEMO_AUTHENTIC_RETAIL_EXE")
	if path == "" {
		t.Skip("authentic retail EXE not supplied")
	}
	retail, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(retail) != 667648 {
		t.Fatal("wrong original size")
	}
	const base uint32 = 0x80040800
	sites := [...]struct{ name, quote uint32 }{
		{0x8007FBAC, 0x8007FBF4}, {0x8007FC6C, 0x8007FCB4},
		{0x8007FE70, 0x8007FEB8}, {0x800800C8, 0x80080110},
		{0x80080188, 0x800801D0}, {0x80081060, 0x800810A8},
	}
	// Verify exact input words before making a self-contained fixture.
	current := bytes.Clone(retail)
	for _, s := range sites {
		old := binary.LittleEndian.Uint32(retail[s.name-base:])
		if old>>26 != 9 || old&0xffff != 0xff98 {
			t.Fatalf("unexpected retail opcode at %x", s.name)
		}
		binary.LittleEndian.PutUint32(current[s.name-base:], old&0xffff0000|0xff9b)
		binary.LittleEndian.PutUint32(current[s.quote-base:], 0x2484ff97)
	}
	names := []string{"Fujisaki", "Kisaragi", "Nijino", "Katagiri", "Himoo", "Koshiki", "Asahina", "Saotome", "Kagami", "Mikihara", "Kiyokawa", "Tatebayashi", "Ijuin", "Saki", "Yoshio", "Mio"}
	out, err := FirstLineNPCGeometry(retail, current, names)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for i := range current {
		if current[i] != out[i] {
			count++
		}
	}
	if count != 12 { // each low immediate changes by one byte
		// The expected patch changes ONLY the low immediate byte per word.
		t.Fatalf("unexpected changed-byte count %d", count)
	}
	for _, s := range sites {
		if binary.LittleEndian.Uint32(out[s.name-base:])&0xffff != 0xff9e ||
			binary.LittleEndian.Uint32(out[s.quote-base:]) != 0x2484ff9a {
			t.Fatal("wrong simultaneous NPC coordinates")
		}
	}
	if _, err := FirstLineNPCGeometry(retail, out, names); err == nil {
		t.Fatal("reapplication accepted")
	}
	if _, err := FirstLineNPCGeometry(retail, retail, names); err == nil {
		t.Fatal("missing prerequisites accepted")
	}
	bad := bytes.Clone(current)
	bad[sites[0].quote-base] ^= 1
	if _, err := FirstLineNPCGeometry(retail, bad, names); err == nil {
		t.Fatal("foreign opcode accepted")
	}
	badNames := append([]string(nil), names...)
	badNames[0] = "Mio-san"
	if _, err := FirstLineNPCGeometry(retail, current, badNames); err == nil {
		t.Fatal("unsupported name accepted")
	}
}
