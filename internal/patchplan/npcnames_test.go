package patchplan

import (
	"encoding/binary"
	"os"
	"testing"
	"tokimemo/internal/script"
)

func TestPrepareNPCSourceAuthentic(t *testing.T) {
	path := os.Getenv("TOKIMEMO_AUTHENTIC_RETAIL_EXE")
	if path == "" {
		t.Skip("authentic EXE not supplied")
	}
	exe, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gekoPath := os.Getenv("TOKIMEMO_AUTHENTIC_GEKO_OVERLAY")
	if gekoPath == "" {
		t.Skip("authentic GEKO overlay not supplied")
	}
	geko, err := os.ReadFile(gekoPath)
	if err != nil {
		t.Fatal(err)
	}
	// Obtain one pointer-targeted original entry rather than inventing a slot.
	ptr := binary.LittleEndian.Uint32(exe[npcShortPtrs+5*4:])
	off := int(ptr - npcExeBase)
	if off < npcShortStart || off >= npcShortPtrs {
		t.Fatalf("unexpected source pointer %#x", ptr)
	}
	// Other source bytes are verified from the genuine EXE by the production codec.
	s := script.InPlaceString{File: "SLPM_86.053", Source: "character_names.json", Offset: off, Original: "古式", Text: "Koshiki"}
	b := Batch{Strings: []script.InPlaceString{s}}
	result, err := PrepareNPCSource(exe, geko, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.NameEdits) != 1 || len(result.stage.Strings) != 0 || result.NameEdits[0].Index != 5 || result.NameEdits[0].Text != "Koshiki" {
		t.Fatalf("wrong name deferral %+v", result)
	}
	b.Strings[0].Original = "違う"
	if _, err := PrepareNPCSource(exe, geko, b); err == nil {
		t.Fatal("accepted forged original text")
	}
	b.Strings[0].Original = "古式"
	b.Strings[0].Source = "not_character_names.json"
	result, err = PrepareNPCSource(exe, geko, b)
	if err != nil || len(result.NameEdits) != 0 || len(result.stage.Strings) != 1 {
		t.Fatal("failed to preserve unrelated source")
	}
	badGeko := append([]byte(nil), geko...)
	badGeko[0] ^= 1
	if _, err := PrepareNPCSource(exe, badGeko, b); err == nil {
		t.Fatal("accepted foreign overlay")
	}
}
