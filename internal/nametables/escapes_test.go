package nametables

import (
	"encoding/binary"
	"os"
	"testing"
)

func escapeWords(words ...uint32) []byte {
	b := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[i*4:], w)
	}
	return b
}

func TestPointerEscapeCallAfterDelaySlot(t *testing.T) {
	// Caller sets a1 with LUI and ADDIU, passes it to jal; the delay slot
	// changes a0 only and must not invalidate the a1 argument.
	b := escapeWords(0x3c058014, 0x24a54b1c, 0x0c02b83c, 0x24840004)
	got, err := FindGEKOPointerEscapes(b, 0x80144b1c, 0x80144b30, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != "call-argument" || got[0].Address != 0x80144b1c || got[0].Register != 5 || got[0].UseOffset != 8 {
		t.Fatalf("did not report caller argument: %+v", got)
	}
}
func TestPointerEscapeInDelaySlotAndClobber(t *testing.T) {
	tests := []struct {
		name  string
		words []uint32
		want  int
	}{
		{"construct in delay slot", []uint32{0x3c058014, 0x0c02b83c, 0x24a54b1c}, 1},
		{"overwrite in delay slot", []uint32{0x3c058014, 0x24a54b1c, 0x0c02b83c, 0x24050000}, 0},
		{"overwrite before call", []uint32{0x3c058014, 0x24a54b1c, 0x24050000, 0x0c02b83c, 0}, 0},
		{"non-call branch", []uint32{0x3c058014, 0x24a54b1c, 0x10000000, 0, 0x0c02b83c, 0}, 0},
		{"branch slot stores pointer", []uint32{0x3c058014, 0x24a54b1c, 0x10000000, 0xaca50000}, 1},
		{"alias then store pointer", []uint32{0x3c058014, 0x24a54b1c, 0x00a03021, 0xacc60000}, 1},
		{"call through alias", []uint32{0x3c058014, 0x24a54b1c, 0x00a03021, 0x0c02b83c, 0}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FindGEKOPointerEscapes(escapeWords(tc.words...), 0x80144b1c, 0x80144b30, 32)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}
func TestPointerEscapeStageRejectsNewConsumer(t *testing.T) {
	orig, combined := adjacentTestFixture(t)
	audit, err := AuditGEKOLiteralProvenance(orig)
	if err != nil {
		t.Fatal(err)
	}
	if audit.ReviewedEscapes != 2 || audit.UnreviewedEscapes != 0 {
		t.Fatalf("expected two reviewed call arguments: %+v", audit.PointerEscapes)
	}
	// Neither site creates an address in the literal interval: the old G27
	// scan missed this LUI -> (base below interval) -> a1 -> jal escape.
	binary.LittleEndian.PutUint32(orig[0x500:], 0x3c058014)
	binary.LittleEndian.PutUint32(orig[0x504:], 0x24a54b08)
	binary.LittleEndian.PutUint32(orig[0x508:], 0x24a50014)
	binary.LittleEndian.PutUint32(orig[0x50c:], 0x0c02b83c)
	binary.LittleEndian.PutUint32(orig[0x510:], 0)
	audit, err = AuditGEKOLiteralProvenance(orig)
	if err != nil {
		t.Fatal(err)
	}
	if audit.UnreviewedEscapes == 0 {
		t.Fatalf("missing unreviewed call: %+v", audit.PointerEscapes)
	}
	if result, _, e := stageGEKOAdjacentAfterIdentityProof(orig, combined); e == nil || result != nil {
		t.Fatalf("unsafe research stage accepted new escape: %v", e)
	}
}
func TestPointerEscapeInvalidInput(t *testing.T) {
	_, e := FindGEKOPointerEscapes([]byte{1}, 0x80144b1c, 0x80144b30, 32)
	if e == nil {
		t.Fatal("accepted non-word-aligned input")
	}
}

// Optional private fixture: a reviewer can pass the original R04 bounded
// slice via an environment variable; the archive never bundles game bytes.
func TestGEKOPointerEscapesAgainstPrivateR04Slice(t *testing.T) {
	path := os.Getenv("TOKIMEMO_R04_GEKO_SLICE")
	if path == "" {
		t.Skip("private original R04 evidence unavailable")
	}
	fragment, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragment) != 0x3c0 {
		t.Fatalf("unexpected R04 GEKO slice size %d", len(fragment))
	}
	// The virtual sparse image is only a test adapter for bounded original
	// code. Zero-filled portions are NOT evidence about the rest of GEKO.
	data := make([]byte, 0x13000)
	copy(data[0xf2f0:], fragment)
	a, err := AuditGEKOLiteralProvenance(data)
	if err != nil {
		t.Fatal(err)
	}
	if a.DirectKnown != 2 || a.AdditionalCandidates != 0 || a.ReviewedEscapes != 2 || a.UnreviewedEscapes != 0 {
		t.Fatalf("R04 bounded original GEKO unexpected candidates: %+v", a)
	}
}
