package nametables

import (
	"encoding/binary"
	"testing"
)

func TestSixN10FixedLiteralSites(t *testing.T) {
	exe := make([]byte, 667648)
	geko := make([]byte, 196608)
	for _, site := range fixedLiteralSites {
		raw := exe
		if site.file == Geko {
			raw = geko
		}
		copy(raw[site.offset:], []byte{'S', 'h', 'i', 'o', 'r', 'i', 0})
	}
	// LUI + ADDIU references, one each: indirect references remain UNKNOWN.
	binary.LittleEndian.PutUint32(exe[0x100:], 0x3c04800b)
	binary.LittleEndian.PutUint32(exe[0x104:], 0x24842180)
	binary.LittleEndian.PutUint32(geko[0x100:], 0x3c058014)
	binary.LittleEndian.PutUint32(geko[0x104:], 0x24a54b1c)
	rows, e := AuditFixedLiterals(exe, geko)
	if e != nil || len(rows) != 6 {
		t.Fatalf("failed six-slot audit: %d %v", len(rows), e)
	}
	if rows[0].DirectAddressCandidates != 1 || rows[4].DirectAddressCandidates != 1 || rows[2].DirectAddressCandidates != 0 {
		t.Fatalf("wrong direct vs unresolved distinction %+v", rows)
	}
	for _, r := range rows {
		if r.SafeToRewrite || !r.PointerOrIndirectConsumersUnknown || r.OriginalBytesBeforeNUL != 6 {
			t.Fatalf("unsafe classification %+v", r)
		}
	}
	exe[0x71980+6] = 0x7f
	exe[0x71980+7] = 0x7f
	if _, e := AuditFixedLiterals(exe, geko); e == nil {
		t.Fatal("accepted unterminated fixed slot")
	}
}
