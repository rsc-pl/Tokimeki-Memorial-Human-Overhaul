package nametables

import (
	"encoding/binary"
	"testing"
)

func TestExactPointerWordsAlignedAndBounded(t *testing.T) {
	b := make([]byte, 128)
	address := uint32(0x800b219c)
	binary.LittleEndian.PutUint32(b[8:], address)
	binary.LittleEndian.PutUint32(b[20:], address)
	// Misaligned accidental bytes are not a valid aligned word candidate.
	binary.LittleEndian.PutUint32(b[57:], address)
	count, offsets, err := ExactPointerWords(b, address, 1)
	if err != nil || count != 2 || len(offsets) != 1 || offsets[0] != 8 {
		t.Fatalf("wrong census %d %v %v", count, offsets, err)
	}
	for _, x := range []int{-1, 129} {
		if _, _, e := ExactPointerWords(b, address, x); e == nil {
			t.Fatal("accepted bad sample limit")
		}
	}
	if _, _, e := ExactPointerWords(b[:127], address, 1); e == nil {
		t.Fatal("accepted unaligned file")
	}
}

func TestSixLiteralAliasMappingNoUnsafeApproval(t *testing.T) {
	exe := make([]byte, 0xB0000)
	geko := make([]byte, 0x30000)
	binary.LittleEndian.PutUint32(exe[0x400:], 0x800b219c)
	binary.LittleEndian.PutUint32(geko[0x404:], 0x80144b24)
	rows, err := AuditLiteralAliases(exe, geko)
	if err != nil || len(rows) != 6 {
		t.Fatalf("alias census: %v, %d", err, len(rows))
	}
	if rows[2].EXEWordCandidates != 1 || rows[2].EXEOffsetsSample[0] != 0x400 {
		t.Fatalf("third Fujisaki pointer lost: %+v", rows[2])
	}
	if rows[5].GEKOWordCandidates != 1 || rows[5].GEKOOffsetsSample[0] != 0x404 {
		t.Fatalf("GEKO pointer lost: %+v", rows[5])
	}
	for i, r := range rows {
		want := 0
		if i >= 4 {
			want = 11
		}
		if r.SharedSurnameIndex != want || r.HonorificSensitive != (i == 5) || r.EligibleToRedirect || r.EntireConsumerGraphKnown {
			t.Fatalf("unsafe alias claim at %d: %+v", i, r)
		}
	}
}
