package nametables

import (
	"encoding/binary"
	"testing"
)

func put(b []byte, at int, w uint32) { binary.LittleEndian.PutUint32(b[at:], w) }
func TestRAMXrefsKindsAndConservativeFlows(t *testing.T) {
	b := make([]byte, 112)
	put(b, 0, 0x3c04800d)
	put(b, 4, 0x2484a188) // addiu a0,a0,-24184
	put(b, 16, 0x3c08800d)
	put(b, 20, 0x9108a190) // lbu t0,-24176(t0)
	put(b, 32, 0x3c04800d)
	put(b, 36, 0xa084a19c) // sb a0,-24164(a0)
	put(b, 48, 0x3c04800d)
	put(b, 52, 0x08000020)
	put(b, 56, 0x2484a188) // delay slot
	put(b, 72, 0x3c04800d)
	put(b, 76, 0x24840001)
	put(b, 80, 0x2484a188) // clobbered
	v, e := FindRAMReferences(b, 0x800ca180, 0x800ca1c0)
	if e != nil {
		t.Fatal(e)
	}
	if len(v) != 4 {
		t.Fatalf("expected 4 got %d: %+v", len(v), v)
	}
	want := []string{"address-construction", "memory-read", "memory-write", "address-construction"}
	for i, x := range v {
		if x.Kind != want[i] {
			t.Fatalf("record %d got %s", i, x.Kind)
		}
	}
}
func TestAuditReviewedSiteMissingFails(t *testing.T) {
	b := make([]byte, 0x44060)
	if _, e := AuditXrefs("SLPM_86.053", b); e == nil {
		t.Fatal("accepted file missing reviewed sites")
	}
	if _, e := FindRAMReferences([]byte{1}, 0x800ca180, 0x800ca1c0); e == nil {
		t.Fatal("accepted unaligned file")
	}
}

func TestReviewedKnownSitesIncludedInCensus(t *testing.T) {
	for _, name := range []string{EXE, Geko} {
		b, pairs := createKnownFixture(t, name)
		v, e := AuditXrefs(name, b)
		if e != nil {
			t.Fatal(e)
		}
		if v.ReviewedSitesMatched != len(pairs) || v.CompleteCallerCoverage || v.SafeToRelocate {
			t.Fatalf("invalid audit %+v", v)
		}
	}
}
