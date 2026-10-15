package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestInheritedFujisakiBranchProvenance(t *testing.T) {
	ex, _ := directFixture(t)
	// This low-level primitive consumes the G23 direct-stage result, not raw EXE.
	ex, b, _, err := stageDirectFixedAliasesAfterIdentityProof(ex, func() []byte { _, ge := directFixture(t); return ge }())
	_ = b
	if err != nil {
		t.Fatal(err)
	}
	// The direct stage already applies the inherited change. Verify the
	// low-level primitive independently on the pre-inherited fixture below.
	orig, _ := directFixture(t)
	binary.LittleEndian.PutUint32(orig[0x3ffb4:], 0x3c048005)
	old := bytes.Clone(orig)
	out, err := RewriteGuardedInheritedFujisaki(orig, 0x8004ba78)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(orig, old) {
		t.Fatal("changed input")
	}
	if got := binary.LittleEndian.Uint32(out[0x3ff94:]); got != 0x3c048005 {
		t.Fatalf("wrong high half %#x", got)
	}
	if got := binary.LittleEndian.Uint32(out[0x40068:]); got != 0x2484ba78 {
		t.Fatalf("wrong low half %#x", got)
	}
	if got := binary.LittleEndian.Uint32(out[0x3ffb4:]); got != 0x3c048005 {
		t.Fatalf("fall-through changed %#x", got)
	}
	if !bytes.Equal(ex[0x3ff94:0x3ff98], out[0x3ff94:0x3ff98]) {
		t.Fatal("integrated result disagrees")
	}
}
func TestInheritedFujisakiRejectsUnprovenPath(t *testing.T) {
	ex, _ := directFixture(t)
	binary.LittleEndian.PutUint32(ex[0x3ffb4:], 0x3c048005)
	for _, off := range []int{0x3ff94, 0x3ff98, 0x3ff9c, 0x3ffa4, 0x3ffa8, 0x3ffac, 0x3ffb4, 0x40064, 0x40068} {
		mutated := bytes.Clone(ex)
		mutated[off] ^= 1
		if res, err := RewriteGuardedInheritedFujisaki(mutated, 0x8004ba78); err == nil || res != nil {
			t.Fatalf("accepted mutated path %#x", off)
		}
	}
}
