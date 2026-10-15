package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMergeDisjointByteEdits(t *testing.T) {
	base := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	a := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	b := []byte{0, 0, 0, 0, 0, 2, 0, 0}
	got, count, err := MergeDisjointByteEdits(base, a, b)
	if err != nil || count != 2 || !bytes.Equal(got, []byte{1, 0, 0, 0, 0, 2, 0, 0}) {
		t.Fatalf("unexpected merge %v %d %v", got, count, err)
	}
	if !bytes.Equal(base, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatal("changed baseline")
	}
	shared := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	if _, n, err := MergeDisjointByteEdits(base, a, shared); err != nil || n != 1 {
		t.Fatalf("identical word overlap rejected: %v", err)
	}
	// Different writes in the same MIPS instruction are NEVER composable,
	// even if they touch different bytes. Otherwise neither stage validates
	// the merged instruction.
	if out, _, err := MergeDisjointByteEdits(base, a, []byte{0, 2, 0, 0, 0, 0, 0, 0}); err == nil || out != nil {
		t.Fatal("accepted hybrid MIPS instruction")
	}
	if out, _, err := MergeDisjointByteEdits(base, a, []byte{2, 0, 0, 0, 0, 0, 0, 0}); err == nil || out != nil {
		t.Fatal("accepted conflicting byte edits")
	}
	if out, _, err := MergeDisjointByteEdits(base, []byte{0, 0, 0}); err == nil || out != nil {
		t.Fatal("accepted truncated candidate")
	}
	if out, _, err := MergeDisjointByteEdits(base[:3], []byte{0, 0, 0}); err == nil || out != nil {
		t.Fatal("accepted unaligned candidate")
	}
	if out, _, err := MergeDisjointByteEdits(base); err == nil || out != nil {
		t.Fatal("accepted zero candidates")
	}
}

func TestCombinedPartialN10UnionAndSafety(t *testing.T) {
	exe, geko := directFixture(t)
	oldEXE, oldGEKO := bytes.Clone(exe), bytes.Clone(geko)
	combinedEXE, combinedGEKO, result, err := combinePartialAfterIdentityProof(exe, geko)
	if err != nil {
		t.Fatal(err)
	}
	if !result.UnsafeToBoot || result.Complete || result.RuntimeApproved || result.Status != "N10_COMBINED_PARTIAL_RESEARCH_NOT_BOOTABLE" {
		t.Fatalf("incorrect approval flags %+v", result)
	}
	if result.EXEABSites != 20 || result.GEKOABSites != 6 || result.EXEDirectSites != 3 || result.EXEInheritedSites != 1 || result.GEKODirectSites != 1 {
		t.Fatalf("wrong stage site counts %+v", result)
	}
	if !bytes.Equal(exe, oldEXE) || !bytes.Equal(geko, oldGEKO) {
		t.Fatal("stage changed its inputs")
	}
	if !bytes.Equal(exe[ShortStart:ShortEnd], combinedEXE[ShortStart:ShortEnd]) {
		t.Fatal("retired source overwritten")
	}
	if !bytes.Equal(geko[0xf47c:0xf488], combinedGEKO[0xf47c:0xf488]) || !bytes.Equal(geko[0x12b24:0x12b30], combinedGEKO[0x12b24:0x12b30]) {
		t.Fatal("lost GEKO -san")
	}
	if binary.LittleEndian.Uint32(combinedGEKO[0xf488:]) == binary.LittleEndian.Uint32(geko[0xf488:]) {
		t.Fatal("GEKO B destination not redirected")
	}
	ax, ag, _, err := stageABAfterIdentityProof(exe, geko)
	if err != nil {
		t.Fatal(err)
	}
	fx, fg, _, err := stageDirectFixedAliasesAfterIdentityProof(exe, geko)
	if err != nil {
		t.Fatal(err)
	}
	unionEXE, _, err := MergeDisjointByteEdits(exe, ax, fx)
	if err != nil {
		t.Fatal(err)
	}
	unionGEKO, _, err := MergeDisjointByteEdits(geko, ag, fg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(combinedEXE, unionEXE) || !bytes.Equal(combinedGEKO, unionGEKO) {
		t.Fatal("combined candidate lost a stage")
	}
}

func TestCombinedPartialN10FailClosed(t *testing.T) {
	exe, geko := directFixture(t)
	exe[0x3ff94] ^= 1
	before := bytes.Clone(exe)
	a, b, _, err := combinePartialAfterIdentityProof(exe, geko)
	if err == nil || a != nil || b != nil {
		t.Fatal("accepted altered inherited path")
	}
	if !bytes.Equal(exe, before) {
		t.Fatal("mutated failing source")
	}
	if x, y, _, err := CombinePartialN10Research(before, geko); err == nil || x != nil || y != nil {
		t.Fatal("public path skipped retail GEKO SHA guard")
	}
}
