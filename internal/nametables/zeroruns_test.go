package nametables

import (
	"encoding/binary"
	"testing"
)

func TestGEKOZeroRunsAreNeverApproval(t *testing.T) {
	data := make([]byte, 0x16000)
	for i := range data {
		data[i] = 0x41
	}
	for i := 0x15003; i < 0x15027; i++ {
		data[i] = 0
	}
	for i := gekoAdjacentNamesStart; i < gekoAdjacentNamesEnd; i++ {
		data[i] = 0
	}
	candidates := CandidateGEKOZeroRuns(data, 17, 10)
	if len(candidates) != 1 || candidates[0].FileOffset != 0x15004 || candidates[0].Length != 0x23 || candidates[0].OwnershipVerified || candidates[0].ExcludedForStaging || candidates[0].ExtentKind != "INTERIOR_ZERO_RUN_UNVERIFIED" {
		t.Fatalf("bad candidates: %+v", candidates)
	}
	if x := CandidateGEKOZeroRuns(data, 40, 10); len(x) != 0 {
		t.Fatal("accepted undersized run")
	}
}

func TestTailZeroRunIsFlaggedEvenWhenHuge(t *testing.T) {
	data := make([]byte, 0x30000)
	for i := 0; i < 0x15c84; i++ {
		data[i] = 0x41
	}
	candidates := CandidateGEKOZeroRuns(data, 17, 30)
	if len(candidates) != 1 || candidates[0].FileOffset != 0x15c84 || candidates[0].Length != 0x30000-0x15c84 || !candidates[0].ExcludedForStaging || candidates[0].ExtentKind != "TRAILING_OR_NEAR_TRAILER_ZERO_FILL_NOT_AN_ALLOCATION" || candidates[0].OwnershipVerified {
		t.Fatalf("tail wrongly approved: %+v", candidates)
	}
}

func TestG29OwnerNearTrailerRunClassification(t *testing.T) {
	b := make([]byte, 0x30000)
	for i := 0; i < 0x15c84; i++ {
		b[i] = 0x41
	}
	for i := 0x2fffc; i < len(b); i++ {
		b[i] = 0x42
	}
	c := CandidateGEKOZeroRuns(b, 17, 30)
	if len(c) != 1 || c[0].FileOffset != 0x15c84 || c[0].Length != 107384 || !c[0].ExcludedForStaging || c[0].ExtentKind != "TRAILING_OR_NEAR_TRAILER_ZERO_FILL_NOT_AN_ALLOCATION" {
		t.Fatalf("G29 near-trailer misclassified: %+v", c)
	}
	a, z := zeroContainingExtent(b, 0x15c88, 24)
	if a != 0x15c84 || z != 0x2fffc {
		t.Fatalf("wrong connected extent: %#x..%#x", a, z)
	}
}

func TestGEKOZeroRunDirectBranchIsExcluded(t *testing.T) {
	b := make([]byte, 0x16000)
	for i := range b {
		b[i] = 0x41
	}
	for i := 0x15000; i < 0x15018; i++ {
		b[i] = 0
	}
	binary.LittleEndian.PutUint32(b[0x100:], encodeDirectJump(2, gekoOverlayRAMBase+0x15000))
	c := CandidateGEKOZeroRuns(b, 17, 20)
	if len(c) != 1 || !c[0].ExcludedForStaging || c[0].DirectControlTargets != 1 || c[0].ExtentKind != "DIRECT_MIPS_CONTROL_TARGET_REJECT" {
		t.Fatalf("branch into cave accepted: %+v", c)
	}
}
