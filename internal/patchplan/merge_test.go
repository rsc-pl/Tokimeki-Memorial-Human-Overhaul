package patchplan

import (
	"bytes"
	"testing"
	"tokimemo/internal/ps1"
)

func TestMergeLayerDisjointAndSharedOwnership(t *testing.T) {
	retail := make([]byte, 64)
	english := bytes.Clone(retail)
	english[4] = 0x11
	code := bytes.Clone(retail)
	code[5] = 0x22
	output, count, conflicts, err := MergeFile("demo.bin", retail, english, code)
	if err != nil || count != 0 || len(conflicts) != 0 || output[4] != 0x11 || output[5] != 0x22 {
		t.Fatalf("disjoint edits refused: %v", err)
	}
	code[4] = english[4]
	if got, n, c, e := MergeFile("demo.bin", retail, english, code); e != nil || got != nil || n != 1 || len(c) != 1 || c[0].Offset != 4 {
		t.Fatalf("overlapping edit accepted: %v", e)
	}
}
func TestMergeEXNChecksumAndUnrelatedTranslation(t *testing.T) {
	retail := make([]byte, 96)
	retail[94] = 0x12
	retail[95] = 0x10
	if err := ps1.FixTailChecksum(retail); err != nil {
		t.Fatal(err)
	}
	if !ps1.TailChecksumValid(retail) {
		t.Fatal("checksum precondition")
	}
	english := bytes.Clone(retail)
	english[10] = 1
	code := bytes.Clone(retail)
	code[16] = 2
	if err := ps1.FixTailChecksum(english); err != nil {
		t.Fatal(err)
	}
	if err := ps1.FixTailChecksum(code); err != nil {
		t.Fatal(err)
	}
	out, count, _, err := MergeFile("CDROM/EXEDIR/ETC.EXN", retail, english, code)
	if err != nil || count != 0 || out[10] != 1 || out[16] != 2 || !ps1.TailChecksumValid(out) {
		t.Fatalf("derived checksum failed: %v", err)
	}
	if !ps1.TailChecksumValid(retail) {
		t.Fatal("mutated retail")
	}
}
func TestMergeAbortWithoutCodeOwnershipAndOnCorruptLengths(t *testing.T) {
	retail := make([]byte, 100)
	if _, _, _, err := MergeFile("dummy", retail, retail, make([]byte, 99)); err == nil {
		t.Fatal("accepted short code")
	}
	invalid := map[string][]byte{"SLPM_86.053": bytes.Clone(retail)}
	_, err := MergeLayeredFiles(func(string) ([]byte, error) { return retail, nil }, nil, invalid, nil, nil, nil)
	if err == nil {
		t.Fatal("accepted executable without source-name provenance")
	}
}
