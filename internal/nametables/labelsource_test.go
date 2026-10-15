package nametables

import (
	"encoding/binary"
	"testing"
)

func psxFixture() []byte {
	x := make([]byte, 0x800+0x9000)
	copy(x, []byte("PS-X EXE"))
	binary.LittleEndian.PutUint32(x[0x18:], 0x80041000)
	binary.LittleEndian.PutUint32(x[0x1c:], 0x9000)
	copy(x[0x800+0x820:], []byte{'x', 'y', 0, 'Q'})
	return x
}
func TestResidentSourceHeaderAndBounds(t *testing.T) {
	x := psxFixture()
	v, e := ResidentCStringLength(x, 0x80041820, 64)
	if e != nil || v.FileOffset != 0x1020 || v.BytesBeforeNUL != 2 || !v.NULTerminated {
		t.Fatalf("wrong PS-X header offset: %+v %v", v, e)
	}
	for _, tc := range []struct {
		addr  uint32
		limit int
	}{{0x80040fff, 64}, {0x8004a000, 64}, {0x80041821, 1}, {0x80041820, 1}, {0x80041820, 0}} {
		if _, e := ResidentCStringLength(x, tc.addr, tc.limit); e == nil {
			t.Fatalf("accepted invalid source %#x/%d", tc.addr, tc.limit)
		}
	}
	x[0x1c] = 0xff
	if _, e := ResidentCStringLength(x, 0x80041820, 64); e == nil {
		t.Fatal("accepted corrupt EXE mapping")
	}
}
func TestLabelCapacityIncludesSingleNUL(t *testing.T) {
	for _, tc := range []struct {
		suffix int
		fits   bool
		used   int
	}{{0, true, 13}, {19, true, 32}, {20, false, 33}} {
		got, e := CheckN10LongestLabelSuffix(tc.suffix)
		if e != nil || got.Fits != tc.fits || got.RequiredWithNUL != tc.used || got.ProvenForAllRuntimeSources {
			t.Fatalf("bad label footprint: %+v %v", got, e)
		}
	}
	if _, e := CheckLabelCapacity(1, -1, 32); e == nil {
		t.Fatal("negative suffix accepted")
	}
}

// Owner G21's original-EXE evidence shows a two-byte append source in one
// R07 call. It proves only that call's static byte footprint, never a
// worst-case dynamic label length or permission to boot the candidate.
func TestOwnerG21ObservedAppendBound(t *testing.T) {
	got, err := CheckN10LongestLabelSuffix(2)
	if err != nil || got.RequiredWithNUL != 15 || !got.Fits || got.ProvenForAllRuntimeSources {
		t.Fatalf("invalid static R07 append evidence: %+v %v", got, err)
	}
}
