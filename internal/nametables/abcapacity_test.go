package nametables

import (
	"bytes"
	"testing"
)

func TestPackedNameBoundRequiresEveryNameFitsA(t *testing.T) {
	// 16 strings; one long 17-byte item cannot be made safe by shortening
	// other items in the shared 132-byte pool.
	names := make([][]byte, 16)
	for i := range names {
		names[i] = []byte("TEST")
	}
	names[0] = []byte("ABCDEFGHIJKLMNOPQ") // 17 + NUL
	pool := []byte{}
	for _, name := range names {
		pool = append(pool, name...)
		pool = append(pool, 0)
	}
	longest, e := MaxPackedNameBytesWithNUL(pool, 16)
	if e != nil || longest != 18 {
		t.Fatalf("max=%d e=%v", longest, e)
	}
	if longest <= N10BufferACapacity {
		t.Fatal("would overflow A")
	}
	// Also reject dangling bytes, empty names, missing terminators.
	for _, bad := range [][]byte{append(bytes.Clone(pool), 1), bytes.Replace(pool, []byte("TEST"), []byte{0, 0, 0, 0}, 1), pool[:len(pool)-1]} {
		if _, e := MaxPackedNameBytesWithNUL(bad, 16); e == nil {
			t.Fatalf("accepted invalid pool of length %d", len(bad))
		}
	}
}
func TestExistingN10NamesRespectConditionalABCapacity(t *testing.T) {
	exe, _ := n10SyntheticABFixture(t)
	start := int(N10TailRAMAddress - Base)
	n, e := MaxPackedNameBytesWithNUL(exe[start:start+N10CompactExpectedBytes], 16)
	if e != nil {
		t.Fatal(e)
	}
	if n != 13 || n > N10BufferACapacity {
		t.Fatalf("max name bytes=%d", n)
	}
	// 32 - 13 = 19 additional bytes, but no proof every appended text
	// (possibly multiple fragments) remains below that bound.
	if N10BufferBCapacity-n != 19 {
		t.Fatal("wrong remaining conditional B budget")
	}
}
