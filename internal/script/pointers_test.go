package script

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type pointerVector struct {
	Binary string `json:"binary_hex"`
	Query  struct {
		Base    uint32    `json:"base"`
		Range   [2]uint32 `json:"range"`
		Target  uint32    `json:"target"`
		Pointer uint32    `json:"pointer"`
		Window  int       `json:"window"`
	} `json:"query"`
	Pointers [][2]uint32 `json:"pointers_into"`
	Find     []int       `json:"find_pointers"`
	Code     []int       `json:"code_references"`
	CodeAlt  []int       `json:"code_references_alt"`
}

func TestWordIndexPythonGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/pointer_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v pointerVector
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	input, e := hex.DecodeString(v.Binary)
	if e != nil {
		t.Fatal(e)
	}
	idx := NewWordIndex(input)
	got := idx.PointersInto(v.Query.Base, v.Query.Range[0], v.Query.Range[1])
	want := make([]Pointer, len(v.Pointers))
	for i, x := range v.Pointers {
		want[i] = Pointer{int(x[0]), x[1]}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pointers: %v != %v", got, want)
	}
	if got := FindPointers(input, v.Query.Base, v.Query.Pointer); !reflect.DeepEqual(got, v.Find) {
		t.Errorf("find: %v != %v", got, v.Find)
	}
	if got := idx.CodeReferences(v.Query.Base, v.Query.Target, v.Query.Window); !reflect.DeepEqual(got, v.Code) {
		t.Errorf("MIPS code refs: %v != %v", got, v.Code)
	}
	if got := idx.CodeReferences(v.Query.Base, 0x9000, v.Query.Window); !reflect.DeepEqual(got, v.CodeAlt) {
		t.Errorf("MIPS alternative: %v != %v", got, v.CodeAlt)
	}
}
func TestChecksumAndRead(t *testing.T) {
	raw := []byte{1, 2, 3, 4, 0, 0, 0x12, 0x10}
	if HasChecksum(raw) {
		t.Fatal("incorrect checksum accepted")
	}
	if e := FixChecksum(raw); e != nil {
		t.Fatal(e)
	}
	if !HasChecksum(raw) {
		t.Fatalf("checksum invalid after fixing %x", raw)
	}
	if !bytes.Equal(raw[4:6], []byte{0, 10}) {
		t.Fatalf("wrong checksum: %x", raw)
	}
	if e := FixChecksum([]byte{1, 2}); e == nil {
		t.Fatal("missing marker accepted")
	}
	data := []byte{'a', 'b', 0, 'c'}
	got, e := ReadString(data, 0)
	if e != nil || !bytes.Equal(got, []byte("ab")) {
		t.Fatalf("read: %q %v", got, e)
	}
	if _, e := ReadString(data, 3); e == nil {
		t.Fatal("unterminated string accepted")
	}
}
