package script

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type inPlaceFixture struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Data        string `json:"data"`
	Original    string `json:"original"`
	Text        string `json:"text"`
	Replacement string `json:"replacement"`
	Offset      int    `json:"offset"`
	Slot        *int   `json:"slot"`
	Encoding    string `json:"encoding"`
}

func TestInPlacePythonGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/inplace_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	wantRaw, e := os.ReadFile("testdata/inplace_expected.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []inPlaceFixture
	var wanted []plannerExpected
	if e = json.Unmarshal(raw, &cases); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(wantRaw, &wanted); e != nil {
		t.Fatal(e)
	}
	if len(cases) != len(wanted) {
		t.Fatalf("case count mismatch")
	}
	for i, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			data, e := base64.StdEncoding.DecodeString(c.Data)
			if e != nil {
				t.Fatal(e)
			}
			switch c.Kind {
			case "string":
				e = ApplyInPlaceString(data, InPlaceString{File: "SYNTHETIC.BIN", Source: "G04", Offset: c.Offset, Original: c.Original, Text: c.Text, Slot: c.Slot, Encoding: c.Encoding}, &PairEncoder{})
			case "bytes":
				orig, oe := hex.DecodeString(c.Original)
				if oe != nil {
					t.Fatal(oe)
				}
				repl, re := hex.DecodeString(c.Replacement)
				if re != nil {
					t.Fatal(re)
				}
				e = ApplyBytesPatch(data, BytesPatch{File: "SYNTHETIC.BIN", Source: "G04", Offset: c.Offset, Original: orig, Replacement: repl})
			default:
				t.Fatal("unknown fixture kind")
			}
			if (e == nil) != wanted[i].OK {
				t.Fatalf("Go error %v, Python %+v", e, wanted[i])
			}
			if e == nil {
				if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != wanted[i].SHA256 {
					t.Errorf("output hash Go %s vs Python %s", got, wanted[i].SHA256)
				}
			}
		})
	}
}
func TestInMemoryTextEditsAreAtomic(t *testing.T) {
	original := make([]byte, 128)
	current := append([]byte(nil), original...)
	patches := []BytesPatch{
		{Offset: 12, Original: []byte{0, 0}, Replacement: []byte{0x42, 0x43}},
		{Offset: 25, Original: []byte{1}, Replacement: []byte{2}},
	}
	_, e := ApplyTextEdits(original, current, nil, patches, nil)
	if e == nil {
		t.Fatal("expected second patch to fail")
	}
	for i, b := range current {
		if b != original[i] {
			t.Fatalf("partial write at %d", i)
		}
	}
}
