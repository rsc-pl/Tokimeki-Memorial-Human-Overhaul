package graphics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestGlyphPythonGoldens(t *testing.T) {
	var fixture struct {
		Chars        string            `json:"chars"`
		PairSHA      string            `json:"pair_sha256"`
		NarrowSHA    string            `json:"narrow_sha256"`
		NarrowLength int               `json:"narrow_length"`
		PairCount    int               `json:"pair_count"`
		Pairs        map[string]string `json:"pairs"`
	}
	raw, e := os.ReadFile("testdata/glyph_golden.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	digest := sha256.New()
	count := 0
	for i := 0; i < len(fixture.Chars); i++ {
		for j := 0; j < len(fixture.Chars); j++ {
			glyph, e := RenderPair(fixture.Chars[i], fixture.Chars[j])
			if e != nil {
				t.Fatal(e)
			}
			digest.Write(glyph[:])
			count++
			if v, ok := fixture.Pairs[fixture.Chars[i:i+1]+fixture.Chars[j:j+1]]; ok && hex.EncodeToString(glyph[:]) != v {
				t.Errorf("render %q%q mismatch", fixture.Chars[i], fixture.Chars[j])
			}
		}
	}
	if count != fixture.PairCount || hex.EncodeToString(digest.Sum(nil)) != fixture.PairSHA {
		t.Fatalf("rendered pairs %d sha %x; expected %d %s", count, digest.Sum(nil), fixture.PairCount, fixture.PairSHA)
	}
	table, e := NarrowFont()
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(table)
	if len(table) != fixture.NarrowLength || hex.EncodeToString(h[:]) != fixture.NarrowSHA {
		t.Fatalf("narrow font %d bytes hash %x, expected %d %s", len(table), h, fixture.NarrowLength, fixture.NarrowSHA)
	}
}
