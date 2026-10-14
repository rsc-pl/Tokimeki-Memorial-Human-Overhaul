package script

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

type codecVector struct {
	Kind     string            `json:"kind"`
	Original string            `json:"original"`
	Text     string            `json:"text"`
	Encoding string            `json:"encoding"`
	Want     []json.RawMessage `json:"want"`
}

func TestGoldenLegacyCodec(t *testing.T) {
	raw, e := os.ReadFile("testdata/codec_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []codecVector
	if e := json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for i, row := range vectors {
		orig, e := EncodeOriginal(row.Original)
		origHash := "ERR"
		if e == nil {
			origHash = fmt.Sprintf("%x", sha256.Sum256(orig))
		}
		var expected string
		if e := json.Unmarshal(row.Want[0], &expected); e != nil {
			t.Fatal(e)
		}
		if origHash != expected {
			t.Fatalf("vector %d original digest %s != %s", i, origHash, expected)
		}
		var target []byte
		var widths []int
		if row.Kind == "dialogue" || row.Encoding == "pairs" {
			target, widths, e = EncodeEnglish(row.Text, &PairEncoder{})
		} else {
			target, e = EncodeFullwidth(row.Text)
		}
		targetHash := "ERR"
		if e == nil {
			targetHash = fmt.Sprintf("%x", sha256.Sum256(target))
		}
		if e := json.Unmarshal(row.Want[1], &expected); e != nil {
			t.Fatal(e)
		}
		if targetHash != expected {
			t.Fatalf("vector %d target digest %s != %s", i, targetHash, expected)
		}
		if string(row.Want[2]) != "null" {
			var expectedWidth []int
			if e := json.Unmarshal(row.Want[2], &expectedWidth); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(widths, expectedWidth) {
				t.Errorf("vector %d widths %v != %v", i, widths, expectedWidth)
			}
		}
		if row.Kind == "dialogue" {
			var wantOrig, wantNew string
			_ = json.Unmarshal(row.Want[3], &wantOrig)
			_ = json.Unmarshal(row.Want[4], &wantNew)
			if got := Structure(row.Original); got != wantOrig {
				t.Errorf("vector %d original structure %q != %q", i, got, wantOrig)
			}
			if got := Structure(row.Text); got != wantNew {
				t.Errorf("vector %d target structure %q != %q", i, got, wantNew)
			}
		}
	}
}
func TestPairEncoderAndDecode(t *testing.T) {
	p := &PairEncoder{}
	got, e := p.Encode("  ")
	if e != nil || !reflect.DeepEqual(got, []byte{0x81, 0x40}) || p.Used {
		t.Fatalf("pair blank: %x / %v / used=%v", got, e, p.Used)
	}
	got, e = p.Encode("A")
	if e != nil || !reflect.DeepEqual(got, []byte{0xc1, 0xa0}) || !p.Used {
		t.Fatalf("odd pair: %x / %v", got, e)
	}
	for _, text := range []string{"こんにちは\n{P}さん", "{>部長}こんにちは", "はい{q}いや{q}{n}{n}", "あ{n}{n}"} {
		raw, e := EncodeOriginal(text)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := Decode(raw)
		if e != nil || decoded != text {
			t.Errorf("%q => %x => %q (%v)", text, raw, decoded, e)
		}
	}
}
func TestInvalidByteAndUnicode(t *testing.T) {
	if _, e := Decode([]byte{0x7f}); e == nil {
		t.Fatal("accepted invalid dialogue byte")
	}
	if _, e := EncodeOriginal("🤍"); e == nil {
		t.Fatal("accepted non Shift-JIS original")
	}
	if _, _, e := EncodeEnglish("unsupported_", nil); e == nil {
		t.Fatal("accepted unsupported pair glyph")
	}
	if _, _, e := EncodeEnglish("{z}", nil); e == nil {
		t.Fatal("accepted unknown control token")
	}
	if _, e := EncodeFullwidth("🤍"); e == nil {
		t.Fatal("accepted unavailable fullwidth glyph")
	}
}
