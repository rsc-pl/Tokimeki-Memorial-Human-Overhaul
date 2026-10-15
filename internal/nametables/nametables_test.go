package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"tokimemo/internal/script"
)

func TestSlotAccountingAndN10Requirements(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required int
	}{{"Koshiki", 9}, {"Asahina", 9}, {"Saotome", 9}, {"Kagami", 7}, {"Tatebayashi", 13}, {"Fujisaki", 9}} {
		raw, e := (&script.PairEncoder{}).Encode(tc.name)
		if e != nil || len(raw)+1 != tc.required {
			t.Fatalf("%s got %d err %v", tc.name, len(raw)+1, e)
		}
	}
	names := []string{"Fujisaki", "Kisaragi", "Himoo", "Katagiri", "Nijino", "Koshiki", "Kiyokawa", "Kagami", "Asahina", "Mikihara", "Saotome", "Tatebayashi", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
	got, e := ShortNamesRequired(names)
	if e != nil || got != 132 {
		t.Fatalf("expected 132 incl terminators, got %d, %v", got, e)
	}
	if got-(ShortEnd-ShortStart) != 8 {
		t.Fatal("expected an eight-byte shortage")
	}
}

func TestN10ReportParsingAndTampering(t *testing.T) {
	s := "file\toffset\tline\tjp\tcurrent\tsurname\tslot_bytes\tsurname_bytes\trequired_bytes\tstatus\n" +
		"translation/character_names.json\t0x72DA0\t1\t古式\tYukari\tKoshiki\t8\t8\t9\tNEEDS_TECHNICAL_CHANGE\n"
	got, e := ReadCapacityReport(strings.NewReader(s))
	if e != nil || len(got) != 1 || got[0].Required != 9 {
		t.Fatalf("valid TSV: %v %#v", e, got)
	}
	for _, bad := range []string{strings.Replace(s, "\t9\tNEEDS", "\t8\tNEEDS", 1), strings.Replace(s, "\t8\t9\tNEEDS", "\t7\t9\tNEEDS", 1), strings.Replace(s, "\t0x72DA0\t", "\twrong\t", 1)} {
		if _, e := ReadCapacityReport(strings.NewReader(bad)); e == nil {
			t.Fatal("bad input accepted")
		}
	}
}

func synthetic(t *testing.T) ([]byte, TableRequest) {
	t.Helper()
	// Deliberately synthetic offsets and no executable instructions.
	file := bytes.Repeat([]byte{0x11}, 0x1500)
	const pool, table, dest = 0x200, 0x300, 0x800
	expected := make([]string, Entries)
	newer := make([]string, Entries)
	at := pool
	for i := 0; i < Entries; i++ {
		expected[i] = fmt.Sprintf("A%d", i)
		newer[i] = fmt.Sprintf("LongName%d", i)
		old, e := (&script.PairEncoder{}).Encode(expected[i])
		if e != nil {
			t.Fatal(e)
		}
		copy(file[at:], old)
		file[at+len(old)] = 0
		binary.LittleEndian.PutUint32(file[table+i*4:], 0x80040800+uint32(at))
		at += len(old) + 1
	}
	if at > table {
		t.Fatal("fixture pool overflow")
	}
	for i := dest; i < dest+256; i++ {
		file[i] = 0
	}
	q := TableRequest{Base: Base, PoolStart: pool, PoolEnd: table, TableOffset: table, DestOffset: dest, DestBefore: make([]byte, 256), ExpectedSource: expected, NewNames: newer, ExpectedFileSHA256: sha256.Sum256(file)}
	return file, q
}

func TestGuardedTableRelocation(t *testing.T) {
	file, q := synthetic(t)
	before := append([]byte(nil), file...)
	out, result, e := RelocateShortTable(file, q)
	if e != nil {
		t.Fatal(e)
	}
	if result.PointerCount != 16 || result.NewBytes <= 0 || result.RuntimeValidated {
		t.Fatalf("wrong report %+v", result)
	}
	if len(out) != len(file) || !bytes.Equal(file, before) {
		t.Fatal("source changed or file resized")
	}
	for i, n := range q.NewNames {
		at := int(binary.LittleEndian.Uint32(out[q.TableOffset+i*4:]) - Base)
		raw, _ := (&script.PairEncoder{}).Encode(n)
		if at < q.DestOffset || at >= q.DestOffset+len(q.DestBefore) || !bytes.Equal(out[at:at+len(raw)], raw) || out[at+len(raw)] != 0 {
			t.Fatalf("name %d bad relocation", i)
		}
	}
	for i := q.PoolStart; i < q.PoolEnd; i++ {
		if out[i] != file[i] {
			t.Fatalf("original pool overwritten at %#x", i)
		}
	}
}

func TestRelocationFailsClosed(t *testing.T) {
	tests := []struct {
		label  string
		damage func([]byte, *TableRequest)
	}{
		{"wrong sha", func(f []byte, q *TableRequest) { f[100] ^= 1 }},
		{"missing destination byte", func(f []byte, q *TableRequest) { f[q.DestOffset] ^= 1; q.ExpectedFileSHA256 = sha256.Sum256(f) }},
		{"pointer redirected", func(f []byte, q *TableRequest) {
			binary.LittleEndian.PutUint32(f[q.TableOffset:], Base+0x100)
			q.ExpectedFileSHA256 = sha256.Sum256(f)
		}},
		{"source changed", func(f []byte, q *TableRequest) { f[q.PoolStart] ^= 1; q.ExpectedFileSHA256 = sha256.Sum256(f) }},
		{"extra direct reference", func(f []byte, q *TableRequest) {
			binary.LittleEndian.PutUint32(f[0x400:], Base+uint32(q.PoolStart))
			q.ExpectedFileSHA256 = sha256.Sum256(f)
		}},
		{"insufficient destination", func(f []byte, q *TableRequest) { q.DestBefore = q.DestBefore[:10] }},
		{"overlapping destination", func(f []byte, q *TableRequest) {
			q.DestOffset = q.PoolStart
			q.DestBefore = append([]byte(nil), f[q.PoolStart:q.PoolStart+150]...)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			f, q := synthetic(t)
			orig := append([]byte(nil), f...)
			tc.damage(f, &q)
			before := append([]byte(nil), f...)
			if out, _, e := RelocateShortTable(f, q); e == nil {
				t.Fatalf("unsafe relocation accepted; output bytes %d", len(out))
			}
			if !bytes.Equal(f, before) {
				t.Fatal("failed relocation modified input")
			}
			_ = orig
		})
	}
}

func TestTokenPressureDoesNotCombineSeparateLines(t *testing.T) {
	_, w, e := script.EncodeEnglish("1234567890123456{G}\nHello{G}", &script.PairEncoder{})
	if e != nil {
		t.Fatal(e)
	}
	tokens, atRisk := GPressure("1234567890123456{G}\nHello{G}", w, 28)
	if tokens != 2 || atRisk {
		t.Fatalf("unexpected width risk %d %v", tokens, atRisk)
	}
	_, w, e = script.EncodeEnglish("12345678901234567{G}", &script.PairEncoder{})
	if e != nil {
		t.Fatal(e)
	}
	_, atRisk = GPressure("12345678901234567{G}", w, 28)
	if !atRisk {
		t.Fatal("should flag a 29-cell line after +2")
	}
}
