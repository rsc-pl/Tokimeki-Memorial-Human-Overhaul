package graphics

import (
	"bytes"
	"hash/crc32"
	"testing"
)

func TestImage8BPPPatch(t *testing.T) {
	im := Indexed{Width: 3, Height: 2, Pixels: []byte{9, 8, 7, 6, 5, 4}}
	original := make([]byte, 24)
	for i := range original {
		original[i] = byte(i)
	}
	p := Patch{Offset: 1, Stride: 6, X: 1, Y: 1, BPP: 8, Rects: []Rect{{0, 0, 3, 2}}}
	p.OriginalCRC32 = crc32.ChecksumIEEE([]byte{original[8], original[9], original[10], original[14], original[15], original[16]})
	copied, e := ApplyPatch(original, im, p)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(original, func() []byte {
		b := make([]byte, 24)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}()) {
		t.Fatal("modified input")
	}
	for i, at := range []int{8, 9, 10, 14, 15, 16} {
		if copied[at] != im.Pixels[i] {
			t.Fatalf("pixel %d at %d: %d", i, at, copied[at])
		}
	}
}
func TestImage4BPPPatch(t *testing.T) {
	im := Indexed{Width: 2, Height: 2, Pixels: []byte{2, 3, 14, 15}}
	original := []byte{0xAB, 0xCD, 0xEF, 0x01}
	p := Patch{Offset: 0, Stride: 2, X: 1, Y: 0, BPP: 4, Rects: []Rect{{0, 0, 2, 2}}, OriginalCRC32: crc32.ChecksumIEEE([]byte{0xA, 0xD, 0xE, 0x1})}
	patched, e := ApplyPatch(original, im, p)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(patched, []byte{0x2B, 0xC3, 0xEF, 0x0F}) {
		t.Fatalf("nibble write: %x", patched)
	}
}
func TestImageErrorsAreAtomic(t *testing.T) {
	original := []byte{0xAB, 0xCD, 0xEF, 0x01}
	for _, tc := range []struct {
		name string
		im   Indexed
		p    Patch
	}{
		{"bad CRC", Indexed{Width: 2, Height: 1, Pixels: []byte{1, 2}}, Patch{Stride: 2, BPP: 4, Rects: []Rect{{0, 0, 2, 1}}, OriginalCRC32: 0}},
		{"out of bounds", Indexed{Width: 2, Height: 1, Pixels: []byte{1, 2}}, Patch{Stride: 2, BPP: 4, Rects: []Rect{{1, 0, 2, 1}}}},
		{"invalid nibble", Indexed{Width: 2, Height: 1, Pixels: []byte{17, 2}}, Patch{Stride: 2, BPP: 4, Rects: []Rect{{0, 0, 2, 1}}}},
		{"invalid stride", Indexed{Width: 2, Height: 1, Pixels: []byte{1, 2}}, Patch{Stride: 0, BPP: 4, Rects: []Rect{{0, 0, 2, 1}}}},
		{"negative offset", Indexed{Width: 2, Height: 1, Pixels: []byte{1, 2}}, Patch{Offset: -1, Stride: 2, BPP: 4, Rects: []Rect{{0, 0, 2, 1}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]byte(nil), original...)
			if _, e := ApplyPatch(original, tc.im, tc.p); e == nil {
				t.Fatal("invalid edit accepted")
			}
			if !bytes.Equal(before, original) {
				t.Fatal("input modified on error")
			}
		})
	}
}
func TestPNGIndexedRoundtrip(t *testing.T) {
	im := Indexed{Width: 3, Height: 2, Pixels: []byte{0, 1, 2, 2, 0, 1}, Palette: [][3]uint8{{255, 0, 0}, {0, 255, 0}, {0, 0, 255}}, Alpha: []uint8{255, 120, 0}}
	var buf bytes.Buffer
	if e := WriteIndexed(&buf, im); e != nil {
		t.Fatal(e)
	}
	decoded, e := ReadIndexed(buf.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(decoded.Pixels, im.Pixels) || decoded.Width != im.Width || decoded.Height != im.Height {
		t.Fatal("palette indices changed")
	}
	for i := range im.Palette {
		if decoded.Alpha[i] != im.Alpha[i] {
			t.Fatalf("palette alpha index %d changed: %d vs %d", i, decoded.Alpha[i], im.Alpha[i])
		}
		if decoded.Palette[i] != im.Palette[i] {
			t.Fatalf("palette entry %d changed: %v vs %v", i, decoded.Palette[i], im.Palette[i])
		}
	}
	for _, bad := range [][]byte{nil, []byte("not PNG"), buf.Bytes()[:12]} {
		if _, e := ReadIndexed(bad); e == nil {
			t.Fatal("invalid PNG accepted")
		}
	}
}
