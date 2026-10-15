package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

// The synthetic source is made to satisfy renderer's explicit original-code
// and CRC guards. No copyrighted executable bytes are used.
func rendererFixture(t *testing.T) ([]byte, []string, []string) {
	t.Helper()
	f := make([]byte, 0x80000)
	for i := range f {
		f[i] = byte(i*31 + 7)
	}
	// NOTE: original renderer signature and its CRC are checked independently
	// in graphics; here the test may use only the installed code (not build).
	current := []string{"Shiori", "Mio", "Himoo", "Ayako", "Nijino", "Yukari", "Nozomi", "Mira", "Yuko", "Megumi", "Yumi", "Miharu", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
	newer := []string{"Fujisaki", "Kisaragi", "Himoo", "Katagiri", "Nijino", "Koshiki", "Kiyokawa", "Kagami", "Asahina", "Mikihara", "Saotome", "Tatebayashi", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
	p := ShortStart
	for i, n := range current {
		b, e := (&script.PairEncoder{}).Encode(n)
		if e != nil {
			t.Fatal(e)
		}
		copy(f[p:], b)
		f[p+len(b)] = 0
		binary.LittleEndian.PutUint32(f[PointerTable+i*4:], Base+uint32(p))
		p += len(b) + 1
	}
	if p > ShortEnd {
		t.Fatal("bad fixture")
	}
	// Expose renderer package's already-installed reservation creation in the
	// synthetic test through a local test helper there, without bypassing guards.
	return f, current, newer
}

func TestRendererTailIsNotNaivelyWritable(t *testing.T) {
	f, old, newer := rendererFixture(t)
	before := bytes.Clone(f)
	if _, _, e := StageInRendererPool(f, old, newer); e == nil {
		t.Fatal("uninstalled renderer accepted")
	}
	if !bytes.Equal(f, before) {
		t.Fatal("modified source")
	}
}

// Test actual renderer-owned spare space plus full 132-byte N10 pool. The
// public renderer assembler produces all bytes; no game code is distributed.
func TestStageRendererTailFullN10AndPreserveNeighbors(t *testing.T) {
	f, current, desired := rendererFixture(t)
	site, hook, font, scratch, e := graphics.RendererBuild()
	if e != nil {
		t.Fatal(e)
	}
	put := func(addr uint32, b []byte) { copy(f[int(addr-Base):], b) }
	put(0x8004f2cc, site)
	put(0x8004443c, hook)
	// Original unused renderer reservation is cleared by the real installer.
	clear(f[int(0x8004443c-Base)+len(hook) : int(0x8004443c-Base)+708])
	clear(f[int(0x8004b778-Base) : int(0x8004b778-Base)+948])
	put(0x8004b778, font)
	if scratch != 0x8004451c {
		t.Fatal("unexpected renderer scratch")
	}
	before := bytes.Clone(f)
	got, res, e := StageInRendererPool(f, current, desired)
	if e != nil {
		t.Fatal(e)
	}
	if res.NewBytes != 132 || res.OldBytes != 124 || res.PointerCount != 16 || res.RuntimeValidated {
		t.Fatalf("unexpected result %+v", res)
	}
	if !bytes.Equal(f, before) {
		t.Fatal("mutated input")
	}
	// No payload outside the 180-byte font tail and 16 pointers may change.
	for i := range f {
		isPointer := i >= PointerTable && i < PointerTable+Entries*4
		isTail := i >= int(0x8004b778-Base)+len(font) && i < int(0x8004b778-Base)+948
		if f[i] != got[i] && !isPointer && !isTail {
			t.Fatalf("unexpected modification at %#x", i)
		}
	}
	for i, n := range desired {
		pos := int(binary.LittleEndian.Uint32(got[PointerTable+i*4:]) - Base)
		raw, e := (&script.PairEncoder{}).Encode(n)
		if e != nil {
			t.Fatal(e)
		}
		if pos < int(0x8004b778-Base)+len(font) || pos+len(raw)+1 > int(0x8004b778-Base)+948 || !bytes.Equal(got[pos:pos+len(raw)], raw) || got[pos+len(raw)] != 0 {
			t.Fatalf("incorrect pointer %d", i)
		}
	}
	// Reapplication must fail rather than replacing user changes.
	if _, _, e := StageInRendererPool(got, current, desired); e == nil {
		t.Fatal("accepted second relocation")
	}
	damaged := bytes.Clone(before)
	damaged[int(0x8004b778-Base)+len(font)+5] = 1
	if _, _, e := StageInRendererPool(damaged, current, desired); e == nil {
		t.Fatal("modified font tail accepted")
	}
}
