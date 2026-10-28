package n20arch

// name-entry glyphs overlay-local sprite glyph expander. This is an OFFLINE program with
// explicit source/destination pointers, not a hooked game path. It can read
// name-entry drawing's private 18-byte masks without modifying the retail font bank.
// Calling it from the UI requires an independent, lifecycle-proven wrapper
// and screen-scoped GPU routing. safe_to_patch:false, runtime_pass:false.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	LocalExpanderFileOff         = 0x23000
	LocalExpanderRAM      uint32 = OverlaySlotBase + LocalExpanderFileOff
	LocalExpanderMaxBytes        = 256
)

type LocalExpanderCandidate struct {
	Overlay     []byte
	Code        []byte
	Entry       uint32
	SourceBank  uint32
	NoHook      bool
	SafeToPatch bool
	RuntimePass bool
}

// BuildLocalMaskExpander emits actual R3000A instructions for the retail
// padded 12x12 texture layout: a0=18B glyph, a1=96B output; v0=96. Pure leaf,
// preserving a0-a3, s0-s7, sp and ra; clobbers t0-t8 and v0.
func BuildLocalMaskExpander() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	move := func(d, s uint32) { w(olAddu(d, s, 0)) }
	branch := func(op, rs, rt uint32, to string) { a.b(op, rs, rt, to); w(0) }
	lbu := func(d, b uint32, off int16) { w(olIType(0x24, b, d, uint16(off))); w(0) }
	sb := func(d, b uint32, off int16) { w(olIType(0x28, b, d, uint16(off))) }
	move(8, 4)     // t0: source byte
	add(9, 0, 128) // t1: MSB mask
	move(10, 5)    // t2: output
	add(11, 0, 12) // t3: rows
	a.label("row")
	add(12, 0, 12) // t4: columns
	add(13, 0, 0)  // t5: even/odd nibble
	a.label("pixel")
	lbu(14, 8, 0)               // t6 = *src
	w(olRType(14, 9, 15, 0x24)) // and t7,t6,t1
	w(olRType(0, 15, 15, 0x2b)) // sltu t7,zero,t7
	branch(4, 13, 0, "low")
	w(olRType(0, 15, 15, 0x00) | (4 << 6)) // sll t7,t7,4
	lbu(24, 10, 0)                         // t8: output old lower nibble
	w(olRType(24, 15, 24, 0x25))           // or t8,t8,t7
	sb(24, 10, 0)
	add(10, 10, 1)
	add(13, 0, 0)
	branch(4, 0, 0, "next")
	a.label("low")
	sb(15, 10, 0)
	add(13, 0, 1)
	a.label("next")
	w(olRType(0, 9, 9, 0x02) | (1 << 6)) // srl t1,t1,1
	branch(5, 9, 0, "source_ready")
	add(8, 8, 1)
	add(9, 0, 128)
	a.label("source_ready")
	add(12, 12, -1)
	branch(5, 12, 0, "pixel")
	sb(0, 10, 0)
	sb(0, 10, 1)
	add(10, 10, 2)
	add(11, 11, -1)
	branch(5, 11, 0, "row")
	add(2, 0, 96)
	w(olJR(31))
	w(0)
	a.resolve()
	out := words(a.words...)
	if len(out) > LocalExpanderMaxBytes || len(out)%4 != 0 {
		return nil, fmt.Errorf("name-entry glyphs code exceeds private 256B window: %d", len(out))
	}
	return out, nil
}

// BuildNameEntLocalExpander builds a detached, bytewise controlled
// candidate. 42 draw routes remain visually identical, and NO game code calls
// the expander. This deliberately does not manufacture a playable QA image.
func BuildNameEntLocalExpander(original []byte) (LocalExpanderCandidate, error) {
	var c LocalExpanderCandidate
	prev, e := BuildNameEntDrawShadow(original)
	if e != nil {
		return c, e
	}
	code, e := BuildLocalMaskExpander()
	if e != nil {
		return c, e
	}
	if !bytes.Equal(original[LocalExpanderFileOff:LocalExpanderFileOff+LocalExpanderMaxBytes], make([]byte, LocalExpanderMaxBytes)) {
		return c, fmt.Errorf("retail overlay name-entry glyphs expander destination is occupied")
	}
	b := bytes.Clone(prev.ShadowOverlay)
	copy(b[LocalExpanderFileOff:], code)
	binary.BigEndian.PutUint16(b[len(b)-4:], packedTableChecksum(b))
	c = LocalExpanderCandidate{Overlay: b, Code: code, Entry: LocalExpanderRAM, SourceBank: OverlaySlotBase + nameEntryDrawGlyphAtlasFileOff, NoHook: true, SafeToPatch: false, RuntimePass: false}
	return c, nil
}
