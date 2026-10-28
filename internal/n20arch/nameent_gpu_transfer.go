package n20arch

// name-entry transfer: isolated PS1 R3000A GPU-transfer bridge for the NAME_ENT local 12x12
// glyph bank.  OFFLINE ONLY: no queue callsite or game image uses this routine.
//
// This bridges name-entry glyphs's native 96B raster output to the *original retail*
// LoadImage transfer ABI, including its fifth stack argument.  Crucially,
// validating a texture SLOT does not make it OWNED by the keyboard. The
// original shared font staging cache uses the same slots. Before activation,
// the client must establish the correct screen-only slot ownership/lifetime.
// safe_to_patch:false, runtime_pass:false.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	LocalTransferFileOff         = 0x23200
	LocalTransferRAM      uint32 = OverlaySlotBase + LocalTransferFileOff
	LocalTransferMaxBytes        = 512
	GlyphCount                   = 162
	RetailSlotCapacity           = 384
)

type NativeTransferCandidate struct {
	Overlay                []byte
	Code                   []byte
	Entry                  uint32
	RetailUpload           uint32
	RequiresOwnedVRAMSlots bool
	NoHook                 bool
	SafeToPatch            bool
	RuntimePass            bool
}

// BuildNameEntGPUTransfer:
//
//	a0 = glyph index (0..161); a1 = temporary retail font cache slot (0..383)
//	a2 = CALLER-OWNED aligned 96-byte scratch buffer in guest RAM;
//	v0 = 1 if upload called, 0 if arguments fail closed.
//
// No source font modification, no permanent scratch allocation, no hooks.
// The caller MUST prove it owns both the temporary 96B RAM and the selected
// VRAM slot. The 3 retail VRAM banks are SHARED, not keyboard reservations.
func BuildNameEntGPUTransfer() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	li := func(r uint32, n int16) { w(olADDIU(r, 0, n)) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	mv := func(d, s uint32) { w(olAddu(d, s, 0)) }
	br := func(op, rs, rt uint32, label string) { a.b(op, rs, rt, label); w(0) }
	// 0x10: O32 fifth argument. Save register area avoids the fifth arg.
	add(29, 29, -0x60)
	w(olSW(31, 29, 0x5c))
	w(olSW(16, 29, 0x50))
	w(olSW(17, 29, 0x54))
	w(olSW(18, 29, 0x58))
	mv(16, 4)
	mv(17, 5)
	mv(18, 6)
	w(olIType(0x0b, 16, 8, GlyphCount))
	br(4, 8, 0, "fail")
	w(olIType(0x0b, 17, 8, RetailSlotCapacity))
	br(4, 8, 0, "fail")
	br(4, 18, 0, "fail")
	w(olIType(0x0c, 18, 8, 3))
	br(5, 8, 0, "fail") // word alignment
	// Retain guest 0x80010000..0x801FFFA0 range; scratch is 96B.
	w(olLUI(8, 0x80010000))
	w(olRType(18, 8, 9, 0x2b))
	br(5, 9, 0, "fail")
	w(olLUI(8, 0x801F0000))
	w(olORI(8, 8, 0xFFA0))
	w(olRType(8, 18, 9, 0x2b))
	br(5, 9, 0, "fail")
	// name-entry drawing bank + glyphIndex*18; actual name-entry glyphs local expander writes 96B.
	w(olRType(0, 16, 8, 0) | (3 << 6))
	w(olAddu(8, 8, 16))
	w(olRType(0, 8, 8, 0) | (1 << 6))
	w(olLUI(4, OverlaySlotBase+uint32(nameEntryDrawGlyphAtlasFileOff)))
	w(olORI(4, 4, (OverlaySlotBase+uint32(nameEntryDrawGlyphAtlasFileOff))&0xffff))
	w(olAddu(4, 4, 8))
	mv(5, 18)
	w(0x0c000000 | ((LocalExpanderRAM >> 2) & 0x03ffffff))
	w(0)
	li(8, 96)
	br(5, 2, 8, "fail")
	// Retail font slots 0..127 x=0x320, 128..255 x=0x360,
	// 256..383 x=0x3a0. y=0x100+2*(slot&0x78).
	w(olIType(0x0b, 17, 8, 128))
	br(5, 8, 0, "bank0")
	w(olIType(0x0b, 17, 8, 256))
	br(5, 8, 0, "bank1")
	li(9, 0x3a0)
	br(4, 0, 0, "coords")
	a.label("bank1")
	li(9, 0x360)
	br(4, 0, 0, "coords")
	a.label("bank0")
	li(9, 0x320)
	a.label("coords")
	w(olIType(0x0c, 17, 8, 7))
	w(olRType(0, 8, 8, 0) | (2 << 6))
	w(olAddu(4, 9, 8))
	w(olIType(0x0c, 17, 8, 0x78))
	w(olRType(0, 8, 8, 0) | (1 << 6))
	add(5, 8, 0x100)
	li(6, 4)
	li(7, 12)
	w(olSW(18, 29, 0x10)) // fifth O32 arg: 96-byte source data
	w(0x0c000000 | ((RetailLoadImage >> 2) & 0x03ffffff))
	w(0)
	li(2, 1)
	br(4, 0, 0, "done")
	a.label("fail")
	li(2, 0)
	a.label("done")
	w(olLW(16, 29, 0x50))
	w(0)
	w(olLW(17, 29, 0x54))
	w(0)
	w(olLW(18, 29, 0x58))
	w(0)
	w(olLW(31, 29, 0x5c))
	w(0)
	w(olJR(31))
	add(29, 29, 0x60)
	a.resolve()
	code := words(a.words...)
	if len(code) > LocalTransferMaxBytes {
		return nil, fmt.Errorf("name-entry transfer wrapper exceeds private window: %d", len(code))
	}
	return code, nil
}

func BuildNameEntNativeTransfer(original []byte) (NativeTransferCandidate, error) {
	var result NativeTransferCandidate
	old, err := BuildNameEntLocalExpander(original)
	if err != nil {
		return result, err
	}
	code, err := BuildNameEntGPUTransfer()
	if err != nil {
		return result, err
	}
	if !bytes.Equal(original[LocalTransferFileOff:LocalTransferFileOff+LocalTransferMaxBytes], make([]byte, LocalTransferMaxBytes)) {
		return result, fmt.Errorf("retail transfer destination not original-zero")
	}
	overlay := bytes.Clone(old.Overlay)
	copy(overlay[LocalTransferFileOff:], code)
	binary.BigEndian.PutUint16(overlay[len(overlay)-4:], packedTableChecksum(overlay))
	return NativeTransferCandidate{Overlay: overlay, Code: code, Entry: LocalTransferRAM, RetailUpload: RetailLoadImage, RequiresOwnedVRAMSlots: true, NoHook: true, SafeToPatch: false, RuntimePass: false}, nil
}
