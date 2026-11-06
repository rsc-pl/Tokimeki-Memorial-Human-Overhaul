package n20arch

// Two authenticated TEL outgoing self-introductions contain one P marker:
// えっと… Pって言いますけど。 and もしもし、 Pですけど。
// Their callers pass those exact lines to the resident
// 0x80050E8C formatter. The formatter immediately copies its input to its
// own 256-byte stack buffer (BIOS A0:1A strncpy), BEFORE interpreting P and
// queuing any line. This opt-in TEL-local preprocessor substitutes the saved
// player's surname + given name only at those two original callers. It never
// changes the saved kana, source translation, EXE parser or other P records.
// An invalid source, failed converter or missing N6 body runs the unchanged
// retail call. This is an offline candidate pending real frame acceptance.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	telSelfIntroCall        uint32 = 0x80135108
	telSelfIntroSource      uint32 = 0x8013ecd8
	telSelfIntroOtherCall   uint32 = 0x801381b4
	telSelfIntroOtherSource uint32 = 0x8013ef90
	telSelfIntroRetail      uint32 = 0x80050e8c
	telSelfIntroShim        uint32 = OverlaySlotBase + 0x2a000
	telSelfIntroFileOff            = 0x2a000
	telSelfIntroWindow             = 0x1000
	telSelfIntroFrame       int16  = 0xf0
	telSelfIntroMaxSource          = 80
	telSelfIntroOutputLimit        = 128
)

func telSelfIntroRetailSource(exe, original []byte) error {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA || len(original) != 196608 || sha(original) != OverlaySHA["TEL.EXN"] {
		return fmt.Errorf("TEL self-intro: unauthenticated retail inputs")
	}
	for pc, expected := range map[uint32]uint32{
		0x801350f0: 0x3c04800e, 0x801350f4: jalWord(0x80050dfc), 0x801350f8: 0x24846354,
		0x801350fc: 0x3c048014, 0x80135100: 0x2484ecd8, 0x80135104: 0x00002825,
		telSelfIntroCall: jalWord(telSelfIntroRetail), telSelfIntroCall + 4: 0x2406000f,
		0x80135110: jalWord(0x8004ead4), 0x80135114: 0x00002025,
		0x8013819c: 0x3c04800e, 0x801381a0: jalWord(0x80050dfc), 0x801381a4: 0x24846354,
		0x801381a8: 0x3c048014, 0x801381ac: 0x2484ef90, 0x801381b0: 0x00002825,
		telSelfIntroOtherCall: jalWord(telSelfIntroRetail), telSelfIntroOtherCall + 4: 0x2406000f,
		0x801381bc: jalWord(0x8004ead4), 0x801381c0: 0x00002025,
	} {
		if binary.LittleEndian.Uint32(original[pc-OverlaySlotBase:]) != expected {
			return fmt.Errorf("TEL self-intro: caller drift %#x", pc)
		}
	}
	expected := []byte{0x82, 0xa6, 0x82, 0xc1, 0x82, 0xc6, 0x81, 0x63, 0x20, 0x50, 0x82, 0xc1, 0x82, 0xc4, 0x8c, 0xbe, 0x82, 0xa2, 0x82, 0xdc, 0x82, 0xb7, 0x82, 0xaf, 0x82, 0xc7, 0x81, 0x42, 0}
	if !bytes.Equal(original[telSelfIntroSource-OverlaySlotBase:telSelfIntroSource-OverlaySlotBase+uint32(len(expected))], expected) {
		return fmt.Errorf("TEL self-intro: original first source P token mismatch")
	}
	other := []byte{0x82, 0xe0, 0x82, 0xb5, 0x82, 0xe0, 0x82, 0xb5, 0x81, 0x41, 0x20, 0x50, 0x82, 0xc5, 0x82, 0xb7, 0x82, 0xaf, 0x82, 0xc7, 0x81, 0x42, 0}
	if !bytes.Equal(original[telSelfIntroOtherSource-OverlaySlotBase:telSelfIntroOtherSource-OverlaySlotBase+uint32(len(other))], other) {
		return fmt.Errorf("TEL self-intro: original second source P token mismatch")
	}
	// The native formatter's immediate copy must be source-authenticated too.
	const exeBase = uint32(0x80040800)
	for pc, word := range map[uint32]uint32{
		0x80050e8c: 0x27bdfe98, // 360-byte retail frame
		0x80050ed4: 0x27b5004c, // local stack copy destination
		0x80050ed8: 0x02a02025, // move a0,s5
		0x80050edc: 0x24060100, // copy 256 bytes maximum
		0x80050ee0: jalWord(0x800ae090),
	} {
		if binary.LittleEndian.Uint32(exe[pc-exeBase:]) != word {
			return fmt.Errorf("TEL self-intro: resident copy drift %#x", pc)
		}
	}
	if !allZero(original[telSelfIntroFileOff : telSelfIntroFileOff+telSelfIntroWindow]) {
		return fmt.Errorf("TEL self-intro: source window occupied")
	}
	return nil
}

// The code uses exactly 240B of stack, with separate 16B N6 conversion
// buffers and a 128B temporary source line. A source <=80B with one P marker
// and two <=12B converted components cannot overflow the 128B line.
func telSelfIntroPayload() ([]byte, error) {
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, err
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	sw := func(t, b uint32, i int16) { w(olSW(t, b, i)) }
	lw := func(t, b uint32, i int16) { w(olLW(t, b, i)); w(0) }
	lbu := func(t, b uint32, i int16) { w(olLBU(t, b, i)); w(0) }
	sb := func(t, b uint32, i int16) { w(olSB(t, b, i)) }
	beq := func(x, y uint32, lab string) { a.b(4, x, y, lab); w(0) }
	bne := func(x, y uint32, lab string) { a.b(5, x, y, lab); w(0) }
	jump := func(lab string) { beq(0, 0, lab) }
	// 0x10..0x1f surname; 0x20..0x2f given;
	// 0x30..0xaf assembled line (128 bytes); 0xb0..0xcc s0..s7;
	// 0xd0 ra; 0xd4/d8 v0/v1 across register restoration.
	add(29, 29, -telSelfIntroFrame)
	for i, r := range []uint32{16, 17, 18, 19, 20, 21, 22, 23} {
		sw(r, 29, int16(0xb0+4*i))
	}
	sw(31, 29, 0xd0)
	mov(16, 4)
	mov(17, 5)
	mov(18, 6)
	w(olLUI(8, telSelfIntroSource))
	w(olORI(8, 8, telSelfIntroSource&65535))
	beq(16, 8, "source_ok")
	w(olLUI(8, telSelfIntroOtherSource))
	w(olORI(8, 8, telSelfIntroOtherSource&65535))
	bne(16, 8, "retail")
	a.label("source_ok")
	beq(17, 0, "verify_a2")
	jump("retail")
	a.label("verify_a2")
	add(8, 0, 15)
	bne(18, 8, "retail")
	// Guard exact installed TEL-local N6 converter version/length.
	w(olLUI(8, OLGuardBase))
	lw(9, 8, int16(OLGuardBase&65535))
	add(10, 0, int16(OLMagicWord))
	bne(9, 10, "retail")
	lw(9, 8, int16((OLGuardBase+4)&65535))
	add(10, 0, int16(mod.BodyLen))
	bne(9, 10, "retail")
	// Scan only <=80 source bytes, require NUL and exactly one P byte.
	mov(21, 16) // scan pointer
	mov(23, 0)  // P count
	add(22, 0, telSelfIntroMaxSource)
	a.label("source_scan")
	lbu(8, 21, 0)
	beq(8, 0, "source_done")
	add(9, 0, 0x50)
	bne(8, 9, "source_next")
	add(23, 23, 1)
	a.label("source_next")
	add(21, 21, 1)
	add(22, 22, -1)
	bne(22, 0, "source_scan")
	jump("retail")
	a.label("source_done")
	add(9, 0, 1)
	bne(23, 9, "retail")
	// Convert actual immutable saved surname to a private 16B scratch.
	w(olLUI(4, OLA0SurnameField))
	w(olORI(4, 4, OLA0SurnameField&65535))
	add(5, 29, 0x10)
	add(6, 0, 16)
	add(7, 0, 3)
	w(jalWord(OLBodyBase))
	w(0)
	add(19, 2, -1)
	// N6 return includes NUL; 2..12 even encoded glyph bytes.
	w(olSLTIU(8, 19, 13))
	beq(8, 0, "retail")
	w(olSLTIU(8, 19, 2))
	bne(8, 0, "retail")
	w(olIType(12, 19, 8, 1))
	bne(8, 0, "retail")
	add(8, 29, 0x10)
	w(olAddu(9, 8, 19))
	lbu(10, 9, 0)
	bne(10, 0, "retail")
	mov(11, 19)
	a.label("surname_validate")
	lbu(10, 8, 0)
	add(10, 10, -0xa0)
	w(olSLTIU(12, 10, 0x5b))
	beq(12, 0, "retail")
	add(8, 8, 1)
	add(11, 11, -1)
	bne(11, 0, "surname_validate")
	// Drop only N6's final 0xa0 pair pad.
	lbu(10, 9, -1)
	add(11, 0, 0xa0)
	bne(10, 11, "surname_ready")
	add(19, 19, -1)
	a.label("surname_ready")
	beq(19, 0, "retail")
	// Given-name field, separately converted, never mutate save.
	w(olLUI(4, OLFieldPrepSavedGiv))
	w(olORI(4, 4, OLFieldPrepSavedGiv&65535))
	add(5, 29, 0x20)
	add(6, 0, 16)
	add(7, 0, 3)
	w(jalWord(OLBodyBase))
	w(0)
	add(20, 2, -1)
	w(olSLTIU(8, 20, 13))
	beq(8, 0, "retail")
	w(olSLTIU(8, 20, 2))
	bne(8, 0, "retail")
	w(olIType(12, 20, 8, 1))
	bne(8, 0, "retail")
	add(8, 29, 0x20)
	w(olAddu(9, 8, 20))
	lbu(10, 9, 0)
	bne(10, 0, "retail")
	mov(11, 20)
	a.label("given_validate")
	lbu(10, 8, 0)
	add(10, 10, -0xa0)
	w(olSLTIU(12, 10, 0x5b))
	beq(12, 0, "retail")
	add(8, 8, 1)
	add(11, 11, -1)
	bne(11, 0, "given_validate")
	lbu(10, 9, -1)
	add(11, 0, 0xa0)
	bne(10, 11, "given_ready")
	add(20, 20, -1)
	a.label("given_ready")
	beq(20, 0, "retail")
	// Exact worst case: 80-byte original incl NUL, one P removed,
	// +12+1+12 replacement, +optional 1 pad = <=105B incl NUL.
	mov(21, 16)       // source cursor
	add(22, 29, 0x30) // output cursor
	a.label("copy_prefix")
	lbu(8, 21, 0)
	add(9, 0, 0x50)
	beq(8, 9, "prefix_done")
	sb(8, 22, 0)
	add(21, 21, 1)
	add(22, 22, 1)
	jump("copy_prefix")
	a.label("prefix_done")
	add(21, 21, 1) // skip source marker P
	add(8, 29, 0x10)
	mov(9, 19)
	a.label("copy_family")
	beq(9, 0, "family_done")
	lbu(10, 8, 0)
	sb(10, 22, 0)
	add(8, 8, 1)
	add(22, 22, 1)
	add(9, 9, -1)
	jump("copy_family")
	a.label("family_done")
	add(10, 0, 0xa0)
	sb(10, 22, 0)
	add(22, 22, 1)
	add(8, 29, 0x20)
	mov(9, 20)
	a.label("copy_given")
	beq(9, 0, "given_done")
	lbu(10, 8, 0)
	sb(10, 22, 0)
	add(8, 8, 1)
	add(22, 22, 1)
	add(9, 9, -1)
	jump("copy_given")
	a.label("given_done")
	a.label("copy_suffix")
	lbu(8, 21, 0)
	beq(8, 0, "suffix_done")
	sb(8, 22, 0)
	add(21, 21, 1)
	add(22, 22, 1)
	jump("copy_suffix")
	a.label("suffix_done")
	// Pair-font text must be even-length before the final NUL.
	add(8, 29, 0x30)
	w(olSUBU(9, 22, 8))
	w(olIType(12, 9, 10, 1))
	beq(10, 0, "write_nul")
	add(10, 0, 0xa0)
	sb(10, 22, 0)
	add(22, 22, 1)
	a.label("write_nul")
	sb(0, 22, 0)
	add(4, 29, 0x30)
	jump("call_retail")
	a.label("retail")
	mov(4, 16)
	a.label("call_retail")
	mov(5, 17)
	mov(6, 18)
	w(jalWord(telSelfIntroRetail))
	w(0)
	sw(2, 29, 0xd4)
	sw(3, 29, 0xd8)
	for i, r := range []uint32{16, 17, 18, 19, 20, 21, 22, 23} {
		w(olLW(r, 29, int16(0xb0+4*i)))
	}
	w(olLW(31, 29, 0xd0))
	w(olLW(2, 29, 0xd4))
	w(olLW(3, 29, 0xd8))
	w(olJR(31))
	add(29, 29, telSelfIntroFrame)
	a.resolve()
	a.resolveJLabels(telSelfIntroShim)
	code := words(a.words...)
	if len(code) > telSelfIntroWindow {
		return nil, fmt.Errorf("TEL self-intro helper %d exceeds %d", len(code), telSelfIntroWindow)
	}
	out := make([]byte, telSelfIntroWindow)
	copy(out, code)
	return out, nil
}

func telSelfIntroPatch(exe, original, composed []byte) ([]byte, []byte, error) {
	if err := telSelfIntroRetailSource(exe, original); err != nil {
		return nil, nil, err
	}
	code, err := telSelfIntroPayload()
	if err != nil {
		return nil, nil, err
	}
	if len(composed) != len(original) || !allZero(composed[telSelfIntroFileOff:telSelfIntroFileOff+telSelfIntroWindow]) {
		return nil, nil, fmt.Errorf("TEL self-intro: staged code window occupied")
	}
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(composed[OLPayloadFileOff:OLGuardFileEnd], mod.Guard) || !bytes.Equal(composed[OLBodyFileOff:OLBodyFileOff+len(mod.Body)], mod.Body) {
		return nil, nil, fmt.Errorf("TEL self-intro: N6 module not installed")
	}
	dst := bytes.Clone(composed)
	copy(dst[telSelfIntroFileOff:], code)
	for _, pc := range []uint32{telSelfIntroCall, telSelfIntroOtherCall} {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(dst[off:]) != jalWord(telSelfIntroRetail) || binary.LittleEndian.Uint32(dst[off+4:]) != 0x2406000f {
			return nil, nil, fmt.Errorf("TEL self-intro: composed caller drift %#x", pc)
		}
		binary.LittleEndian.PutUint32(dst[off:], jalWord(telSelfIntroShim))
	}
	return code, dst, nil
}

func verifyTELSelfIntro(exe, original, composed, expected []byte) error {
	if err := telSelfIntroRetailSource(exe, original); err != nil {
		return err
	}
	code, err := telSelfIntroPayload()
	if err != nil {
		return err
	}
	if !bytes.Equal(code, expected) || !bytes.Equal(composed[telSelfIntroFileOff:telSelfIntroFileOff+len(code)], code) {
		return fmt.Errorf("TEL self-intro: payload drift")
	}
	for _, pc := range []uint32{telSelfIntroCall, telSelfIntroOtherCall} {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telSelfIntroShim) || binary.LittleEndian.Uint32(composed[off+4:]) != 0x2406000f {
			return fmt.Errorf("TEL self-intro: caller drift %#x", pc)
		}
	}
	return nil
}
