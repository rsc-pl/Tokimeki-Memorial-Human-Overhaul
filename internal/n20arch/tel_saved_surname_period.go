package n20arch

// TEL source-owned period attachment after dynamic saved-surname composition.
// The pair-font converter pads an odd glyph count with 0xA0: a following
// encoded full stop (0xAE,0xA0) otherwise displays an unwanted blank.
// The shim folds only a one-period suffix and only when the exact tail of
// the script buffer matches a fresh, guarded N6 saved-surname conversion.
// The original C strcat, static text, all saved fields and other suffixes
// remain unchanged on every nonmatching path.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	telSurnamePeriodOff                    = 0x26800
	telSurnamePeriodWindow                 = 0x400
	telSurnamePeriodShim            uint32 = OverlaySlotBase + telSurnamePeriodOff
	telSurnamePeriodFrame           int16  = 0x90
	telSurnamePeriodScratch         int16  = 0x20
	telSurnamePeriodScratchCapacity int16  = 24
)

// The four distinct TEL surname copy/append chains all finish with this
// original suffix strcat. Only a suffix which is exactly a packed '.' may
// be folded; the authenticated callers do not prescribe editorial text.
var telSurnamePeriodSites = []struct{ pc, suffix uint32 }{
	{0x80132424, 0x8013e470},
	{0x80132904, 0x8013e5cc},
	{0x80132da0, 0x8013e70c},
	{0x80132e28, 0x8013e724},
}

func telSurnamePeriodSource(original []byte) error {
	if len(original) != 196608 || sha(original) != OverlaySHA["TEL.EXN"] {
		return fmt.Errorf("TEL period: unauthenticated source")
	}
	for _, site := range telSurnamePeriodSites {
		off := int(site.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(original[off-8:]) != olLUI(5, site.suffix+0x8000) ||
			binary.LittleEndian.Uint32(original[off-4:]) != olADDIU(5, 5, int16(site.suffix&65535)) ||
			binary.LittleEndian.Uint32(original[off:]) != jalWord(0x800ae100) ||
			binary.LittleEndian.Uint32(original[off+4:]) != 0x27a4003c {
			return fmt.Errorf("TEL period: wrong retail suffix caller at %#x", site.pc)
		}
	}
	if !allZero(original[telSurnamePeriodOff : telSurnamePeriodOff+telSurnamePeriodWindow]) {
		return fmt.Errorf("TEL period: source-owned window occupied")
	}
	return nil
}

func telSurnamePeriodPayload() ([]byte, error) {
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, err
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, i int16) { w(olADDIU(d, s, i)) }
	sw := func(d, b uint32, i int16) { w(olSW(d, b, i)) }
	lw := func(d, b uint32, i int16) { w(olLW(d, b, i)); w(0) }
	lbu := func(d, b uint32, i int16) { w(olLBU(d, b, i)); w(0) }
	branch := func(op, rs, rt uint32, label string) { a.b(op, rs, rt, label); w(0) }
	add(29, 29, -telSurnamePeriodFrame)
	sw(31, 29, 0x8c)
	sw(4, 29, 0x80)
	sw(5, 29, 0x84)
	// Exact one punctuation pair and NUL. Do not consume other suffixes.
	lw(8, 29, 0x84)
	lbu(9, 8, 0)
	add(10, 0, 0xae)
	branch(5, 9, 10, "retail")
	lbu(9, 8, 1)
	add(10, 0, 0xa0)
	branch(5, 9, 10, "retail")
	lbu(9, 8, 2)
	branch(5, 9, 0, "retail")
	// Require the exact installed local converter and its immutable length.
	w(olLUI(8, OLGuardBase))
	lw(9, 8, int16(OLGuardBase&65535))
	add(10, 0, int16(OLMagicWord))
	branch(5, 9, 10, "retail")
	lw(9, 8, int16((OLGuardBase+4)&65535))
	add(10, 0, int16(mod.BodyLen))
	branch(5, 9, 10, "retail")
	w(olLUI(4, OLA0SurnameField))
	w(olORI(4, 4, OLA0SurnameField&65535))
	add(5, 29, telSurnamePeriodScratch)
	add(6, 0, telSurnamePeriodScratchCapacity)
	w(jalWord(OLBodyBase))
	add(7, 0, 3)
	// v0 includes NUL: allow 2..12 even packed glyph bytes only.
	add(12, 2, -1)
	w(olSLTIU(9, 12, 13))
	branch(4, 9, 0, "retail")
	w(olSLTIU(9, 12, 2))
	branch(5, 9, 0, "retail")
	w(olIType(0x0c, 12, 9, 1))
	branch(5, 9, 0, "retail")
	// Distinguish N6's final pad from actual neighboring sentence spacing.
	add(8, 29, telSurnamePeriodScratch)
	w(olRType(8, 12, 8, 0x21))
	// An intact packed-glyph prefix does not imply N6 terminated it.
	// Check scratch[count-1] before trusting its padded tail.
	lbu(9, 8, 0)
	branch(5, 9, 0, "retail")
	lbu(9, 8, -1)
	add(10, 0, 0xa0)
	branch(5, 9, 10, "retail")
	// Bounded local script destination (sp+0x3c, 36B). A zero byte must
	// exist within its allocation; otherwise preserve the retail operation.
	lw(8, 29, 0x80)
	add(9, 0, telSurnameComposeRoom)
	a.label("scan")
	lbu(10, 8, 0)
	branch(4, 10, 0, "found")
	add(8, 8, 1)
	add(9, 9, -1)
	branch(5, 9, 0, "scan")
	branch(4, 0, 0, "retail")
	a.label("found")
	// The packed name must be a suffix of the exact current destination;
	// this rejects a copied kana field, a custom address form, or a line
	// whose trailing blank came from another source.
	// Compute actual bytes written = room - remaining, and demand >= N6 len.
	add(10, 0, telSurnameComposeRoom)
	w(olSUBU(10, 10, 9))
	w(olRType(10, 12, 11, 0x2b))
	branch(5, 11, 0, "retail")
	w(olSUBU(8, 8, 12))
	add(9, 29, telSurnamePeriodScratch)
	add(10, 12, 0)
	a.label("compare")
	lbu(11, 8, 0)
	lbu(13, 9, 0)
	branch(5, 11, 13, "retail")
	add(8, 8, 1)
	add(9, 9, 1)
	add(10, 10, -1)
	branch(5, 10, 0, "compare")
	// Exact output tail matches N6 converted source; fold a trailing pair
	// pad into its immediate punctuation, no shifting, no length change.
	// Compare advanced t0 to the actual NUL terminator.
	add(11, 0, 0xae)
	w(olSB(11, 8, -1))
	lw(2, 29, 0x80)
	a.j("done")
	w(0)
	a.label("retail")
	lw(4, 29, 0x80)
	lw(5, 29, 0x84)
	w(jalWord(0x800ae100))
	w(0)
	a.label("done")
	lw(31, 29, 0x8c)
	w(olJR(31))
	add(29, 29, telSurnamePeriodFrame)
	a.resolve()
	a.resolveJLabels(telSurnamePeriodShim)
	code := words(a.words...)
	if len(code) > telSurnamePeriodWindow {
		return nil, fmt.Errorf("TEL period: code %d exceeds window", len(code))
	}
	out := make([]byte, telSurnamePeriodWindow)
	copy(out, code)
	return out, nil
}

func telSurnamePeriodPatch(original, composed []byte) ([]byte, []byte, error) {
	if err := telSurnamePeriodSource(original); err != nil {
		return nil, nil, err
	}
	code, err := telSurnamePeriodPayload()
	if err != nil {
		return nil, nil, err
	}
	if len(composed) != len(original) || !allZero(composed[telSurnamePeriodOff:telSurnamePeriodOff+len(code)]) {
		return nil, nil, fmt.Errorf("TEL period: staged window occupied")
	}
	out := bytes.Clone(composed)
	copy(out[telSurnamePeriodOff:], code)
	for _, s := range telSurnamePeriodSites {
		off := int(s.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out[off:]) != jalWord(0x800ae100) {
			return nil, nil, fmt.Errorf("TEL period: staged caller drift %#x", s.pc)
		}
		binary.LittleEndian.PutUint32(out[off:], jalWord(telSurnamePeriodShim))
	}
	return code, out, nil
}

func verifyTELSurnamePeriod(original, composed, expected []byte) error {
	if err := telSurnamePeriodSource(original); err != nil {
		return err
	}
	code, err := telSurnamePeriodPayload()
	if err != nil {
		return err
	}
	if !bytes.Equal(code, expected) || !bytes.Equal(composed[telSurnamePeriodOff:telSurnamePeriodOff+len(code)], code) {
		return fmt.Errorf("TEL period: payload drift")
	}
	for _, s := range telSurnamePeriodSites {
		off := int(s.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telSurnamePeriodShim) || binary.LittleEndian.Uint32(composed[off+4:]) != 0x27a4003c {
			return fmt.Errorf("TEL period: callsite drift %#x", s.pc)
		}
	}
	return nil
}
