package n20arch

// TEL's saved surname is also copied/concatenated into two independent
// script-owned dialogue buffers. Unlike the stand-alone saved-field row, these
// callers create mixed strings before entering the retail formatter. Redirect
// only source-authenticated saved-surname copies and appends, never arbitrary
// text or the player's given/nickname field. Original save bytes are read-only.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	telSurnameComposeOff                    = 0x26200
	telSurnameComposeWindow                 = 0x400
	telSurnameCopyShim               uint32 = OverlaySlotBase + 0x26200
	telSurnameAppendShim             uint32 = OverlaySlotBase + 0x26400
	telSurnameComposeFrame           int16  = 0x90
	telSurnameComposeScratch         int16  = 0x20
	telSurnameComposeScratchCapacity int16  = 24
	// The authenticated TEL caller's local char buffer is sp+0x3c to
	// sp+0x5f (36 bytes). Reserve 8 additional bytes for its later suffix.
	telSurnameComposeRoom          = 36
	telSurnameComposeSuffixReserve = 8
)

type telSurnameCompositionSite struct {
	pc       uint32
	original uint32
}

var telSurnameCompositionSites = []telSurnameCompositionSite{
	{0x80132414, 0x800ae0f0}, // surname -> local first line
	{0x801328f4, 0x800ae100}, // local mixed reply += surname
	{0x80132d90, 0x800ae0f0}, // second source-owned surname copy
	{0x80132e18, 0x800ae100}, // second source-owned surname append
}

func telSurnameComposeSource(original []byte) error {
	if len(original) != 196608 || sha(original) != OverlaySHA["TEL.EXN"] {
		return fmt.Errorf("TEL surname composition: unauthenticated original")
	}
	for _, site := range telSurnameCompositionSites {
		off := int(site.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(original[off-8:]) != 0x3c05800e ||
			binary.LittleEndian.Uint32(original[off-4:]) != 0x24a56354 ||
			binary.LittleEndian.Uint32(original[off:]) != jalWord(site.original) ||
			binary.LittleEndian.Uint32(original[off+4:]) != 0x27a4003c {
			return fmt.Errorf("TEL surname composition: source mismatch at %#x", site.pc)
		}
	}
	if !allZero(original[telSurnameComposeOff : telSurnameComposeOff+telSurnameComposeWindow]) {
		return fmt.Errorf("TEL surname composition: source window occupied")
	}
	return nil
}

// Emit an ABI-conserving, overlay-local helper. The two entry points differ
// only in the retail function they ultimately invoke (strcpy versus strcat).
func telSurnameComposeAdapter(base, target uint32, appendMode bool) ([]byte, error) {
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, err
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, i int16) { w(olADDIU(d, s, i)) }
	sw := func(d, s uint32, i int16) { w(olSW(d, s, i)) }
	lw := func(d, s uint32, i int16) { w(olLW(d, s, i)); w(0) }
	lbu := func(d, s uint32, i int16) { w(olLBU(d, s, i)); w(0) }
	branch := func(op, rs, rt uint32, label string) { a.b(op, rs, rt, label); w(0) }
	add(29, 29, -telSurnameComposeFrame)
	sw(31, 29, 0x8c)
	sw(4, 29, 0x80)
	sw(5, 29, 0x84)
	// Source is always the independently saved surname, not a text match.
	w(olLUI(8, OLA0SurnameField))
	w(olORI(8, 8, OLA0SurnameField&65535))
	branch(5, 5, 8, "retail")
	w(olLUI(8, OLGuardBase))
	lw(9, 8, int16(OLGuardBase&65535))
	add(10, 0, int16(OLMagicWord))
	branch(5, 9, 10, "retail")
	lw(9, 8, int16((OLGuardBase+4)&65535))
	add(10, 0, int16(mod.BodyLen))
	branch(5, 9, 10, "retail")
	lw(4, 29, 0x84)
	add(5, 29, telSurnameComposeScratch)
	add(6, 0, telSurnameComposeScratchCapacity)
	w(jalWord(OLBodyBase))
	add(7, 0, 3)
	// v0 includes the trailing zero; encoded pair length must be even 2..12.
	add(8, 2, -1)
	w(olSLTIU(9, 8, 13))
	branch(4, 9, 0, "retail")
	w(olSLTIU(9, 8, 2))
	branch(5, 9, 0, "retail")
	w(olIType(0x0c, 8, 9, 1))
	branch(5, 9, 0, "retail")
	add(10, 29, telSurnameComposeScratch)
	a.label("validate")
	lbu(11, 10, 0)
	add(11, 11, -0xa0)
	w(olSLTIU(9, 11, 0x5b))
	branch(4, 9, 0, "retail")
	add(8, 8, -1)
	add(10, 10, 1)
	branch(5, 8, 0, "validate")
	// The last (source-owned) append is followed by an original suffix
	// concat. Scan a bounded prefix; on uncertainty use retail kana.
	if appendMode {
		lw(10, 29, 0x80)
		add(11, 0, telSurnameComposeRoom-telSurnameComposeSuffixReserve-12)
		a.label("prefix")
		lbu(9, 10, 0)
		branch(4, 9, 0, "valid")
		add(10, 10, 1)
		add(11, 11, -1)
		branch(5, 11, 0, "prefix")
		branch(4, 0, 0, "retail")
		a.label("valid")
	}
	// Pass original destination, but a stack-local converted *source*.
	lw(4, 29, 0x80)
	add(5, 29, telSurnameComposeScratch)
	a.j("call")
	w(0)
	a.label("retail")
	lw(4, 29, 0x80)
	lw(5, 29, 0x84)
	a.label("call")
	w(jalWord(target))
	w(0)
	lw(31, 29, 0x8c)
	w(olJR(31))
	add(29, 29, telSurnameComposeFrame)
	a.resolve()
	a.resolveJLabels(base)
	code := words(a.words...)
	if len(code) > 0x200 {
		return nil, fmt.Errorf("TEL surname composition adapter exceeds subwindow: %d", len(code))
	}
	out := make([]byte, 0x200)
	copy(out, code)
	return out, nil
}

func telSurnameComposePayload() ([]byte, error) {
	copyCode, e := telSurnameComposeAdapter(telSurnameCopyShim, 0x800ae0f0, false)
	if e != nil {
		return nil, e
	}
	appendCode, e := telSurnameComposeAdapter(telSurnameAppendShim, 0x800ae100, true)
	if e != nil {
		return nil, e
	}
	out := append(copyCode, appendCode...)
	return out, nil
}

func telSurnameComposePatch(original, composed []byte) ([]byte, []byte, error) {
	if e := telSurnameComposeSource(original); e != nil {
		return nil, nil, e
	}
	code, e := telSurnameComposePayload()
	if e != nil {
		return nil, nil, e
	}
	if len(composed) != len(original) || !allZero(composed[telSurnameComposeOff:telSurnameComposeOff+len(code)]) {
		return nil, nil, fmt.Errorf("TEL surname composition: staged window occupied")
	}
	mod, e := BuildOverlayLocalModule()
	if e != nil {
		return nil, nil, e
	}
	if !bytes.Equal(composed[OLPayloadFileOff:OLGuardFileEnd], mod.Guard) ||
		!bytes.Equal(composed[OLBodyFileOff:OLBodyFileOff+len(mod.Body)], mod.Body) {
		return nil, nil, fmt.Errorf("TEL surname composition: source N6 not installed")
	}
	out := bytes.Clone(composed)
	copy(out[telSurnameComposeOff:], code)
	for _, site := range telSurnameCompositionSites {
		off := int(site.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out[off:]) != jalWord(site.original) {
			return nil, nil, fmt.Errorf("TEL surname composition: staged site drift at %#x", site.pc)
		}
		shim := telSurnameCopyShim
		if site.original == 0x800ae100 {
			shim = telSurnameAppendShim
		}
		binary.LittleEndian.PutUint32(out[off:], jalWord(shim))
	}
	return code, out, nil
}

func verifyTELSurnameCompose(original, composed, expected []byte) error {
	if e := telSurnameComposeSource(original); e != nil {
		return e
	}
	code, e := telSurnameComposePayload()
	if e != nil {
		return e
	}
	if !bytes.Equal(code, expected) || !bytes.Equal(composed[telSurnameComposeOff:telSurnameComposeOff+len(code)], code) {
		return fmt.Errorf("TEL surname composition: generated body drift")
	}
	for _, site := range telSurnameCompositionSites {
		off := int(site.pc - OverlaySlotBase)
		shim := telSurnameCopyShim
		if site.original == 0x800ae100 {
			shim = telSurnameAppendShim
		}
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(shim) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != 0x27a4003c {
			return fmt.Errorf("TEL surname composition: callsite drift at %#x", site.pc)
		}
	}
	return nil
}
