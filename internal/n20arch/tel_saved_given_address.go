package n20arch

// TEL mode-13 address preparation is a distinct, source-authenticated case:
// retail EXE 0x80051508 selector 13 -> 0x800519A4 copies *saved given name*
// 0x800E635C (no suffix) into TEL's 16-byte sp+0x2c field. The caller then
// concatenates that field into its own dialogue buffer. The display-only
// replacement is intentionally after the original retail helper: never
// modify the saved kana, EXE selector table, or any other mode's semantics.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	telGivenAddressCall      uint32 = 0x80132498
	telGivenAddressShim      uint32 = OverlaySlotBase + 0x26600
	telGivenAddressOff              = 0x26600
	telGivenAddressWindow           = 0x200
	telGivenAddressFrame     int16  = 0x90
	telGivenAddressScratch   int16  = 0x20
	telGivenAddressCapacity  int16  = 24
	telGivenAddressSlotBytes int16  = 16 // script sp+0x2c..0x3b; next field sp+0x3c
)

func telGivenAddressSource(exe, tel []byte) error {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA || len(tel) != 196608 || sha(tel) != OverlaySHA["TEL.EXN"] {
		return fmt.Errorf("TEL given address: unauthenticated EXE/TEL sources")
	}
	// Retail jump-table selector 13 must dispatch only to the saved given
	// field copy, with no implicit nickname/honorific or global formatter.
	const exeBase = uint32(0x80040800)
	origEXE := map[uint32]uint32{
		0x80051510: 0x2ca10010,          // sltiu at,a1,16
		0x8005152c: 0x8c2efb94,          // 16-way signed-offset table
		0x800AFBC8: 0x800519a4,          // selector 13
		0x800519a4: 0x3c05800e,          // lui a1,0x800e
		0x800519a8: 0x24a5635c,          // saved given name, not surname/nickname
		0x800519ac: jalWord(0x800ae0f0), // strcpy
		0x800519b0: 0x02002025,          // move a0,s0 in delay slot
		0x800519b4: 0x10000029,          // return, not append honorific
	}
	for pc, word := range origEXE {
		if binary.LittleEndian.Uint32(exe[pc-exeBase:]) != word {
			return fmt.Errorf("TEL given address: retail selector mismatch at %#x", pc)
		}
	}
	original := map[uint32]uint32{
		0x80132484:              0x3c058014, // English prefix source
		0x80132488:              0x24a5e47c,
		0x8013248c:              jalWord(0x800ae0f0),
		0x80132490:              0x27a4003c, // script destination sp+0x3c
		0x80132494:              0x27a4002c, // *different* 16-byte given field
		telGivenAddressCall:     jalWord(0x80051508),
		telGivenAddressCall + 4: 0x2405000d, // selector 13, exclusively
		0x801324a0:              0x27a4003c,
		0x801324a4:              jalWord(0x800ae100),
		0x801324a8:              0x27a5002c, // concatenate original field to prefix
		0x801324ac:              0x3c058014,
		0x801324b0:              0x24a5e484,
		0x801324b4:              jalWord(0x800ae100),
		0x801324b8:              0x27a4003c,
		0x801324c4:              jalWord(telDialogOriginalEntry),
		0x801324c8:              0x2406000d,
	}
	for pc, word := range original {
		if binary.LittleEndian.Uint32(tel[pc-OverlaySlotBase:]) != word {
			return fmt.Errorf("TEL given address: caller instruction mismatch at %#x", pc)
		}
	}
	if !allZero(tel[telGivenAddressOff : telGivenAddressOff+telGivenAddressWindow]) {
		return fmt.Errorf("TEL given address: original code window occupied")
	}
	return nil
}

// Retain the *actual* retail selector/copy first, then replace the just-built
// field only when it exactly equals the saved given bytes. No guessed address
// forms, dynamic stack aliases or changes to any other selector are allowed.
func telGivenAddressPayload() ([]byte, error) {
	mod, e := BuildOverlayLocalModule()
	if e != nil {
		return nil, e
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, i int16) { w(olADDIU(d, s, i)) }
	sw := func(d, b uint32, i int16) { w(olSW(d, b, i)) }
	lw := func(d, b uint32, i int16) { w(olLW(d, b, i)); w(0) }
	lbu := func(d, b uint32, i int16) { w(olLBU(d, b, i)); w(0) }
	branch := func(op, rs, rt uint32, label string) { a.b(op, rs, rt, label); w(0) }
	add(29, 29, -telGivenAddressFrame)
	sw(31, 29, 0x8c)
	sw(4, 29, 0x80)
	sw(5, 29, 0x84)
	// Exact original behavior and return are always executed first.
	w(jalWord(0x80051508))
	w(0)
	sw(2, 29, 0x88)
	lw(8, 29, 0x84)
	add(9, 0, 13)
	branch(5, 8, 9, "done")
	lw(8, 29, 0x80)
	// Optional strict consistency check: selector 13 must return dest.
	lw(9, 29, 0x88)
	branch(5, 8, 9, "done")
	// Original output must be exactly saved given (NUL included) within
	// original eight-byte field. Unrecognised runtime selection -> retail.
	w(olLUI(8, OLFieldPrepSavedGiv))
	w(olORI(8, 8, OLFieldPrepSavedGiv&65535))
	lw(9, 29, 0x80)
	add(10, 0, 8)
	a.label("compare")
	lbu(11, 8, 0)
	lbu(12, 9, 0)
	branch(5, 11, 12, "done")
	branch(4, 11, 0, "matched")
	add(8, 8, 1)
	add(9, 9, 1)
	add(10, 10, -1)
	branch(5, 10, 0, "compare")
	branch(4, 0, 0, "done")
	a.label("matched")
	// Guard the installed TEL-local N6 body, not an EXE/global converter.
	w(olLUI(8, OLGuardBase))
	lw(9, 8, int16(OLGuardBase&65535))
	add(10, 0, int16(OLMagicWord))
	branch(5, 9, 10, "done")
	lw(9, 8, int16((OLGuardBase+4)&65535))
	add(10, 0, int16(mod.BodyLen))
	branch(5, 9, 10, "done")
	w(olLUI(4, OLFieldPrepSavedGiv))
	w(olORI(4, 4, OLFieldPrepSavedGiv&65535))
	add(5, 29, telGivenAddressScratch)
	add(6, 0, telGivenAddressCapacity)
	w(jalWord(OLBodyBase))
	add(7, 0, 3)
	// Return length includes NUL; verify even 2..12 encoded bytes and
	// a 16-byte exact destination, independent of owner's sample name.
	add(8, 2, -1)
	w(olSLTIU(9, 8, 13))
	branch(4, 9, 0, "done")
	w(olSLTIU(9, 8, 2))
	branch(5, 9, 0, "done")
	w(olIType(0x0c, 8, 9, 1))
	branch(5, 9, 0, "done")
	add(10, 29, telGivenAddressScratch)
	a.label("valid")
	lbu(11, 10, 0)
	add(11, 11, -0xa0)
	w(olSLTIU(9, 11, 0x5b))
	branch(4, 9, 0, "done")
	add(8, 8, -1)
	add(10, 10, 1)
	branch(5, 8, 0, "valid")
	lw(4, 29, 0x80)
	add(5, 29, telGivenAddressScratch)
	w(jalWord(0x800ae0f0))
	w(0)
	// strcpy return is destination, identical to selector-13 retail return.
	sw(2, 29, 0x88)
	a.label("done")
	lw(2, 29, 0x88)
	lw(31, 29, 0x8c)
	w(olJR(31))
	add(29, 29, telGivenAddressFrame)
	a.resolve()
	a.resolveJLabels(telGivenAddressShim)
	code := words(a.words...)
	if len(code) > telGivenAddressWindow {
		return nil, fmt.Errorf("TEL given address exceeds authenticated window: %d", len(code))
	}
	out := make([]byte, telGivenAddressWindow)
	copy(out, code)
	return out, nil
}

func telGivenAddressPatch(exe, original, composed []byte) ([]byte, []byte, error) {
	if e := telGivenAddressSource(exe, original); e != nil {
		return nil, nil, e
	}
	code, e := telGivenAddressPayload()
	if e != nil {
		return nil, nil, e
	}
	if len(composed) != len(original) || !allZero(composed[telGivenAddressOff:telGivenAddressOff+len(code)]) {
		return nil, nil, fmt.Errorf("TEL given address: staged window occupied")
	}
	mod, e := BuildOverlayLocalModule()
	if e != nil {
		return nil, nil, e
	}
	if !bytes.Equal(composed[OLPayloadFileOff:OLGuardFileEnd], mod.Guard) || !bytes.Equal(composed[OLBodyFileOff:OLBodyFileOff+len(mod.Body)], mod.Body) {
		return nil, nil, fmt.Errorf("TEL given address: N6 body not installed")
	}
	out := bytes.Clone(composed)
	copy(out[telGivenAddressOff:], code)
	off := int(telGivenAddressCall - OverlaySlotBase)
	if binary.LittleEndian.Uint32(out[off:]) != jalWord(0x80051508) || binary.LittleEndian.Uint32(out[off+4:]) != 0x2405000d {
		return nil, nil, fmt.Errorf("TEL given address: staged callsite drift")
	}
	binary.LittleEndian.PutUint32(out[off:], jalWord(telGivenAddressShim))
	return code, out, nil
}

func verifyTELGivenAddress(exe, original, composed, expected []byte) error {
	if e := telGivenAddressSource(exe, original); e != nil {
		return e
	}
	code, e := telGivenAddressPayload()
	if e != nil {
		return e
	}
	if !bytes.Equal(code, expected) || !bytes.Equal(composed[telGivenAddressOff:telGivenAddressOff+len(code)], code) {
		return fmt.Errorf("TEL given address: generated helper drift")
	}
	off := int(telGivenAddressCall - OverlaySlotBase)
	if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telGivenAddressShim) || binary.LittleEndian.Uint32(composed[off+4:]) != 0x2405000d {
		return fmt.Errorf("TEL given address: callsite drift")
	}
	return nil
}
