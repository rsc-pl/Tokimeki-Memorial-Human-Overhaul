package n20arch

// This TEL-owned adapter converts one authenticated saved-surname dialogue
// input for display only. The previous nameplate call already uses the N6
// guard and packed romanizer in the same loaded overlay. The adapter leaves
// the saved CP932 field unchanged and retains the original formatter and
// caller ABI, with a retail fallback for unsupported input.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	telSavedSurnameCall        uint32 = 0x80132878
	telSavedSurnameShim        uint32 = OverlaySlotBase + 0x26000
	telSavedSurnameWindowOff          = 0x26000
	telSavedSurnameWindowBytes        = 0x200
	telSavedSurnameFrame       int16  = 0x80
	telSavedSurnameScratch     int16  = 0x20
	telSavedSurnameCapacity    int16  = 24
)

func telSavedSurnameSource(tel []byte) error {
	if len(tel) != 196608 || sha(tel) != OverlaySHA["TEL.EXN"] {
		return fmt.Errorf("TEL saved surname: original overlay not authenticated")
	}
	source := map[uint32]uint32{
		0x8013284c:              0x3c04800e, // preceding speaker also uses saved surname
		0x80132850:              jalWord(OLOriginalSpeaker),
		0x80132854:              0x24846354,
		0x8013286c:              0x3c04800e, // same saved surname for the following body
		0x80132870:              0x24846354,
		0x80132874:              0x24050001,
		telSavedSurnameCall:     jalWord(telDialogOriginalEntry),
		telSavedSurnameCall + 4: 0x2406000f,
		0x80132880:              0x3c048014,
		0x80132884:              0x2484e5b4,
		0x80132888:              0x24050002,
		0x8013288c:              jalWord(telDialogOriginalEntry),
		0x80132890:              0x2406000f,
	}
	for pc, word := range source {
		if binary.LittleEndian.Uint32(tel[pc-OverlaySlotBase:]) != word {
			return fmt.Errorf("TEL saved surname: source instruction changed at %#x", pc)
		}
	}
	if !allZero(tel[telSavedSurnameWindowOff : telSavedSurnameWindowOff+telSavedSurnameWindowBytes]) {
		return fmt.Errorf("TEL saved surname: owned window occupied in original")
	}
	return nil
}

func telSavedSurnameAdapter() ([]byte, error) {
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, err
	}
	// This is not an alternative converter: the same N6 packed romanizer
	// already used for the preceding source-owned speaker is reused in-place.
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	add := func(d, s uint32, i int16) { w(olADDIU(d, s, i)) }
	lw := func(d, b uint32, i int16) { w(olLW(d, b, i)); w(0) }
	sw := func(d, b uint32, i int16) { w(olSW(d, b, i)) }
	add(29, 29, -telSavedSurnameFrame)
	sw(31, 29, 0x7c)
	sw(4, 29, 0x70)
	sw(5, 29, 0x74)
	sw(6, 29, 0x78)
	sw(7, 29, 0x6c)
	// No dependence on the owner's example name, translation text or ID.
	w(olLUI(8, OLA0SurnameField))
	w(olORI(8, 8, OLA0SurnameField))
	a.b(5, 4, 8, "retail")
	w(0)
	// Fail closed if this overlay's installed N6 body is absent or wrong.
	w(olLUI(8, OLGuardBase))
	lw(9, 8, int16(OLGuardBase&0xffff))
	add(10, 0, int16(OLMagicWord))
	a.b(5, 9, 10, "retail")
	w(0)
	lw(9, 8, int16((OLGuardBase+4)&0xffff))
	add(10, 0, int16(mod.BodyLen))
	a.b(5, 9, 10, "retail")
	w(0)
	lw(4, 29, 0x70)
	add(5, 29, telSavedSurnameScratch)
	add(6, 0, telSavedSurnameCapacity)
	w(jalWord(OLBodyBase))
	add(7, 0, 3) // N20 converter: at most 3 kana, no suffix
	// Return value includes NUL; allow only 2..12 pair bytes.
	add(8, 2, -1)
	w(olSLTIU(9, 8, 13))
	a.b(4, 9, 0, "retail")
	w(0)
	w(olSLTIU(9, 8, 2))
	a.b(5, 9, 0, "retail")
	w(0)
	w(olIType(0x0c, 8, 9, 1))
	a.b(5, 9, 0, "retail")
	w(0)
	// Renderer accepts only authenticated installed pair-font characters.
	add(10, 29, telSavedSurnameScratch)
	a.label("validate")
	w(olLBU(11, 10, 0))
	w(0)
	add(11, 11, -0xa0)
	w(olSLTIU(9, 11, 0x5b))
	a.b(4, 9, 0, "retail")
	w(0)
	add(8, 8, -1)
	add(10, 10, 1)
	a.b(5, 8, 0, "validate")
	w(0)
	// Only the source pointer changes; both original mode arguments survive.
	add(4, 29, telSavedSurnameScratch)
	a.j("format")
	w(0)
	a.label("retail")
	lw(4, 29, 0x70)
	a.label("format")
	lw(5, 29, 0x74)
	lw(6, 29, 0x78)
	lw(7, 29, 0x6c)
	w(jalWord(telDialogOriginalEntry))
	w(0)
	lw(31, 29, 0x7c)
	w(olJR(31))
	add(29, 29, telSavedSurnameFrame)
	a.resolve()
	a.resolveJLabels(telSavedSurnameShim)
	b := words(a.words...)
	if len(b) > telSavedSurnameWindowBytes {
		return nil, fmt.Errorf("TEL saved surname: adapter exceeds isolated window (%d)", len(b))
	}
	out := make([]byte, telSavedSurnameWindowBytes)
	copy(out, b)
	return out, nil
}

func telSavedSurnamePatch(original, staged []byte) ([]byte, []byte, error) {
	if err := telSavedSurnameSource(original); err != nil {
		return nil, nil, err
	}
	shim, err := telSavedSurnameAdapter()
	if err != nil {
		return nil, nil, err
	}
	if len(staged) != len(original) || !allZero(staged[telSavedSurnameWindowOff:telSavedSurnameWindowOff+len(shim)]) {
		return nil, nil, fmt.Errorf("TEL saved surname: staged window occupied")
	}
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(staged[OLPayloadFileOff:OLGuardFileEnd], mod.Guard) ||
		!bytes.Equal(staged[OLBodyFileOff:OLBodyFileOff+len(mod.Body)], mod.Body) {
		return nil, nil, fmt.Errorf("TEL saved surname: source-owned N6 romanizer not present")
	}
	nameOff := int(0x80132850 - OverlaySlotBase)
	if binary.LittleEndian.Uint32(staged[nameOff:]) != jalWord(OLStubRAM) ||
		binary.LittleEndian.Uint32(staged[nameOff+4:]) != OLSpeakerDelay {
		return nil, nil, fmt.Errorf("TEL saved surname: preceding nameplate guard not installed")
	}
	dst := bytes.Clone(staged)
	targetOff := int(telSavedSurnameCall - OverlaySlotBase)
	if binary.LittleEndian.Uint32(dst[targetOff:]) != jalWord(telDialogOriginalEntry) ||
		binary.LittleEndian.Uint32(dst[targetOff+4:]) != 0x2406000f {
		return nil, nil, fmt.Errorf("TEL saved surname: staged caller modified")
	}
	copy(dst[telSavedSurnameWindowOff:], shim)
	binary.LittleEndian.PutUint32(dst[targetOff:], jalWord(telSavedSurnameShim))
	return shim, dst, nil
}
