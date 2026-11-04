package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Valentine name-pair suffix rotation is limited to the original dynamic
// selector path. The retail routine has already populated the original G
// field; the existing guarded N6-FP field preparation still runs first.
// No source translation, save field, other overlay, or global strcat is owned.
const valenDynamicFieldPrepPC uint32 = 0x80132D4C

// valenSanRotationAddress is the beginning of the authenticated, original
// 12-byte name work interval. Neither the presence of the next named field
// nor this shim establishes that larger strings are safe in that interval.
const valenSanRotationAddress uint32 = 0x800CA190

func valenSanRotationBody(entry uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	branch := func(rs, rt uint32, target string) { a.b(5, rs, rt, target); w(0) }
	// Preserve retail's v0/v1 results and the return address. All other
	// registers used here are caller-saved, and no $s register is modified.
	add(29, 29, -0x30)
	w(olSW(31, 29, 0x20))
	w(jalWord(OLStubRAM))
	w(0)
	w(olSW(2, 29, 0x24))
	w(olSW(3, 29, 0x28))
	w(olLUI(8, valenSanRotationAddress+0x8000))
	add(8, 8, -24176)
	// Match only the complete in-bounds layout:
	//   five Latin bytes, 0xA0, encoded -san, NUL.
	// This is the 11-byte old output for a five-letter surname.
	// Rotate the pad to the END, retaining all 11 bytes and pair parity.
	for i, want := range []uint8{0xa0, 0xad, 0xf3, 0xe1, 0xee, 0} {
		w(olLBU(9, 8, int16(i+5)))
		w(0) // original R3000A load delay
		add(10, 0, int16(want))
		branch(9, 10, "return")
	}
	// The preceding five bytes must be actual paired Latin glyphs rather
	// than another control sequence masquerading as a surname.
	for i := int16(0); i < 5; i++ {
		w(olLBU(9, 8, i))
		w(0)
		add(10, 9, -0xa0)
		w(olSLTIU(11, 10, 0x5b)) // 0xa0..0xfa
		a.b(4, 11, 0, "return")
		w(0)
	}
	for i, glyph := range []uint8{0xad, 0xf3, 0xe1, 0xee, 0xa0} {
		add(9, 0, int16(glyph))
		w(olSB(9, 8, int16(i+5)))
	}
	a.label("return")
	w(olLW(2, 29, 0x24))
	w(0)
	w(olLW(3, 29, 0x28))
	w(0)
	w(olLW(31, 29, 0x20))
	w(0)
	w(olJR(31))
	add(29, 29, 0x30)
	a.resolve()
	a.resolveJLabels(entry)
	return words(a.words...)
}

func valenSanExtendedModule(m OverlayFieldPrepModule) (OverlayFieldPrepModule, error) {
	if m.FamilyDst != N20RelocFamilyAddr || m.GivenDst != N20RelocGivenAddr ||
		m.SlotBytes != N20RelocSlotBytes || m.VerifierBytes != 184 {
		return m, fmt.Errorf("Valentine san module source/integration geometry drift")
	}
	m.Guard = bytes.Clone(m.Guard)
	m.Body = bytes.Clone(m.Body)
	entry := m.ModuleEnd()
	body := valenSanRotationBody(entry)
	m.Body = append(m.Body, body...)
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	if len(m.Body) > OLBodyCapacity || entry+uint32(len(body)) > OLBodyBase+OLBodyCapacity {
		return m, fmt.Errorf("Valentine san module code exceeds source-zero carrier")
	}
	m.BodyLen = len(m.Body)
	m.Sum32, m.XOR32 = 0, 0
	for i := 0; i < len(m.Body); i += 4 {
		w := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += w
		m.XOR32 ^= w
	}
	v, err := buildOverlayVerifierMagic(OLFieldPrepMagicWord, m.Sum32, m.XOR32, uint32(m.BodyLen))
	if err != nil || len(v) != m.VerifierBytes {
		return m, fmt.Errorf("Valentine san verifier geometry: %v", err)
	}
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(m.BodyLen))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], v)
	m.BodyEndRAM = OLBodyBase + uint32(m.BodyLen)
	m.SHA = sha(append(append([]byte{}, m.Guard...), m.Body...))
	return m, nil
}

func valenSanPatch(original, patched []byte, base, extended OverlayFieldPrepModule) error {
	if len(original) != 196608 || sha(original) != OverlaySHA["VALEN.EXN"] || len(patched) != len(original) {
		return fmt.Errorf("Valentine san: unauthenticated original overlay")
	}
	off := int(valenDynamicFieldPrepPC - OverlaySlotBase)
	if binary.LittleEndian.Uint32(original[off:]) != jalWord(OLFieldPrepOriginal) ||
		binary.LittleEndian.Uint32(original[off+4:]) != 0xa02471df ||
		binary.LittleEndian.Uint32(patched[off:]) != jalWord(OLStubRAM) ||
		binary.LittleEndian.Uint32(patched[off+4:]) != 0xa02471df {
		return fmt.Errorf("Valentine san: dynamic selector JAL/delay drift")
	}
	if !allZero(original[OLPayloadFileOff:OLPayloadEndOff]) ||
		!allZero(patched[OLBodyFileOff+len(base.Body):OLBodyFileOff+len(extended.Body)]) ||
		!bytes.Equal(patched[OLBodyFileOff:OLBodyFileOff+len(base.Body)], base.Body) {
		return fmt.Errorf("Valentine san: source-zero tail / base module drift")
	}
	if extended.ModuleEnd() > OLBodyBase+OLBodyCapacity {
		return fmt.Errorf("Valentine san: module overrun")
	}
	copy(patched[OLPayloadFileOff:OLGuardFileEnd], extended.Guard)
	copy(patched[OLBodyFileOff:OLBodyFileOff+len(extended.Body)], extended.Body)
	binary.LittleEndian.PutUint32(patched[off:], jalWord(base.ModuleEnd()))
	ck := packedTableChecksum(patched)
	patched[0x2fffc], patched[0x2fffd] = byte(ck>>8), byte(ck)
	return nil
}
