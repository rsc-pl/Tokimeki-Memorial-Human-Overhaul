package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	date2NativePOriginal uint32 = 0x80051508
	date2NativePStub     uint32 = OLVerifierRAM + 184
	date2Nickname        uint32 = 0x800E6364
)

// Both callers use the native destination/selector ABI, not field prep.
// Run the native producer once, then convert only the exact saved given
// name plus kun. A matching nickname (including an ambiguous identical
// spelling) takes precedence and is never converted by this adapter.
func buildDATE2NativePAdapter(entry uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	imm := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	addr := func(r, v uint32) { w(olLUI(r, v)); w(olORI(r, r, v&0xffff)) }
	lbu := func(d, s uint32, off int16) { w(olLBU(d, s, off)); w(0) }
	beq := func(s, t uint32, l string) { a.b(4, s, t, l); w(0) }
	bne := func(s, t uint32, l string) { a.b(5, s, t, l); w(0) }
	// Unexpected arguments retain the exact native ABI.
	addr(8, givenKunExtended)
	bne(4, 8, "native")
	bne(5, 0, "native")
	imm(29, 29, -0x40)
	w(olSW(31, 29, 0x30))
	w(jalWord(date2NativePOriginal))
	w(0)
	w(olSW(2, 29, 0x34))
	w(olSW(3, 29, 0x38))
	// Compare the nickname first. Eight matching bytes are also ambiguous
	// if the native nickname has no terminator inside its saved field.
	addr(8, date2Nickname)
	addr(9, givenKunExtended)
	imm(10, 0, 8)
	a.label("nickname")
	lbu(11, 8, 0)
	lbu(12, 9, 0)
	bne(11, 12, "given")
	beq(11, 0, "retail")
	imm(8, 8, 1)
	imm(9, 9, 1)
	imm(10, 10, -1)
	bne(10, 0, "nickname")
	a.j("retail")
	w(0)
	a.label("given")
	addr(8, OLFieldPrepSavedGiv)
	addr(9, givenKunExtended)
	imm(10, 0, 6)
	a.label("match")
	lbu(11, 8, 0)
	beq(11, 0, "suffix")
	beq(10, 0, "retail")
	lbu(12, 9, 0)
	bne(11, 12, "retail")
	imm(8, 8, 1)
	imm(9, 9, 1)
	imm(10, 10, -1)
	a.j("match")
	w(0)
	a.label("suffix")
	// Native CP932 kun, with exact terminator; no arbitrary suffix guessing.
	lbu(11, 9, 0)
	imm(12, 0, 0x8c)
	bne(11, 12, "retail")
	lbu(11, 9, 1)
	imm(12, 0, 0x4e)
	bne(11, 12, "retail")
	lbu(11, 9, 2)
	bne(11, 0, "retail")
	// The authenticated packed core adds the suffix before pair padding.
	// It writes only to a 16-byte frame-owned scratch C-string.
	addr(4, OLFieldPrepSavedGiv)
	imm(5, 29, 0x10)
	imm(6, 0, 16)
	imm(7, 0, 0x103)
	w(jalWord(OLBodyBase))
	w(0)
	// Core returns zero or the complete length including NUL. Bound the
	// result again before copying; the guard authenticates the core itself.
	imm(8, 2, -1)
	w(olSLTIU(10, 8, 16))
	beq(10, 0, "retail")
	w(olSLTIU(10, 8, 6))
	bne(10, 0, "retail")
	w(olIType(12, 8, 10, 1))
	bne(10, 0, "retail")
	imm(9, 29, 0x10)
	w(olAddu(10, 9, 8))
	lbu(11, 10, 0)
	bne(11, 0, "retail")
	addr(10, givenKunExtended)
	a.label("copy")
	lbu(11, 9, 0)
	w(olSB(11, 10, 0))
	imm(9, 9, 1)
	imm(10, 10, 1)
	imm(2, 2, -1)
	bne(2, 0, "copy")
	a.label("retail")
	w(olLW(2, 29, 0x34))
	w(olLW(3, 29, 0x38))
	w(olLW(31, 29, 0x30))
	w(0)
	w(olJR(31))
	imm(29, 29, 0x40)
	a.label("native")
	w(jWord(date2NativePOriginal))
	w(0)
	a.resolve()
	a.resolveJLabels(entry)
	return words(a.words...)
}

func extendDATE2NativePModule(m OverlayFieldPrepModule) (OverlayFieldPrepModule, error) {
	if m.FamilyDst != N20RelocFamilyAddr || m.GivenDst != N20RelocGivenAddr ||
		m.SlotBytes != N20RelocSlotBytes || m.VerifierBytes != 184 ||
		len(m.Body) != 3584 || len(m.Guard) != OLGuardBytes ||
		date2NativePStub+24 > OLBodyBase || !allZero(m.Guard[date2NativePStub-OLGuardBase:]) {
		return m, fmt.Errorf("DATE2 incompatible field prep module or guard gap")
	}
	entry := m.ModuleEnd()
	m.Guard = bytes.Clone(m.Guard)
	m.Body = append(bytes.Clone(m.Body), buildDATE2NativePAdapter(entry)...)
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	if len(m.Body) > OLBodyCapacity {
		return m, fmt.Errorf("DATE2 native P adapter body %d exceeds %d", len(m.Body), OLBodyCapacity)
	}
	m.BodyLen = len(m.Body)
	m.BodyEndRAM = OLBodyBase + uint32(m.BodyLen)
	m.Sum32, m.XOR32 = 0, 0
	for i := 0; i < m.BodyLen; i += 4 {
		v := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += v
		m.XOR32 ^= v
	}
	verifier, err := buildOverlayVerifierMagic(OLFieldPrepMagicWord, m.Sum32, m.XOR32, uint32(m.BodyLen))
	if err != nil || len(verifier) != m.VerifierBytes {
		return m, fmt.Errorf("DATE2 verifier geometry")
	}
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(m.BodyLen))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], verifier)
	stub, err := buildDispatchStub(date2NativePOriginal, entry)
	if err != nil || len(stub) != 24 {
		return m, fmt.Errorf("DATE2 second stub geometry")
	}
	copy(m.Guard[date2NativePStub-OLGuardBase:], stub)
	m.SHA = sha(append(bytes.Clone(m.Guard), m.Body...))
	return m, nil
}

func date2NativePWords(original []byte) ([]N20ManifestWord, error) {
	const owner = "DATE2.EXN"
	if len(original) != 196608 || sha(original) != OverlaySHA[owner] {
		return nil, fmt.Errorf("DATE2 P source identity mismatch")
	}
	var out []N20ManifestWord
	for _, pc := range []uint32{0x80132F28, 0x801335BC} {
		off := pc - OverlaySlotBase
		if binary.LittleEndian.Uint32(original[off:]) != jalWord(date2NativePOriginal) ||
			binary.LittleEndian.Uint32(original[off+4:]) != 0x00002825 {
			return nil, fmt.Errorf("DATE2 P caller/delay drift %#x", pc)
		}
		out = append(out, N20ManifestWord{Owner: owner, PC: pc, Old: jalWord(date2NativePOriginal),
			New: jalWord(date2NativePStub), Kind: "jal", Role: "DATE2 direct native P producer",
			Reason: "native selector-zero output then exact given-kun conversion; preserve nickname and original fallback"})
	}
	return out, nil
}

func applyDATE2NativeP(original, patched []byte, base, extended OverlayFieldPrepModule) error {
	ws, err := date2NativePWords(original)
	if err != nil {
		return err
	}
	if len(patched) != len(original) || !bytes.Equal(patched[OLPayloadFileOff:OLGuardFileEnd], base.Guard) ||
		!bytes.Equal(patched[OLBodyFileOff:OLBodyFileOff+len(base.Body)], base.Body) ||
		!allZero(patched[OLBodyFileOff+len(base.Body):OLBodyFileOff+len(extended.Body)]) {
		return fmt.Errorf("DATE2 P staged module collision")
	}
	for _, w := range ws {
		off := w.PC - OverlaySlotBase
		if binary.LittleEndian.Uint32(patched[off:]) != w.Old ||
			binary.LittleEndian.Uint32(patched[off+4:]) != 0x00002825 {
			return fmt.Errorf("DATE2 P staged caller collision")
		}
	}
	copy(patched[OLPayloadFileOff:OLGuardFileEnd], extended.Guard)
	copy(patched[OLBodyFileOff:OLBodyFileOff+len(extended.Body)], extended.Body)
	for _, w := range ws {
		binary.LittleEndian.PutUint32(patched[w.PC-OverlaySlotBase:], w.New)
	}
	ck := packedTableChecksum(patched)
	binary.BigEndian.PutUint16(patched[0x2fffc:], ck)
	return nil
}
