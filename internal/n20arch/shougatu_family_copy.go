package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ChristmasFamily guarded, source-specific adapter for the authenticated Christmas overlay.
// Original SHOU 0x8013DC2C is strcpy(dst,src), NOT fieldprep(selector).
// This ABI-compatible adapter is scoped to saved surname -> relocated family.
// Static and guest-MIPS verified; whole-game runtime remains unverified.
const (
	shouFamilySHOUCopyPC  uint32 = 0x8013DC2C
	shouFamilySHOUCopyOld uint32 = 0x800AE0F0
	shouFamilySHOUStub    uint32 = OLVerifierRAM + 184
	shouFamilyFamilyFrame int16  = 0x50
	shouFamilySavedV0     int16  = 0x20
	shouFamilySavedV1     int16  = 0x24
	shouFamilySavedRA     int16  = 0x28
	shouFamilySavedDST    int16  = 0x2C
	shouFamilySavedSRC    int16  = 0x30
	shouFamilyLength      int16  = 0x34
)

func shouFamilyBuildStrcpyAdapter(entry uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	imm := func(dst, src uint32, n int16) { w(olADDIU(dst, src, n)) }
	sw := func(src uint32, off int16) { w(olSW(src, 29, off)) }
	lw := func(dst uint32, off int16) { w(olLW(dst, 29, off)) }
	j := func(addr uint32) { w(jalWord(addr)); w(0) }
	addr := func(reg, addr uint32) { w(olLUI(reg, addr)); w(olORI(reg, reg, addr&0xffff)) }
	imm(29, 29, -shouFamilyFamilyFrame)
	sw(31, shouFamilySavedRA)
	sw(4, shouFamilySavedDST)
	sw(5, shouFamilySavedSRC)
	// Run retail first: ABI/side effects/copying remain unchanged on rejection.
	j(shouFamilySHOUCopyOld)
	sw(2, shouFamilySavedV0)
	sw(3, shouFamilySavedV1)
	lw(8, shouFamilySavedDST)
	lw(9, shouFamilySavedSRC)
	// The original Christmas source keeps four scene-local A labels in its
	// original buffer. Some selected N10 formatters read the relocated A.
	// Preserve the retail destination and mirror only exact original labels
	// into the 16-byte relocated A if the *complete* source C-string fits.
	addr(10, 0x800CA188)
	a.b(5, 8, 10, "family")
	w(0)
	for _, source := range []uint32{0x80143760, 0x8014394c, 0x80143954, 0x80143960} {
		addr(10, source)
		a.b(4, 9, 10, "mirror_verify")
		w(0)
	}
	a.j("retail")
	w(0)
	a.label("mirror_verify")
	imm(10, 0, 16) // capacity includes NUL
	imm(11, 9, 0)  // source pointer (MIPS load-delay safe)
	a.label("mirror_scan")
	a.b(4, 10, 0, "retail")
	w(0)
	w(olLBU(12, 11, 0))
	w(0)
	a.b(4, 12, 0, "mirror_copy")
	w(0)
	imm(11, 11, 1)
	imm(10, 10, -1)
	a.j("mirror_scan")
	w(0)
	a.label("mirror_copy")
	addr(4, 0x800B35A4)
	lw(5, shouFamilySavedSRC)
	j(shouFamilySHOUCopyOld)
	a.j("retail")
	w(0)
	a.label("family")
	addr(10, N20RelocFamilyAddr)
	a.b(5, 8, 10, "retail")
	w(0)
	addr(10, OLA0SurnameField)
	a.b(5, 9, 10, "retail")
	w(0)
	// Run rebuilt N20 packed romanizer into owned stack scratch.
	addr(4, OLA0SurnameField)
	imm(5, 29, 0)
	imm(6, 0, 16)
	imm(7, 0, 3)
	j(OLBodyBase)
	a.b(4, 2, 0, "retail")
	w(0)
	w(olSLTIU(1, 2, N20RelocSlotBytes))
	a.b(4, 1, 0, "retail")
	w(0)
	sw(2, shouFamilyLength)
	lw(8, shouFamilyLength)
	imm(9, 29, 0)
	addr(10, N20RelocFamilyAddr)
	a.label("copy")
	a.b(4, 8, 0, "retail")
	w(0)
	w(olLBU(11, 9, 0))
	w(0)
	w(olSB(11, 10, 0))
	imm(9, 9, 1)
	imm(10, 10, 1)
	imm(8, 8, -1)
	a.j("copy")
	w(0)
	a.label("retail")
	lw(2, shouFamilySavedV0)
	lw(3, shouFamilySavedV1)
	lw(31, shouFamilySavedRA)
	w(0)
	w(olJR(31))
	imm(29, 29, shouFamilyFamilyFrame)
	a.resolve()
	a.resolveJLabels(entry)
	return words(a.words...)
}

// shouFamilyExtendFieldPrepModule rechecks the known SHOU-specific hook geometry.
// The same guarded payload is placed in the 14 N6-FP carriers because the
// production planner shares one module layout; only SHOUGATU receives a new
// JAL. No additional global or resident-memory hook is introduced.
func shouFamilyExtendFieldPrepModule(m OverlayFieldPrepModule) (OverlayFieldPrepModule, error) {
	if m.FamilyDst != N20RelocFamilyAddr || m.GivenDst != N20RelocGivenAddr || m.SlotBytes != N20RelocSlotBytes || m.VerifierBytes != 184 {
		return m, fmt.Errorf("ChristmasFamily incompatible N20 fieldprep module")
	}
	if shouFamilySHOUStub != OLVerifierRAM+uint32(m.VerifierBytes) || shouFamilySHOUStub+24 > OLBodyBase {
		return m, fmt.Errorf("ChristmasFamily second stub outside 32-byte gap")
	}
	// Clone the shared base module before changing the guard, or all 14
	// carriers would silently inherit a new verifier/header.
	m.Guard = bytes.Clone(m.Guard)
	m.Body = bytes.Clone(m.Body)
	entry := m.ModuleEnd()
	adapter := shouFamilyBuildStrcpyAdapter(entry)
	m.Body = append(m.Body, adapter...)
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	if len(m.Body) > OLBodyCapacity {
		return m, fmt.Errorf("ChristmasFamily adapter overrun")
	}
	m.BodyLen = len(m.Body)
	m.Sum32, m.XOR32 = 0, 0
	for i := 0; i < len(m.Body); i += 4 {
		w := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += w
		m.XOR32 ^= w
	}
	v, e := buildOverlayVerifierMagic(OLFieldPrepMagicWord, m.Sum32, m.XOR32, uint32(m.BodyLen))
	if e != nil {
		return m, e
	}
	if len(v) != m.VerifierBytes {
		return m, fmt.Errorf("ChristmasFamily verifier size drift")
	}
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(m.BodyLen))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], v)
	stub, e := buildDispatchStub(shouFamilySHOUCopyOld, entry)
	if e != nil {
		return m, e
	}
	if len(stub) != 24 {
		return m, fmt.Errorf("ChristmasFamily stub geometry drift")
	}
	copy(m.Guard[shouFamilySHOUStub-OLGuardBase:], stub)
	m.BodyEndRAM = OLBodyBase + uint32(m.BodyLen)
	m.SHA = sha(append(append([]byte{}, m.Guard...), m.Body...))
	return m, nil
}
func shouFamilyAuthenticatedSHOUCopyPatch(orig, patched []byte) (n20RelocWord, error) {
	const owner = "SHOUGATU.EXN"
	var zero n20RelocWord
	off := int(shouFamilySHOUCopyPC - OverlaySlotBase)
	if len(orig) != 196608 || sha(orig) != OverlaySHA[owner] || len(patched) != len(orig) {
		return zero, fmt.Errorf("ChristmasFamily unauthenticated SHOUGATU input")
	}
	if binary.LittleEndian.Uint32(orig[off:]) != jalWord(shouFamilySHOUCopyOld) || binary.LittleEndian.Uint32(orig[off+4:]) != 0x2484A16C {
		return zero, fmt.Errorf("ChristmasFamily original JAL/delay drift")
	}
	// Relocation has already changed the delay to the family working address.
	if binary.LittleEndian.Uint32(patched[off:]) != jalWord(shouFamilySHOUCopyOld) || binary.LittleEndian.Uint32(patched[off+4:]) != n20RelocADDIUWord(0x2484A16C, N20RelocFamilyAddr) {
		return zero, fmt.Errorf("ChristmasFamily staged JAL/delay drift")
	}
	w := n20RelocWord{Owner: owner, PC: shouFamilySHOUCopyPC, Old: jalWord(shouFamilySHOUCopyOld), New: jalWord(shouFamilySHOUStub), Kind: "jal", Role: "SHOU guarded duplicate surname copy"}
	binary.LittleEndian.PutUint32(patched[off:], w.New)
	ck := packedTableChecksum(patched)
	patched[0x2fffc] = byte(ck >> 8)
	patched[0x2fffd] = byte(ck)
	return w, nil
}

// All four scene-local labels are authenticated against original SHOUGATU.
// The retail strcpy still targets old A. Guarded mirrors update relocated A
// only when the literal source is expected and its NUL fits the 16-byte slot.
var shouSceneLabelCalls = [...]struct {
	pc, delay uint32
}{
	{0x80137F1C, 0x24A53760},
	{0x8013DC90, 0x2484A188},
	{0x8013DCA0, 0x24A53954},
	{0x8013DF90, 0x24A53960},
}

func shouSceneLabelAuthenticatedPatches(orig, patched []byte) ([]n20RelocWord, error) {
	const owner = "SHOUGATU.EXN"
	if len(orig) != 196608 || sha(orig) != OverlaySHA[owner] || len(patched) != len(orig) {
		return nil, fmt.Errorf("Christmas scene-label unauthenticated overlay")
	}
	var words []n20RelocWord
	for _, site := range shouSceneLabelCalls {
		off := int(site.pc - OverlaySlotBase)
		if off < 0 || off+8 > len(patched) ||
			binary.LittleEndian.Uint32(orig[off:]) != jalWord(shouFamilySHOUCopyOld) ||
			binary.LittleEndian.Uint32(orig[off+4:]) != site.delay ||
			binary.LittleEndian.Uint32(patched[off:]) != jalWord(shouFamilySHOUCopyOld) ||
			binary.LittleEndian.Uint32(patched[off+4:]) != site.delay {
			return nil, fmt.Errorf("Christmas scene-label changed JAL/delay at %#x", site.pc)
		}
		words = append(words, n20RelocWord{Owner: owner, PC: site.pc, Old: jalWord(shouFamilySHOUCopyOld), New: jalWord(shouFamilySHOUStub), Kind: "jal", Role: "source-bounded Christmas A dual-write"})
	}
	for _, word := range words {
		binary.LittleEndian.PutUint32(patched[word.PC-OverlaySlotBase:], word.New)
	}
	ck := packedTableChecksum(patched)
	patched[0x2fffc] = byte(ck >> 8)
	patched[0x2fffd] = byte(ck)
	return words, nil
}
