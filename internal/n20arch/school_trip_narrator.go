package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/graphics"
)

const schoolTripContinuationEntry = OLBodyBase + 3584

// Build the scoped selector-zero continuation without additional resident storage.
func buildSchoolTripNarratorContinuation(exe []byte) ([]byte, error) {
	i := func(op, rs, rt uint32, imm int) uint32 { return op<<26 | rs<<21 | rt<<16 | uint32(uint16(imm)) }
	r := func(rs, rt, rd, sh, fn uint32) uint32 { return rs<<21 | rt<<16 | rd<<11 | sh<<6 | fn }
	j := func(pc uint32) uint32 { return 0x08000000 | ((pc >> 2) & 0x3ffffff) }
	jal := func(pc uint32) uint32 { return j(pc) | 0x04000000 }
	var w []uint32
	emit := func(x ...uint32) { w = append(w, x...) }
	labels := map[string]int{}
	type fix struct {
		at   int
		name string
	}
	var fixes []fix
	label := func(s string) { labels[s] = len(w) }
	b := func(op, rs, rt uint32, s string, delay uint32) {
		fixes = append(fixes, fix{len(w), s})
		emit(i(op, rs, rt, 0), delay)
	}
	fail := func(rs, rt uint32) { b(5, rs, rt, "fallback", 0) }
	addr := func(rt, v uint32) { emit(i(15, 0, rt, int(v>>16)), i(13, rt, rt, int(v&65535))) }
	// Verify the two resident roots actually consumed by this dispatcher,
	// exact row/column and original table identity.
	addr(8, 0x800ca2d0)
	addr(9, 0x801ab00c)
	emit(i(35, 8, 10, 0), i(9, 9, 11, 0x17c))
	b(5, 9, 10, "fallback", i(35, 8, 10, 4))
	emit(i(37, 8, 9, 12))
	b(5, 10, 11, "fallback", i(37, 8, 10, 16))
	emit(r(9, 0, 11, 0, 0x21))
	emit(i(9, 0, 9, 2))
	b(5, 10, 0, "fallback", i(15, 0, 8, 0x801a))
	emit(i(13, 8, 8, 0xa2bc))
	b(4, 11, 0, "row", i(9, 8, 12, 0xdfc))
	b(5, 11, 9, "fallback", i(9, 8, 8, 0x74))
	emit(i(9, 12, 12, 8))
	label("row")
	// Exact table and control pointers (not translated text address).
	addr(9, 0x801ab00c)
	emit(r(0, 11, 11, 2, 0), r(9, 11, 9, 0, 0x21), i(35, 9, 10, 0), i(9, 9, 9, 0x17c))
	b(5, 10, 8, "fallback", i(35, 9, 10, 0))
	emit(i(35, 8, 11, 0))
	b(5, 10, 12, "fallback", i(36, 12, 10, 0))
	b(5, 11, 16, "fallback", i(15, 0, 8, 0x8019))
	b(5, 10, 0, "fallback", i(13, 8, 8, 0x7000))
	// Restrict body to the loaded SERIFU asset; check each byte in the
	// first line. Only complete pair-font bytes, no dynamic marker.
	emit(r(16, 8, 9, 0, 0x23))
	addr(8, 0x167e4) // asset length minus safe 28-byte lookahead
	emit(r(9, 8, 10, 0, 0x2b))
	b(4, 10, 0, "fallback", r(16, 0, 8, 0, 0x21))
	emit(i(9, 0, 9, 0))
	label("body")
	emit(i(36, 8, 10, 0), i(9, 8, 8, 1))
	b(4, 10, 0, "body_end", i(9, 10, 10, -0x20))
	b(4, 10, 0, "body_end", i(9, 10, 10, -0x80))
	emit(i(11, 10, 10, 0x5b))
	b(4, 10, 0, "fallback", i(9, 9, 9, 1))
	emit(i(11, 9, 10, 27))
	b(5, 10, 0, "body", 0)
	b(4, 0, 0, "fallback", 0)
	label("body_end")
	emit(i(12, 9, 10, 1))
	b(5, 10, 0, "fallback", i(33, 29, 9, 0x286))
	// Native formatter's measured count and exact formatted working copy.
	emit(i(9, 29, 8, 0x68))
	b(5, 7, 8, "fallback", i(9, 9, 10, -6))
	emit(i(11, 10, 10, 5))
	b(4, 10, 0, "fallback", i(12, 9, 10, 1))
	b(5, 10, 0, "fallback", i(15, 0, 8, int(N20RelocFamilyAddr>>16)))
	emit(i(13, 8, 8, int(N20RelocFamilyAddr&65535)))
	emit(r(7, 0, 11, 0, 0x21))
	label("name")
	emit(i(36, 8, 10, 0), i(36, 11, 12, 0), i(9, 8, 8, 1))
	b(5, 10, 12, "fallback", i(9, 10, 10, -0xa0))
	emit(i(11, 10, 10, 0x5b))
	b(4, 10, 0, "fallback", i(9, 9, 9, -1))
	b(5, 9, 0, "name", i(9, 11, 11, 1))
	emit(i(36, 8, 10, 0), i(36, 11, 12, 0), i(9, 0, 8, 0x20))
	b(5, 10, 0, "fallback", i(36, 11, 13, 1))
	fail(12, 8)
	fail(13, 0)
	// Direct retail surname queue; native caller frame and arg5 unchanged.
	emit(jal(0x8004e788), 0)
	// Reproduce native quote setup exactly except x. Recompute after each
	// queue because all caller-saved registers are volatile.
	word := func(pc uint32) uint32 { return binary.LittleEndian.Uint32(exe[pc-0x80040800:]) }
	emit(i(33, 29, 10, 0x286))
	for pc := uint32(0x8007f8a0); pc < 0x8007f8b8; pc += 4 {
		emit(word(pc))
	}
	x := func(base int) {
		emit(r(0, 10, 10, 2, 0), i(9, 10, 4, base))
	}
	x(-102)
	emit(jal(0x8004e788), word(0x8007f8c0))
	emit(i(33, 29, 10, 0x286))
	for pc := uint32(0x8007f8c4); pc < 0x8007f8e0; pc += 4 {
		emit(word(pc))
	}
	x(-86)
	emit(j(0x8007f8e4), 0)
	label("fallback")
	emit(j(BridgeRAM), 0)
	for _, f := range fixes {
		to, ok := labels[f.name]
		if !ok {
			return nil, fmt.Errorf("school trip continuation: unresolved branch %s", f.name)
		}
		w[f.at] |= uint32(uint16(to - f.at - 1))
	}

	if len(w)*4 != 464 || len(w)*4 > OLBodyCapacity-3584 {
		return nil, fmt.Errorf("school trip continuation: body size %d", len(w)*4)
	}
	return words(w...), nil
}

// PlanSchoolTripNarratorGeometry updates only the authenticated school trip
// carrier. All other renderer callers retain their existing return path.
func PlanSchoolTripNarratorGeometry(retail, exe, original, trip []byte) ([]byte, error) {
	fail := func(reason string) ([]byte, error) { return nil, fmt.Errorf("school trip narrator: %s", reason) }
	if sha(retail) != OriginalEXESHA || sha(original) != OverlaySHA["SHUGAKU.EXN"] || len(exe) != len(retail) || len(trip) != len(original) {
		return fail("source identity")
	}
	word := func(d []byte, pc, base uint32) uint32 { return binary.LittleEndian.Uint32(d[pc-base:]) }
	for i, w := range []uint32{jalWord(OLStubRAM), 0x00002025, 0x3c04800b, 0x3c058013, 0x24a5b500, 0x0c02b83c, 0x248435a4, 0x0c04d8e0, 0} {
		if word(trip, 0x80137e20+uint32(i*4), OverlaySlotBase) != w {
			return fail("prepared surname caller")
		}
	}
	for _, span := range [][2]uint32{{0x8007f8a0, 0x8007f8f8}, {0x8004e788, 0x8004e884}} {
		if !bytes.Equal(exe[span[0]-Base:span[1]-Base], retail[span[0]-Base:span[1]-Base]) {
			return fail(fmt.Sprintf("native continuation/queue drift %#x", span[0]))
		}
	}
	// The glyph routine retains its native ABI with the installed pair-font
	// hook. Authenticate that version, rather than the unmodified decoder.
	renderer, e := graphics.InstallRenderer(retail)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(exe[0x8004f268-Base:0x8004f364-Base], renderer[0x8004f268-Base:0x8004f364-Base]) {
		return fail("installed glyph routine")
	}
	if word(exe, 0x8007f898, Base) != jalWord(C10EXETerminalGate) || word(exe, 0x8007f89c, Base) != word(retail, 0x8007f89c, Base) {
		return fail("terminal caller")
	}
	router, e := formatterBridgeRouter()
	if e != nil {
		return nil, e
	}
	if !allZero(original[SlotOff:C10DistributedSourceEnd]) || !allZero(original[OLPayloadFileOff:OLPayloadEndOff]) || !bytes.Equal(trip[SlotOff+4:SlotOff+4+RouterBytes], router) || !allZero(trip[SlotOff+504:SlotOff+512]) || !formatterBridgeVerified(trip[SlotOff:C10DistributedSourceEnd]) || word(trip, OverlayBase, OverlaySlotBase) != C10Magic {
		return fail("carrier router or reservation")
	}
	m, e := buildOverlayFieldPrepModuleAtWithGivenKun(N20RelocFamilyAddr, N20RelocGivenAddr, N20RelocSlotBytes, true)
	if e != nil {
		return nil, e
	}
	stubOff := int(OLFullNameStubRAM - OLGuardBase)
	if m.BodyLen != 3584 || !bytes.Equal(trip[OLPayloadFileOff:OLGuardFileEnd], m.Guard) || !bytes.Equal(trip[OLBodyFileOff:OLBodyFileOff+m.BodyLen], m.Body) || !allZero(trip[OLBodyFileOff+m.BodyLen:OLPayloadEndOff]) || !allZero(m.Guard[stubOff:]) || stubOff+24 != OLGuardBytes-4 {
		return fail("field preparation module or reservation")
	}
	continuation, e := buildSchoolTripNarratorContinuation(exe)
	if e != nil {
		return nil, e
	}
	m.Body = append(m.Body, continuation...)
	m.Sum32, m.XOR32 = 0, 0
	for i := 0; i < len(m.Body); i += 4 {
		w := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += w
		m.XOR32 ^= w
	}
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(len(m.Body)))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	verifier, e := buildOverlayVerifierMagic(OLFieldPrepMagicWord, m.Sum32, m.XOR32, uint32(len(m.Body)))
	if e != nil {
		return nil, e
	}
	if len(verifier) != m.VerifierBytes || int(OLVerifierRAM-OLGuardBase)+len(verifier) > stubOff {
		return fail("verifier boundary")
	}
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], verifier)
	stub, e := buildDispatchStub(BridgeRAM, schoolTripContinuationEntry)
	if e != nil {
		return nil, e
	}
	copy(m.Guard[stubOff:], stub)
	out := bytes.Clone(trip)
	copy(out[OLPayloadFileOff:OLGuardFileEnd], m.Guard)
	copy(out[OLBodyFileOff:], m.Body)
	const branchPC = RouterRAM + 16
	const pad = SlotRAM + 504
	binary.LittleEndian.PutUint32(out[branchPC-OverlaySlotBase:], olIType(4, 31, 25, uint16((pad-branchPC-4)/4)))
	binary.LittleEndian.PutUint32(out[pad-OverlaySlotBase:], jWord(OLFullNameStubRAM))
	seed, e := formatterBridgeSeed(out[SlotOff:C10DistributedSourceEnd])
	if e != nil {
		return nil, e
	}
	binary.LittleEndian.PutUint32(out[SlotOff:], seed)
	if !formatterBridgeVerified(out[SlotOff:C10DistributedSourceEnd]) {
		return fail("carrier verification")
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return out, nil
}
