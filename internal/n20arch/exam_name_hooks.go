package n20arch

// Builds two authenticated exam-name callsite adaptations in ETC.EXN:
// the player-row name join and the lower result-caption surname.
// The functions operate on in-memory copies and do not alter saved names.
// Authentic source checks alone do not prove runtime memory safety.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	ETCJoinSite    uint32 = 0x80147BD0
	ETCCaptionSite uint32 = 0x80147DB0
	JoinOriginal   uint32 = 0x800AE110
	ETCTableStub   uint32 = OLVerifierRAM + 184 // verified 32 free bytes in the 256 B guard
	MaxTableBytes         = 32                  // stack-owned, at s5=sp+0x7c in this one caller
)

type ETCPrivateCandidate struct {
	Overlay                  []byte
	JoinShim                 uint32
	JoinShimBytes            int
	OriginalEXEAuthenticated bool
	PatchedCallsites         []uint32
	SafeToPatch              bool
	RuntimePass              bool
	BlockedReason            string
}

// buildExamNameJoin runs the canonical packed N20 MIPS converter twice,
// once per player-entered CP932 field. It builds the pair-glyph surname +
// separator + given in caller-owned scratch ONLY after both outputs fit. The
// nickname at 0x800E6364 is never read. Failure tails through the original
// strncat with original a0/a1/a2 and preserves the first strncpy output.
// a0=dst, a1=saved given, a2=8; v0=dst on success.
func buildExamNameJoin(romanizer uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	sw := func(t, b uint32, o int16) { w(olSW(t, b, o)) }
	lw := func(t, b uint32, o int16) { w(olLW(t, b, o)); w(0) }
	lbu := func(t, b uint32, o int16) { w(olLBU(t, b, o)); w(0) }
	sb := func(t, b uint32, o int16) { w(olSB(t, b, o)) }
	beq := func(x, y uint32, l string) { a.b(4, x, y, l); w(0) }
	bne := func(x, y uint32, l string) { a.b(5, x, y, l); w(0) }
	jump := func(l string) { beq(0, 0, l) }
	// Two immutable 16-byte intermediate outputs. 0x60-0x70 saved s0-s4,
	// 0x80/0x84 return registers, 0x90 saved ra. Frame 0xa0.
	add(29, 29, -0xa0)
	for i, r := range []uint32{16, 17, 18, 19, 20} {
		sw(r, 29, int16(0x60+i*4))
	}
	sw(31, 29, 0x90)
	mov(16, 4) // saved destination
	mov(17, 5) // saved original given field
	// Scope guard: only correct given pointer and n=8 may use this shim.
	w(olLUI(8, OLFieldPrepSavedGiv))
	w(olORI(8, 8, OLFieldPrepSavedGiv&65535))
	bne(17, 8, "fallback")
	add(9, 0, 8)
	bne(6, 9, "fallback")
	beq(16, 0, "fallback")
	// Original surname is read from the saved field, NOT from the already
	// copied CP932 bytes in the caller stack.
	w(olLUI(4, OLA0SurnameField))
	w(olORI(4, 4, OLA0SurnameField&65535))
	add(5, 29, 0x20)
	add(6, 0, 16)
	add(7, 0, 3)
	w(jalWord(romanizer))
	w(0)
	beq(2, 0, "fallback")
	add(18, 2, -1)        // s2 = bytes without NUL
	w(olSLTIU(8, 18, 13)) // lengths 1..12, v0 <= 13
	beq(8, 0, "fallback")
	beq(18, 0, "fallback")
	// Drop final pair-glyph alignment 0xa0 if present.
	add(9, 29, 0x20)
	w(olAddu(9, 9, 18))
	lbu(10, 9, -1)
	add(8, 0, 0xa0)
	bne(10, 8, "family_len")
	add(18, 18, -1)
	a.label("family_len")
	beq(18, 0, "fallback")
	mov(4, 17)
	add(5, 29, 0x30)
	add(6, 0, 16)
	add(7, 0, 3)
	w(jalWord(romanizer))
	w(0)
	beq(2, 0, "fallback")
	add(19, 2, -1)
	w(olSLTIU(8, 19, 13))
	beq(8, 0, "fallback")
	beq(19, 0, "fallback")
	add(9, 29, 0x30)
	w(olAddu(9, 9, 19))
	lbu(10, 9, -1)
	add(8, 0, 0xa0)
	bne(10, 8, "given_len")
	add(19, 19, -1)
	a.label("given_len")
	beq(19, 0, "fallback")
	// family + one 0xa0 separator + given + optional trailing pair pad + NUL
	w(olAddu(20, 18, 19))
	add(20, 20, 1)
	add(8, 20, 2) // worst-case pad+NUL
	w(olSLTIU(9, 8, MaxTableBytes+1))
	beq(9, 0, "fallback")
	// Commit begins ONLY after successful conversion of both names.
	mov(8, 0)
	a.label("family_copy")
	beq(8, 18, "space")
	w(olAddu(9, 29, 8))
	lbu(10, 9, 0x20)
	w(olAddu(9, 16, 8))
	sb(10, 9, 0)
	add(8, 8, 1)
	jump("family_copy")
	a.label("space")
	w(olAddu(9, 16, 18))
	add(10, 0, 0xa0)
	sb(10, 9, 0)
	mov(8, 0)
	a.label("given_copy")
	beq(8, 19, "pad")
	w(olAddu(9, 29, 8))
	lbu(10, 9, 0x30)
	w(olAddu(9, 18, 8))
	add(9, 9, 1)
	w(olAddu(9, 16, 9))
	sb(10, 9, 0)
	add(8, 8, 1)
	jump("given_copy")
	a.label("pad")
	w(olAddu(9, 16, 20))
	w(olIType(12, 20, 8, 1)) // andi t0,s4,1
	beq(8, 0, "terminate")
	add(10, 0, 0xa0)
	sb(10, 9, 0)
	add(9, 9, 1)
	a.label("terminate")
	sb(0, 9, 0)
	mov(2, 16)
	mov(3, 0)
	jump("restore")
	a.label("fallback")
	mov(4, 16)
	mov(5, 17)
	add(6, 0, 8)
	w(jalWord(JoinOriginal))
	w(0)
	a.label("restore")
	sw(2, 29, 0x80)
	sw(3, 29, 0x84)
	for i, r := range []uint32{16, 17, 18, 19, 20} {
		lw(r, 29, int16(0x60+i*4))
	}
	lw(31, 29, 0x90)
	lw(2, 29, 0x80)
	lw(3, 29, 0x84)
	w(olJR(31))
	add(29, 29, 0xa0)
	a.resolve()
	return words(a.words...), nil
}

// PlanETCExamPrivateOverlay takes ORIGINAL authenticated evidence plus
// the exact candidate ETC data (retail or an owner-built English ETC). The
// latter must have the original executable callsite words, a zero-filled
// source-owned local payload and a valid trailer/checksum. It emits actual
// modified overlay bytes, with a verifier-backed separate table adapter and
// existing verified speaker adapter. It NEVER writes a file or marks safe.
func PlanETCExamPrivateOverlay(originalEXE, retailETC, inputETC []byte) (ETCPrivateCandidate, error) {
	var out ETCPrivateCandidate
	if len(originalEXE) != 667648 || sha(originalEXE) != OriginalEXESHA {
		return out, fmt.Errorf("exam labels retail EXE authentication failed")
	}
	if len(retailETC) != 196608 || sha(retailETC) != OverlaySHA["ETC.EXN"] {
		return out, fmt.Errorf("exam labels retail ETC authentication failed")
	}
	if len(inputETC) != len(retailETC) || inputETC[0x2fffe] != 0x12 || inputETC[0x2ffff] != 0x10 || binary.BigEndian.Uint16(inputETC[0x2fffc:]) != packedTableChecksum(inputETC) {
		return out, fmt.Errorf("exam labels candidate ETC missing original checksum/trailer")
	}
	if !allZero(retailETC[OLPayloadFileOff:OLPayloadEndOff]) {
		return out, fmt.Errorf("exam labels authenticated retail ETC local payload is not empty")
	}
	// A normal English suffix punctuation/formatter bridge image already has N6 speaker hooks and an N6
	// body in ETC. Extend precisely that installed module instead of trying
	// to overwrite it with an unrelated second overlay patch.
	module, err := BuildOverlayLocalModule()
	if err != nil {
		return out, err
	}
	inputN6 := bytes.Equal(inputETC[OLPayloadFileOff:OLGuardFileEnd], module.Guard) &&
		bytes.Equal(inputETC[OLBodyFileOff:OLBodyFileOff+len(module.Body)], module.Body)
	inputRetail := allZero(inputETC[OLPayloadFileOff:OLPayloadEndOff])
	if !inputN6 && !inputRetail {
		return out, fmt.Errorf("exam labels ETC carrier neither retail nor exact installed suffix punctuation/N6 module")
	}
	for _, site := range []struct{ pc, target, delay uint32 }{
		{ETCJoinSite, JoinOriginal, 0x24060008},
		{ETCCaptionSite, OLOriginalSpeaker, OLSpeakerDelay},
	} {
		off := int(site.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(retailETC[off:]) != jalWord(site.target) || binary.LittleEndian.Uint32(retailETC[off+4:]) != site.delay {
			return out, fmt.Errorf("exam labels authenticated retail callsite drift at %#x", site.pc)
		}
		want := jalWord(site.target)
		// The original caller's LUI is NOT immediately before its JAL:
		// integrated baseline leaves this one caption call retail. exam labels owns its hook.
		if binary.LittleEndian.Uint32(inputETC[off:]) != want || binary.LittleEndian.Uint32(inputETC[off+4:]) != site.delay {
			return out, fmt.Errorf("exam labels English N6 preimage mismatch at %#x", site.pc)
		}
	}

	// Speaker surname caller must retain lui a0,0x800e; table destination is
	// s5 and its given source must remain exactly 0x800e635c.
	for _, pc := range []uint32{0x80147da0, 0x80147bb0, 0x80147bb4, 0x80147bc4, 0x80147bc8, 0x80147b30, 0x8014790c} {
		off := int(pc - OverlaySlotBase)
		if !bytes.Equal(inputETC[off:off+4], retailETC[off:off+4]) {
			return out, fmt.Errorf("exam labels ETC surrounding ABI drift at %#x", pc)
		}
	}
	if module.VerifierBytes != 184 || ETCTableStub != OLVerifierRAM+uint32(module.VerifierBytes) {
		return out, fmt.Errorf("exam labels guard geometry drift")
	}
	shim, err := buildExamNameJoin(OLBodyBase)
	if err != nil {
		return out, err
	}
	if len(module.Body)+len(shim) > OLBodyCapacity {
		return out, fmt.Errorf("exam labels join adapter %d exceeds %d free body bytes", len(shim), OLBodyCapacity-len(module.Body))
	}
	out.JoinShim = OLBodyBase + uint32(len(module.Body))
	out.JoinShimBytes = len(shim)
	module.Body = append(module.Body, shim...)
	for len(module.Body)%16 != 0 {
		module.Body = append(module.Body, 0)
	}
	if len(module.Body) > OLBodyCapacity {
		return out, fmt.Errorf("exam labels padded body too large")
	}
	module.BodyLen = len(module.Body)
	module.Sum32, module.XOR32 = 0, 0
	for i := 0; i < len(module.Body); i += 4 {
		v := binary.LittleEndian.Uint32(module.Body[i:])
		module.Sum32 += v
		module.XOR32 ^= v
	}
	binary.LittleEndian.PutUint32(module.Guard[4:], uint32(module.BodyLen))
	binary.LittleEndian.PutUint32(module.Guard[8:], module.Sum32)
	binary.LittleEndian.PutUint32(module.Guard[12:], module.XOR32)
	verify, err := buildOverlayVerifier(module.Sum32, module.XOR32, uint32(module.BodyLen))
	if err != nil {
		return out, err
	}
	if len(verify) != module.VerifierBytes {
		return out, fmt.Errorf("exam labels verifier layout drift")
	}
	copy(module.Guard[OLVerifierRAM-OLGuardBase:], verify)
	stub, err := buildDispatchStub(JoinOriginal, out.JoinShim)
	if err != nil {
		return out, err
	}
	if len(stub) > int(OLBodyBase-ETCTableStub) {
		return out, fmt.Errorf("exam labels verifier-adjacent stub won't fit")
	}
	if !allZero(module.Guard[ETCTableStub-OLGuardBase:]) {
		return out, fmt.Errorf("exam labels guard tail not empty")
	}
	copy(module.Guard[ETCTableStub-OLGuardBase:], stub)
	dst := bytes.Clone(inputETC)
	copy(dst[OLPayloadFileOff:OLGuardFileEnd], module.Guard)
	copy(dst[OLBodyFileOff:OLBodyFileOff+len(module.Body)], module.Body)
	binary.LittleEndian.PutUint32(dst[int(ETCJoinSite-OverlaySlotBase):], jalWord(ETCTableStub))
	binary.LittleEndian.PutUint32(dst[int(ETCCaptionSite-OverlaySlotBase):], jalWord(OLStubRAM))
	binary.BigEndian.PutUint16(dst[0x2fffc:], packedTableChecksum(dst))
	for i := range dst {
		if dst[i] == inputETC[i] {
			continue
		}
		ok := (i >= OLPayloadFileOff && i < OLPayloadEndOff) || i == 0x2fffc || i == 0x2fffd ||
			(i >= int(ETCJoinSite-OverlaySlotBase) && i < int(ETCJoinSite-OverlaySlotBase)+4) ||
			(i >= int(ETCCaptionSite-OverlaySlotBase) && i < int(ETCCaptionSite-OverlaySlotBase)+4)
		if !ok {
			return out, fmt.Errorf("exam labels modified unapproved input byte %#x", i)
		}
	}
	out.Overlay = dst
	out.PatchedCallsites = []uint32{ETCJoinSite, ETCCaptionSite}
	out.OriginalEXEAuthenticated = true
	out.BlockedReason = "exam labels PRIVATE EXECUTABLE ETC OVERLAY CANDIDATE ONLY: two actual redirected JALs, checked 32-byte table output, existing surname shim. Still lacks installed English ETC runtime, CPU/DMA/IRQ overlay ownership, exact frame alias and queue/GPU lifetime proof. No release or original-game writes."
	return out, nil
}
