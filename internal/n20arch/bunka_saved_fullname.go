package n20arch

// The BUNKA_SD school-festival scene constructs surname + JP full-width
// separator + given in a 24-byte caller stack slot before drawing it. Its
// original strlen-derived center coordinate must be updated together with
// the display-only pair-font text; saved CP932 fields are never modified.
// This is a strictly source-authenticated, fallback-preserving overlay hook.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	bunkaJoinPC                  uint32 = 0x80133088
	bunkaRetailAppend            uint32 = 0x800AE100
	bunkaCallerStackTextOffset          = 0x38
	bunkaCallerCountOffset              = 0x34
	bunkaCallerStackTextCapacity        = 24
)

type BUNKASavedFullNameCandidate struct {
	Overlay       []byte
	ShimPC        uint32
	ShimBytes     int
	SafeToPatch   bool
	RuntimePass   bool
	BlockedReason string
}

// The source call has a0=caller sp+0x38 and a1=saved given. The caller has
// already copied saved surname + full-width space into the same buffer.
// Convert BOTH fields into private scratch and commit only when the complete
// result fits 24 bytes including NUL; update caller sp+0x34 only on success.
// No partial write or incorrect width is ever exposed on conversion failure.
func buildBUNKASavedFullNameJoin(romanizer uint32) ([]byte, error) {
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
	// 0x20/0x30: 16B source scratch each; write only after full validation.
	// 0x80..0x94: saved s0..s5, 0xa0: ra, 0xa4: saved v1.
	// 0xa8/0xac: final v0/v1 across callee-saved restores.
	add(29, 29, -0xc0)
	for i, r := range []uint32{16, 17, 18, 19, 20, 21} {
		sw(r, 29, int16(0x80+4*i))
	}
	sw(31, 29, 0xa0)
	sw(3, 29, 0xa4)
	mov(16, 4)
	mov(17, 5)
	add(21, 29, 0xc0) // s5: original caller sp
	add(8, 21, bunkaCallerStackTextOffset)
	bne(16, 8, "fallback")
	w(olLUI(8, OLFieldPrepSavedGiv))
	w(olORI(8, 8, OLFieldPrepSavedGiv&65535))
	bne(17, 8, "fallback")
	// The first N6 conversion must read the distinct SAVED surname.
	w(olLUI(4, OLA0SurnameField))
	w(olORI(4, 4, OLA0SurnameField&65535))
	add(5, 29, 0x20)
	add(6, 0, 16)
	add(7, 0, 3)
	w(jalWord(romanizer))
	w(0)
	beq(2, 0, "fallback")
	add(18, 2, -1) // surname bytes without trailing NUL
	w(olSLTIU(8, 18, 16))
	beq(8, 0, "fallback")
	w(olSLTIU(8, 18, 2))
	bne(8, 0, "fallback")
	w(olIType(12, 18, 8, 1))
	bne(8, 0, "fallback")
	add(8, 29, 0x20)
	w(olAddu(8, 8, 18))
	lbu(9, 8, 0)
	bne(9, 0, "fallback")
	add(10, 29, 0x20)
	mov(8, 18)
	a.label("validate_surname")
	lbu(11, 10, 0)
	add(11, 11, -0xa0)
	w(olSLTIU(9, 11, 0x5b))
	beq(9, 0, "fallback")
	add(10, 10, 1)
	add(8, 8, -1)
	bne(8, 0, "validate_surname")
	add(9, 29, 0x20)
	w(olAddu(9, 9, 18))
	lbu(10, 9, -1)
	add(8, 0, 0xa0)
	bne(10, 8, "surname_length")
	add(18, 18, -1)
	a.label("surname_length")
	beq(18, 0, "fallback")
	// The second conversion reads only the saved GIVEN field.
	mov(4, 17)
	add(5, 29, 0x30)
	add(6, 0, 16)
	add(7, 0, 3)
	w(jalWord(romanizer))
	w(0)
	beq(2, 0, "fallback")
	add(19, 2, -1)
	w(olSLTIU(8, 19, 16))
	beq(8, 0, "fallback")
	w(olSLTIU(8, 19, 2))
	bne(8, 0, "fallback")
	w(olIType(12, 19, 8, 1))
	bne(8, 0, "fallback")
	add(8, 29, 0x30)
	w(olAddu(8, 8, 19))
	lbu(9, 8, 0)
	bne(9, 0, "fallback")
	add(10, 29, 0x30)
	mov(8, 19)
	a.label("validate_given")
	lbu(11, 10, 0)
	add(11, 11, -0xa0)
	w(olSLTIU(9, 11, 0x5b))
	beq(9, 0, "fallback")
	add(10, 10, 1)
	add(8, 8, -1)
	bne(8, 0, "validate_given")
	add(9, 29, 0x30)
	w(olAddu(9, 9, 19))
	lbu(10, 9, -1)
	add(8, 0, 0xa0)
	bne(10, 8, "given_length")
	add(19, 19, -1)
	a.label("given_length")
	beq(19, 0, "fallback")
	// Max total = surname+separator+given+alignment+NUL, 24B.
	w(olAddu(20, 18, 19))
	add(20, 20, 1)
	add(8, 20, 2)
	w(olSLTIU(9, 8, bunkaCallerStackTextCapacity+1))
	beq(9, 0, "fallback")
	// Both complete conversions and destination capacity are validated:
	// committing bytes now cannot encounter a late failure.
	mov(8, 0)
	a.label("surname_copy")
	beq(8, 18, "space")
	w(olAddu(9, 29, 8))
	lbu(10, 9, 0x20)
	w(olAddu(9, 16, 8))
	sb(10, 9, 0)
	add(8, 8, 1)
	jump("surname_copy")
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
	w(olIType(12, 20, 8, 1))
	beq(8, 0, "terminate")
	add(10, 0, 0xa0)
	sb(10, 9, 0)
	add(9, 9, 1)
	a.label("terminate")
	sb(0, 9, 0)
	a.label("success")
	w(olAddu(8, 18, 19))
	sw(8, 21, bunkaCallerCountOffset)
	mov(2, 16)
	lw(3, 29, 0xa4)
	jump("restore")
	a.label("fallback")
	mov(4, 16)
	mov(5, 17)
	w(jalWord(bunkaRetailAppend))
	w(0)
	a.label("restore")
	sw(2, 29, 0xa8)
	sw(3, 29, 0xac)
	// Independent register reloads fill the R3000A load-delay slots.
	for i, r := range []uint32{16, 17, 18, 19, 20, 21} {
		w(olLW(r, 29, int16(0x80+4*i)))
	}
	w(olLW(31, 29, 0xa0))
	w(olLW(2, 29, 0xa8))
	w(olLW(3, 29, 0xac))
	w(olJR(31))
	add(29, 29, 0xc0)
	a.resolve()
	return words(a.words...), nil
}

func PlanBUNKASavedFullName(originalBUNKA, currentBUNKA []byte) (BUNKASavedFullNameCandidate, error) {
	var out BUNKASavedFullNameCandidate
	if len(originalBUNKA) != OverlayLoadSectors*2048 || sha(originalBUNKA) != OverlaySHA["BUNKA_SD.EXN"] {
		return out, fmt.Errorf("BUNKA_SD original identity mismatch")
	}
	if len(currentBUNKA) != len(originalBUNKA) || binary.BigEndian.Uint16(currentBUNKA[len(currentBUNKA)-4:]) != packedTableChecksum(currentBUNKA) {
		return out, fmt.Errorf("BUNKA_SD current image size/checksum invalid")
	}
	// Exact original source and caller stack layout (80B frame, 24B output).
	for _, x := range []struct{ pc, word uint32 }{
		{0x80132ff8, 0x27bdffb0},
		{0x8013303c, jalWord(0x800ae0e0)},
		{0x80133040, 0x24846354},
		{0x80133050, 0x2484635c},
		{0x80133064, 0x24a56354},
		{0x80133068, jalWord(0x800ae0f0)},
		{0x8013306c, 0x27a40038},
		{0x80133078, jalWord(bunkaRetailAppend)},
		{0x8013307c, 0x27a40038},
		{0x80133084, 0x24a5635c},
		{bunkaJoinPC, jalWord(bunkaRetailAppend)},
		{bunkaJoinPC + 4, 0x27a40038},
		{0x80133090, 0x8fa80034},
		{0x801330b8, jalWord(0x8004e788)},
		{0x801330bc, 0xafa00010},
	} {
		off := int(x.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(originalBUNKA[off:]) != x.word || binary.LittleEndian.Uint32(currentBUNKA[off:]) != x.word {
			return out, fmt.Errorf("BUNKA_SD saved-fullname caller preimage drift %#x", x.pc)
		}
	}
	if !allZero(originalBUNKA[OLPayloadFileOff:OLPayloadEndOff]) || !allZero(currentBUNKA[OLPayloadFileOff:OLPayloadEndOff]) {
		return out, fmt.Errorf("BUNKA_SD local guarded code reserve occupied")
	}
	if !formatterBridgeVerified(currentBUNKA[SlotOff:C10DistributedSourceEnd]) {
		return out, fmt.Errorf("BUNKA_SD missing authenticated formatter/C10 carrier")
	}
	module, err := BuildOverlayLocalModule()
	if err != nil {
		return out, err
	}
	helper, err := buildBUNKASavedFullNameJoin(OLBodyBase)
	if err != nil {
		return out, err
	}
	out.ShimPC = OLBodyBase + uint32(len(module.Body))
	out.ShimBytes = len(helper)
	module.Body = append(module.Body, helper...)
	for len(module.Body)%16 != 0 {
		module.Body = append(module.Body, 0)
	}
	if len(module.Body) > OLBodyCapacity {
		return out, fmt.Errorf("BUNKA_SD code exceeds N6 reservation: %d>%d", len(module.Body), OLBodyCapacity)
	}
	module.BodyLen = len(module.Body)
	module.Sum32 = 0
	module.XOR32 = 0
	for i := 0; i < len(module.Body); i += 4 {
		w := binary.LittleEndian.Uint32(module.Body[i:])
		module.Sum32 += w
		module.XOR32 ^= w
	}
	binary.LittleEndian.PutUint32(module.Guard[4:], uint32(module.BodyLen))
	binary.LittleEndian.PutUint32(module.Guard[8:], module.Sum32)
	binary.LittleEndian.PutUint32(module.Guard[12:], module.XOR32)
	verify, err := buildOverlayVerifier(module.Sum32, module.XOR32, uint32(module.BodyLen))
	if err != nil {
		return out, err
	}
	if len(verify) != module.VerifierBytes {
		return out, fmt.Errorf("BUNKA_SD verifier size drift")
	}
	copy(module.Guard[OLVerifierRAM-OLGuardBase:], verify)
	stub, err := buildDispatchStub(bunkaRetailAppend, out.ShimPC)
	if err != nil {
		return out, err
	}
	copy(module.Guard[OLStubRAM-OLGuardBase:], stub)
	out.Overlay = bytes.Clone(currentBUNKA)
	copy(out.Overlay[OLPayloadFileOff:OLGuardFileEnd], module.Guard)
	copy(out.Overlay[OLBodyFileOff:OLBodyFileOff+len(module.Body)], module.Body)
	at := int(bunkaJoinPC - OverlaySlotBase)
	binary.LittleEndian.PutUint32(out.Overlay[at:], jalWord(OLStubRAM))
	binary.BigEndian.PutUint16(out.Overlay[len(out.Overlay)-4:], packedTableChecksum(out.Overlay))
	for i := range out.Overlay {
		if out.Overlay[i] == currentBUNKA[i] {
			continue
		}
		if (i >= OLPayloadFileOff && i < OLPayloadEndOff) || (i >= at && i < at+4) || (i >= len(out.Overlay)-4 && i < len(out.Overlay)-2) {
			continue
		}
		return BUNKASavedFullNameCandidate{}, fmt.Errorf("BUNKA_SD unowned byte changed %#x", i)
	}
	out.BlockedReason = "BUNKA_SD source-owned saved surname+given queue join: 24B atomic stack slot and guard proven; actual runtime overlay/R3000A stack/VRAM lifetime and scene visual remain unverified; safe_to_patch=false, runtime_pass=false"
	return out, nil
}
