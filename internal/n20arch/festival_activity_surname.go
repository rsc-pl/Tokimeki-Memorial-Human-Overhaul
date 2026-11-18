package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const festivalQueueStub = OLGuardBase + 0xcc

// The same NF verifier as the ordinary field-preparation module, with the
// expected sum and xor retained in t8/t9 and the body base derived from the
// guard base. This leaves space for both original-size dispatch stubs.
func buildFestivalVerifier(sum, xor, length uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	a.w(olLUI(10, OLGuardBase))
	a.w(olADDIU(10, 10, int16(OLGuardBase&0xffff)))
	for _, check := range []struct {
		off        int16
		reg, value uint32
	}{
		{0, 25, OLFieldPrepMagicWord}, {4, 25, length},
		{8, 24, sum}, {12, 25, xor},
	} {
		a.w(olLW(14, 10, check.off))
		a.w(olLUI(check.reg, check.value))
		a.w(olORI(check.reg, check.reg, check.value))
		a.b(5, 14, check.reg, "fail")
		a.w(0)
	}
	a.w(olADDIU(10, 10, OLGuardBytes))
	a.w(olAddu(11, 10, 11))
	a.w(olORI(13, 0, length/4))
	a.w(olAddu(15, 0, 0))
	a.w(olAddu(9, 0, 0))
	a.label("loop")
	a.w(olLW(14, 10, 0))
	a.w(olADDIU(13, 13, -1))
	a.w(olAddu(15, 15, 14))
	a.w(olRType(9, 14, 9, 0x26))
	a.b(5, 13, 0, "loop")
	a.w(olADDIU(10, 10, 4))
	a.b(5, 15, 24, "fail")
	a.w(0)
	a.b(5, 9, 25, "fail")
	a.w(0)
	a.w(olJR(11))
	a.w(0)
	a.label("fail")
	a.w(olJR(12))
	a.w(0)
	a.resolve()
	v := words(a.words...)
	if OLVerifierRAM+uint32(len(v)) != festivalQueueStub {
		return nil, fmt.Errorf("festival verifier extent drift: %d", len(v))
	}
	return v, nil
}

// PlanFestivalActivitySurname adds the existing alternate F1 speaker route
// to the festival overlay while preserving its field-preparation and direct
// name queue bodies. The resident F1 gate and DATE bytes need no changes.
func PlanFestivalActivitySurname(originals map[string][]byte, current []byte) ([]byte, error) {
	const name = "BUNKASAI.EXN"
	original := originals[name]
	if len(original) != 196608 || len(current) != len(original) || sha(original) != OverlaySHA[name] ||
		!allZero(original[OLPayloadFileOff:OLPayloadEndOff]) ||
		binary.LittleEndian.Uint32(current[C10DistributedSourceFileOff:]) == C10Magic {
		return nil, fmt.Errorf("festival name source or reservation drift")
	}
	fp, err := buildOverlayFieldPrepModuleAtWithGivenKun(N20RelocFamilyAddr, N20RelocGivenAddr, N20RelocSlotBytes, true)
	if err != nil {
		return nil, err
	}
	sites, err := ScanDirectSavedNameQueueSites(originals)
	if err != nil {
		return nil, err
	}
	var direct []DirectSavedNameQueueSite
	for _, s := range sites {
		if s.Overlay == name {
			direct = append(direct, s)
		}
	}
	if len(direct) != 3 {
		return nil, fmt.Errorf("festival name queue count drift")
	}
	base := bytes.Clone(original)
	copy(base[OLPayloadFileOff:], fp.Guard)
	copy(base[OLBodyFileOff:], fp.Body)
	want, err := extendN20FPWithDirectQueue(original, base, fp, direct)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want[OLPayloadFileOff:OLPayloadEndOff], current[OLPayloadFileOff:OLPayloadEndOff]) {
		return nil, fmt.Errorf("festival composed field-preparation or queue module drift")
	}
	n := int(binary.LittleEndian.Uint32(want[OLPayloadFileOff+4:]))
	shim, err := BuildCompactSpeakerShim(OLBodyBase)
	if err != nil {
		return nil, err
	}
	if n%16 != 0 || n+len(shim) > OLBodyCapacity || !allZero(current[OLBodyFileOff+n:OLPayloadEndOff]) {
		return nil, fmt.Errorf("festival speaker body does not fit existing reservation: %d+%d", n, len(shim))
	}
	body := append(bytes.Clone(current[OLBodyFileOff:OLBodyFileOff+n]), shim...)
	for len(body)%16 != 0 {
		body = append(body, 0)
	}
	var sum, xor uint32
	for i := 0; i < len(body); i += 4 {
		w := binary.LittleEndian.Uint32(body[i:])
		sum += w
		xor ^= w
	}
	v, err := buildFestivalVerifier(sum, xor, uint32(len(body)))
	if err != nil {
		return nil, err
	}
	stub, err := buildDispatchStub(OLOriginalSpeaker, OLBodyBase+uint32(n))
	if err != nil {
		return nil, err
	}
	queue := bytes.Clone(current[OLPayloadFileOff+directQueueStubOffset : OLPayloadFileOff+directQueueStubOffset+24])
	if festivalQueueStub+uint32(len(queue)) != dateActivityStubPC || dateActivityStubPC+uint32(len(stub)) != dateActivityMarkerPC {
		return nil, fmt.Errorf("festival dispatch extent drift")
	}
	out := bytes.Clone(current)
	binary.LittleEndian.PutUint32(out[OLPayloadFileOff+4:], uint32(len(body)))
	binary.LittleEndian.PutUint32(out[OLPayloadFileOff+8:], sum)
	binary.LittleEndian.PutUint32(out[OLPayloadFileOff+12:], xor)
	copy(out[OLPayloadFileOff+int(OLVerifierRAM-OLGuardBase):], v)
	copy(out[OLPayloadFileOff+int(festivalQueueStub-OLGuardBase):], queue)
	copy(out[OLPayloadFileOff+int(dateActivityStubPC-OLGuardBase):], stub)
	binary.LittleEndian.PutUint32(out[OLPayloadFileOff+OLGuardBytes-4:], dateActivityMarker)
	copy(out[OLBodyFileOff:], body)
	for _, s := range direct {
		off := int(s.PC - OverlaySlotBase)
		if binary.LittleEndian.Uint32(current[off:]) != jalWord(directQueueStubRAM) ||
			binary.LittleEndian.Uint32(current[off+4:]) != s.Delay ||
			!bytes.Equal(current[off-20:off-12], original[off-20:off-12]) {
			return nil, fmt.Errorf("festival queue caller drift at %08x", s.PC)
		}
		binary.LittleEndian.PutUint32(out[off:], jalWord(festivalQueueStub))
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return out, nil
}
