package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	dateActivityGatePC     uint32 = 0x800446e8
	dateActivityF1BranchPC uint32 = C10EXEGuardF1 + 16
	dateActivityFallback   uint32 = C10EXEGuardF1 + 44
	dateActivityMarkerPC   uint32 = OLBodyBase - 4
	dateActivityStubPC     uint32 = OLFullNameStubRAM
	dateActivityMarker            = C10Magic
)

// PlanDATEActivitySurname extends DATE's existing field-preparation module.
// DATE's C10 window contains live data; only a C10 magic miss can select this
// alternative. The existing C10 length/body failures remain retail fallbacks.
// No saved fields, caller instructions, or other overlay bytes are changed.
// Static preimage and bounds checks do not certify overlay lifetime or runtime safety.
func PlanDATEActivitySurname(retailEXE, currentEXE []byte, originals, current map[string][]byte) ([]byte, []byte, error) {
	fail := func(reason string) ([]byte, []byte, error) { return nil, nil, fmt.Errorf("DATE surname: %s", reason) }
	if sha(retailEXE) != OriginalEXESHA || len(currentEXE) != len(retailEXE) || len(originals) != len(OverlaySHA) || len(current) != len(OverlaySHA) {
		return fail("source identity or coverage drift")
	}
	markerOff := int(dateActivityMarkerPC - OverlaySlotBase)
	for name, want := range OverlaySHA {
		o, c := originals[name], current[name]
		if len(o) != 196608 || len(c) != len(o) || sha(o) != want {
			return fail("overlay identity drift: " + name)
		}
		if binary.LittleEndian.Uint32(o[markerOff:]) == dateActivityMarker || binary.LittleEndian.Uint32(c[markerOff:]) == dateActivityMarker {
			return fail("alternate marker collision: " + name)
		}
	}
	date := current["DATE.EXN"]
	if !allZero(originals["DATE.EXN"][OLPayloadFileOff:OLPayloadEndOff]) || binary.LittleEndian.Uint32(date[SlotOff:]) == C10Magic {
		return fail("DATE reservation or C10-miss assumption drift")
	}
	m, err := buildOverlayFieldPrepModuleAtWithGivenKun(N20RelocFamilyAddr, N20RelocGivenAddr, N20RelocSlotBytes, true)
	if err != nil {
		return nil, nil, err
	}
	if m.BodyLen != 3584 || !bytes.Equal(date[OLPayloadFileOff:OLGuardFileEnd], m.Guard) || !bytes.Equal(date[OLBodyFileOff:OLBodyFileOff+m.BodyLen], m.Body) || !allZero(date[OLBodyFileOff+m.BodyLen:OLPayloadEndOff]) {
		return fail("existing field-preparation module or spare drift")
	}
	stubOff := int(dateActivityStubPC - OLGuardBase)
	if !allZero(m.Guard[stubOff:]) || stubOff+24 != OLGuardBytes-4 {
		return fail("field-preparation guard tail occupied")
	}
	f1Off := int(C10EXEGuardF1 - Base)
	gateOff := int(dateActivityGatePC - Base)
	if sha(currentEXE[f1Off:f1Off+C10EXEGuardTailBytes]) != "51e7fbeec244efacfa23660bd8eeff5b4475c84039d4f74e3ed1320aab215666" || !allZero(currentEXE[gateOff:gateOff+24]) {
		return fail("F1 or renderer HOOK spare preimage drift")
	}
	// The compact speaker consumes only the authenticated saved surname and
	// produces the same width-aware queue ABI as the standard C10 path.
	shim, err := BuildCompactSpeakerShim(OLBodyBase)
	if err != nil {
		return nil, nil, err
	}
	entry := OLBodyBase + uint32(m.BodyLen)
	m.Body = append(m.Body, shim...)
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	if len(m.Body) > OLBodyCapacity {
		return fail("field-preparation spare too small")
	}
	m.Sum32, m.XOR32 = 0, 0
	for i := 0; i < len(m.Body); i += 4 {
		w := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += w
		m.XOR32 ^= w
	}
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(len(m.Body)))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	v, err := buildOverlayVerifierMagic(OLFieldPrepMagicWord, m.Sum32, m.XOR32, uint32(len(m.Body)))
	if err != nil {
		return nil, nil, err
	}
	if len(v) != m.VerifierBytes || int(OLVerifierRAM-OLGuardBase)+len(v) > stubOff {
		return fail("verifier crosses alternate stub")
	}
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], v)
	stub, err := buildDispatchStub(OLOriginalSpeaker, entry)
	if err != nil {
		return nil, nil, err
	}
	copy(m.Guard[stubOff:], stub)
	binary.LittleEndian.PutUint32(m.Guard[OLGuardBytes-4:], dateActivityMarker)
	newDATE := bytes.Clone(date)
	copy(newDATE[OLPayloadFileOff:OLGuardFileEnd], m.Guard)
	copy(newDATE[OLBodyFileOff:], m.Body)
	binary.BigEndian.PutUint16(newDATE[len(newDATE)-4:], packedTableChecksum(newDATE))
	// F1's magic comparison has t0=0x80160000 and t2=C10Magic. On a
	// mismatch only, inspect the alternate marker in the existing NF guard.
	// The local dispatch verifies the full NF body before entering the shim.
	branch := func(pc, target uint32) uint32 {
		return olIType(5, 9, 10, uint16(int16((int64(target)-int64(pc)-4)/4)))
	}
	newEXE := bytes.Clone(currentEXE)
	binary.LittleEndian.PutUint32(newEXE[dateActivityF1BranchPC-Base:], branch(dateActivityF1BranchPC, dateActivityGatePC))
	copy(newEXE[gateOff:gateOff+24], words(olLW(9, 8, int16(dateActivityMarkerPC&0xffff)), 0, branch(dateActivityGatePC+8, dateActivityFallback), 0, jWord(dateActivityStubPC), 0))
	return newEXE, newDATE, nil
}

// PlanDATEContextSpeaker relocates the two scene-owned label producers to the
// same 16-byte name field used by the resident NPC dialogue formatter. Keep
// the original selector and source string; neither is inferred from the date
// partner. The legacy strlen reads are superseded by the formatted byte count.
func PlanDATEContextSpeaker(retailEXE, currentEXE, original, current []byte) ([]byte, error) {
	if sha(retailEXE) != OriginalEXESHA || len(currentEXE) != len(retailEXE) || sha(original) != OverlaySHA["DATE.EXN"] || len(current) != len(original) {
		return nil, fmt.Errorf("DATE contextual label: source identity changed")
	}
	exeWord := func(pc uint32) uint32 { return binary.LittleEndian.Uint32(currentEXE[pc-Base:]) }
	// These are the six existing name consumers; the corrected formatter
	// length must also be present so the legacy short buffer is irrelevant.
	for _, route := range npcNameQueueNPCNameQueues {
		if exeWord(route.FormatPC-16) != 0x3c06800b || exeWord(route.FormatPC-8) != 0x24c635a4 ||
			exeWord(route.FormatPC+8)&0xffe0ffff != 0x2440ffff {
			return nil, fmt.Errorf("DATE contextual label: resident name-field contract changed")
		}
	}
	type site struct {
		pc, source uint32
		selector   uint32
		sourceSize int
		label      []byte
	}
	sites := []site{
		{0x8013cb84, 0x8015aea0, 0x2409000e, 8, []byte{0x95, 0x73, 0x97, 0xc7, 0}},
		{0x8015a43c, 0x8015b510, 0x240e000b, 16, []byte{0x93, 0xe4, 0x82, 0xcc, 0x8f, 0x97, 0}},
	}
	out := bytes.Clone(current)
	for _, s := range sites {
		off := int(s.pc - OverlaySlotBase)
		src := int(s.source - OverlaySlotBase)
		hiOff := off - 16
		// Both sites have the same destination LUI, source LUI/ADDIU,
		// original strcpy JAL and destination ADDIU in its delay slot.
		if binary.LittleEndian.Uint32(original[hiOff:]) != 0x3c04800d ||
			binary.LittleEndian.Uint32(original[off-12:]) != 0x3c058016 ||
			binary.LittleEndian.Uint32(original[off-4:]) != 0x24a50000|uint32(uint16(s.source)) ||
			binary.LittleEndian.Uint32(original[off:]) != jalWord(0x800ae0f0) ||
			binary.LittleEndian.Uint32(original[off+4:]) != 0x2484a188 ||
			!bytes.Equal(original[src:src+len(s.label)], s.label) ||
			!bytes.Equal(current[off-24:off+8], original[off-24:off+8]) {
			return nil, fmt.Errorf("DATE contextual label: caller or original literal changed at %#x", s.pc)
		}
		// Selector setup differs by one instruction between the two sites.
		if binary.LittleEndian.Uint32(original[off-20:]) != s.selector &&
			binary.LittleEndian.Uint32(original[off-24:]) != s.selector {
			return nil, fmt.Errorf("DATE contextual label: selector changed at %#x", s.pc)
		}
		end := bytes.IndexByte(current[src:src+s.sourceSize], 0)
		if end <= 0 || end%2 != 0 {
			return nil, fmt.Errorf("DATE contextual label: invalid source string at %#x", s.source)
		}
		// The destination is already allocated by the name-table relocation.
		// A native copy directly to it also avoids overrunning legacy A/B.
		binary.LittleEndian.PutUint32(out[hiOff:], 0x3c04800b)
		binary.LittleEndian.PutUint32(out[off+4:], 0x248435a4)
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return out, nil
}
