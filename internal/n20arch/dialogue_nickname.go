package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Selector three chooses the saved nickname or family plus the native suffix.
// Match the finished native string, not the relationship flag. The packed
// core checks its complete output extent before storing even the first byte.
func nicknamePContinuation(entry, matchExisting, restore uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	w(olLW(8, 29, 0x34))
	w(0)
	w(olIType(12, 8, 8, 0xff))
	w(olADDIU(9, 0, 3))
	a.b(5, 8, 9, "existing")
	w(0)
	w(olLUI(4, 0x800e6364))
	w(olORI(4, 4, 0x6364))
	w(olLUI(5, givenKunExtended))
	w(olORI(5, 5, givenKunExtended&0xffff))
	w(olAddu(8, 4, 0))
	w(olAddu(9, 5, 0))
	w(olADDIU(10, 0, 11))
	a.label("compare")
	w(olLBU(11, 8, 0))
	w(olLBU(12, 9, 0))
	w(0)
	a.b(5, 11, 12, "existing")
	w(0)
	a.b(4, 11, 0, "convert")
	w(olADDIU(8, 8, 1))
	w(olADDIU(10, 10, -1))
	a.b(5, 10, 0, "compare")
	w(olADDIU(9, 9, 1))
	a.label("existing")
	w(jWord(matchExisting))
	w(0)
	a.label("convert")
	w(olADDIU(6, 0, 16))
	w(jalWord(OLBodyBase))
	w(olADDIU(7, 0, 5))
	// A rejected conversion leaves the native bytes intact.
	w(jWord(restore))
	w(0)
	a.resolve()
	a.resolveJLabels(entry)
	return words(a.words...)
}

func refreshNicknameVerifier(m *OverlayFieldPrepModule) error {
	m.Sum32, m.XOR32 = 0, 0
	for i := 0; i < len(m.Body); i += 4 {
		v := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += v
		m.XOR32 ^= v
	}
	m.BodyLen = len(m.Body)
	m.BodyEndRAM = OLBodyBase + uint32(m.BodyLen)
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(m.BodyLen))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	v, err := buildOverlayVerifierMagic(OLFieldPrepMagicWord, m.Sum32, m.XOR32, uint32(m.BodyLen))
	if err != nil || len(v) != m.VerifierBytes {
		return fmt.Errorf("nickname verifier geometry")
	}
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], v)
	return nil
}

// PlanDialogueNickname extends only the two authenticated field preparation
// carriers after their independent speaker and saved-family extensions.
func PlanDialogueNickname(name string, original, current []byte) ([]byte, error) {
	fail := func(reason string) ([]byte, error) {
		return nil, fmt.Errorf("dialogue nickname %s: %s", name, reason)
	}
	if (name != "DATE.EXN" && name != "GEKO.EXN") || len(original) != 196608 || len(current) != len(original) || sha(original) != OverlaySHA[name] || !allZero(original[OLPayloadFileOff:OLPayloadEndOff]) {
		return fail("source identity or reservation")
	}
	base, err := buildOverlayFieldPrepModuleAtWithGivenKun(N20RelocFamilyAddr, N20RelocGivenAddr, N20RelocSlotBytes, true)
	if err != nil {
		return nil, err
	}
	if base.BodyLen != 3584 || base.VerifierBytes != 184 {
		return fail("base geometry")
	}
	m := base
	if name == "GEKO.EXN" {
		m, err = extendSavedFamilyFieldPrepModule(base, false)
		if err != nil {
			return nil, err
		}
	} else {
		m.Body, m.Guard = bytes.Clone(base.Body), bytes.Clone(base.Guard)
		shim, e := BuildCompactSpeakerShim(OLBodyBase)
		if e != nil {
			return nil, e
		}
		m.Body = append(m.Body, shim...)
		for len(m.Body)%16 != 0 {
			m.Body = append(m.Body, 0)
		}
		stub, e := buildDispatchStub(OLOriginalSpeaker, base.ModuleEnd())
		if e != nil {
			return nil, e
		}
		copy(m.Guard[OLFullNameStubRAM-OLGuardBase:], stub)
		binary.LittleEndian.PutUint32(m.Guard[OLGuardBytes-4:], dateActivityMarker)
		if e := refreshNicknameVerifier(&m); e != nil {
			return nil, e
		}
	}
	if !bytes.Equal(current[OLPayloadFileOff:OLGuardFileEnd], m.Guard) || !bytes.Equal(current[OLBodyFileOff:OLBodyFileOff+len(m.Body)], m.Body) || !allZero(current[OLBodyFileOff+len(m.Body):OLPayloadEndOff]) {
		return fail("inherited body, guard or tail drift")
	}
	word := func(i int) uint32 { return binary.LittleEndian.Uint32(base.Body[i:]) }
	start := int(base.ShimBodyRAM - OLBodyBase)
	if word(start+8) != jalWord(OLFieldPrepOriginal) || word(start+12) != 0 || word(start+16) != olSW(2, 29, OLFieldPrepV0Off) {
		return fail("native call delay drift")
	}
	// Locate the unique existing P matcher and return, using their exact
	// generated instructions. Do not move either or any inherited stub.
	match, restore, branch := -1, -1, -1
	for i := start; i+24 <= len(base.Body); i += 4 {
		if word(i) == olADDIU(15, 0, 0) && word(i+4)>>16 == olIType(4, 15, 0, 0)>>16 && word(i+8) == 0 {
			if match >= 0 {
				return fail("ambiguous matcher")
			}
			match = i
		}
		if word(i) == olLW(2, 29, OLFieldPrepV0Off) && word(i+4) == olLW(3, 29, OLFieldPrepV1Off) && word(i+8) == olLW(31, 29, OLFieldPrepRAOff) && word(i+12) == 0 && word(i+16) == olJR(31) && word(i+20) == olADDIU(29, 29, OLFieldPrepFrame) {
			if restore >= 0 {
				return fail("ambiguous return")
			}
			restore = i
		}
	}
	if match < 0 || restore < 0 {
		return fail("matcher or return missing")
	}
	for i := start; i < match; i += 4 {
		v := word(i)
		if v>>16 == olIType(4, 8, 0, 0)>>16 && i+4+int(int16(v))*4 == match && word(i+4) == 0 {
			if branch >= 0 {
				return fail("ambiguous copy exit")
			}
			branch = i
		}
	}
	if branch < 0 {
		return fail("copy exit missing")
	}
	entry := OLBodyBase + uint32(len(m.Body))
	// Save a0 in the unused word of the existing frame, then redirect
	// the exact successful given-copy exit. No new caller or stack frame.
	binary.LittleEndian.PutUint32(m.Body[start+12:], olSW(4, 29, 0x34))
	binary.LittleEndian.PutUint32(m.Body[branch:], olIType(4, 8, 0, uint16((int(entry-OLBodyBase)-branch-4)/4)))
	m.Body = append(m.Body, nicknamePContinuation(entry, OLBodyBase+uint32(match), OLBodyBase+uint32(restore))...)
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	if len(m.Body) > OLBodyCapacity {
		return fail("body capacity")
	}
	if err := refreshNicknameVerifier(&m); err != nil {
		return nil, err
	}
	out := bytes.Clone(current)
	copy(out[OLPayloadFileOff:OLGuardFileEnd], m.Guard)
	copy(out[OLBodyFileOff:], m.Body)
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return out, nil
}
