package n20arch

// speaker bridge: source-authenticated, OFFLINE-ONLY expansion of the existing speaker rendering F1
// gate. 16 exact EXE callers load the saved surname into a0 and invoke the
// same retail speaker routine. speaker rendering covered two; these fourteen are omitted.
// This adds no ROM write, no new RAM region and no gate/body bytes.
// It does not prove which one emitted the reported activity label.

import (
	"encoding/binary"
	"fmt"
)

// Each of these is an authentic, *additional* direct JAL 0x80050DFC.
// The immediately previous word MUST be lui a0,0x800e, and the original
// JAL delay MUST be addiu a0,a0,0x6354 (saved surname field).
var speakerGeometryAdditionalSurnameSpeakerCalls = [...]uint32{
	0x80060978, 0x80060D18, 0x80061328, 0x800615BC,
	0x8006AE8C, 0x80072738, 0x80072A94, 0x800731E4,
	0x8007333C, 0x8007341C, 0x80076694, 0x80076CCC,
	0x80077EC0, 0x8007801C,
}

func PlanExactSurnameF1Offline(exe []byte, originals map[string][]byte) (C10DistributedCandidate, error) {
	d, err := PlanC10State3SharedQueueOffline(exe, originals)
	if err != nil {
		return d, err
	}
	if len(d.AddedEXEWords) != 7 || d.SafeToPatch || d.RuntimePass {
		return C10DistributedCandidate{}, fmt.Errorf("speaker bridge speaker rendering predecessor drift")
	}
	return applyF1Additional(exe, d)
}

// The telephone phone-local path also begins from speaker rendering and keeps the very same
// EXE F1 gate. Compose the additional speaker coverage with telephone rather than
// dropping the already-implemented telephone full-name code.
func PlanTELAndExactSurnameF1Offline(exe []byte, originals map[string][]byte) (C10DistributedCandidate, error) {
	phone, err := PlanTELFullnameOffline(exe, originals)
	if err != nil {
		return C10DistributedCandidate{}, err
	}
	if len(phone.AddedEXEWords) != 7 || phone.SafeToPatch || phone.RuntimePass {
		return C10DistributedCandidate{}, fmt.Errorf("speaker bridge telephone predecessor drift")
	}
	return applyF1Additional(exe, phone.C10DistributedCandidate)
}

func applyF1Additional(exe []byte, d C10DistributedCandidate) (C10DistributedCandidate, error) {
	// The two existing F1 callers are intentionally untouched; the full
	// approved set is 16, each with the SAME saved surname and queue ABI.
	seen := map[uint32]bool{}
	for _, pc := range c10EXEF1RetailCalls {
		seen[pc] = true
	}
	for _, pc := range speakerGeometryAdditionalSurnameSpeakerCalls {
		if seen[pc] || pc < 0x80041004 || int(pc-0x80040800+8) > len(exe) {
			return C10DistributedCandidate{}, fmt.Errorf("speaker bridge duplicate/out-of-range %08x", pc)
		}
		seen[pc] = true
		off := int(pc - 0x80040800)
		old := binary.LittleEndian.Uint32(exe[off:])
		pre := binary.LittleEndian.Uint32(exe[off-4:])
		delay := binary.LittleEndian.Uint32(exe[off+4:])
		if old != jalWord(OLOriginalSpeaker) || pre != olLUI(4, OLA0SurnameField) ||
			delay != olADDIU(4, 4, int16(OLA0SurnameField&0xffff)) ||
			binary.LittleEndian.Uint32(d.EnglishEXE[off:]) != old ||
			binary.LittleEndian.Uint32(d.EnglishEXE[off+4:]) != delay {
			return C10DistributedCandidate{}, fmt.Errorf("speaker bridge original surname callsite drift %08x", pc)
		}
		replacement := jalWord(C10EXEGuardF1)
		binary.LittleEndian.PutUint32(d.EnglishEXE[off:], replacement)
		d.AddedEXEWords = append(d.AddedEXEWords, n20RelocWord{
			Owner: "SLPM_86.053", PC: pc, Old: old, New: replacement,
			Kind: "exact_surname_speaker_f1", Role: "source-gated speaker surname, protected speaker rendering F1 and retail fallback",
		})
	}
	if len(seen) != 16 || len(d.AddedEXEWords) != 21 || d.SafeToPatch || d.RuntimePass {
		return C10DistributedCandidate{}, fmt.Errorf("speaker bridge safety/inventory drift")
	}
	return d, nil
}
