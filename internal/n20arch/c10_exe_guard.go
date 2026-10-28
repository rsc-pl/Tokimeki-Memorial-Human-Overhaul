package n20arch

// C10's persistent-name entry must never be called by an EXE caller before
// promotion. The existing English renderer reserves a 180-byte, zero-filled
// tail after its 96 glyphs. This candidate uses a *small, permanent EXE-side
// F1 gate* there; it does not place another romanizer in EXE RAM.
//
// The guarded gate always has a retail destination, including on cold boot,
// and its JAL callsites do not depend on which overlay is loaded. It is a
// private offline candidate: the renderer tail's whole-game write ownership
// and C10 destination lifetime still require in-game QA before release.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/graphics"
)

const (
	C10EXEGuardF1        uint32 = 0x8004BA78 // renderer font tail, after 96 * 8 glyph bytes
	C10EXEGuardTailBytes        = 180
)

var c10EXEF1RetailCalls = [...]uint32{0x800756A4, 0x8005A6B4}

type C10EXEGuardCandidate struct {
	EnglishEXE  []byte
	Guard       []byte
	Words       []n20RelocWord
	GuardPC     uint32
	SafeToPatch bool
	RuntimePass bool
}

// BuildC10EXEGuardF1 creates a branch-delay-aware, no-stack tail-jump gate.
// Only $t0/$t1/$t2 are scratched; $a0..$a3, $sp, $ra and $v0/$v1 are left
// untouched. It verifies both resident magic and declared resident length.
func BuildC10EXEGuardF1() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	w(olLUI(8, C10ResidentGuard+0x10000))
	w(olLW(9, 8, int16(uint16Low(C10ResidentGuard))))
	// Load delay is filled by constructing the expected magic.
	w(olLUI(10, C10Magic))
	w(olORI(10, 10, C10Magic&0xffff))
	a.b(5, 9, 10, "retail")
	// Branch delay loads the length; the subsequent ADDIU covers its delay.
	w(olLW(9, 8, int16(uint16Low(C10ResidentGuard+4))))
	w(olADDIU(10, 0, C10ResidentBodyBytes))
	a.b(5, 9, 10, "retail")
	w(0)
	w(jWord(C10F1Entry))
	w(0)
	a.label("retail")
	w(jWord(OLOriginalSpeaker))
	w(0)
	a.resolve()
	out := words(a.words...)
	if len(out) != 52 {
		return nil, fmt.Errorf("F1 compact gate expected 52 B, got %d", len(out))
	}
	return out, nil
}

// PlanC10EXEGuardF1 accepts only the authenticated original retail EXE and
// a byte-perfect installed English renderer. It is not an image builder.
func PlanC10EXEGuardF1(originalEXE, englishEXE []byte) (C10EXEGuardCandidate, error) {
	var out C10EXEGuardCandidate
	if sha(originalEXE) != "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae" || len(originalEXE) != len(englishEXE) {
		return out, fmt.Errorf("EXE original identity/size mismatch")
	}
	off, tail, err := graphics.ReservedNamePool(englishEXE)
	if err != nil {
		return out, fmt.Errorf("English renderer reservation: %w", err)
	}
	if off != int(C10EXEGuardF1-0x80040800) || len(tail) != C10EXEGuardTailBytes {
		return out, fmt.Errorf("unexpected renderer tail offset/length: %x/%d", off, len(tail))
	}
	gate, err := BuildC10EXEGuardF1()
	if err != nil {
		return out, err
	}
	out.EnglishEXE = bytes.Clone(englishEXE)
	copy(out.EnglishEXE[off:], gate)
	out.Guard = gate
	out.GuardPC = C10EXEGuardF1
	for _, pc := range c10EXEF1RetailCalls {
		p := int(pc - 0x80040800)
		old := binary.LittleEndian.Uint32(originalEXE[p:])
		want := jalWord(OLOriginalSpeaker)
		if old != want || binary.LittleEndian.Uint32(englishEXE[p:]) != want ||
			binary.LittleEndian.Uint32(originalEXE[p+4:]) != OLSpeakerDelay ||
			binary.LittleEndian.Uint32(englishEXE[p+4:]) != OLSpeakerDelay {
			return C10EXEGuardCandidate{}, fmt.Errorf("speaker JAL/delay changed at %08x", pc)
		}
		replacement := jalWord(C10EXEGuardF1)
		binary.LittleEndian.PutUint32(out.EnglishEXE[p:], replacement)
		out.Words = append(out.Words, n20RelocWord{Owner: "SLPM_86.053", PC: pc, Old: old, New: replacement, Kind: "c10_exe_resident_guarded_f1", Role: "EXE speaker F1: cold-boot retail fallback"})
	}
	return out, nil
}
