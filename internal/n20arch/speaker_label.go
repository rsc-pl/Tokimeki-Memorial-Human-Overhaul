package n20arch

// speaker bridge — width-independent rendering of the SAVED PLAYER SURNAME in the retail
// speaker call (0x80050DFC). PRIVATE OFFLINE CANDIDATE, DISABLED BY DEFAULT.
//
// The retail speaker picks its X origin from the byte length of the kana
// string (2/4/6 bytes -> -114/-121/-128, 14 px per 2-byte cell). Once the
// surname has been romanised into the pair font it is 2..12 bytes long, and
// the retail table has no entry for that case: it falls back to -128, so a
// 4- or 5-cell roman name is drawn 7 or 14 px right of centre.
//
// The authenticated table is exactly a centred formula:
//
//	-114 + 7 = -121 + 14 = -128 + 21 = -107
//	x = -107 - 7 * cells, cells = pairBytes / 2
//
// This file therefore adds a resident F1 shim that (a) accepts only the 16
// exact EXE callers whose a0 is the saved surname field, (b) romanises with
// the existing packed romanizer, (c) rejects anything that is not an even
// 2..12-byte sequence of installed pair-font glyphs, (d) enqueues directly
// with the computed X, and (e) otherwise tail-calls the untouched retail
// speaker with the original kana pointer. The EXE side is the SAME 52-byte
// guard used by speaker rendering; only the resident F1 body behind it changes.
//
// speaker bridge BLOCKED: the resident window lifetime, overlay reloads, pair-font
// rendering, real queue consumption and in-game positioning have NOT been
// observed. safe_to_patch=false and runtime_pass=false are intentional.
//
// Nothing here writes translation data, the retail EXE, overlays on disk,
// saves, memory cards, DuckStation, .local/museresearch, guest RAM outside
// the offline test Machine, or the original kana storage.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/graphics"
)

const (
	// SpeakerExperimentEnabled is the explicit disabled-by-default guard. No
	// production path may call PlanSpeakerDisplayOffline while this is
	// false; the plan itself also returns Blocked=true.
	SpeakerExperimentEnabled = false
	SpeakerBlocked           = true
	SpeakerBlockedReason     = "speaker bridge BLOCKED: private offline candidate only. The 16 exact speaker callers are redirected to a resident C10 F1 shim, but persistent resident-window lifetime, overlay reload/reuse, DMA/IRQ/cache coherency, English pair-font rendering and in-game position have not been observed. safe_to_patch=false, runtime_pass=false; no guest RAM, EXE, overlay, save, translation or public builder change is authorised."

	speakerGeometryQueueEntry   uint32 = 0x8004E788 // authenticated retail speaker queue
	speakerGeometryAdvanceRAM   uint32 = 0x800B3F6A // renderer cell advance byte, retail default 14
	speakerGeometryAdvanceCell         = 14
	speakerGeometrySurnameMax          = 12 // pair bytes; 6 cells, 3 kana + digraph slack
	speakerGeometryFrameBytes          = 0x80
	speakerGeometryNameBufOff          = 0x20
	speakerGeometryNameBufBytes        = 24
	speakerGeometryShimMaxBytes        = 256 // measured geometry headroom in the 3800 B body

	SiteExact      = "exact_surname"
	SiteInterposed = "surname_after_interposed_store"
	SiteOther      = "other_text"
)

// SpeakerSite is one authenticated direct EXE JAL to the retail speaker.
type SpeakerSite struct {
	PC         uint32
	Previous   uint32
	Delay      uint32
	Class      string
	Interposed bool // delay still supplies the surname, but pc-4 is not LUI a0,0x800E
}

// SpeakerCandidate is a private, runtime-unverified speaker bridge plan. It contains
// bytes only; the caller decides whether to materialise anything offline.
type SpeakerCandidate struct {
	EnglishEXE    []byte
	SourceImage   []byte
	SourceOverlay []byte
	Sites         []SpeakerSite
	Words         []n20RelocWord
	ShimBytes     int
	ShimEntry     uint32
	PatchedSites  int
	AlreadyHooked int
	SafeToPatch   bool
	RuntimePass   bool
	Blocked       bool
	BlockedReason string
}

// speakerGeometrySpeakerSites classifies every EXE JAL to 0x80050DFC. The inventory is
// authenticated: 16 exact surname callers, 3 that still pass the surname but
// have an interposed `sb t0,0x6375(at)` at pc-4, and 2 that pass other text.
// speaker bridge only redirects the 16 exact sites; the other 5 stay retail.
func speakerGeometrySpeakerSites(exe []byte) ([]SpeakerSite, error) {
	if len(exe) != 667648 {
		return nil, fmt.Errorf("speaker bridge speaker scan needs the 667648-byte EXE")
	}
	const lo, hi = 0x80041000, 0x800AF390
	var out []SpeakerSite
	for pc := uint32(lo); pc+8 <= hi; pc += 4 {
		if wordAt(exe, pc) != jalWord(OLOriginalSpeaker) {
			continue
		}
		prev, delay := wordAt(exe, pc-4), wordAt(exe, pc+4)
		s := SpeakerSite{PC: pc, Previous: prev, Delay: delay, Class: SiteOther}
		switch {
		case prev == 0x3C04800E && delay == 0x24846354: // lui a0,0x800E ; addiu a0,a0,0x6354
			s.Class = SiteExact
		case delay == 0x24846354: // surname still supplied; pc-4 is sb t0,0x6375(at)
			s.Class = SiteInterposed
			s.Interposed = true
		}
		out = append(out, s)
	}
	var exact, interposed, other int
	for _, s := range out {
		switch s.Class {
		case SiteExact:
			exact++
		case SiteInterposed:
			interposed++
			if s.Previous != 0xA0286375 {
				return nil, fmt.Errorf("speaker bridge interposed caller %08x has unexpected pc-4 %08x", s.PC, s.Previous)
			}
		default:
			other++
			if s.Delay != 0x24840A94 && s.Delay != 0x24840B8C {
				return nil, fmt.Errorf("speaker bridge other caller %08x has unexpected delay %08x", s.PC, s.Delay)
			}
		}
	}
	if len(out) != 21 || exact != 16 || interposed != 3 || other != 2 {
		return nil, fmt.Errorf("speaker bridge speaker inventory drift: total=%d exact=%d interposed=%d other=%d", len(out), exact, interposed, other)
	}
	return out, nil
}

// BuildSpeakerShim emits the resident F1 body. It is position-independent
// apart from the three absolute call targets it is given/embedded:
// romanizer, the authenticated queue and the retail speaker fallback.
func BuildSpeakerShim(romanizer uint32) ([]byte, error) {
	if romanizer&3 != 0 {
		return nil, fmt.Errorf("misaligned speaker bridge romanizer %#x", romanizer)
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	add := func(d, s uint32, i int16) { w(olADDIU(d, s, i)) }
	sw := func(t, b uint32, o int16) { w(olSW(t, b, o)) }
	lw := func(t, b uint32, o int16) { w(olLW(t, b, o)) }
	lbu := func(t, b uint32, o int16) { w(olLBU(t, b, o)) }
	andi := func(t, s uint32, imm uint16) { w(olIType(0x0C, s, t, imm)) }
	sltiu := func(t, s uint32, imm int16) { w(olSLTIU(t, s, imm)) }
	subu := func(d, x, y uint32) { w(olRType(x, y, d, 0x23)) }
	srl := func(d, s uint32, sh uint32) { w(olRType(0, s, d, 0x02) | sh<<6) }
	sll := func(d, s uint32, sh uint32) { w(olRType(0, s, d, 0x00) | sh<<6) }
	beq := func(x, y uint32, l string) { a.b(4, x, y, l); w(0) }
	bne := func(x, y uint32, l string) { a.b(5, x, y, l); w(0) }

	// Frame 0x80: name buffer +0x20 (24 B), saved s0 +0x60, saved ra +0x7C.
	add(29, 29, -speakerGeometryFrameBytes)
	sw(31, 29, 0x7C)
	sw(16, 29, 0x60)
	mov(16, 4) // s0 = original a0

	// Accept only the saved-surname field.
	w(olLUI(8, OLA0SurnameField))
	add(8, 8, int16(OLA0SurnameField&0xFFFF))
	bne(16, 8, "retail")

	// Fail closed unless the shared renderer still advances 14 px per cell.
	w(olLUI(8, speakerGeometryAdvanceRAM))
	lbu(9, 8, int16(speakerGeometryAdvanceRAM&0xFFFF))
	w(0) // R3000A load delay
	add(10, 0, speakerGeometryAdvanceCell)
	bne(9, 10, "retail")

	// Romanise the kana surname into our own stack buffer.
	mov(4, 16)
	add(5, 29, speakerGeometryNameBufOff)
	add(6, 0, speakerGeometryNameBufBytes)
	add(7, 0, 3) // suffix none, max 3 kana
	w(jalWord(romanizer))
	w(0)
	beq(2, 0, "retail")
	add(8, 2, -1) // t0 = pair bytes (v0 includes the NUL)
	// Even, 2..12 bytes. Out-of-range/negative values fail the unsigned check.
	andi(9, 8, 1)
	bne(9, 0, "retail")
	add(9, 8, -2)
	sltiu(9, 9, speakerGeometrySurnameMax-1)
	beq(9, 0, "retail")

	// Every byte must be an installed pair-font glyph (space..'z' high bit).
	add(9, 29, speakerGeometryNameBufOff)
	a.label("pairs")
	lbu(10, 9, 0)
	w(0) // load delay
	add(10, 10, -0xA0)
	sltiu(10, 10, 0x5B)
	beq(10, 0, "retail")
	add(8, 8, -1)
	add(9, 9, 1)
	bne(8, 0, "pairs")

	// x = -107 - 7 * (pairBytes/2). Retail's 2/4/6-byte table is the same
	// formula and is provably centred (see file comment).
	add(8, 2, -1)
	srl(8, 8, 1) // cells
	sll(9, 8, 3)
	subu(9, 9, 8) // 7*cells
	add(4, 0, -107)
	subu(4, 4, 9)

	// Direct retail queue call: same a1/a2/a3 and O32 fifth argument as
	// 0x80050DFC. The queue consumes/copies the pointer synchronously.
	add(5, 0, 50)
	add(6, 0, 0)
	add(7, 29, speakerGeometryNameBufOff)
	sw(0, 29, 0x10)
	w(jalWord(speakerGeometryQueueEntry))
	w(0)
	lw(31, 29, 0x7C)
	lw(16, 29, 0x60)
	w(olJR(31))
	add(29, 29, speakerGeometryFrameBytes)

	a.label("retail")
	mov(4, 16) // original kana pointer; retail 0x80050DFC reads only a0
	w(jalWord(OLOriginalSpeaker))
	w(0)
	lw(31, 29, 0x7C)
	lw(16, 29, 0x60)
	w(olJR(31))
	add(29, 29, speakerGeometryFrameBytes)

	a.resolve()
	out := words(a.words...)
	if len(out) > speakerGeometryShimMaxBytes {
		return nil, fmt.Errorf("speaker bridge shim %d B exceeds the %d-byte body headroom", len(out), speakerGeometryShimMaxBytes)
	}
	return out, nil
}

// PlanC10GyoziSource is the speaker bridge resident variant: identical guard,
// romanizer, suffix helper and queue adapter geometry as C10/speaker rendering, with the
// width-aware F1 shim behind the same 52-byte EXE gate.
func PlanSpeakerBridgeSource(original []byte) (C10SourceCandidate, error) {
	return planC10GyoziSource(original, BuildSpeakerShim)
}

// PlanSpeakerDisplayOffline builds the private EXE plan:
//   - originalEXE must be the authenticated retail SLPM_86.053;
//   - englishEXE must carry the installed English renderer (site/hook/font);
//   - overlays must contain the authenticated original GYOZI.EXN.
//
// It patches the 52-byte speaker rendering gate at 0x8004BA78 (identical bytes) and the 16
// exact speaker JALs, preserving every delay slot. It never returns a
// safe-to-patch or runtime-passing verdict.
func PlanSpeakerDisplayOffline(originalEXE, englishEXE []byte, overlays map[string][]byte) (SpeakerCandidate, error) {
	var out SpeakerCandidate
	if len(originalEXE) != 667648 || len(englishEXE) != len(originalEXE) || sha(originalEXE) != OriginalEXESHA {
		return out, fmt.Errorf("speaker bridge original EXE identity/size mismatch")
	}
	// Original must still be the pristine retail renderer.
	if _, err := graphics.InstallRenderer(originalEXE); err != nil {
		return out, fmt.Errorf("speaker bridge original renderer authenticity: %w", err)
	}
	// English EXE must have the complete pair-font renderer installed.
	tailOff, tail, err := graphics.RendererNameTail(englishEXE)
	if err != nil {
		return out, fmt.Errorf("speaker bridge installed English renderer: %w", err)
	}
	if tailOff != int(C10EXEGuardF1-0x80040800) || len(tail) != C10EXEGuardTailBytes {
		return out, fmt.Errorf("unexpected speaker bridge gate reservation %x/%d", tailOff, len(tail))
	}
	gate, err := BuildC10EXEGuardF1()
	if err != nil {
		return out, err
	}
	// The F1 slot must be empty or already hold the identical gate. Bytes
	// beyond it belong to resident module/queue routing/queue routing/speaker rendering and are left untouched.
	out.EnglishEXE = bytes.Clone(englishEXE)
	occupied := out.EnglishEXE[tailOff : tailOff+len(gate)]
	if !allZero(occupied) && !bytes.Equal(occupied, gate) {
		return SpeakerCandidate{}, fmt.Errorf("speaker bridge F1 slot occupied by a foreign gate")
	}
	copy(out.EnglishEXE[tailOff:], gate)

	sites, err := speakerGeometrySpeakerSites(originalEXE)
	if err != nil {
		return SpeakerCandidate{}, err
	}
	out.Sites = sites
	wantOld := jalWord(OLOriginalSpeaker)
	newWord := jalWord(C10EXEGuardF1)
	for _, s := range sites {
		if s.Class != SiteExact {
			continue
		}
		at := int(s.PC - 0x80040800)
		old := binary.LittleEndian.Uint32(originalEXE[at:])
		cur := binary.LittleEndian.Uint32(out.EnglishEXE[at:])
		if old != wantOld || binary.LittleEndian.Uint32(originalEXE[at+4:]) != 0x24846354 ||
			binary.LittleEndian.Uint32(out.EnglishEXE[at+4:]) != 0x24846354 {
			return SpeakerCandidate{}, fmt.Errorf("speaker bridge speaker JAL/delay drift at %08x", s.PC)
		}
		switch cur {
		case wantOld:
			out.PatchedSites++
		case newWord:
			out.AlreadyHooked++
		default:
			return SpeakerCandidate{}, fmt.Errorf("speaker bridge speaker call already owned at %08x (%08x)", s.PC, cur)
		}
		binary.LittleEndian.PutUint32(out.EnglishEXE[at:], newWord)
		out.Words = append(out.Words, n20RelocWord{
			Owner: "SLPM_86.053", PC: s.PC, Old: wantOld, New: newWord,
			Kind: "speaker_surname_display",
			Role: "EXE speaker F1: surname-only width-aware display via the shared resident gate",
		})
	}
	if len(out.Words) != 16 || out.PatchedSites+out.AlreadyHooked != 16 {
		return SpeakerCandidate{}, fmt.Errorf("speaker bridge site accounting drift %d/%d", len(out.Words), out.PatchedSites)
	}

	gyozi, ok := overlays["GYOZI.EXN"]
	if !ok || len(gyozi) == 0 {
		return SpeakerCandidate{}, fmt.Errorf("speaker bridge requires the authenticated original GYOZI.EXN")
	}
	src, err := PlanSpeakerBridgeSource(gyozi)
	if err != nil {
		return SpeakerCandidate{}, fmt.Errorf("speaker bridge resident source: %w", err)
	}
	out.SourceImage = src.SourceImage
	out.SourceOverlay = src.SourceOverlay
	out.ShimEntry = src.ShimEntry
	out.ShimBytes = src.ShimBytes
	out.SafeToPatch = false
	out.RuntimePass = false
	out.Blocked = SpeakerBlocked
	out.BlockedReason = SpeakerBlockedReason
	return out, nil
}
