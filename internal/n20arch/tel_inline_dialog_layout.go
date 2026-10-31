package n20arch

// The telephone has an independent first-line queue immediately after its
// nameplate queue.  A 12-character surname can occupy six 14px cells while
// the retail body begins only 42px after the start of the nameplate.  This
// TEL-LOCAL renderer clone moves the first line only when its *already
// formatted* byte length fits the remaining line width. All other phones,
// overlays, and the resident renderer remain unchanged.
//
// This is a strictly scoped candidate; real GPU/frame acceptance is not
// inferred from static or guest-MIPS tests.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	telDialogOriginalEntry     uint32 = 0x80051010
	telDialogOriginalEnd       uint32 = 0x8005142C // exclusive, includes final return delay slot
	telDialogCloneEntry        uint32 = OverlaySlotBase + 0x25000
	telDialogCloneStub         uint32 = telDialogCloneEntry + 0x500
	telDialogueWrapperOriginal uint32 = 0x80050E8C
	telDialogueWrapperEnd      uint32 = 0x80051010
	telDialogueWrapperClone    uint32 = telDialogCloneEntry + 0x600
	telDialogWindowEnd                = 0x26000
	telDialogWidthHelper       uint32 = telDialogCloneEntry + 0x800
	telDialogBodyXOld          int16  = -86
	telDialogBodyXSafe         int16  = -30
	telDialogMaxFirstLineBytes int16  = 54 // 27 7px Latin glyphs at X=-30, right edge <= 160
)

type TelScopedDialogPlan struct {
	Bytes               []byte
	SavedNameBytes      []byte
	SurnameComposeBytes []byte
	GivenAddressBytes   []byte
	Calls               []N20ManifestWord
}

func telOriginalDialogSites(tel []byte) ([]uint32, error) {
	if len(tel) != 196608 || sha(tel) != OverlaySHA["TEL.EXN"] {
		return nil, fmt.Errorf("TEL dialogue: unauthenticated original overlay")
	}
	var out []uint32
	// The adjacent speaker/body pattern is an original source fact.  There are
	// exactly 29 NPC-nameplate calls in mode 0x0D; it must never be widened to
	// the saved-player-speaker modes 0x0F/0x1F or other overlays.
	for off := 20; off+8 < overlayCodeEnd(tel); off += 4 {
		if binary.LittleEndian.Uint32(tel[off:]) != jalWord(telDialogOriginalEntry) ||
			binary.LittleEndian.Uint32(tel[off+4:]) != 0x2406000D ||
			binary.LittleEndian.Uint32(tel[off-20:]) != jalWord(OLOriginalSpeaker) {
			continue
		}
		out = append(out, OverlaySlotBase+uint32(off))
	}
	if len(out) != 29 {
		return nil, fmt.Errorf("TEL dialogue: callsite set changed (%d, expected 29)", len(out))
	}
	return out, nil
}

// The source-indexed telephone greeting is distinct from the fixed dialogue
// callers. Its speaker comes from the EXE character-name pointer table while
// the first spoken line comes from the TEL dialogue pointer table. Both share
// the same script index and the retail body formatter. The index is preserved:
// only the body call is retargeted to the existing bounded TEL-local clone.
const (
	telIndexedGreetingCall uint32 = OverlaySlotBase + 0x308c
	// Two source-attested first-line calls display a nameplate from the
	// independent surname slot, including the greeting before the later
	// multiline conversation. Both share the same first-line mode and source.
	telAdjacentGreetingCall uint32 = OverlaySlotBase + 0x66c
	telAdjacentDialogueCall uint32 = OverlaySlotBase + 0x750
)

func telOriginalAdjacentSpeakerFirstLines(tel []byte) ([]uint32, error) {
	if len(tel) != 196608 || sha(tel) != OverlaySHA["TEL.EXN"] {
		return nil, fmt.Errorf("TEL adjacent speaker: unauthenticated original overlay")
	}
	// Authenticate the complete speaker/first-line pairs, not just the JALs:
	// the nameplate precedes the source-owned body in each independent call.
	expected := map[uint32]uint32{
		0x80132650:                  0x3c04800b, // surname table slot
		0x80132654:                  0x8c84361c,
		0x80132658:                  jalWord(OLOriginalSpeaker),
		0x8013265c:                  0,
		0x80132660:                  0x3c048014, // first greeting source
		0x80132664:                  0x2484e508,
		0x80132668:                  0x00002825, // a1 = 0
		telAdjacentGreetingCall:     jalWord(telDialogOriginalEntry),
		telAdjacentGreetingCall + 4: 0x2406000a,
		0x80132734:                  0x3c04800b,
		0x80132738:                  0x8c84361c,
		0x8013273c:                  jalWord(OLOriginalSpeaker),
		0x80132740:                  0,
		0x80132744:                  0x3c048014, // later first-line source
		0x80132748:                  0x2484e540,
		0x8013274c:                  0x00002825,
		telAdjacentDialogueCall:     jalWord(telDialogOriginalEntry),
		telAdjacentDialogueCall + 4: 0x2406000a,
		0x80132764:                  jalWord(telDialogOriginalEntry), // later following lines retail
		0x80132778:                  jalWord(telDialogOriginalEntry),
	}
	for pc, word := range expected {
		if binary.LittleEndian.Uint32(tel[pc-OverlaySlotBase:]) != word {
			return nil, fmt.Errorf("TEL adjacent speaker: source instruction drift at %#x", pc)
		}
	}
	return []uint32{telAdjacentGreetingCall, telAdjacentDialogueCall}, nil
}

func telOriginalIndexedGreeting(exe, tel []byte) (uint32, error) {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA ||
		len(tel) != 196608 || sha(tel) != OverlaySHA["TEL.EXN"] {
		return 0, fmt.Errorf("TEL indexed greeting: unauthenticated source")
	}
	// Exact retail dataflow: girl index -> EXE speaker pointer, then the same
	// index -> TEL first-line pointer. This is not an adjacency heuristic.
	words := map[uint32]uint32{
		0x80135054:                 0x3c04800b, // EXE table base
		0x80135058:                 0x00034880, // index * 4
		0x80135064:                 0x00892021,
		0x80135068:                 0x8c8435f4, // EXE speaker pointer table
		0x8013506c:                 jalWord(OLOriginalSpeaker),
		0x80135074:                 0x3c038014,
		0x80135078:                 0x906605e4, // current character index
		0x8013507c:                 0x3c048014,
		0x80135080:                 0x00065080,
		0x80135084:                 0x008a2021,
		0x80135088:                 0x8c8406e0, // TEL greeting pointer table
		telIndexedGreetingCall:     jalWord(telDialogOriginalEntry),
		telIndexedGreetingCall + 4: 0x00002825, // first line (a1=0)
	}
	for pc, expected := range words {
		if binary.LittleEndian.Uint32(tel[pc-OverlaySlotBase:]) != expected {
			return 0, fmt.Errorf("TEL indexed greeting: source instruction mismatch at %#x", pc)
		}
	}
	// The 12 consecutive retail records pair exactly twelve named speakers
	// with twelve different first-line greetings, indexed by the script. The
	// hash-authenticated original tables must not be substituted by test names.
	for i := uint32(0); i < 12; i++ {
		namePtr := binary.LittleEndian.Uint32(exe[0x800b35f4-0x80040800+4*i:])
		textPtr := binary.LittleEndian.Uint32(tel[0x801406e0-OverlaySlotBase+4*i:])
		if namePtr < 0x800b3578 || namePtr >= 0x800b35f4 ||
			textPtr < 0x801405f0 || textPtr >= 0x801406e0 {
			return 0, fmt.Errorf("TEL indexed greeting: pointer pair %d outside authenticated name/text tables", i)
		}
		name := exe[namePtr-0x80040800:]
		text := tel[textPtr-OverlaySlotBase:]
		if name[0] == 0 || text[0] == 0 || bytes.IndexByte(name[:16], 0) < 0 || bytes.IndexByte(text[:48], 0) < 0 {
			return 0, fmt.Errorf("TEL indexed greeting: unterminated speaker/line pair %d", i)
		}
	}
	return telIndexedGreetingCall, nil
}

// telIndexedWrappedGirlSites is a distinct original caller family. Each
// selected call has an EXE character-table speaker call immediately before a
// FIRST-line body call through the retail multi-line wrapper. The wrapper is
// different from 0x80051010 and internally invokes it once per text line.
// Authentication is over original TEL bytes, never string contents.
func telIndexedWrappedGirlSites(tel []byte) ([]uint32, error) {
	if len(tel) != 196608 || sha(tel) != OverlaySHA["TEL.EXN"] {
		return nil, fmt.Errorf("TEL indexed multiline: unauthenticated original overlay")
	}
	var out []uint32
	for off := 0x44; off+8 < overlayCodeEnd(tel); off += 4 {
		if binary.LittleEndian.Uint32(tel[off:]) != jalWord(telDialogueWrapperOriginal) ||
			binary.LittleEndian.Uint32(tel[off+4:]) != 0x00002825 { // a1 = 0: first dialogue line
			continue
		}
		// The nearest speaker call in this same basic block must use the indexed
		// original EXE name table. A generic speaker/text adjacency is insufficient.
		for prior := off - 0x44; prior < off; prior += 4 {
			if binary.LittleEndian.Uint32(tel[prior:]) != jalWord(OLOriginalSpeaker) {
				continue
			}
			if off-prior > 0x44 {
				continue
			}
			for load := prior - 36; load < prior; load += 4 {
				if binary.LittleEndian.Uint32(tel[load:]) == 0x8c8435f4 { // indexed name ptr
					out = append(out, OverlaySlotBase+uint32(off))
					goto selected
				}
			}
		}
	selected:
	}
	if len(out) != 29 {
		return nil, fmt.Errorf("TEL indexed multiline: callsite family drift (%d, expected 29)", len(out))
	}
	return out, nil
}

// telWrapperCloneSource preserves the retail multiline preprocessor, including
// its split-line state, caller ABI, and every external call except the two
// authenticated formatter JALs. Those call the already installed local clone.
func telWrapperCloneSource(exe []byte) ([]byte, error) {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return nil, fmt.Errorf("TEL multiline wrapper: unauthenticated original EXE")
	}
	lo := int(telDialogueWrapperOriginal - 0x80040800)
	hi := int(telDialogueWrapperEnd - 0x80040800)
	result := bytes.Clone(exe[lo:hi])
	if len(result) != 0x184 {
		return nil, fmt.Errorf("TEL multiline wrapper: unexpected body size")
	}
	patched := 0
	for i := 0; i < len(result); i += 4 {
		pc := telDialogueWrapperOriginal + uint32(i)
		word := binary.LittleEndian.Uint32(result[i:])
		op := word >> 26
		if op == 1 || (op >= 4 && op <= 7) {
			dst := int64(pc) + 4 + int64(int16(word&0xffff))*4
			if dst < int64(telDialogueWrapperOriginal) || dst >= int64(telDialogueWrapperEnd) {
				return nil, fmt.Errorf("TEL multiline wrapper: external branch at %#x", pc)
			}
		}
		if op == 2 || op == 3 {
			dst := (pc & 0xf0000000) | ((word & 0x3ffffff) << 2)
			if dst >= telDialogueWrapperOriginal && dst < telDialogueWrapperEnd {
				return nil, fmt.Errorf("TEL multiline wrapper: absolute internal jump at %#x", pc)
			}
		}
		if word == jalWord(telDialogOriginalEntry) {
			if i != 0x100 && i != 0x12c {
				return nil, fmt.Errorf("TEL multiline wrapper: unexpected formatter JAL at %#x", pc)
			}
			binary.LittleEndian.PutUint32(result[i:], jalWord(telDialogCloneEntry))
			patched++
		}
	}
	if patched != 2 || binary.LittleEndian.Uint32(result[0x44:]) != 0x00c0a025 ||
		binary.LittleEndian.Uint32(result[0x104:]) != 0x02803025 ||
		binary.LittleEndian.Uint32(result[0x130:]) != 0x02803025 {
		return nil, fmt.Errorf("TEL multiline wrapper: original formatter/argument ABI changed")
	}
	return result, nil
}

func telCloneSource(exe, originalTEL []byte) ([]byte, error) {
	// Identify the only TEL body callsites that read their speaker from the
	// shared pointer. This list is derived from authenticated retail instructions,
	// not from character identities or dialogue text.
	sharedSites, err := telOriginalDialogSites(originalTEL)
	if err != nil {
		return nil, err
	}
	adjacent, err := telOriginalAdjacentSpeakerFirstLines(originalTEL)
	if err != nil {
		return nil, err
	}
	for _, pc := range sharedSites {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(originalTEL[off-28:]) != 0x3c04800b ||
			binary.LittleEndian.Uint32(originalTEL[off-24:]) != 0x8c843628 {
			return nil, fmt.Errorf("TEL dialogue: shared speaker source changed at %#x", pc)
		}
	}
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return nil, fmt.Errorf("TEL dialogue: unauthenticated original EXE")
	}
	lo := int(telDialogOriginalEntry - 0x80040800)
	hi := int(telDialogOriginalEnd - 0x80040800)
	body := bytes.Clone(exe[lo:hi])
	// All PC-relative branches must stay inside the copied routine. No
	// branch target, internal J, literal-pool or external jump may be guessed.
	for i := 0; i < len(body); i += 4 {
		pc := telDialogOriginalEntry + uint32(i)
		w := binary.LittleEndian.Uint32(body[i:])
		op := w >> 26
		if op == 1 || (op >= 4 && op <= 7) {
			n := int32(int16(w & 0xffff))
			dst := int64(pc) + 4 + int64(n)*4
			if dst < int64(telDialogOriginalEntry) || dst >= int64(telDialogOriginalEnd) {
				return nil, fmt.Errorf("TEL dialogue: external relative branch at %#x to %#x", pc, dst)
			}
		}
		if op == 2 || op == 3 {
			dst := (pc & 0xF0000000) | ((w & 0x03ffffff) << 2)
			if dst >= telDialogOriginalEntry && dst < telDialogOriginalEnd {
				return nil, fmt.Errorf("TEL dialogue: internal absolute jump at %#x", pc)
			}
		}
	}
	// At the first-line queue call (only for mode != 0xFF), replace the two
	// queue setup instructions with a jump into a TEL-owned size guard.  Branch
	// delay behavior remains unchanged for the caller's preceding bne.
	off := int(uint32(0x80051374) - telDialogOriginalEntry)
	if binary.LittleEndian.Uint32(body[off:]) != 0x24050032 || binary.LittleEndian.Uint32(body[off+4:]) != 0x00003025 ||
		binary.LittleEndian.Uint32(body[off-4:]) != 0x8fbf001c {
		return nil, fmt.Errorf("TEL dialogue: first-line queue preimage mismatch")
	}
	binary.LittleEndian.PutUint32(body[off:], jWord(telDialogCloneStub))
	binary.LittleEndian.PutUint32(body[off+4:], 0)
	// Original parser is 0x41C bytes. The bounded hook body is resident in the
	// same TEL overlay, not a shared C10 window. The tail of the 0x1000-byte window
	// stays zero.
	image := make([]byte, 0x1000)
	copy(image, body)
	const stubOff = 0x500
	// Inspect at most 55 bytes of the retail 64-byte staging line. There is
	// deliberately NO unbounded strlen: a missing terminator must retain X
	// = -86.  The scan operates *after* dynamic expansion, so {P}/{F}
	// expansion cannot make the width check stale.
	a := &miniAsm{labels: map[string]int{}}
	a.w(olADDIU(8, 29, 172))                         // t0 = bounded stage cursor
	a.w(olADDIU(9, 0, telDialogMaxFirstLineBytes+1)) // 55 reads, bytes [0,54]
	a.label("scan")
	a.w(olLBU(10, 8, 0))
	a.w(0) // MIPS load delay
	a.b(4, 10, 0, "safe")
	a.w(0)
	a.w(olADDIU(8, 8, 1))
	a.w(olADDIU(9, 9, -1))
	a.b(5, 9, 0, "scan")
	a.w(0)
	a.label("original")
	a.w(olADDIU(4, 0, telDialogBodyXOld))
	a.j("common")
	a.w(0)
	a.label("safe")
	a.w(jWord(telDialogWidthHelper))
	a.w(0)
	a.label("common")
	a.w(olADDIU(5, 0, 50))
	a.w(0x00003025) // or a2,zero,zero
	a.w(olADDIU(7, 29, 172))
	a.w(jalWord(0x8004E788))
	a.w(0xafa00010) // retail queue delay slot: sw zero,16(sp)
	a.w(jWord(telDialogCloneEntry + uint32(0x80051388-0x80051010)))
	a.w(0)
	a.resolve()
	a.resolveJLabels(telDialogCloneStub)
	if len(a.words)*4 > 0x100 {
		return nil, fmt.Errorf("TEL dialogue: first-line hook exceeds its isolated stub slot")
	}
	for i, w := range a.words {
		binary.LittleEndian.PutUint32(image[stubOff+i*4:], w)
	}
	// The first-line branch at retail 0x8005134C jumps directly to
	// 0x80051374, skipping the ra reload at 0x80051370. The current ra
	// still belongs to the last internal JAL (0x80051344). The genuine
	// caller was saved at 28(sp) by the formatter prologue; read that
	// frame slot WITHOUT changing ra or the original return flow.
	// The 3 indexed routes use the indexed EXE name table; 29 other authenticated routes
	// use the original shared speaker pointer at 0x800B3628. All other
	// callers keep the conservative fallback. In particular, there is no
	// character-ID whitelist or text-dependent branch.
	// The first-line staging scan has already verified <=54 bytes. At a
	// 12-byte maximum speaker name, X=-40 and 27 7px glyphs end at X=149,
	// inside the established X=160 right boundary. The previous <=28-byte
	// condition rejected ordinary 21-character greetings unnecessarily.
	b := &miniAsm{labels: map[string]int{}}
	b.w(olADDIU(11, 0, telDialogMaxFirstLineBytes+1)) // t3 = 55
	b.w(olSUBU(11, 11, 9))                            // encoded first-line bytes = 55 - remaining
	b.w(olADDIU(11, 11, 1))
	b.w(olRType(0, 11, 11, 0) | (1 << 6) | 2) // t3 = ceil(bytes / 2) drawn glyphs
	b.w(olLW(12, 29, 28))                     // t4 = authentic saved caller ra
	b.w(0)                                    // load delay; current ra remains unchanged
	// Direct greeting and wrapped conversations receive their character index
	// from DIFFERENT source-owned state: the direct call uses TEL+0xE5E4;
	// the retail multiline wrapper copies its caller's a2 into s4 at entry.
	// Reading TEL+0xE5E4 for every wrapped call would choose the wrong name
	// for the other authenticated source-index families.
	b.w(olLUI(8, telIndexedGreetingCall+8))
	b.w(olORI(8, 8, telIndexedGreetingCall+8))
	b.b(4, 12, 8, "greeting")
	b.w(0)
	for _, ra := range []uint32{telDialogueWrapperClone + 0x108, telDialogueWrapperClone + 0x134} {
		b.w(olLUI(8, ra))
		b.w(olORI(8, 8, ra))
		b.b(4, 12, 8, "wrapped")
		b.w(0)
	}
	// The shared-speaker family has 29 immutable, source-authenticated
	// return addresses. The source passed to the speaker call is the given
	// name at 0x800B3628 (Yoshio in the owner live trace), while the
	// displayed surname label is supplied by the neighbouring original
	// surname slot 0x800B361C. Measure that same source, and align the
	// first line with the retail continuation's fixed origin.
	// Never apply this source relationship to other telephone callers.
	for _, pc := range sharedSites {
		b.w(olLUI(8, pc+8))
		b.w(olORI(8, 8, pc+8))
		b.b(4, 12, 8, "sharedSpeaker")
		b.w(0)
	}
	// This retail first-line route reads a different actual speaker pointer.
	// Do not treat its source as the Yoshio shared pointer or an indexed name.
	for _, pc := range adjacent {
		b.w(olLUI(8, pc+8))
		b.w(olORI(8, 8, pc+8))
		b.b(4, 12, 8, "adjacentSpeaker")
		b.w(0)
	}
	b.label("fallback")
	b.w(olADDIU(4, 0, telDialogBodyXSafe))
	b.w(jWord(telDialogCloneStub + uint32(a.labels["common"]*4)))
	b.w(0)
	b.label("greeting")
	b.w(olLUI(8, 0x801405e4))
	b.w(olLBU(9, 8, 0x05e4)) // authenticated greeting selector
	b.w(0)
	b.j("indexed")
	b.w(0)
	b.label("wrapped")
	b.w(olAddu(9, 20, 0)) // s4 = original wrapper a2 (indexed speaker)
	b.label("indexed")
	b.w(olSLTIU(5, 9, 12))
	b.b(4, 5, 0, "fallback")
	b.w(0)
	b.w(olRType(0, 9, 9, 0) | (2 << 6)) // sll t1,t1,2
	b.w(olLUI(8, 0x800b35f4))
	b.w(olORI(8, 8, 0x35f4))
	b.w(olAddu(8, 8, 9))
	b.w(olLW(8, 8, 0))
	b.w(0)                // load delay: name pointer from indexed table
	b.w(olADDIU(9, 0, 0)) // indexed first lines retain the accepted gap
	b.j("scanInit")
	b.w(0)
	b.label("sharedSpeaker")
	b.w(olLUI(8, 0x800b361c))
	b.w(olLW(8, 8, 0x361c)) // rendered surname source, not given-name source 0x3628
	b.w(0)                  // load delay
	b.w(olADDIU(9, 0, 1))   // mark shared source; adjust only documented pair-padding
	b.j("scanInit")
	b.w(0)
	b.label("adjacentSpeaker")
	b.w(olLUI(8, 0x800b361c))
	b.w(olLW(8, 8, 0x361c)) // original source of the adjacent nameplate
	b.w(0)                  // load delay
	b.w(olADDIU(9, 0, 0))   // adjacent mode keeps its previously tested geometry
	b.label("scanInit")
	b.w(olADDIU(10, 0, 0)) // t2 = bounded encoded byte count
	b.label("scan")
	b.w(olLBU(5, 8, 0))
	b.w(0) // load delay
	b.b(4, 5, 0, "end")
	b.w(0)
	b.w(olADDIU(10, 10, 1))
	b.w(olSLTIU(5, 10, 13))
	b.b(4, 5, 0, "fallback") // reject >12, missing NUL
	b.w(0)
	b.w(olADDIU(8, 8, 1))
	b.j("scan")
	b.w(0)
	b.label("end")
	b.w(olIType(0x0c, 10, 5, 1)) // andi a1,t2,1
	b.b(5, 5, 0, "fallback")     // odd byte count
	b.w(0)
	b.w(olSLTIU(5, 10, 2))
	b.b(5, 5, 0, "fallback") // empty name
	b.w(0)
	// Only the shared speaker family can end with an encoded ASCII pair-
	// padding space (0xA0).  It is not part of the visible surname. Align
	// this first line with its retail continuation by four native units,
	// but keep the existing safety margin for a full-width last glyph.
	b.b(4, 9, 0, "noPairPadding")
	b.w(0)
	b.w(olLBU(5, 8, -1)) // last encoded speaker byte after bounded NUL scan
	b.w(0)
	b.w(olADDIU(12, 0, 0xa0))
	b.b(5, 5, 12, "noPairPadding")
	b.w(0)
	b.w(olADDIU(9, 0, -4)) // invisible pair-pad: align with retail continuation
	b.j("widthReady")
	b.w(0)
	b.label("noPairPadding")
	b.w(olADDIU(9, 0, 0))
	b.label("widthReady")
	// Compute from the rendered name's encoded byte width.  For the
	// shared-speaker source family only, account for a trailing invisible
	// pair pad, without reducing clearance for fully occupied pairs.
	// Name-length and right-edge guards still apply; the adjacent/Yumi and
	// indexed character-name families remain unchanged.
	b.w(olAddu(5, 10, 11))
	b.w(olSLTIU(5, 5, 41))
	b.b(4, 5, 0, "fallback")
	b.w(0)
	b.w(olRType(0, 10, 4, 0) | (3 << 6)) // sll a0,t2,3
	b.w(olSUBU(4, 4, 10))                // 7 native X units per English letter
	b.w(olADDIU(4, 4, -124))             // speaker X=-128 plus four units margin
	b.w(olAddu(4, 4, 9))                 // shared-family continuation alignment in native X units
	b.w(jWord(telDialogCloneStub + uint32(a.labels["common"]*4)))
	b.w(0)
	b.resolve()
	b.resolveJLabels(telDialogWidthHelper)
	if len(b.words)*4 > 0x800 {
		return nil, fmt.Errorf("TEL dialogue: bounded width helper exceeds its slot")
	}
	for i, w := range b.words {
		binary.LittleEndian.PutUint32(image[0x800+i*4:], w)
	}
	wrapped, err := telWrapperCloneSource(exe)
	if err != nil {
		return nil, err
	}
	copy(image[0x600:], wrapped)
	if len(image) > telDialogWindowEnd-0x25000 {
		return nil, fmt.Errorf("TEL dialogue: clone overrun")
	}
	return image, nil
}

func telScopedDialogPatch(exe, original, staged []byte) (TelScopedDialogPlan, []byte, error) {
	var result TelScopedDialogPlan
	sites, err := telOriginalDialogSites(original)
	if err != nil {
		return result, nil, err
	}
	payload, err := telCloneSource(exe, original)
	if err != nil {
		return result, nil, err
	}
	indexedGreeting, err := telOriginalIndexedGreeting(exe, original)
	if err != nil {
		return result, nil, err
	}
	wrappedGirls, err := telIndexedWrappedGirlSites(original)
	if err != nil {
		return result, nil, err
	}
	adjacent, err := telOriginalAdjacentSpeakerFirstLines(original)
	if err != nil {
		return result, nil, err
	}
	if len(staged) != len(original) || !allZero(original[0x25000:0x25000+len(payload)]) ||
		!allZero(staged[0x25000:0x25000+len(payload)]) {
		return result, nil, fmt.Errorf("TEL dialogue: local window not exclusively zero")
	}
	dest := bytes.Clone(staged)
	copy(dest[0x25000:], payload)
	for _, pc := range sites {
		off := int(pc - OverlaySlotBase)
		old := jalWord(telDialogOriginalEntry)
		if binary.LittleEndian.Uint32(dest[off:]) != old || binary.LittleEndian.Uint32(dest[off+4:]) != 0x2406000D {
			return result, nil, fmt.Errorf("TEL dialogue: unexpected callsite %#x", pc)
		}
		newJ := jalWord(telDialogCloneEntry)
		binary.LittleEndian.PutUint32(dest[off:], newJ)
		result.Calls = append(result.Calls, N20ManifestWord{
			Owner: "TEL.EXN", PC: pc, Old: old, New: newJ, Kind: "jal", Role: "TEL-local NPC inline body",
			Reason: "only authenticated adjacent NPC speaker/0x0D body calls; bounded first-line X, retail fallback for long lines",
		})
	}
	// The girls' source-indexed greeting uses the same retail first-line
	// renderer and queue, but is NOT one of the 29 Yoshio mode-0x0D calls.
	// Its original a1=0 delay slot and dynamic a2/index must survive intact.
	greetOff := int(indexedGreeting - OverlaySlotBase)
	if binary.LittleEndian.Uint32(dest[greetOff:]) != jalWord(telDialogOriginalEntry) ||
		binary.LittleEndian.Uint32(dest[greetOff+4:]) != 0x00002825 {
		return result, nil, fmt.Errorf("TEL indexed greeting: staged callsite modified")
	}
	binary.LittleEndian.PutUint32(dest[greetOff:], jalWord(telDialogCloneEntry))
	result.Calls = append(result.Calls, N20ManifestWord{
		Owner: "TEL.EXN", PC: indexedGreeting, Old: jalWord(telDialogOriginalEntry),
		New: jalWord(telDialogCloneEntry), Kind: "jal", Role: "TEL indexed NPC greeting inline body",
		Reason: "source-indexed EXE speaker/TEL first-line pair, retail argument/delay preservation; bounded X with long-line fallback",
	})
	for _, pc := range adjacent {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(dest[off:]) != jalWord(telDialogOriginalEntry) ||
			binary.LittleEndian.Uint32(dest[off+4:]) != 0x2406000a {
			return result, nil, fmt.Errorf("TEL adjacent speaker: staged first line modified at %#x", pc)
		}
		binary.LittleEndian.PutUint32(dest[off:], jalWord(telDialogCloneEntry))
		result.Calls = append(result.Calls, N20ManifestWord{
			Owner: "TEL.EXN", PC: pc, Old: jalWord(telDialogOriginalEntry),
			New: jalWord(telDialogCloneEntry), Kind: "jal", Role: "TEL adjacent source-owned speaker first line",
			Reason: "retail surname nameplate and first-line body pair; unchanged other lines and renderer",
		})
	}
	for _, pc := range wrappedGirls {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(dest[off:]) != jalWord(telDialogueWrapperOriginal) ||
			binary.LittleEndian.Uint32(dest[off+4:]) != 0x00002825 {
			return result, nil, fmt.Errorf("TEL indexed multiline: staged first-line call modified at %#x", pc)
		}
		binary.LittleEndian.PutUint32(dest[off:], jalWord(telDialogueWrapperClone))
		result.Calls = append(result.Calls, N20ManifestWord{
			Owner: "TEL.EXN", PC: pc, Old: jalWord(telDialogueWrapperOriginal), New: jalWord(telDialogueWrapperClone), Kind: "jal", Role: "TEL indexed multiline girl first-line wrapper",
			Reason: "source-indexed EXE girl speaker and first-line body; authentic multiline wrapper with two local formatters and bounded X",
		})
	}
	shim, withSavedName, err := telSavedSurnamePatch(original, dest)
	if err != nil {
		return result, nil, err
	}
	dest = withSavedName
	result.SavedNameBytes = shim
	result.Calls = append(result.Calls, N20ManifestWord{
		Owner: "TEL.EXN", PC: telSavedSurnameCall, Old: jalWord(telDialogOriginalEntry),
		New: jalWord(telSavedSurnameShim), Kind: "jal", Role: "TEL saved surname dialogue display",
		Reason: "authenticated saved-surname first conversation line; same-overlay N6 romanizer with original formatter fallback",
	})
	composedBytes, afterComposition, err := telSurnameComposePatch(original, dest)
	if err != nil {
		return result, nil, err
	}
	dest = afterComposition
	result.SurnameComposeBytes = composedBytes
	for _, site := range telSurnameCompositionSites {
		shim := telSurnameCopyShim
		if site.original == 0x800ae100 {
			shim = telSurnameAppendShim
		}
		result.Calls = append(result.Calls, N20ManifestWord{
			Owner: "TEL.EXN", PC: site.pc, Old: jalWord(site.original), New: jalWord(shim), Kind: "jal",
			Role: "TEL saved surname mixed-dialogue composition", Reason: "exact source-owned surname into TEL script buffer, guarded same-overlay N6 conversion with retail fallback",
		})
	}
	// Selector-13 TEL player-address text is separate from surname copying.
	given, afterGiven, err := telGivenAddressPatch(exe, original, dest)
	if err != nil {
		return result, nil, err
	}
	dest = afterGiven
	result.GivenAddressBytes = given
	result.Calls = append(result.Calls, N20ManifestWord{
		Owner: "TEL.EXN", PC: telGivenAddressCall, Old: jalWord(0x80051508), New: jalWord(telGivenAddressShim),
		Kind: "jal", Role: "TEL saved given-name address, selector 13",
		Reason: "source-dispatched selector 13 performs exact saved given copy; guard N6 conversion and 16-byte local field; retail fallback",
	})
	ck := packedTableChecksum(dest)
	dest[0x2fffc], dest[0x2fffd] = byte(ck>>8), byte(ck)
	result.Bytes = payload
	return result, dest, nil
}

// VerifyComposedTELNPCInlineLayout asserts that the FINAL public English TEL
// already contains the authenticated phone renderer installed by the N20
// composition ancestor. This must NOT install the module a second time: its
// 0x25000 code window is legitimately nonzero in the inherited overlay.
// Ordinary source-authored dialogue bytes outside the owned windows are left
// entirely to the source-owned merge and content-proof checks.
func VerifyComposedTELNPCInlineLayout(exe, original, composed []byte) error {
	sites, err := telOriginalDialogSites(original)
	if err != nil {
		return err
	}
	payload, err := telCloneSource(exe, original)
	if err != nil {
		return err
	}
	indexedGreeting, err := telOriginalIndexedGreeting(exe, original)
	if err != nil {
		return err
	}
	wrappedGirls, err := telIndexedWrappedGirlSites(original)
	if err != nil {
		return err
	}
	adjacent, err := telOriginalAdjacentSpeakerFirstLines(original)
	if err != nil {
		return err
	}
	if len(composed) != len(original) || len(sites) != 29 ||
		!allZero(original[0x25000:0x25000+len(payload)]) ||
		!bytes.Equal(composed[0x25000:0x25000+len(payload)], payload) {
		return fmt.Errorf("TEL dialogue: inherited renderer missing or modified")
	}
	for _, pc := range sites {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telDialogCloneEntry) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != 0x2406000D {
			return fmt.Errorf("TEL dialogue: inherited caller missing or modified at %#x", pc)
		}
	}
	greetOff := int(indexedGreeting - OverlaySlotBase)
	if binary.LittleEndian.Uint32(composed[greetOff:]) != jalWord(telDialogCloneEntry) ||
		binary.LittleEndian.Uint32(composed[greetOff+4:]) != 0x00002825 {
		return fmt.Errorf("TEL indexed greeting: inherited caller missing or modified")
	}
	for _, pc := range adjacent {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telDialogCloneEntry) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != 0x2406000a {
			return fmt.Errorf("TEL adjacent speaker: inherited caller drift at %#x", pc)
		}
	}
	// The two later dialogue rows belong to the original formatter; their
	// destinations and argument delay slots must remain byte-identical.
	for _, pc := range []uint32{0x80132764, 0x80132778} {
		off := int(pc - OverlaySlotBase)
		if !bytes.Equal(composed[off:off+8], original[off:off+8]) {
			return fmt.Errorf("TEL adjacent speaker: subsequent retail row changed at %#x", pc)
		}
	}
	for _, pc := range wrappedGirls {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telDialogueWrapperClone) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != 0x00002825 {
			return fmt.Errorf("TEL indexed multiline: inherited caller missing or modified at %#x", pc)
		}
	}
	if err := telSavedSurnameSource(original); err != nil {
		return err
	}
	shim, err := telSavedSurnameAdapter()
	if err != nil {
		return err
	}
	if !allZero(original[telSavedSurnameWindowOff:telSavedSurnameWindowOff+len(shim)]) ||
		!bytes.Equal(composed[telSavedSurnameWindowOff:telSavedSurnameWindowOff+len(shim)], shim) ||
		binary.LittleEndian.Uint32(composed[telSavedSurnameCall-OverlaySlotBase:]) != jalWord(telSavedSurnameShim) ||
		binary.LittleEndian.Uint32(composed[telSavedSurnameCall-OverlaySlotBase+4:]) != 0x2406000f {
		return fmt.Errorf("TEL saved surname: inherited display adapter missing or modified")
	}
	// Do not alter the next line or the surname field in saved RAM.
	for _, pc := range []uint32{0x8013288c, 0x80132890} {
		if binary.LittleEndian.Uint32(composed[pc-OverlaySlotBase:]) != binary.LittleEndian.Uint32(original[pc-OverlaySlotBase:]) {
			return fmt.Errorf("TEL saved surname: next row drift at %#x", pc)
		}
	}
	composition, err := telSurnameComposePayload()
	if err != nil {
		return err
	}
	if err := verifyTELSurnameCompose(original, composed, composition); err != nil {
		return err
	}
	givenAddress, err := telGivenAddressPayload()
	if err != nil {
		return err
	}
	if err := verifyTELGivenAddress(exe, original, composed, givenAddress); err != nil {
		return err
	}
	if binary.BigEndian.Uint16(composed[len(composed)-4:]) != packedTableChecksum(composed) ||
		!bytes.Equal(composed[len(composed)-2:], original[len(original)-2:]) {
		return fmt.Errorf("TEL dialogue: composed checksum or trailer mismatch")
	}
	return nil
}
