package n20arch

// Overlay-local, lifecycle-safe N20 architecture ("N6" prototype).
//
// The previous N20 design hooked five EXE call sites and dispatched into a
// window supplied by whichever overlay happened to be loaded. That design is
// rejected: before the first overlay load the window is absent, and no EXE
// word can both validate and dispatch. This file implements a different
// contract:
//
//   - the EXE is byte-identical to retail and contains no hook;
//   - every patched JAL lives inside the overlay that already owns the call
//     site, and targets a guard in that same overlay's own zero-filled tail;
//   - the guard is loaded by the same 96-sector operation-6 read as the call
//     site, so the two cannot have different lifetimes;
//   - the guard verifies a body (romanizer + speaker shim) with magic,
//     length, sum32 and xor32 before entering it;
//   - a missing/corrupt body tails to the original EXE target with the
//     original $ra, so the retail continuation runs unchanged;
//   - no code is shared between overlays and no persistent RAM is claimed.
//
// safe_to_patch remains false: this is an offline, in-memory prototype.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	// The guard occupies the first 256 B of the same zero-filled payload
	// region the superseded design used. The body follows.
	OLGuardBase   uint32 = 0x80160E00
	OLGuardBytes         = 256
	OLStubRAM     uint32 = 0x80160E10
	OLVerifierRAM uint32 = 0x80160E28
	OLBodyBase    uint32 = 0x80160F00

	OLPayloadFileOff = 0x2EE00
	OLPayloadEndOff  = 0x2FED8
	OLGuardFileEnd   = 0x2EF00
	OLBodyFileOff    = 0x2EF00
	OLBodyCapacity   = 0xFD8 // 0x2FED8-0x2EF00

	OLMagicWord uint32 = 0x0000364E // "N6\0\0"

	// Authenticated arguments/targets this architecture relies on.
	OLA0SurnameField  uint32 = 0x800E6354
	OLOriginalSpeaker uint32 = 0x80050DFC
	OLSpeakerDelay           = 0x24846354 // addiu a0,a0,0x6354
	OLSpeakerLUI             = 0x3C04800E // lui a0,0x800e

	OLPayloadMagicWord = OLMagicWord

	// Speaker-tail shim frame. The romanizer owns 0x90 of its own frame, so
	// this shim adds its frame size on top of that when both are live.
	OLSurnameShimFrame  = 0x80
	OLSurnameScratchOff = 0x20
	OLSurnameScratchLen = 64
	OLSurnameSaveOff    = 0x60 // s0,s3,s4,s5,s6
	OLSurnameSaveCount  = 5
	OLSurnameV0Off      = 0x74
	OLSurnameV1Off      = 0x78
	OLSurnameRAOff      = 0x7C
	OLRomanizerFrame    = 0x90
	// OLSurnameShimAddedStack is the known generated stack added by the shim
	// plus the nested romanizer call. The retail speaker callee's own frame is
	// intentionally not included: it is unchanged from retail.
	OLSurnameShimAddedStack = OLSurnameShimFrame + OLRomanizerFrame
)

// OverlayNameTarget is one authenticated EXE routine an overlay may call
// directly. Only 0x80050DFC (speaker) has an overlay-owned argument form this
// prototype can safely intercept. The other targets are inventoried so the
// blocked routes are explicit rather than silently dropped.
type OverlayNameTarget struct {
	Name  string
	Class string
	Entry bool // true when the address is a function entry
}

var OverlayNameTargets = map[uint32]OverlayNameTarget{
	0x8007EF48: {"formatter_queue_family", "formatter", true},
	0x80050DFC: {"speaker", "speaker", true},
	// 0x80081DC8 is the renderer's generic text queue (jal 0x8004E788),
	// reached by every rendered line. It is not an honourific or surname
	// route; the historical "surname_san" label is retained only in prose.
	0x80081DC8: {"generic_renderer_queue_site", "renderer_queue", false},
	0x80081DA8: {"alternate_preparser_site", "san_alt", false},
	0x80082764: {"fullname", "fullname", true},
	0x80085910: {"formatter_top", "formatter_top", true},
	0x80082700: {"renderer_queue_exit_a", "renderer_queue_exit", false},
	0x80082724: {"renderer_queue_exit_b", "renderer_queue_exit", false},
	0x80081DD0: {"generic_renderer_queue_return", "renderer_queue_return", false},
}

// OverlayCallsite is one decoded direct JAL that reaches a player-name
// routine. PC is the loaded address (overlay base 0x80132000 + FileOff).
type OverlayCallsite struct {
	Overlay       string
	FileOff       int
	PC            uint32
	Target        uint32
	TargetName    string
	Class         string
	EnclosingFrom uint32
	EnclosingTo   uint32
	DelayPC       uint32
	DelayWord     uint32
	A0Arg         string
	LiveAfter     []string
	Authentic     bool
	NameRoute     bool
	Coverage      string
	Reason        string
}

// ScanOverlayCallsites decodes all 26 authenticated overlays. It distinguishes
// executable control flow from JAL-shaped data by requiring the call site to
// be inside the overlay's prologue-bounded code region. Indirect (jalr)
// references are counted separately; none target the name routines.
func ScanOverlayCallsites(overlays map[string][]byte) ([]OverlayCallsite, error) {
	if len(overlays) != len(OverlaySHA) {
		return nil, fmt.Errorf("need all 26 authenticated overlays, got %d", len(overlays))
	}
	names := make([]string, 0, len(overlays))
	for n := range overlays {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []OverlayCallsite
	for _, name := range names {
		d := overlays[name]
		want, ok := OverlaySHA[name]
		if !ok {
			return nil, fmt.Errorf("unrecognised overlay %s", name)
		}
		if len(d) != 196608 || sha(d) != want {
			return nil, fmt.Errorf("overlay %s is not the authenticated original", name)
		}
		if d[0x2FFFE] != 0x12 || d[0x2FFFF] != 0x10 {
			return nil, fmt.Errorf("overlay %s trailer mismatch", name)
		}
		if packedTableChecksum(d) != binary.BigEndian.Uint16(d[0x2FFFC:]) {
			return nil, fmt.Errorf("overlay %s checksum mismatch", name)
		}
		codeEnd := overlayCodeEnd(d)
		starts := overlayFunctionStarts(d)
		for off := 0; off+8 <= codeEnd; off += 4 {
			w := binary.LittleEndian.Uint32(d[off:])
			if w>>26 != 0x03 {
				continue
			}
			tgt := ((w & 0x03FFFFFF) << 2) | 0x80000000
			nt, ok := OverlayNameTargets[tgt]
			if !ok {
				continue
			}
			from, to := overlayEnclosing(starts, codeEnd, off)
			cs := OverlayCallsite{
				Overlay: name, FileOff: off, PC: OverlaySlotBase + uint32(off),
				Target: tgt, TargetName: nt.Name, Class: nt.Class,
				EnclosingFrom: OverlaySlotBase + uint32(from),
				EnclosingTo:   OverlaySlotBase + uint32(to),
				DelayPC:       OverlaySlotBase + uint32(off+4),
				DelayWord:     binary.LittleEndian.Uint32(d[off+4:]),
				Authentic:     from >= 0,
				LiveAfter:     overlayLiveAfter(d, off),
			}
			switch nt.Class {
			case "speaker":
				if off >= 4 && binary.LittleEndian.Uint32(d[off-4:]) == OLSpeakerLUI &&
					cs.DelayWord == OLSpeakerDelay {
					cs.A0Arg = "surname_field 0x800E6354 (lui/addiu in caller)"
					cs.NameRoute = true
					cs.Coverage = "implemented (overlay-local speaker shim)"
					cs.Reason = "caller sets a0=0x800E6354 in the JAL delay slot; delay word preserved"
				} else {
					cs.A0Arg = "other text pointer (not 0x800E6354)"
					cs.Coverage = "not a player-name route"
					cs.Reason = "authentic speaker call, but the caller does not pass the saved surname field"
				}
			case "fullname":
				cs.A0Arg = "a0/a1/a2 owned by 0x80082764"
				cs.Coverage = "owned callsite, not implemented"
				cs.Reason = "0x80082764 is the talk runner (a0=index), not a name builder; full-name expansion is inside EXE renderer 0x80081190"
			default:
				cs.A0Arg = "unknown"
				cs.Coverage = "blocked"
				cs.Reason = "the owning queue/return site is inside the EXE, not this overlay"
			}
			out = append(out, cs)
		}
	}
	return out, nil
}

// overlayCodeEnd returns the first offset >= 0x1000 followed by 512 zero
// bytes. Overlays place code first and data after; all observed call sites
// are well inside this bound.
func overlayCodeEnd(d []byte) int {
	for off := 0x1000; off+512 <= len(d); off += 4 {
		zero := true
		for i := 0; i < 512; i++ {
			if d[off+i] != 0 {
				zero = false
				break
			}
		}
		if zero {
			return off
		}
	}
	return len(d)
}

// overlayFunctionStarts lists conservative function starts: offset 0 (the
// scene entry) and aligned `addiu sp,sp,-N` prologues followed within four
// words by a store based on sp. This is a reporting bound, not a full
// disassembler.
func overlayFunctionStarts(d []byte) []int {
	starts := []int{0}
	for off := 0; off+20 <= len(d); off += 4 {
		w := binary.LittleEndian.Uint32(d[off:])
		if w>>26 != 0x09 || (w>>21)&31 != 29 || (w>>16)&31 != 29 {
			continue
		}
		if int16(w&0xFFFF) >= 0 {
			continue
		}
		ok := false
		for j := 1; j <= 4 && off+4*j+4 <= len(d); j++ {
			y := binary.LittleEndian.Uint32(d[off+4*j:])
			if y>>26 == 0x2B && (y>>21)&31 == 29 {
				ok = true
				break
			}
		}
		if ok {
			starts = append(starts, off)
		}
	}
	return starts
}

func overlayEnclosing(starts []int, codeEnd, off int) (int, int) {
	from := -1
	to := codeEnd
	for _, s := range starts {
		if s <= off && s > from {
			from = s
		}
		if s > off && s < to {
			to = s
		}
	}
	return from, to
}

var olRegNames = [32]string{
	"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
	"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
	"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
	"t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
}

// overlayLiveAfter is a bounded local liveness note. It reports registers
// read after the call before being written in the same basic run, and always
// includes the ABI callee-saved set the shim must preserve.
func overlayLiveAfter(d []byte, off int) []string {
	live := map[int]bool{}
	written := map[int]bool{}
	for pc := off + 8; pc+4 <= len(d); pc += 4 {
		w := binary.LittleEndian.Uint32(d[pc:])
		op := w >> 26
		rs, rt, rd := int((w>>21)&31), int((w>>16)&31), int((w>>11)&31)
		var reads, writes []int
		stop := false
		switch op {
		case 0x00:
			switch w & 63 {
			case 0x08: // jr
				reads = append(reads, rs)
				stop = true
			case 0x09: // jalr
				reads = append(reads, rs)
				writes = append(writes, rd, 31)
			case 0x00, 0x02, 0x03:
				reads = append(reads, rt)
				writes = append(writes, rd)
			default:
				reads = append(reads, rs, rt)
				if rd != 0 {
					writes = append(writes, rd)
				}
			}
		case 0x0F:
			writes = append(writes, rt)
		case 0x0D, 0x0C, 0x09, 0x0A, 0x0B:
			reads = append(reads, rs)
			writes = append(writes, rt)
		case 0x23, 0x24, 0x25:
			reads = append(reads, rs)
			writes = append(writes, rt)
		case 0x2B, 0x28, 0x29:
			reads = append(reads, rs, rt)
		case 0x04, 0x05:
			reads = append(reads, rs, rt)
			stop = true
		case 0x02:
			stop = true
		case 0x03:
			writes = append(writes, 31)
			for r := 1; r <= 15; r++ {
				written[r] = true
			}
			written[24], written[25] = true, true
		default:
			stop = true
		}
		for _, r := range reads {
			if r != 0 && !written[r] {
				live[r] = true
			}
		}
		for _, r := range writes {
			if r != 0 && !live[r] {
				written[r] = true
			}
		}
		if stop {
			break
		}
	}
	for r := 16; r <= 23; r++ {
		live[r] = true
	}
	live[28], live[29], live[30], live[31] = true, true, true, true
	var out []string
	for r := 0; r < 32; r++ {
		if live[r] {
			out = append(out, olRegNames[r])
		}
	}
	return out
}

// OverlayLocalModule is the guard + body installed in one carrier overlay.
type OverlayLocalModule struct {
	Guard           []byte
	Body            []byte
	BodyLen         int
	Sum32           uint32
	XOR32           uint32
	RomanizerBytes  int
	VerifierBytes   int
	SpeakerBodyRAM  uint32
	FullNameBodyRAM uint32
	FullNameBytes   int
	BodyEndRAM      uint32
	SHA             string
}

func (m OverlayLocalModule) ModuleEnd() uint32 { return OLBodyBase + uint32(len(m.Body)) }

func align16(v uint32) uint32 { return (v + 15) &^ 15 }

// BuildOverlayLocalModule assembles the self-contained guard/body pair. The
// romanizer is the rebuilt N20 packed core (packed romanizer-compatible ABI) rebased to
// this overlay's own body. Nothing is copied to 0x801FF000.
func BuildOverlayLocalModule() (OverlayLocalModule, error) {
	var m OverlayLocalModule
	if err := RefuseForbidden(OLBodyBase); err != nil {
		return m, err
	}
	r, err := BuildN20PackedRomanizer(OLBodyBase)
	if err != nil {
		return m, err
	}
	if r.CodeBytes != N20PackedCodeBytes || r.ProgramBytes != N20PackedProgramBytes ||
		len(r.Binary) != N20PackedProgramBytes || r.TableBytes != N20PackedTableBytes {
		return m, fmt.Errorf("romanizer geometry %d/%d/%d", r.CodeBytes, r.ProgramBytes, len(r.Binary))
	}
	m.RomanizerBytes = len(r.Binary)
	m.SpeakerBodyRAM = align16(OLBodyBase + uint32(m.RomanizerBytes))
	body, err := buildSpeakerTailShim()
	if err != nil {
		return m, err
	}
	m.Body = make([]byte, int(m.SpeakerBodyRAM-OLBodyBase)+len(body))
	copy(m.Body, r.Binary)
	copy(m.Body[int(m.SpeakerBodyRAM-OLBodyBase):], body)
	// The full-name handler shares the same verified body. It is a latent
	// capability: overlays reach only the generic renderer, never a
	// surname/given entry, so nothing patches into it, but it is covered by
	// the same sum32/xor32 and would share the carrier's load lifetime.
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	fn, err := buildFullNameHandler(OLBodyBase)
	if err != nil {
		return m, err
	}
	m.FullNameBodyRAM = OLBodyBase + uint32(len(m.Body))
	m.FullNameBytes = len(fn)
	m.Body = append(m.Body, fn...)
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	if len(m.Body) > OLBodyCapacity {
		return m, fmt.Errorf("body %d exceeds %d", len(m.Body), OLBodyCapacity)
	}
	m.BodyLen = len(m.Body)
	for i := 0; i < len(m.Body); i += 4 {
		w := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += w
		m.XOR32 ^= w
	}
	m.BodyEndRAM = OLBodyBase + uint32(len(m.Body))
	// Build the verifier once with dummy moments to size it, then with the
	// real moments; the instruction count is unchanged.
	v0, err := buildOverlayVerifier(0, 0, uint32(m.BodyLen))
	if err != nil {
		return m, err
	}
	if int(OLVerifierRAM-OLGuardBase)+len(v0) > OLGuardBytes {
		return m, fmt.Errorf("verifier does not fit guard")
	}
	v, err := buildOverlayVerifier(m.Sum32, m.XOR32, uint32(m.BodyLen))
	if err != nil {
		return m, err
	}
	if len(v) != len(v0) {
		return m, fmt.Errorf("verifier size drift")
	}
	m.VerifierBytes = len(v)
	if OLVerifierRAM+uint32(len(v)) > OLBodyBase {
		return m, fmt.Errorf("verifier crosses body base")
	}
	m.Guard = make([]byte, OLGuardBytes)
	binary.LittleEndian.PutUint32(m.Guard[0:], OLMagicWord)
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(m.BodyLen))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	stub, err := buildSpeakerStub(m.SpeakerBodyRAM)
	if err != nil {
		return m, err
	}
	copy(m.Guard[OLStubRAM-OLGuardBase:], stub)
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], v)
	m.SHA = sha(append(append([]byte{}, m.Guard...), m.Body...))
	return m, nil
}

func olRType(rs, rt, rd, fn uint32) uint32 { return rs<<21 | rt<<16 | rd<<11 | fn }
func olAddu(rd, rs, rt uint32) uint32      { return olRType(rs, rt, rd, 0x21) }
func olIType(op, rs, rt uint32, imm uint16) uint32 {
	return op<<26 | rs<<21 | rt<<16 | uint32(imm)
}
func olLUI(rt, v uint32) uint32               { return olIType(0x0F, 0, rt, uint16(v>>16)) }
func olORI(rt, rs, v uint32) uint32           { return olIType(0x0D, rs, rt, uint16(v)) }
func olADDIU(rt, rs uint32, imm int16) uint32 { return olIType(0x09, rs, rt, uint16(imm)) }
func olLW(rt, base uint32, off int16) uint32  { return olIType(0x23, base, rt, uint16(off)) }
func olSW(rt, base uint32, off int16) uint32  { return olIType(0x2B, base, rt, uint16(off)) }
func olJR(rs uint32) uint32                   { return olRType(rs, 0, 0, 0x08) }

// buildDispatchStub tail-jumps through the verifier. t4 carries the untouched
// original target so both verifier failure and shim fallback preserve the
// caller's return address. t3 carries the body offset.
func buildDispatchStub(originalTarget, bodyRAM uint32) ([]byte, error) {
	off := bodyRAM - OLBodyBase
	if off > 0x7FFF {
		return nil, fmt.Errorf("body offset %d does not fit addiu", off)
	}
	a := &miniAsm{labels: map[string]int{}}
	a.w(olLUI(14, originalTarget))     // lui t6,target hi
	a.w(olORI(14, 14, originalTarget)) // ori t6,t6,target lo
	a.w(olAddu(12, 14, 0))             // addu t4,t6,zero
	a.w(olADDIU(11, 0, int16(off)))    // addiu t3,zero,body offset
	a.w(jWord(OLVerifierRAM))          // j verifier
	a.w(0)
	return words(a.words...), nil
}

// buildSpeakerStub is the N6 speaker tail stub: t4 = 0x80050DFC.
func buildSpeakerStub(bodyRAM uint32) ([]byte, error) {
	return buildDispatchStub(OLOriginalSpeaker, bodyRAM)
}

// buildOverlayVerifier checks the guard header and the body moments in place.
// It preserves a0-a3, t0, t4, sp and ra; it clobbers only t1-t3 and t5-t9.
func buildOverlayVerifier(sum32, xor32, bodyLen uint32) ([]byte, error) {
	return buildOverlayVerifierMagic(OLMagicWord, sum32, xor32, bodyLen)
}

// buildOverlayVerifierMagic is the same verifier with a caller-supplied magic,
// so the independent field-prep module cannot be mistaken for N6.
func buildOverlayVerifierMagic(magic, sum32, xor32, bodyLen uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	a.w(olLUI(10, OLGuardBase))
	a.w(olADDIU(10, 10, int16(OLGuardBase&0xFFFF))) // t2 = guard base
	a.w(olLW(14, 10, 0))                            // magic
	a.w(olLUI(25, magic))
	a.w(olORI(25, 25, magic))
	a.b(5, 14, 25, "fail")
	a.w(0)
	a.w(olLW(14, 10, 4)) // body length
	a.w(olLUI(25, bodyLen))
	a.w(olORI(25, 25, bodyLen))
	a.b(5, 14, 25, "fail")
	a.w(0)
	a.w(olLW(14, 10, 8)) // header sum
	a.w(olLUI(25, sum32))
	a.w(olORI(25, 25, sum32))
	a.b(5, 14, 25, "fail")
	a.w(0)
	a.w(olLW(14, 10, 12)) // header xor
	a.w(olLUI(25, xor32))
	a.w(olORI(25, 25, xor32))
	a.b(5, 14, 25, "fail")
	a.w(0)
	a.w(olLUI(10, OLBodyBase))
	a.w(olADDIU(10, 10, int16(OLBodyBase&0xFFFF))) // t2 = body base
	a.w(olAddu(11, 10, 11))                        // t3 = body base + body offset
	a.w(olLUI(24, sum32))                          // t8 = expected sum
	a.w(olORI(24, 24, sum32))
	a.w(olLUI(25, xor32)) // t9 = expected xor
	a.w(olORI(25, 25, xor32))
	a.w(olORI(13, 0, bodyLen/4)) // t5 = words
	a.w(olAddu(15, 0, 0))        // t7 = sum acc
	a.w(olAddu(9, 0, 0))         // t1 = xor acc
	// t2 is the cursor: the verifier must not touch t0 because the latent
	// full-name handler receives its honourific selector there.
	a.label("loop")
	a.w(olLW(14, 10, 0))
	a.w(olADDIU(13, 13, -1))
	a.w(olAddu(15, 15, 14))
	a.w(olRType(9, 14, 9, 0x26)) // xor t1,t1,t6
	a.b(5, 13, 0, "loop")
	a.w(olADDIU(10, 10, 4)) // delay: cursor += 4
	a.b(5, 15, 24, "fail")
	a.w(0)
	a.b(5, 9, 25, "fail")
	a.w(0)
	a.w(olJR(11))
	a.w(0)
	a.label("fail")
	a.w(olJR(12)) // t4 = original target
	a.w(0)
	a.resolve()
	return words(a.words...), nil
}

// buildSpeakerTailShim is the body entered after verification. On entry a0 is
// the caller's text pointer. It romanizes the saved surname field (1-3 kana,
// no suffix) into an owned 64-byte stack buffer, calls the original speaker
// routine exactly once, and returns the speaker's v0/v1 to the original
// caller. The 0x80 frame stays allocated across the nested call, so the text
// buffer sits above the speaker's own frames and cannot be clobbered by them.
func buildSpeakerTailShim() ([]byte, error) { return buildSpeakerTailShimFor(OLBodyBase) }

func buildSpeakerTailShimFor(romanizer uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	mov := func(dst, src uint32) { a.w(olAddu(dst, src, 0)) }
	addiu := func(dst, src uint32, imm int16) { a.w(olADDIU(dst, src, imm)) }
	lw := func(dst, base uint32, off int16) { a.w(olLW(dst, base, off)) }
	sw := func(src, base uint32, off int16) { a.w(olSW(src, base, off)) }
	jal := func(t uint32) { a.w(jalWord(t)); a.w(0) }
	// Frame 0x80: scratch 0x20..0x5f, s0/s3/s4/s5/s6 0x60..0x70,
	// v0/v1 0x74/0x78, ra 0x7c. s1/s2 are not used. The frame remains
	// allocated during the speaker call, and the romanizer's own 0x90 frame
	// nests below the shim's sp.
	addiu(29, 29, -OLSurnameShimFrame)
	sw(31, 29, OLSurnameRAOff)
	for i, r := range []uint32{16, 19, 20, 21, 22} {
		sw(r, 29, int16(OLSurnameSaveOff+i*4))
	}
	mov(16, 4) // s0 = original a0
	mov(19, 5) // s3 = a1
	mov(20, 6) // s4 = a2
	mov(21, 7) // s5 = a3
	a.w(olLUI(8, OLA0SurnameField))
	addiu(8, 8, int16(OLA0SurnameField&0xFFFF)) // t0 = 0x800E6354
	a.b(5, 16, 8, "fail")                       // bne s0,t0,fail
	a.w(0)
	mov(4, 16)                        // a0 = surname field
	addiu(5, 29, OLSurnameScratchOff) // a1 = owned scratch
	addiu(6, 0, OLSurnameScratchLen)  // a2 = 64
	addiu(7, 0, 3)                    // a3 = suffix none, max 3 kana
	jal(romanizer)                    // romanizer entry
	a.b(4, 2, 0, "fail")
	a.w(0)
	addiu(22, 29, OLSurnameScratchOff) // s6 = scratch
	a.b(4, 0, 0, "done")
	a.w(0)
	a.label("fail")
	mov(22, 16) // s6 = original a0
	a.label("done")
	mov(4, 22)
	mov(5, 19)
	mov(6, 20)
	mov(7, 21)
	jal(OLOriginalSpeaker)
	a.w(0)
	sw(2, 29, OLSurnameV0Off) // preserve speaker v0
	sw(3, 29, OLSurnameV1Off) // preserve speaker v1
	lw(31, 29, OLSurnameRAOff)
	for i, r := range []uint32{16, 19, 20, 21, 22} {
		lw(r, 29, int16(OLSurnameSaveOff+i*4))
	}
	lw(2, 29, OLSurnameV0Off)
	lw(3, 29, OLSurnameV1Off)
	a.w(olJR(31))
	addiu(29, 29, OLSurnameShimFrame)
	a.resolve()
	return words(a.words...), nil
}

// EXECallsite is one authenticated direct JAL inside the retail EXE that
// reaches a player-name routine. These callsites are EXE-owned: N6 cannot
// redirect them without an EXE hook, so they are inventoried as blocked.
type EXECallsite struct {
	PC            uint32
	Target        uint32
	TargetName    string
	Class         string
	EnclosingFrom uint32
	EnclosingTo   uint32
	DelayPC       uint32
	DelayWord     uint32
	A0Arg         string
	NameRoute     bool
	Authentic     bool
}

// ScanEXENameCallsites inventories EXE-owned calls. The code bound and
// prologue heuristic match the previous reachability analysis: direct calls
// only, JAL-shaped data outside [0x80041000,0x800AF390) is excluded.
func ScanEXENameCallsites(exe []byte) ([]EXECallsite, error) {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return nil, fmt.Errorf("unrecognised original EXE")
	}
	const lo, hi = 0x80041000, 0x800AF390
	starts := []uint32{lo}
	for pc := uint32(lo); pc+20 <= hi; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 != 0x09 || (w>>21)&31 != 29 || (w>>16)&31 != 29 || int16(w&0xFFFF) >= 0 {
			continue
		}
		ok := false
		for j := 1; j <= 4; j++ {
			y := wordAt(exe, pc+uint32(4*j))
			if y>>26 == 0x2B && (y>>21)&31 == 29 {
				ok = true
				break
			}
		}
		if ok {
			starts = append(starts, pc)
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	enclosing := func(pc uint32) (uint32, uint32) {
		var from, to uint32 = lo, hi
		for _, s := range starts {
			if s <= pc && s >= from {
				from = s
			}
			if s > pc && s < to {
				to = s
			}
		}
		return from, to
	}
	var out []EXECallsite
	jalr := 0
	for pc := uint32(lo); pc+8 <= hi; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 == 0 && w&63 == 9 {
			rs := (w >> 21) & 31
			for back := uint32(1); back <= 8 && pc-4*back >= lo; back++ {
				pw := wordAt(exe, pc-4*back)
				if pw>>26 == 0x0D && (pw>>16)&31 == rs {
					prev := wordAt(exe, pc-4*(back+1))
					if prev>>26 == 0x0F && (prev>>16)&31 == rs {
						v := ((prev & 0xFFFF) << 16) | (pw & 0xFFFF)
						if _, ok := OverlayNameTargets[v]; ok {
							jalr++
						}
					}
				}
			}
			continue
		}
		if w>>26 != 0x03 {
			continue
		}
		tgt := ((w & 0x03FFFFFF) << 2) | 0x80000000
		nt, ok := OverlayNameTargets[tgt]
		if !ok {
			continue
		}
		from, to := enclosing(pc)
		cs := EXECallsite{PC: pc, Target: tgt, TargetName: nt.Name, Class: nt.Class,
			EnclosingFrom: from, EnclosingTo: to, DelayPC: pc + 4, DelayWord: wordAt(exe, pc+4),
			Authentic: from < pc && pc < to}
		if nt.Class == "speaker" {
			if wordAt(exe, pc-4) == OLSpeakerLUI && cs.DelayWord == OLSpeakerDelay {
				cs.A0Arg = "surname_field 0x800E6354"
				cs.NameRoute = true
			} else {
				cs.A0Arg = "other text pointer"
			}
		}
		out = append(out, cs)
	}
	if jalr != 0 {
		return out, fmt.Errorf("%d resolved EXE jalr sites target name routines", jalr)
	}
	return out, nil
}

// OverlayLocalPlan is an in-memory delivery plan. No file is written.
type OverlayLocalPlan struct {
	Module         OverlayLocalModule
	Patched        map[string][]byte
	SitesByOverlay map[string][]OverlayCallsite
	PatchedWords   map[string][]int
	PatchedSites   int
	Report         OverlayLocalReport
}

type OverlayLocalReport struct {
	Carriers          int
	PatchedOverlays   []string
	PatchedCallsites  int
	SpeakerSites      int
	OtherSpeakerSites int
	FullnameSites     int
	FormatterTopSites int
	BlockedEXESites   int
	ModuleBytes       int
	GuardBytes        int
	BodyBytes         int
	BodySum32         uint32
	BodyXOR32         uint32
	OverlayPlanSHA    map[string]string
	// EXEChangedWords is the N6/N6-FP entry-hook count, not the total EXE
	// change count. The integrated relocation plan changes 30 EXE words.
	EXEChangedWords  int `json:"exe_entry_hooks"`
	EXEHookTargets   int
	EXESlotCodeRefs  int
	EXESlotDataWords int
	EXESlotRefPCs    []uint32
	AtomicLoadBytes  int
	ResidualTornLoad bool
}

// PlanOverlayLocal patches only the overlay-owned speaker call sites. Every
// other route is reported, not disguised. The planner refuses any overlay
// that is not authenticated, any non-zero target region, any unknown call
// word and any delta outside its declared ranges.
func PlanOverlayLocal(overlays map[string][]byte, sites []OverlayCallsite) (OverlayLocalPlan, error) {
	p := OverlayLocalPlan{Patched: map[string][]byte{}, SitesByOverlay: map[string][]OverlayCallsite{},
		PatchedWords: map[string][]int{}}
	m, err := BuildOverlayLocalModule()
	if err != nil {
		return p, err
	}
	p.Module = m
	p.Report.GuardBytes = len(m.Guard)
	p.Report.BodyBytes = len(m.Body)
	p.Report.ModuleBytes = len(m.Guard) + len(m.Body)
	p.Report.BodySum32 = m.Sum32
	p.Report.BodyXOR32 = m.XOR32
	p.Report.OverlayPlanSHA = map[string]string{}
	p.Report.EXEChangedWords = 0
	p.Report.EXEHookTargets = 0
	p.Report.AtomicLoadBytes = OverlayLoadSectors * 2048
	p.Report.ResidualTornLoad = true

	for _, cs := range sites {
		if cs.NameRoute {
			p.SitesByOverlay[cs.Overlay] = append(p.SitesByOverlay[cs.Overlay], cs)
			p.Report.SpeakerSites++
			continue
		}
		switch cs.Class {
		case "speaker":
			p.Report.OtherSpeakerSites++
		case "fullname":
			p.Report.FullnameSites++
		case "formatter_top":
			p.Report.FormatterTopSites++
		default:
			p.Report.BlockedEXESites++
		}
	}
	if p.Report.SpeakerSites == 0 {
		return p, fmt.Errorf("no overlay-owned speaker name route found")
	}
	names := make([]string, 0, len(p.SitesByOverlay))
	for n := range p.SitesByOverlay {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		src, ok := overlays[name]
		if !ok {
			return p, fmt.Errorf("missing overlay %s", name)
		}
		if len(src) != 196608 || sha(src) != OverlaySHA[name] {
			return p, fmt.Errorf("overlay %s not authenticated", name)
		}
		if name == "EVENT.EXN" || name == "TACO.EXN" {
			return p, fmt.Errorf("refusing to patch stub-only overlay %s", name)
		}
		if src[0x2FFFE] != 0x12 || src[0x2FFFF] != 0x10 {
			return p, fmt.Errorf("trailer mismatch %s", name)
		}
		if packedTableChecksum(src) != binary.BigEndian.Uint16(src[0x2FFFC:]) {
			return p, fmt.Errorf("checksum mismatch %s", name)
		}
		if !allZero(src[OLPayloadFileOff:OLPayloadEndOff]) {
			return p, fmt.Errorf("payload region not zero in %s", name)
		}
		if err := AssertCarrierPayload(name, src, m.ModuleEnd()); err != nil {
			return p, err
		}
		d := bytes.Clone(src)
		copy(d[OLPayloadFileOff:OLGuardFileEnd], m.Guard)
		copy(d[OLBodyFileOff:OLBodyFileOff+len(m.Body)], m.Body)
		for _, cs := range p.SitesByOverlay[name] {
			off := cs.FileOff
			if off < 4 || off+8 > len(d) {
				return p, fmt.Errorf("%s callsite offset %d", name, off)
			}
			if binary.LittleEndian.Uint32(d[off:]) != jalWord(cs.Target) {
				return p, fmt.Errorf("%s callsite %08x is not the authenticated JAL", name, cs.PC)
			}
			if binary.LittleEndian.Uint32(d[off+4:]) != OLSpeakerDelay ||
				binary.LittleEndian.Uint32(d[off-4:]) != OLSpeakerLUI {
				return p, fmt.Errorf("%s callsite %08x lost its authenticated argument pattern", name, cs.PC)
			}
			binary.LittleEndian.PutUint32(d[off:], jalWord(OLStubRAM))
			p.PatchedWords[name] = append(p.PatchedWords[name], off)
		}
		ck := packedTableChecksum(d)
		d[0x2FFFC] = byte(ck >> 8)
		d[0x2FFFD] = byte(ck)
		if len(d) != len(src) || d[0x2FFFE] != 0x12 || d[0x2FFFF] != 0x10 ||
			binary.BigEndian.Uint16(d[0x2FFFC:]) != packedTableChecksum(d) {
			return p, fmt.Errorf("geometry/checksum damaged %s", name)
		}
		allowedWord := map[int]bool{}
		for _, off := range p.PatchedWords[name] {
			allowedWord[off] = true
		}
		for i := range d {
			if d[i] == src[i] {
				continue
			}
			ok := i >= OLPayloadFileOff && i < OLPayloadEndOff
			ok = ok || allowedWord[(i/4)*4]
			ok = ok || i == 0x2FFFC || i == 0x2FFFD
			if !ok {
				return p, fmt.Errorf("delta outside plan %s+0x%x", name, i)
			}
		}
		p.Patched[name] = d
		p.Report.OverlayPlanSHA[name] = sha(d)
		p.Report.PatchedOverlays = append(p.Report.PatchedOverlays, name)
		p.Report.PatchedCallsites += len(p.SitesByOverlay[name])
	}
	p.Report.Carriers = len(p.Patched)
	if p.Report.PatchedCallsites != p.Report.SpeakerSites {
		return p, fmt.Errorf("patched callsite count drift")
	}
	if m.ModuleEnd() > OLBodyBase+OLBodyCapacity || m.ModuleEnd() > 0x80161ED8 {
		return p, fmt.Errorf("module end %08x exceeds payload", m.ModuleEnd())
	}
	return p, nil
}

// AssertNoEXEHooks proves the new architecture changes zero EXE bytes and
// adds zero hooks. It decodes every EXE J/JAL word that names an address in
// the overlay slot and classifies it by the authenticated code bound
// [0x80041000,0x800AF390): zero are in executable code; the remaining
// JAL-shaped words live in data tables and are coincidental. A failure is
// any code transfer or any reference to the N6 guard/body.
func AssertNoEXEHooks(exe []byte) (OverlayLocalReport, error) {
	var r OverlayLocalReport
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return r, fmt.Errorf("unrecognised original EXE")
	}
	r.EXEChangedWords = 0
	const exeCodeEnd = 0x800AF390
	for i := 0; i+4 <= len(exe); i += 4 {
		w := binary.LittleEndian.Uint32(exe[i:])
		op := w >> 26
		if op != 0x02 && op != 0x03 {
			continue
		}
		tgt := ((w & 0x03FFFFFF) << 2) | 0x80000000
		if tgt < OverlaySlotBase || tgt >= OverlaySlotEnd {
			continue
		}
		pc := 0x80040800 + uint32(i)
		if tgt >= OLGuardBase && tgt < OLBodyBase+OLBodyCapacity {
			return r, fmt.Errorf("EXE references N6 module at %08x", tgt)
		}
		r.EXESlotRefPCs = append(r.EXESlotRefPCs, pc)
		if pc >= 0x80041000 && pc < exeCodeEnd {
			r.EXESlotCodeRefs++
		} else {
			r.EXESlotDataWords++
		}
	}
	if r.EXESlotCodeRefs != 0 {
		return r, fmt.Errorf("EXE code has %d direct transfers into the overlay slot", r.EXESlotCodeRefs)
	}
	return r, nil
}

// OverlayLocalRoute is one row of the new route matrix. It does not re-label
// blocked EXE-owned routes as implemented.
type OverlayLocalRoute struct {
	ID        string
	Site      string
	Owner     string
	Status    string
	Callsites int
	Reason    string
}

func OverlayLocalRoutes(sites []OverlayCallsite, exeSites []EXECallsite) []OverlayLocalRoute {
	counts := map[string]int{}
	nameSpeaker := 0
	for _, s := range sites {
		counts[s.Class]++
		if s.NameRoute {
			nameSpeaker++
		}
	}
	exeSpeaker := 0
	for _, s := range exeSites {
		if s.NameRoute {
			exeSpeaker++
		}
	}
	return []OverlayLocalRoute{
		{"speaker_surname", "overlay JALs to 0x80050DFC with a0=0x800E6354", "TEL.EXN, ETC.EXN, NAME_ENT.EXN", "implemented", nameSpeaker, "same-overlay shim, verifier, tail to original speaker"},
		{"speaker_exe_owned", "EXE JALs to 0x80050DFC with a0=0x800E6354", "EXE", "blocked", exeSpeaker, fmt.Sprintf("%d EXE callers pass the saved surname field; redirecting them needs an EXE hook", exeSpeaker)},
		{"speaker_other_text", "overlay JALs to 0x80050DFC with other text", "TEL.EXN, ETC.EXN, NAME_ENT.EXN", "not_a_name_route", counts["speaker"] - nameSpeaker, "authentic speaker calls that do not pass the saved surname field; left on retail"},
		{"formatter_top", "overlay JAL to 0x80085910", "KANGEI.EXN", "blocked", counts["formatter_top"], "enclosing formatter path is EXE-owned; one overlay call does not expose the name fields"},
		{"formatter_a", "0x8007F7D4", "EXE", "blocked", 0, "the queue JAL is inside EXE function 0x8007EF48; no overlay owns it"},
		{"formatter_b", "0x8007F898", "EXE", "blocked", 0, "same EXE-owned formatter body; previous version observed RA 0x8007F8A0 five times (surname-only 8-byte queued string) reading working family 0x800CA16C"},
		{"formatter_c", "0x8007F95C", "EXE", "blocked", 0, "same EXE-owned formatter body; sibling of formatter_b, not observed in previous version"},
		{"formatter_d", "0x80080C30", "EXE", "blocked", 0, "same EXE-owned formatter body; previous version observed RA 0x80080C38 once (surname-only 8-byte queued string) reading working family 0x800CA16C"},
		{"generic_renderer_queue", "0x80081DC8", "EXE", "blocked", 0, "generic queue JAL inside EXE renderer 0x80081190 (historical id surname_san); reached by every rendered line; no overlay callsite to intercept; previous version observed RA 0x80081DD0 once with a 27-byte surname+given F join"},
		{"alternate_parser_branch", "0x80081DA8", "EXE", "blocked", 0, "alternative EXE path; no overlay callsite"},
		{"fullname", "overlay JALs to 0x80082764", "DATE, DATE2, GEKO, KANGEI, SHOUGATU, SHUGAKU, VALEN", "owned_not_implemented", counts["fullname"], "0x80082764 is the talk runner (a0=index); full-name expansion is owned by EXE renderer 0x80081190, so no tail shim can replace it"},
		{"shared_exe_wrapper", "0x800E5238", "EXE", "blocked", 0, "internal EXE wrapper fallback"},
		{"detached_san_suffix", "detached さん", "UNKNOWN", "unresolved", 0, "producer unknown; retail kana remains"},
	}
}

// ExEDirFileLBAs is the authenticated EXEDIR directory mapping from ISO9660
// start LBA to filename. Provenance: Track 1 (Mode2/2352), PVD at sector 16,
// root directory at LBA 22, EXEDIR directory at LBA 37129 (2,048 B), all files
// 196,608 B. Every scene-table LBA below resolves to one of these entries.
// O.BIN is present on the disc but is not one of the 26 patched overlays.
var ExEDirFileLBAs = map[uint32]string{
	0x910A: "BUNKAKEN.EXN", 0x916A: "BUNKASAI.EXN", 0x91CA: "BUNKA_SD.EXN",
	0x922A: "DATE.EXN", 0x928A: "DATE2.EXN", 0x92EA: "ENDING.EXN",
	0x934A: "EN_NICHI.EXN", 0x93AA: "ETC.EXN", 0x940A: "EVENT.EXN",
	0x946A: "GEKO.EXN", 0x94CA: "GYOZI.EXN", 0x952A: "KANGEI.EXN",
	0x958A: "MASTER.EXN", 0x95EA: "NAME_ENT.EXN", 0x964A: "O.BIN",
	0x96AA: "OLH.EXN", 0x970A: "OMIMAI.EXN", 0x976A: "OPTION.EXN",
	0x97CA: "RENSYU.EXN", 0x982A: "RPG_BAT.EXN", 0x988A: "SHOUGATU.EXN",
	0x98EA: "SHUGAKU.EXN", 0x994A: "TACO.EXN", 0x99AA: "TAIIKU.EXN",
	0x9A0A: "TEL.EXN", 0x9A6A: "TT.EXN", 0x9ACA: "VALEN.EXN",
}

// SceneOverlayRef ties one authenticated scene-table entry to the EXEDIR file
// whose start LBA it names.
type SceneOverlayRef struct {
	Scene   byte   `json:"scene"`
	LBA     uint32 `json:"lba"`
	Overlay string `json:"overlay"`
	Loads   bool   `json:"loads_overlay"`
}

// SceneOverlayRefs resolves all 129 scene entries through SceneSlots. The
// second return value is every entry that did not resolve; it must be empty
// for the retail table (tested).
func SceneOverlayRefs(exe []byte) ([]SceneOverlayRef, []SceneOverlayRef) {
	var mapped, unmapped []SceneOverlayRef
	for _, s := range SceneSlots(exe) {
		r := SceneOverlayRef{Scene: s.Scene, LBA: s.LBA, Overlay: ExEDirFileLBAs[s.LBA], Loads: s.Loads}
		if r.Overlay == "" {
			unmapped = append(unmapped, r)
		} else {
			mapped = append(mapped, r)
		}
	}
	return mapped, unmapped
}

// EarlySceneEvidence is a code/ISO reference. Scene IDs and LBAs are
// authenticated; the semantic label is string evidence, never a runtime claim.
type EarlySceneEvidence struct {
	Scene         string
	Scenes        []int
	Overlays      []string
	LBAs          []uint32
	SpeakerSites  int
	FullnameSites int
	Status        string
	Note          string
}

// EarlyGameSceneMatrix returns the honest early-scene coverage matrix. Early
// means scenes below 80 (the first DATE scene). Overlay membership comes from
// the authenticated scene->LBA table and the ISO9660 EXEDIR extents; semantic
// labels come only from CP932 strings inside those overlays.
func EarlyGameSceneMatrix(exe []byte, overlays map[string][]byte, sites []OverlayCallsite) []EarlySceneEvidence {
	const earlyCutoff = 80
	terms := map[string][][]byte{
		"activity_selection": {{0x95, 0x94, 0x8a, 0x88}, {0x8a, 0x88, 0x93, 0xae}, {0x91, 0x49, 0x91, 0xf0}}, // 部活/活動/選択
		"mio_dialogue":       {{0x96, 0xa2, 0x8f, 0x8f}},                                                     // 未緒 (Kisaragi Mio)
		"shiori_dialogue":    {{0x8e, 0x8d, 0x90, 0x44}},                                                     // 詩織
		"corridor_encounter": {{0x98, 0x4c, 0x89, 0xba}},                                                     // 廊下
	}
	refs, _ := SceneOverlayRefs(exe)
	early := map[string][]SceneOverlayRef{}
	allForOverlay := map[string][]SceneOverlayRef{}
	for _, r := range refs {
		if !r.Loads {
			continue
		}
		allForOverlay[r.Overlay] = append(allForOverlay[r.Overlay], r)
		if int(r.Scene) < earlyCutoff {
			early[r.Overlay] = append(early[r.Overlay], r)
		}
	}
	nameSpeaker := map[string]int{}
	fullname := map[string]int{}
	for _, s := range sites {
		if s.NameRoute {
			nameSpeaker[s.Overlay]++
		}
		if s.Class == "fullname" {
			fullname[s.Overlay]++
		}
	}
	matched := func(termKey string, restrictEarly bool, minHits int) []string {
		var out []string
		for name, d := range overlays {
			hits := 0
			for _, term := range terms[termKey] {
				hits += bytes.Count(d, term)
			}
			if hits < minHits {
				continue
			}
			if restrictEarly {
				if len(early[name]) == 0 {
					continue
				}
			}
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	makeRow := func(scene, status, note string, ovs []string, restrictEarly bool) EarlySceneEvidence {
		e := EarlySceneEvidence{Scene: scene, Status: status, Note: note}
		if restrictEarly {
			for _, n := range ovs {
				for _, r := range early[n] {
					e.Scenes = append(e.Scenes, int(r.Scene))
					e.LBAs = append(e.LBAs, r.LBA)
				}
				e.SpeakerSites += nameSpeaker[n]
				e.FullnameSites += fullname[n]
			}
		} else {
			for _, n := range ovs {
				for _, r := range allForOverlay[n] {
					e.Scenes = append(e.Scenes, int(r.Scene))
					e.LBAs = append(e.LBAs, r.LBA)
				}
				e.SpeakerSites += nameSpeaker[n]
				e.FullnameSites += fullname[n]
			}
		}
		e.Overlays = ovs
		sort.Ints(e.Scenes)
		sort.Slice(e.LBAs, func(i, j int) bool { return e.LBAs[i] < e.LBAs[j] })
		return e
	}
	out := []EarlySceneEvidence{}
	out = append(out, makeRow("activity_selection", "unsupported",
		"early scenes 32-34 load OPTION.EXN and scene 58 loads OLH.EXN; both contain 部/活動/選択 but own no speaker name callsite, so the speaker route does not run on this screen", matched("activity_selection", true, 2), true))
	if ovs := matched("mio_dialogue", true, 1); len(ovs) == 0 {
		out = append(out, makeRow("mio_dialogue", "unresolved",
			"no 未緒 string in an overlay loaded before scene 80; Mio evidence is confined to BUNKAKEN/BUNKASAI/BUNKA_SD/TAIIKU at scenes 112-128", nil, true))
	} else {
		out = append(out, makeRow("mio_dialogue", "partial", "未緒 string evidence in an early mapped overlay; speaker surname route exists but full-name route is blocked", ovs, true))
	}
	shiori := matched("shiori_dialogue", true, 1)
	out = append(out, makeRow("shiori_dialogue", "partial_surname",
		"early 詩織 scenes 17-21 (NAME_ENT), 53-55 (ETC) and 67/69 (TEL) load overlays carrying the implemented speaker-surname route; the separate full-name renderer route remains blocked", shiori, true))
	if ovs := matched("corridor_encounter", true, 1); len(ovs) == 0 {
		out = append(out, makeRow("corridor_encounter", "unsupported",
			"no 廊下 string in an overlay loaded before scene 80; corridor strings first appear in SHOUGATU/GEKO and later overlays", nil, true))
	} else {
		out = append(out, makeRow("corridor_encounter", "partial", "廊下 string evidence in an early mapped overlay; name coverage depends on that overlay's callsites", ovs, true))
	}
	return out
}
