package n20arch

// Overlay-local field-preparation route ("N6-FP").
//
// This is a second, independent overlay-local route. It does not replace or
// widen the N6 speaker-surname route and it shares no guard, body or carrier
// with it: the speaker carriers are TEL.EXN, ETC.EXN and NAME_ENT.EXN, while
// the authenticated field-prep callsites live in fourteen different overlays.
//
// Retail EXE 0x800847B8 is the field-preparation routine used by dialogue
// overlays before the renderer runs. Its authenticated body is 0x90 B:
//
//   addiu sp,sp,-0x30
//   sw    a0,0x30(sp)                 ; caller selector
//   sw    ra,0x14(sp)
//   strcpy(0x800CA16C, 0x800E6354)    ; working family <- saved family
//   strcpy(0x800CA174, 0x800E635C)    ; working given  <- saved given
//   v0 = lbu 0x30(sp)
//   if v0 < 14:
//       build 0x800CA17C from selector
//       strcpy(0x800CA188, surnameTable[v0])
//       build 0x800CA190 from selector
//   return
//
// The renderer 0x80081190 later expands p/m/F from 0x800CA16C/0x800CA174.
// Overlay-local callsites to 0x800847B8 are therefore a real, authenticated
// entry point into the family/given working fields.
//
// The shim below keeps retail behavior as the default: it calls the original
// routine first, then tries to romanize BOTH saved fields into the two working
// fields. The copy is all-or-nothing. A field is only accepted when the packed
// romanizer succeeds and the result including the NUL terminator fits the
// 8-byte working slot (at most seven output bytes including the NUL). A failure of either field
// leaves both working fields exactly as the retail routine wrote them (kana).
//
// 0x800CA17C and 0x800CA190 are deliberately NOT converted: they are built by
// the EXE suffix/name-table helpers 0x80051508/0x80051438, whose inputs include
// kanji name-table output, so they are not dynamically kana-romanizable at
// this route. They remain documented blocked fields.
//
// safe_to_patch remains false. This is an offline, in-memory prototype.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	// Authenticated EXE entry and fields this route relies on.
	OLFieldPrepOriginal uint32 = 0x800847B8
	OLFieldPrepWorkFam  uint32 = 0x800CA16C
	OLFieldPrepWorkGiv  uint32 = 0x800CA174
	OLFieldPrepSavedGiv uint32 = 0x800E635C
	// Blocked working fields: built from kanji/suffix tables, not kana.
	OLFieldPrepBlockedFam uint32 = 0x800CA17C
	OLFieldPrepBlockedGiv uint32 = 0x800CA190

	// A distinct guard magic keeps this module from ever being mistaken for an
	// N6 speaker module if a future carrier set overlaps.
	OLFieldPrepMagicWord uint32 = 0x0000464E // "NF\0\0"

	// Shim frame. 0x00..0x0F and 0x10..0x1F are the two romanizer scratch
	// buffers; the remaining slots hold ra, the retail routine's v0/v1 and the
	// two accepted output lengths. The slot layout is checked by tests.
	OLFieldPrepFrame          = 0x40
	OLFieldPrepFamilyOff      = 0x00
	OLFieldPrepGivenOff       = 0x10
	OLFieldPrepRAOff          = 0x20
	OLFieldPrepV0Off          = 0x24
	OLFieldPrepV1Off          = 0x28
	OLFieldPrepFamilyLenOff   = 0x2C
	OLFieldPrepGivenLenOff    = 0x30
	OLFieldPrepScratchBytes   = 16
	OLFieldPrepSlotBytes      = 8 // working slot including NUL
	OLFieldPrepMaxOutputBytes = 7 // maximum accepted bytes including the NUL
	// Known generated added stack: this shim plus the nested romanizer frame.
	OLFieldPrepAddedStack = OLFieldPrepFrame + OLRomanizerFrame
)

// FieldPrepCallsite is one authenticated direct JAL to EXE 0x800847B8 inside
// an overlay's prologue-bounded code region.
type FieldPrepCallsite struct {
	Overlay       string
	FileOff       int
	PC            uint32
	Target        uint32
	EnclosingFrom uint32
	EnclosingTo   uint32
	DelayPC       uint32
	DelayWord     uint32
	A0Arg         string
	LiveAfter     []string
	Authentic     bool
}

// ScanOverlayFieldPrepCallsites decodes all 26 authenticated overlays and
// returns every direct JAL to 0x800847B8 inside a function body. JAL-shaped
// data outside the code bound is excluded, and indirect jalr is rejected.
func ScanOverlayFieldPrepCallsites(overlays map[string][]byte) ([]FieldPrepCallsite, error) {
	if len(overlays) != len(OverlaySHA) {
		return nil, fmt.Errorf("need all 26 authenticated overlays, got %d", len(overlays))
	}
	names := make([]string, 0, len(overlays))
	for n := range overlays {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []FieldPrepCallsite
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
			if tgt != OLFieldPrepOriginal {
				continue
			}
			from, to := overlayEnclosing(starts, codeEnd, off)
			out = append(out, FieldPrepCallsite{
				Overlay: name, FileOff: off, PC: OverlaySlotBase + uint32(off),
				Target:        tgt,
				EnclosingFrom: OverlaySlotBase + uint32(from),
				EnclosingTo:   OverlaySlotBase + uint32(to),
				DelayPC:       OverlaySlotBase + uint32(off+4),
				DelayWord:     binary.LittleEndian.Uint32(d[off+4:]),
				A0Arg:         "caller-owned selector (a0)",
				LiveAfter:     overlayLiveAfter(d, off),
				Authentic:     from >= 0,
			})
		}
	}
	return out, nil
}

// OverlayFieldPrepModule is the guard + body installed in one field-prep
// carrier. It contains the rebuilt N20 packed romanizer and the field-prep shim; it
// deliberately does not contain the speaker shim or the latent full-name
// handler.
type OverlayFieldPrepModule struct {
	Guard          []byte
	Body           []byte
	BodyLen        int
	Sum32          uint32
	XOR32          uint32
	RomanizerBytes int
	VerifierBytes  int
	ShimBodyRAM    uint32
	ShimBytes      int
	FamilyDst      uint32
	GivenDst       uint32
	SlotBytes      int
	BodyEndRAM     uint32
	SHA            string
}

func (m OverlayFieldPrepModule) ModuleEnd() uint32 { return OLBodyBase + uint32(len(m.Body)) }

// BuildOverlayFieldPrepModule assembles the independent field-prep module in
// the same overlay-owned zero tail the N6 speaker module uses. Different
// carrier sets mean the two modules never share a loaded image.
func BuildOverlayFieldPrepModule() (OverlayFieldPrepModule, error) {
	return buildOverlayFieldPrepModuleAt(OLFieldPrepWorkFam, OLFieldPrepWorkGiv, OLFieldPrepSlotBytes)
}

// buildOverlayFieldPrepModuleAt is the same module with caller-chosen working
// slot addresses and slot size. The N20 relocation prototype uses it to write
// the two EXE-resident fields at their relocated addresses with a 12-byte
// slot; the default wrapper above keeps the retail 8-byte N6-FP behaviour
// byte-identical.
func buildOverlayFieldPrepModuleAt(famDst, givDst uint32, slotBytes int) (OverlayFieldPrepModule, error) {
	var m OverlayFieldPrepModule
	m.FamilyDst, m.GivenDst, m.SlotBytes = famDst, givDst, slotBytes
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
	m.ShimBodyRAM = align16(OLBodyBase + uint32(m.RomanizerBytes))
	shim, err := buildFieldPrepShimAt(OLBodyBase, m.ShimBodyRAM, famDst, givDst, slotBytes)
	if err != nil {
		return m, err
	}
	m.ShimBytes = len(shim)
	m.Body = make([]byte, int(m.ShimBodyRAM-OLBodyBase)+len(shim))
	copy(m.Body, r.Binary)
	copy(m.Body[int(m.ShimBodyRAM-OLBodyBase):], shim)
	for len(m.Body)%16 != 0 {
		m.Body = append(m.Body, 0)
	}
	if len(m.Body) > OLBodyCapacity {
		return m, fmt.Errorf("fieldprep body %d exceeds %d", len(m.Body), OLBodyCapacity)
	}
	m.BodyLen = len(m.Body)
	for i := 0; i < len(m.Body); i += 4 {
		w := binary.LittleEndian.Uint32(m.Body[i:])
		m.Sum32 += w
		m.XOR32 ^= w
	}
	m.BodyEndRAM = OLBodyBase + uint32(len(m.Body))

	v0, err := buildOverlayVerifierMagic(OLFieldPrepMagicWord, 0, 0, uint32(m.BodyLen))
	if err != nil {
		return m, err
	}
	if int(OLVerifierRAM-OLGuardBase)+len(v0) > OLGuardBytes {
		return m, fmt.Errorf("fieldprep verifier does not fit guard")
	}
	v, err := buildOverlayVerifierMagic(OLFieldPrepMagicWord, m.Sum32, m.XOR32, uint32(m.BodyLen))
	if err != nil {
		return m, err
	}
	if len(v) != len(v0) {
		return m, fmt.Errorf("fieldprep verifier size drift")
	}
	m.VerifierBytes = len(v)
	if OLVerifierRAM+uint32(len(v)) > OLBodyBase {
		return m, fmt.Errorf("fieldprep verifier crosses body base")
	}
	m.Guard = make([]byte, OLGuardBytes)
	binary.LittleEndian.PutUint32(m.Guard[0:], OLFieldPrepMagicWord)
	binary.LittleEndian.PutUint32(m.Guard[4:], uint32(m.BodyLen))
	binary.LittleEndian.PutUint32(m.Guard[8:], m.Sum32)
	binary.LittleEndian.PutUint32(m.Guard[12:], m.XOR32)
	stub, err := buildDispatchStub(OLFieldPrepOriginal, m.ShimBodyRAM)
	if err != nil {
		return m, err
	}
	copy(m.Guard[OLStubRAM-OLGuardBase:], stub)
	copy(m.Guard[OLVerifierRAM-OLGuardBase:], v)
	m.SHA = sha(append(append([]byte{}, m.Guard...), m.Body...))
	return m, nil
}

// buildFieldPrepShim emits the body entered after verification.
//
// Entry ABI (unchanged from retail 0x800847B8): a0 = caller selector.
// It calls retail first, so every behavior other than the two working fields
// (selector return value, 0x800CA17C/0x800CA190 construction) is untouched.
func buildFieldPrepShim(romanizer, shimRAM uint32) ([]byte, error) {
	return buildFieldPrepShimAt(romanizer, shimRAM, OLFieldPrepWorkFam, OLFieldPrepWorkGiv, OLFieldPrepSlotBytes)
}

func buildFieldPrepShimAt(romanizer, shimRAM, famDst, givDst uint32, slotBytes int) ([]byte, error) {
	if slotBytes < 2 || slotBytes > 0x7FFF {
		return nil, fmt.Errorf("fieldprep slot bytes %d", slotBytes)
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	mov := func(dst, src uint32) { w(olAddu(dst, src, 0)) }
	addiu := func(dst, src uint32, imm int16) { w(olADDIU(dst, src, imm)) }
	lw := func(dst, base uint32, off int16) { w(olLW(dst, base, off)) }
	sw := func(src, base uint32, off int16) { w(olSW(src, base, off)) }
	jal := func(t uint32) { w(jalWord(t)); w(0) }
	// ori is used for the low half: the working fields have bit 15 set in
	// 0xA16C/0xA174, and addiu would sign-extend those halves.
	luiAddr := func(rt, addr uint32) {
		w(olLUI(rt, addr))
		w(olORI(rt, rt, addr&0xFFFF))
	}

	addiu(29, 29, -OLFieldPrepFrame)
	sw(31, 29, OLFieldPrepRAOff) // save caller return

	// 1. Run retail first with the caller's untouched a0-a3.
	jal(OLFieldPrepOriginal)
	sw(2, 29, OLFieldPrepV0Off) // retail v0, restored on every path
	sw(3, 29, OLFieldPrepV1Off)

	// 2. Romanize saved family into owned scratch.
	luiAddr(4, OLA0SurnameField)
	addiu(5, 29, OLFieldPrepFamilyOff)
	addiu(6, 0, OLFieldPrepScratchBytes)
	addiu(7, 0, 3) // max 3 kana, suffix none
	jal(romanizer)
	a.b(4, 2, 0, "retail") // beq v0,zero,retail
	w(0)
	// v0 is the romanizer's byte count *including* the NUL. The gate accepts
	// v0 < slotBytes. For the retail 8-byte slot that is v0 <= 7; for the
	// relocated 12-byte slot it is v0 <= 11 (9 roman + pad + NUL), which is
	// exactly the widest three-kana output.
	w(olSLTIU(1, 2, int16(slotBytes)))
	a.b(4, 1, 0, "retail")
	w(0)
	sw(2, 29, OLFieldPrepFamilyLenOff)

	// 3. Romanize saved given into owned scratch.
	luiAddr(4, OLFieldPrepSavedGiv)
	addiu(5, 29, OLFieldPrepGivenOff)
	addiu(6, 0, OLFieldPrepScratchBytes)
	addiu(7, 0, 3)
	jal(romanizer)
	a.b(4, 2, 0, "retail")
	w(0)
	w(olSLTIU(1, 2, int16(slotBytes)))
	a.b(4, 1, 0, "retail")
	w(0)
	sw(2, 29, OLFieldPrepGivenLenOff)

	// 4. Both fit: copy both outputs (including NUL) into the working slots.
	copyBytes := func(lenOff int16, scratchOff int16, dst uint32, label string) {
		lw(8, 29, lenOff) // t0 = bytes incl NUL
		mov(9, 29)        // t1 = src
		addiu(9, 9, scratchOff)
		luiAddr(10, dst) // t2 = destination
		a.label(label + "_loop")
		a.b(4, 8, 0, label+"_done")
		w(0)
		w(olLBU(11, 9, 0)) // t3 = byte
		w(0)               // load delay
		w(olSB(11, 10, 0))
		addiu(9, 9, 1)
		addiu(10, 10, 1)
		addiu(8, 8, -1)
		a.j(label + "_loop")
		w(0)
		a.label(label + "_done")
	}
	copyBytes(OLFieldPrepFamilyLenOff, OLFieldPrepFamilyOff, famDst, "fam")
	copyBytes(OLFieldPrepGivenLenOff, OLFieldPrepGivenOff, givDst, "giv")

	// 5. Restore retail v0/v1, ra, sp. Nothing else was modified.
	a.label("retail")
	lw(2, 29, OLFieldPrepV0Off)
	lw(3, 29, OLFieldPrepV1Off)
	lw(31, 29, OLFieldPrepRAOff)
	w(0) // load delay before jr
	w(olJR(31))
	addiu(29, 29, OLFieldPrepFrame)
	a.resolve()
	a.resolveJLabels(shimRAM)
	return words(a.words...), nil
}

// OverlayFieldPrepReport is the honest coverage report for this route.
type OverlayFieldPrepReport struct {
	Carriers         int
	PatchedOverlays  []string
	PatchedCallsites int
	CandidateSites   int
	SpeakerCarriers  []string
	GuardBytes       int
	BodyBytes        int
	ModuleBytes      int
	BodySum32        uint32
	BodyXOR32        uint32
	OverlayPlanSHA   map[string]string
	// EXEChangedWords is the N6/N6-FP entry-hook count, not the total EXE
	// change count. The integrated relocation plan changes 30 EXE words.
	EXEChangedWords      int `json:"exe_entry_hooks"`
	FieldPrepTarget      uint32
	WorkingFamily        uint32
	WorkingGiven         uint32
	BlockedFields        []string
	DisjointFromSpeaker  bool
	MaxAcceptedWireBytes int
	AtomicLoadBytes      int
	ResidualTornLoad     bool
}

// OverlayFieldPrepPlan is an in-memory delivery plan. No file is written.
type OverlayFieldPrepPlan struct {
	Module         OverlayFieldPrepModule
	Patched        map[string][]byte
	SitesByOverlay map[string][]FieldPrepCallsite
	PatchedWords   map[string][]int
	PatchedSites   int
	Report         OverlayFieldPrepReport
}

// PlanOverlayFieldPrep patches only the overlay-owned JALs to 0x800847B8.
// It refuses any unauthenticated overlay, any non-zero payload, any changed
// delay word and any carrier that also belongs to the N6 speaker route.
func PlanOverlayFieldPrep(overlays map[string][]byte, sites []FieldPrepCallsite) (OverlayFieldPrepPlan, error) {
	m, err := BuildOverlayFieldPrepModule()
	if err != nil {
		return OverlayFieldPrepPlan{}, err
	}
	return planOverlayFieldPrepWithModule(overlays, sites, m, nil)
}

// planOverlayFieldPrepWithModule is the shared installer. extra carries
// non-JAL overlay instruction replacements (used only by the relocation
// prototype); nil preserves the retail N6-FP plan byte-for-byte.
func planOverlayFieldPrepWithModule(overlays map[string][]byte, sites []FieldPrepCallsite,
	m OverlayFieldPrepModule, extra map[string][]n20RelocWord) (OverlayFieldPrepPlan, error) {
	p := OverlayFieldPrepPlan{Patched: map[string][]byte{},
		SitesByOverlay: map[string][]FieldPrepCallsite{}, PatchedWords: map[string][]int{}}
	p.Module = m
	p.Report.GuardBytes = len(m.Guard)
	p.Report.BodyBytes = len(m.Body)
	p.Report.ModuleBytes = len(m.Guard) + len(m.Body)
	p.Report.BodySum32 = m.Sum32
	p.Report.BodyXOR32 = m.XOR32
	p.Report.OverlayPlanSHA = map[string]string{}
	p.Report.EXEChangedWords = 0
	p.Report.FieldPrepTarget = OLFieldPrepOriginal
	p.Report.WorkingFamily = m.FamilyDst
	p.Report.WorkingGiven = m.GivenDst
	p.Report.BlockedFields = []string{
		fmt.Sprintf("0x%08x", OLFieldPrepBlockedFam),
		fmt.Sprintf("0x%08x", OLFieldPrepBlockedGiv),
	}
	p.Report.MaxAcceptedWireBytes = m.SlotBytes - 1
	p.Report.AtomicLoadBytes = OverlayLoadSectors * 2048
	p.Report.ResidualTornLoad = true

	for _, cs := range sites {
		if !cs.Authentic || cs.Target != OLFieldPrepOriginal {
			return p, fmt.Errorf("unauthenticated fieldprep callsite %s+0x%x", cs.Overlay, cs.FileOff)
		}
		p.SitesByOverlay[cs.Overlay] = append(p.SitesByOverlay[cs.Overlay], cs)
		p.Report.PatchedCallsites++
	}
	p.Report.CandidateSites = len(sites)
	if p.Report.PatchedCallsites == 0 {
		return p, fmt.Errorf("no overlay-owned fieldprep route found")
	}

	// Prove the two route families never share a loaded image.
	speakerSites, err := ScanOverlayCallsites(overlays)
	if err != nil {
		return p, err
	}
	speaker := map[string]bool{}
	for _, s := range speakerSites {
		if s.NameRoute {
			speaker[s.Overlay] = true
		}
	}
	for n := range speaker {
		p.Report.SpeakerCarriers = append(p.Report.SpeakerCarriers, n)
	}
	sort.Strings(p.Report.SpeakerCarriers)
	p.Report.DisjointFromSpeaker = true
	for n := range p.SitesByOverlay {
		if speaker[n] {
			p.Report.DisjointFromSpeaker = false
			return p, fmt.Errorf("fieldprep carrier %s also carries the speaker route", n)
		}
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
			delay := binary.LittleEndian.Uint32(d[off+4:])
			if delay != cs.DelayWord {
				return p, fmt.Errorf("%s callsite %08x delay changed at scan time", name, cs.PC)
			}
			binary.LittleEndian.PutUint32(d[off:], jalWord(OLStubRAM))
			p.PatchedWords[name] = append(p.PatchedWords[name], off)
		}
		extraOffsets := map[int]bool{}
		for _, w := range extra[name] {
			off := int(w.PC - OverlaySlotBase)
			if off < 0 || off+4 > len(d) {
				return p, fmt.Errorf("%s relocation word %08x outside overlay", name, w.PC)
			}
			if binary.LittleEndian.Uint32(d[off:]) != w.Old {
				return p, fmt.Errorf("%s relocation word %08x is %08x want %08x",
					name, w.PC, binary.LittleEndian.Uint32(d[off:]), w.Old)
			}
			binary.LittleEndian.PutUint32(d[off:], w.New)
			extraOffsets[off] = true
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
		for off := range extraOffsets {
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
				return p, fmt.Errorf("delta outside fieldprep plan %s+0x%x", name, i)
			}
		}
		for _, off := range p.PatchedWords[name] {
			if binary.LittleEndian.Uint32(d[off+4:]) != binary.LittleEndian.Uint32(src[off+4:]) {
				return p, fmt.Errorf("%s+0x%x delay slot changed", name, off)
			}
		}
		p.Patched[name] = d
		p.Report.OverlayPlanSHA[name] = sha(d)
		p.Report.PatchedOverlays = append(p.Report.PatchedOverlays, name)
	}
	p.Report.Carriers = len(p.Patched)
	if p.Report.PatchedCallsites != len(sites) {
		return p, fmt.Errorf("fieldprep patched callsite count drift")
	}
	if m.ModuleEnd() > OLBodyBase+OLBodyCapacity || m.ModuleEnd() > 0x80161ED8 {
		return p, fmt.Errorf("fieldprep module end %08x exceeds payload", m.ModuleEnd())
	}
	return p, nil
}

// OverlayFieldPrepRoute is one row of the field-prep route matrix.
type OverlayFieldPrepRoute struct {
	ID        string
	Site      string
	Status    string
	Callsites int
	Reason    string
}

// OverlayFieldPrepRoutes reports the implemented working-field route and the
// tokens it deliberately leaves in kana.
func OverlayFieldPrepRoutes(sites []FieldPrepCallsite) []OverlayFieldPrepRoute {
	return OverlayFieldPrepRoutesForSlot(sites, OLFieldPrepSlotBytes)
}

// OverlayFieldPrepRoutesForSlot is the same row set for a caller-chosen slot.
func OverlayFieldPrepRoutesForSlot(sites []FieldPrepCallsite, slotBytes int) []OverlayFieldPrepRoute {
	return []OverlayFieldPrepRoute{
		{"working_family_given", "overlay JALs to 0x800847B8", "implemented", len(sites),
			fmt.Sprintf("same-overlay shim calls retail first, then copies romanized saved family/given only when both fit the slot (at most %d bytes including NUL)", slotBytes-1)},
		{"working_family_kanji_table", "0x800CA17C", "blocked", 0,
			"built by EXE 0x80051508 from selector and kanji name-table output; not dynamically kana-romanizable"},
		{"working_given_kanji_table", "0x800CA190", "blocked", 0,
			"built by EXE 0x80051438 from selector and the kanji surname table; not dynamically kana-romanizable"},
		{"speaker_exe_owned", "EXE JALs to 0x80050DFC", "blocked", 0,
			"redirecting EXE-owned callers still needs an EXE hook; the N6 speaker route is unchanged"},
	}
}

// FieldPrepReportFor exposes the built module and route rows to the evidence
// generator without duplicating geometry constants.
func FieldPrepReportFor(m OverlayFieldPrepModule, sites []FieldPrepCallsite) map[string]any {
	return map[string]any{
		"guard_base":  fmt.Sprintf("0x%08x", OLGuardBase),
		"guard_bytes": len(m.Guard), "body_base": fmt.Sprintf("0x%08x", OLBodyBase),
		"body_bytes": m.BodyLen, "romanizer_bytes": m.RomanizerBytes,
		"shim_body": fmt.Sprintf("0x%08x", m.ShimBodyRAM), "shim_bytes": m.ShimBytes,
		"verifier_bytes": m.VerifierBytes, "module_end": fmt.Sprintf("0x%08x", m.ModuleEnd()),
		"module_sha256": m.SHA, "body_sum32": fmt.Sprintf("0x%08x", m.Sum32),
		"body_xor32":  fmt.Sprintf("0x%08x", m.XOR32),
		"magic":       fmt.Sprintf("0x%08x", OLFieldPrepMagicWord),
		"frame_bytes": OLFieldPrepFrame, "added_stack": OLFieldPrepAddedStack,
		"working_family": fmt.Sprintf("0x%08x", m.FamilyDst),
		"working_given":  fmt.Sprintf("0x%08x", m.GivenDst),
		"slot_bytes":     m.SlotBytes, "max_wire_bytes": m.SlotBytes - 1,
		"relocated": m.FamilyDst != OLFieldPrepWorkFam || m.GivenDst != OLFieldPrepWorkGiv,
		"callsites": len(sites), "routes": OverlayFieldPrepRoutesForSlot(sites, m.SlotBytes),
	}
}
