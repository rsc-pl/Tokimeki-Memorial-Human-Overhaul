package n20arch

// N20 EXE-side working-name-field relocation prototype (offline only).
//
// The 8-byte retail working fields 0x800CA16C (family) and 0x800CA174 (given)
// cannot hold the rebuilt romanizer's 9-byte maximum: nine letters + one pad
// + NUL is 11 bytes, and an aligned slot is 12. This file relocates both
// fields to a 12-byte EXE-resident destination and redirects every
// authenticated EXE reader/writer, plus the six overlay field references.
//
// Destination: BSS slack.
//   0x8012B500..0x8012B50B  family (12 bytes, 16-byte aligned)
//   0x8012B50C..0x8012B50F  four guard bytes (never written by the shim)
//   0x8012B510..0x8012B51B  given  (12 bytes, 16-byte aligned)
//   0x8012B51C..0x8012B52F  remaining zeroed slack
//   0x8012B530              last statically referenced BSS word (4 bytes)
//   0x8012B538              authenticated boot BSS end
//
// The boot clear 0x80042108 covers 0x800E60A0..0x8012B538, so the destination
// is zero at boot. The fieldprep writer runs before every authenticated
// renderer read, so the zero initial state is equivalent to the retail file
// zero initialisation of the old fields. The destination is below the overlay
// slot (0x80132000..0x80162000), so overlay loads cannot replace it.
//
// No EXE, overlay, image, save, emulator or production file is written. The
// patch words exist only in returned byte slices. safe_to_patch stays false
// and runtime_pass stays false.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	// Relocated EXE-resident working fields.
	N20RelocFamilyAddr uint32 = 0x8012B500
	N20RelocGivenAddr  uint32 = 0x8012B510
	N20RelocSlotBytes         = 12
	N20RelocGuardGap          = 4

	// Authenticated BSS geometry and the one referenced tail word.
	N20RelocBSSStart    uint32 = BootBSSStart
	N20RelocBSSEnd      uint32 = BootBSSEnd
	N20RelocBSSLastWord uint32 = 0x8012B530

	// The old fields remain in place as shadow storage; every consumer is
	// redirected, including the four overlay duplicate writers, so the retail
	// write order is preserved exactly rather than silently diverging.
	N20RelocOldFamily uint32 = OLFieldPrepWorkFam
	N20RelocOldGiven  uint32 = OLFieldPrepWorkGiv
)

// n20RelocWord is one private instruction replacement.
type n20RelocWord struct {
	Owner string `json:"owner"`
	PC    uint32 `json:"pc"`
	Old   uint32 `json:"old"`
	New   uint32 `json:"new"`
	Kind  string `json:"kind"`
	Role  string `json:"role"`
}

// n20RelocPair is one authenticated LUI/ADDIU address materialisation.
type n20RelocPair struct {
	Field string
	LUI   uint32
	ADDIU uint32
	Role  string
}

// n20RelocEXEPairs is every EXE instruction pair that materialises one of the
// two old fields. Counts: 10 family + 5 given. The list was re-derived from
// the authenticated bytes with a backward LUI-base resolver, not copied from
// prose.
var n20RelocEXEPairs = []n20RelocPair{
	{"family", 0x8007F77C, 0x8007F788, "formatter_a strlen(family)"},
	{"family", 0x8007F790, 0x8007F798, "formatter_a sprintf arg3=family"},
	{"family", 0x8007F844, 0x8007F84C, "formatter_b strlen(family)"},
	{"family", 0x8007F854, 0x8007F85C, "formatter_b sprintf arg3=family"},
	{"family", 0x8007F908, 0x8007F910, "formatter_c strlen(family)"},
	{"family", 0x8007F918, 0x8007F920, "formatter_c sprintf arg3=family"},
	{"family", 0x80080BDC, 0x80080BE4, "formatter_d strlen(family)"},
	{"family", 0x80080BEC, 0x80080BF4, "formatter_d sprintf arg3=family"},
	{"family", 0x800813FC, 0x80081408, "renderer p s6=family"},
	{"family", 0x800847C4, 0x800847D4, "fieldprep writer family"},
	{"given", 0x800818E4, 0x800818E8, "renderer F sprintf arg4=given"},
	{"given", 0x800819A4, 0x800819A8, "renderer m strcpy src=given"},
	{"given", 0x80082220, 0x80082224, "renderer second F sprintf arg4=given"},
	{"given", 0x800822E0, 0x800822E4, "renderer second m strcpy src=given"},
	{"given", 0x800847D8, 0x800847E8, "fieldprep writer given"},
}

// n20RelocOverlayPairs is every overlay instruction pair that materialises the
// family field. Four duplicate writers (GEKO x3, SHOUGATU x1) and two
// SHOUGATU consumers (strlen and queue a3). There are zero overlay given
// references.
var n20RelocOverlayPairs = []n20RelocPair{
	{"family", 0x80141150, 0x80141164, "GEKO duplicate writer family (strcpy)"},
	{"family", 0x80141280, 0x80141294, "GEKO duplicate writer family (strcpy)"},
	{"family", 0x8014144C, 0x80141460, "GEKO duplicate writer family (strcpy)"},
	{"family", 0x80133B78, 0x80133B88, "SHOUGATU strlen(family) NAME_ENT confirmation"},
	{"family", 0x80133B9C, 0x80133BA0, "SHOUGATU queue a3=family"},
	{"family", 0x8013DC20, 0x8013DC30, "SHOUGATU duplicate writer family (strcpy)"},
}

// n20RelocLUIWord returns the LUI that materialises addr in the low half.
func n20RelocLUIWord(old, addr uint32) uint32 {
	rt := (old >> 16) & 31
	hi := (addr + 0x8000) >> 16
	return 0x3C000000 | rt<<16 | hi&0xFFFF
}

func n20RelocADDIUWord(old, addr uint32) uint32 {
	rs := (old >> 21) & 31
	rt := (old >> 16) & 31
	return 0x24000000 | rs<<21 | rt<<16 | addr&0xFFFF
}

func n20RelocExpectedOldLow(field string) uint32 {
	if field == "given" {
		return 0xA174
	}
	return 0xA16C
}

// n20RelocWordsForPairs validates each pair and returns the two replacement
// words. off converts a loaded PC to a file offset in d.
func n20RelocWordsForPairs(d []byte, owner string, pairs []n20RelocPair, target uint32,
	off func(uint32) int) ([]n20RelocWord, error) {
	var out []n20RelocWord
	for _, p := range pairs {
		lo, la := off(p.LUI), off(p.ADDIU)
		if lo < 0 || lo+4 > len(d) || la < 0 || la+4 > len(d) {
			return nil, fmt.Errorf("%s pair %08x/%08x outside file", owner, p.LUI, p.ADDIU)
		}
		lui := binary.LittleEndian.Uint32(d[lo:])
		add := binary.LittleEndian.Uint32(d[la:])
		wantLow := n20RelocExpectedOldLow(p.Field)
		if lui>>26 != 0x0F || lui&0xFFFF != 0x800D {
			return nil, fmt.Errorf("%s %08x not lui,0x800d: %08x", owner, p.LUI, lui)
		}
		if add>>26 != 0x09 || add&0xFFFF != wantLow {
			return nil, fmt.Errorf("%s %08x not addiu,%04x: %08x", owner, p.ADDIU, wantLow, add)
		}
		out = append(out,
			n20RelocWord{owner, p.LUI, lui, n20RelocLUIWord(lui, target), "lui", p.Role},
			n20RelocWord{owner, p.ADDIU, add, n20RelocADDIUWord(add, target), "addiu", p.Role})
	}
	return out, nil
}

// PatchN20RelocEXE returns a private patched EXE copy and its changed words.
// The input slice is never modified.
func PatchN20RelocEXE(exe []byte) ([]byte, []n20RelocWord, error) {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return nil, nil, fmt.Errorf("unrecognised original EXE")
	}
	var words []n20RelocWord
	for _, field := range []string{"family", "given"} {
		var pairs []n20RelocPair
		for _, p := range n20RelocEXEPairs {
			if p.Field == field {
				pairs = append(pairs, p)
			}
		}
		target := N20RelocFamilyAddr
		if field == "given" {
			target = N20RelocGivenAddr
		}
		ws, err := n20RelocWordsForPairs(exe, "EXE", pairs, target,
			func(pc uint32) int { return int(pc - 0x80040800) })
		if err != nil {
			return nil, nil, err
		}
		words = append(words, ws...)
	}
	d := bytes.Clone(exe)
	changed := map[int]bool{}
	for _, w := range words {
		o := int(w.PC - 0x80040800)
		binary.LittleEndian.PutUint32(d[o:], w.New)
		changed[o] = true
	}
	for i := 0; i < len(exe); i += 4 {
		if binary.LittleEndian.Uint32(d[i:]) != binary.LittleEndian.Uint32(exe[i:]) && !changed[i] {
			return nil, nil, fmt.Errorf("unplanned EXE delta at file+0x%x", i)
		}
	}
	return d, words, nil
}

func n20RelocOverlayOwner(addiuPC uint32) string {
	switch addiuPC {
	case 0x80141164, 0x80141294, 0x80141460:
		return "GEKO.EXN"
	case 0x80133B88, 0x80133BA0, 0x8013DC30:
		return "SHOUGATU.EXN"
	}
	return ""
}

// n20RelocOverlayWordSets is the single overlay-relocation path. It validates
// the six authenticated overlay family pairs against the original bytes and
// returns their two replacement words, grouped by owning overlay.
//
// This replaces the former standalone PatchN20RelocOverlays helper. That
// helper produced a second, unused patched-overlay map and was therefore dead
// code: the actual integrated path installs the relocation words together with
// the N6-FP callsite patches in planOverlayFieldPrepWithModule. Keeping one
// used word-set function avoids two divergent patchers.
func n20RelocOverlayWordSets(overlays map[string][]byte) (map[string][]n20RelocWord, error) {
	out := map[string][]n20RelocWord{}
	byOwner := map[string][]n20RelocPair{}
	for _, p := range n20RelocOverlayPairs {
		owner := n20RelocOverlayOwner(p.ADDIU)
		if owner == "" {
			return nil, fmt.Errorf("unowned overlay pair %08x", p.ADDIU)
		}
		byOwner[owner] = append(byOwner[owner], p)
	}
	names := make([]string, 0, len(byOwner))
	for n := range byOwner {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		src, ok := overlays[name]
		if !ok {
			return nil, fmt.Errorf("missing overlay %s", name)
		}
		if len(src) != 196608 || sha(src) != OverlaySHA[name] {
			return nil, fmt.Errorf("overlay %s is not authenticated", name)
		}
		ws, err := n20RelocWordsForPairs(src, name, byOwner[name], N20RelocFamilyAddr,
			func(pc uint32) int { return int(pc - OverlaySlotBase) })
		if err != nil {
			return nil, err
		}
		out[name] = ws
	}
	return out, nil
}

// N20RelocDestRef is one static reference into the destination window.
type N20RelocDestRef struct {
	Owner string `json:"owner"`
	PC    uint32 `json:"pc"`
	Kind  string `json:"kind"`
	Addr  uint32 `json:"addr"`
	Word  uint32 `json:"word"`
}

// N20RelocDestAudit proves the destination window is slack.
type N20RelocDestAudit struct {
	FamilyAddr   uint32            `json:"family_addr"`
	GivenAddr    uint32            `json:"given_addr"`
	SlotBytes    int               `json:"slot_bytes"`
	GuardGap     int               `json:"guard_gap_bytes"`
	BSSStart     uint32            `json:"bss_start"`
	BSSEnd       uint32            `json:"bss_end"`
	BSSLastWord  uint32            `json:"bss_last_referenced_word"`
	BootCleared  bool              `json:"boot_cleared"`
	BelowOverlay bool              `json:"below_overlay_slot"`
	CandidateRef int               `json:"candidate_refs"`
	LastWordRefs int               `json:"last_word_refs"`
	OtherTailRef int               `json:"other_tail_refs"`
	Refs         []N20RelocDestRef `json:"refs"`
	Viable       bool              `json:"viable"`
	Reason       string            `json:"reason"`
}

// ScanN20RelocDestination resolves LUI/ADDIU/ORI/load/store pairs, pointer
// literals and gp-relative references in the EXE and all 26 overlays.
func ScanN20RelocDestination(exe []byte, overlays map[string][]byte) (N20RelocDestAudit, error) {
	var a N20RelocDestAudit
	a.FamilyAddr, a.GivenAddr = N20RelocFamilyAddr, N20RelocGivenAddr
	a.SlotBytes, a.GuardGap = N20RelocSlotBytes, N20RelocGuardGap
	a.BSSStart, a.BSSEnd, a.BSSLastWord = N20RelocBSSStart, N20RelocBSSEnd, N20RelocBSSLastWord
	a.BootCleared = N20RelocFamilyAddr >= N20RelocBSSStart &&
		N20RelocGivenAddr+N20RelocSlotBytes <= N20RelocBSSEnd
	a.BelowOverlay = N20RelocGivenAddr+N20RelocSlotBytes <= OverlaySlotBase
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return a, fmt.Errorf("unrecognised original EXE")
	}
	lo, hi := N20RelocFamilyAddr, N20RelocBSSEnd
	a.Refs = append(a.Refs, scanN20RelocRefs(exe[0x800:], 0x80041000, "EXE", lo, hi)...)
	names := make([]string, 0, len(overlays))
	for n := range overlays {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		d := overlays[n]
		if len(d) != 196608 || sha(d) != OverlaySHA[n] {
			return a, fmt.Errorf("overlay %s is not authenticated", n)
		}
		a.Refs = append(a.Refs, scanN20RelocRefs(d, OverlaySlotBase, n, lo, hi)...)
	}
	for _, r := range a.Refs {
		switch {
		case r.Addr >= N20RelocFamilyAddr && r.Addr < N20RelocGivenAddr+N20RelocSlotBytes:
			a.CandidateRef++
		case r.Addr >= N20RelocBSSLastWord && r.Addr < N20RelocBSSLastWord+4:
			a.LastWordRefs++
		case r.Addr >= N20RelocBSSLastWord+4 && r.Addr < N20RelocBSSEnd:
			a.OtherTailRef++
		}
	}
	a.Viable = a.CandidateRef == 0 && a.LastWordRefs == 1 && a.OtherTailRef == 0 &&
		a.BootCleared && a.BelowOverlay
	a.Reason = fmt.Sprintf(
		"destination 0x%08x/0x%08x is a %d-byte boot-cleared BSS tail below the overlay slot; the only reference in [0x%08x,0x%08x) is the 4-byte word at 0x%08x (candidate refs=%d, last-word refs=%d, other tail refs=%d)",
		a.FamilyAddr, a.GivenAddr, a.SlotBytes, a.BSSStart, a.BSSEnd,
		a.BSSLastWord, a.CandidateRef, a.LastWordRefs, a.OtherTailRef)
	return a, nil
}

func scanN20RelocRefs(d []byte, base uint32, owner string, lo, hi uint32) []N20RelocDestRef {
	var out []N20RelocDestRef
	const gp = uint32(0x800EB670)
	memOps := map[uint32]bool{0x20: true, 0x21: true, 0x23: true, 0x24: true, 0x25: true,
		0x28: true, 0x29: true, 0x2A: true, 0x2B: true, 0x22: true, 0x26: true, 0x2E: true}
	for i := 0; i+4 <= len(d); i += 4 {
		w := binary.LittleEndian.Uint32(d[i:])
		op := w >> 26
		rs := (w >> 21) & 31
		imm := w & 0xFFFF
		pc := base + uint32(i)
		if op == 0x09 || op == 0x0D || memOps[op] {
			if hiBase, ok := n20ResolveBase(d, i, rs); ok {
				var ea uint32
				if op == 0x0D {
					ea = hiBase<<16 | imm
				} else {
					ea = uint32(hiBase)<<16 + uint32(int32(int16(imm)))
				}
				if ea >= lo && ea < hi {
					out = append(out, N20RelocDestRef{owner, pc, fmt.Sprintf("op%02x", op), ea, w})
				}
			}
		}
		if memOps[op] && rs == 28 {
			ea := gp + uint32(int32(int16(imm)))
			if ea >= lo && ea < hi {
				out = append(out, N20RelocDestRef{owner, pc, "gp", ea, w})
			}
		}
		if w >= lo && w < hi {
			out = append(out, N20RelocDestRef{owner, pc, "literal", w, w})
		}
	}
	return out
}

// N20RelocOldRef is one authenticated reference to an old working field.
type N20RelocOldRef struct {
	Owner string `json:"owner"`
	PC    uint32 `json:"pc"`
	Field string `json:"field"`
	Kind  string `json:"kind"`
	Addr  uint32 `json:"addr"`
	Word  uint32 `json:"word"`
}

// ScanN20RelocOldFieldRefs re-derives every old-field reference from the
// authenticated EXE and all 26 overlays. It is the independent coverage check
// for the hard-coded patch table: the tests require exactly the 15 EXE and 6
// overlay materialisations, zero pointer literals and zero gp-relative or
// write-through-table references.
func ScanN20RelocOldFieldRefs(exe []byte, overlays map[string][]byte) ([]N20RelocOldRef, error) {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return nil, fmt.Errorf("unrecognised original EXE")
	}
	var out []N20RelocOldRef
	add := func(owner string, refs []N20RelocDestRef) {
		for _, r := range refs {
			if r.Addr >= OLFieldPrepBlockedFam {
				continue
			}
			field := "family"
			if r.Addr >= N20RelocOldGiven {
				field = "given"
			}
			kind := r.Kind
			switch r.Kind {
			case "op09", "op0d":
				kind = "address"
			case "op2b", "op28", "op29":
				kind = "write"
			case "op23", "op24", "op21", "op25", "op22", "op26", "op2a", "op2e":
				kind = "read"
			}
			out = append(out, N20RelocOldRef{owner, r.PC, field, kind, r.Addr, r.Word})
		}
	}
	add("EXE", scanN20RelocRefs(exe[0x800:], 0x80041000, "EXE", N20RelocOldFamily, OLFieldPrepBlockedFam))
	names := make([]string, 0, len(overlays))
	for n := range overlays {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		d := overlays[n]
		if len(d) != 196608 || sha(d) != OverlaySHA[n] {
			return nil, fmt.Errorf("overlay %s is not authenticated", n)
		}
		add(n, scanN20RelocRefs(d, OverlaySlotBase, n, N20RelocOldFamily, OLFieldPrepBlockedFam))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner == out[j].Owner {
			return out[i].PC < out[j].PC
		}
		return out[i].Owner < out[j].Owner
	})
	return out, nil
}

// N20RelocCoverage is the consumer inventory summary.
type N20RelocCoverage struct {
	EXEPairs            int      `json:"exe_pairs"`
	EXEWords            int      `json:"exe_words"`
	FamilyPairs         int      `json:"exe_family_pairs"`
	GivenPairs          int      `json:"exe_given_pairs"`
	OverlayPairs        int      `json:"overlay_pairs"`
	OverlayWords        int      `json:"overlay_words"`
	OverlayWriters      int      `json:"overlay_writers"`
	OverlayConsumers    int      `json:"overlay_consumers"`
	OldEXERefs          int      `json:"old_exe_refs"`
	OldOverlayRefs      int      `json:"old_overlay_refs"`
	OldFamilyRefs       int      `json:"old_family_refs"`
	OldGivenRefs        int      `json:"old_given_refs"`
	PointerLiterals     int      `json:"pointer_literals"`
	GPRelativeRefs      int      `json:"gp_relative_refs"`
	ExplicitInitializer int      `json:"explicit_initializers"`
	DMAOrSaveRefs       int      `json:"dma_or_save_refs"`
	Unknowns            []string `json:"unknowns"`
	Reason              string   `json:"reason"`
}

// N20RelocPlan is the complete in-memory relocation plan.
type N20RelocPlan struct {
	PatchedEXE     []byte                 `json:"-"`
	EXEWords       []n20RelocWord         `json:"exe_words"`
	PatchedOverlay map[string][]byte      `json:"-"`
	OverlayWords   []n20RelocWord         `json:"overlay_words"`
	SHOUCopyWord   n20RelocWord           `json:"-"`
	SHOULabelWords []n20RelocWord         `json:"-"`
	Module         OverlayFieldPrepModule `json:"-"`
	FieldPrep      OverlayFieldPrepPlan   `json:"-"`
	Destination    N20RelocDestAudit      `json:"destination"`
	Coverage       N20RelocCoverage       `json:"coverage"`
	Verdict        string                 `json:"verdict"`
	SafeToPatch    bool                   `json:"safe_to_patch"`
	RuntimePass    bool                   `json:"runtime_pass"`
}

// PlanN20Relocation builds the private patched EXE, the relocated N6-FP
// module and patched overlay bytes.
func PlanN20Relocation(exe []byte, overlays map[string][]byte,
	sites []FieldPrepCallsite) (N20RelocPlan, error) {
	var p N20RelocPlan
	d, words, err := PatchN20RelocEXE(exe)
	if err != nil {
		return p, err
	}
	p.PatchedEXE, p.EXEWords = d, words
	dest, err := ScanN20RelocDestination(exe, overlays)
	if err != nil {
		return p, err
	}
	p.Destination = dest
	if !dest.Viable {
		return p, fmt.Errorf("relocation destination is not viable: %s", dest.Reason)
	}
	m, err := buildOverlayFieldPrepModuleAt(N20RelocFamilyAddr, N20RelocGivenAddr, N20RelocSlotBytes)
	if err != nil {
		return p, err
	}
	p.Module = m

	byOwner, err := n20RelocOverlayWordSets(overlays)
	if err != nil {
		return p, err
	}
	extra := map[string][]n20RelocWord{}
	for owner, ws := range byOwner {
		extra[owner] = ws
	}
	fp, err := planOverlayFieldPrepWithModule(overlays, sites, m, extra)
	if err != nil {
		return p, err
	}
	// Only SHOUGATU receives the extended module; the other 25 overlays
	// remain bit-for-bit identical to the authenticated predecessor.
	shouModule, err := shouFamilyExtendFieldPrepModule(m)
	if err != nil {
		return p, err
	}
	shou := fp.Patched["SHOUGATU.EXN"]
	if shou == nil {
		return p, fmt.Errorf("ChristmasFamily SHOUGATU not a verified N6-FP carrier")
	}
	copy(shou[OLPayloadFileOff:OLGuardFileEnd], shouModule.Guard)
	copy(shou[OLBodyFileOff:OLBodyFileOff+len(shouModule.Body)], shouModule.Body)
	fp.SHOUCopyModule = &shouModule
	copyWord, err := shouFamilyAuthenticatedSHOUCopyPatch(overlays["SHOUGATU.EXN"], shou)
	if err != nil {
		return p, err
	}
	fp.Report.OverlayPlanSHA["SHOUGATU.EXN"] = sha(fp.Patched["SHOUGATU.EXN"])
	p.SHOUCopyWord = copyWord
	labelWords, err := shouSceneLabelAuthenticatedPatches(overlays["SHOUGATU.EXN"], shou)
	if err != nil {
		return p, err
	}
	p.SHOULabelWords = labelWords
	fp.Report.OverlayPlanSHA["SHOUGATU.EXN"] = sha(shou)
	p.FieldPrep = fp
	p.PatchedOverlay = fp.Patched
	for _, ws := range extra {
		p.OverlayWords = append(p.OverlayWords, ws...)
	}
	sort.Slice(p.OverlayWords, func(i, j int) bool { return p.OverlayWords[i].PC < p.OverlayWords[j].PC })

	for _, pair := range n20RelocEXEPairs {
		if pair.Field == "family" {
			p.Coverage.FamilyPairs++
		} else {
			p.Coverage.GivenPairs++
		}
	}
	p.Coverage.Unknowns = []string{}
	p.Coverage.EXEPairs = len(n20RelocEXEPairs)
	p.Coverage.EXEWords = len(p.EXEWords)
	p.Coverage.OverlayPairs = len(n20RelocOverlayPairs)
	p.Coverage.OverlayWords = len(p.OverlayWords)
	for _, pair := range n20RelocOverlayPairs {
		if pair.Role == "SHOUGATU strlen(family) NAME_ENT confirmation" ||
			pair.Role == "SHOUGATU queue a3=family" {
			p.Coverage.OverlayConsumers++
		} else {
			p.Coverage.OverlayWriters++
		}
	}
	for _, r := range dest.Refs {
		if r.Kind == "literal" {
			p.Coverage.PointerLiterals++
		}
		if r.Kind == "gp" {
			p.Coverage.GPRelativeRefs++
		}
	}
	oldRefs, err := ScanN20RelocOldFieldRefs(exe, overlays)
	if err != nil {
		return p, err
	}
	patchPC := map[uint32]bool{}
	for _, pair := range n20RelocEXEPairs {
		patchPC[pair.ADDIU] = true
	}
	for _, pair := range n20RelocOverlayPairs {
		patchPC[pair.ADDIU] = true
	}
	for _, r := range oldRefs {
		if r.Owner == "EXE" {
			p.Coverage.OldEXERefs++
		} else {
			p.Coverage.OldOverlayRefs++
		}
		if r.Field == "family" {
			p.Coverage.OldFamilyRefs++
		} else {
			p.Coverage.OldGivenRefs++
		}
		switch r.Kind {
		case "literal":
			p.Coverage.PointerLiterals++
		case "gp":
			p.Coverage.GPRelativeRefs++
		case "address":
			if !patchPC[r.PC] {
				return p, fmt.Errorf("independent scan found unpatched old-field materialisation at %08x", r.PC)
			}
		default:
			return p, fmt.Errorf("independent scan found direct %s old-field reference at %08x", r.Kind, r.PC)
		}
	}
	if p.Coverage.OldEXERefs != 15 || p.Coverage.OldOverlayRefs != 6 ||
		p.Coverage.OldFamilyRefs != 16 || p.Coverage.OldGivenRefs != 5 {
		return p, fmt.Errorf("independent old-field scan drifted: %+v", p.Coverage)
	}
	p.Coverage.Reason = fmt.Sprintf(
		"independent scan finds %d EXE + %d overlay old-field materialisations (%d family + %d given); all %d EXE pairs and %d overlay pairs are redirected; explicit initializers=0 (fieldprep is the only writer), pointer literals=%d, gp-relative/dma/save references=%d; P/G 0x800CA17C/0x800CA188/0x800CA190 remain retail",
		p.Coverage.OldEXERefs, p.Coverage.OldOverlayRefs, p.Coverage.OldFamilyRefs,
		p.Coverage.OldGivenRefs, p.Coverage.EXEPairs, p.Coverage.OverlayPairs,
		p.Coverage.PointerLiterals, p.Coverage.GPRelativeRefs)
	p.Verdict = "implemented_offline_exe_field_relocation"
	p.SafeToPatch = false
	p.RuntimePass = false
	return p, nil
}

// N20RelocReportFor exposes the plan to the evidence generator.
func N20RelocReportFor(p N20RelocPlan, sites []FieldPrepCallsite) map[string]any {
	return map[string]any{
		"verdict": p.Verdict, "safe_to_patch": p.SafeToPatch, "runtime_pass": p.RuntimePass,
		"family_addr": fmt.Sprintf("0x%08x", N20RelocFamilyAddr),
		"given_addr":  fmt.Sprintf("0x%08x", N20RelocGivenAddr),
		"slot_bytes":  N20RelocSlotBytes, "guard_gap_bytes": N20RelocGuardGap,
		"destination": p.Destination, "coverage": p.Coverage,
		"exe_words": p.EXEWords, "overlay_words": p.OverlayWords,
		"module":                   FieldPrepReportFor(p.Module, sites),
		"fieldprep_working_family": fmt.Sprintf("0x%08x", p.FieldPrep.Report.WorkingFamily),
		"fieldprep_working_given":  fmt.Sprintf("0x%08x", p.FieldPrep.Report.WorkingGiven),
		"fieldprep_slot_bytes":     p.Module.SlotBytes,
		"fieldprep_carriers":       p.FieldPrep.Report.PatchedOverlays,
		"fieldprep_callsites":      p.FieldPrep.Report.PatchedCallsites,
	}
}
