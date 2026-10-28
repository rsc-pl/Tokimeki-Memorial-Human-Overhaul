package n20arch

// guarded copying is an OFFLINE-only candidate. The retail parser has two manual byte
// copying loops whose `sb` writes occur in MIPS JAL delay slots. The existing
// 32 string-library guards cannot intercept those stores. This variant checks
// the entire source name length against the remaining scratch capacity BEFORE
// either loop starts. It preserves the retail strlen return contract on valid
// inputs and aborts through the authenticated parser epilogue on overflow.
//
// This is a bounded source/stack correctness improvement, NOT evidence of
// runtime ownership of the N10/N20 executable pages or of all parser paths.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	nametables "tokimemo/internal/namepatch"
)

const (
	parserCopyGuardFirstLoopLengthJAL  uint32 = 0x80081578
	parserCopyGuardSecondLoopLengthJAL uint32 = 0x80081620
	parserCopyGuardNativeStrlen        uint32 = 0x800ae0e0
)

type ManualNameLoopCandidate struct {
	StrncpyCandidate
	GuardedManualLoops int
	GuardCodeBytes     int
	SafeToPatch        bool
	RuntimePass        bool
}

func parserCopyGuardCompactParserProgram() (parserGuardProgram, error) {
	a := &miniAsm{labels: map[string]int{}}
	// parser copying's exact retail strncpy ABI, including n==0 and non-NUL n-byte copies.
	a.label("strncpy")
	a.w(0x3c0f800a)
	a.w(0x35efe090)
	a.b(4, 6, 0, "success")
	a.w(0)
	a.w(0x27ab02a4)
	a.w(0x008b602b)
	a.b(5, 12, 0, "fail")
	a.w(0x256d0040)
	a.w(0x008d602b)
	a.b(4, 12, 0, "fail")
	a.w(0x01a47023)
	a.w(0x01c6602b)
	a.b(5, 12, 0, "fail")
	a.w(0)
	a.j("success")
	a.w(0)

	// Same constrained strcat destination and bounded source check as parser copying.
	a.label("strcat")
	a.w(0x27ab02a4)
	a.b(5, 4, 11, "fail")
	a.w(0x256d0040)
	a.w(0x00804821)
	a.label("dstscan")
	a.w(0x912c0000)
	a.w(0)
	a.b(4, 12, 0, "dstok")
	a.w(0x25290001)
	a.w(0x012d602b)
	a.b(5, 12, 0, "dstscan")
	a.w(0)
	a.j("fail")
	a.w(0)
	a.label("dstok")
	a.w(0x01a94023)
	a.w(0x25080001)
	a.w(0x3c0f800a)
	a.w(0x35efe100)
	a.j("scan")
	a.w(0)

	// Compact destination-role selection. Original six authenticated callsites
	// remain pinned by PlanH62; capacity follows the actual buffer pointer.
	a.label("strcpy")
	a.w(0x27ab0084) // t3 = sp + 132, original first short field
	a.b(4, 4, 11, "copy8")
	a.w(0x24080008)
	a.w(0x27ab008c) // t3 = sp + 140, original input line field
	a.b(4, 4, 11, "copy512")
	a.w(0)
	a.w(0x27ab028c) // t3 = sp + 652, original branch token buffer
	a.b(5, 4, 11, "fail")
	a.w(0x24080018)
	a.j("copypre")
	a.w(0)
	a.label("copy8")
	a.j("copypre")
	a.w(0)
	a.label("copy512")
	a.w(0x24080200)
	a.label("copypre")
	a.w(0x3c0f800a)
	a.w(0x35efe0f0)
	a.j("scan")
	a.w(0)

	// This same bounded scan is reused by strcat/strcpy and the two manual
	// strlen wrappers. It deliberately does not dereference beyond its budget.
	a.label("scan")
	a.w(0x00a04821)
	a.label("srcloop")
	a.w(0x912a0000)
	a.w(0)
	a.b(4, 10, 0, "success")
	a.w(0x25290001)
	a.w(0x2508ffff)
	a.b(5, 8, 0, "srcloop")
	a.w(0)
	a.label("fail")
	a.j("epilogue") // placeholder rewritten below, not an in-module target
	a.w(0x00001025)
	a.label("success")
	a.w(0x01e00008)
	a.w(0)

	// On entry, a0 holds source pointer (original JAL delay-slot has run),
	// s1 holds the destination of the complete manual name expansion. The
	// original byte-copy loop will write precisely strlen(source) bytes.
	a.label("checkedstrlen")
	a.w(0x27ab02a4) // t3 = scratch beginning
	a.w(0x022b602b) // sltu t4,s1,t3
	a.b(5, 12, 0, "fail")
	a.w(0x27ad02e4) // t5 = scratch end (sp+740)
	a.w(0x022d602b) // sltu t4,s1,t5
	a.b(4, 12, 0, "fail")
	a.w(0x01b14023) // t0 = end - s1
	a.w(0x00802821) // a1 = original a0, scanner input
	a.w(0x3c0f800a)
	a.w(0x35efe0e0) // native strlen, tailcalled
	a.j("scan")
	a.w(0)

	// Our handwritten epilogue is the authenticated original parser early exit.
	// Resolve only branches and local jumps, then overwrite the fail J target.
	a.label("epilogue")
	a.resolve()
	a.resolveJLabels(parserGuardParserGuardRAM)
	code := words(a.words...)
	failOff := a.labels["fail"] * 4
	binary.LittleEndian.PutUint32(code[failOff:], jWord(parserExitGuardOriginalEpilogue))
	if uint32(len(code)) > parserGuardParserGuardEnd-parserGuardParserGuardRAM {
		return parserGuardProgram{}, fmt.Errorf("guarded copying checked loops need %d B, only %d B in owned renderer reserve", len(code), parserGuardParserGuardEnd-parserGuardParserGuardRAM)
	}
	return parserGuardProgram{code: code, entries: map[string]uint32{
		"initial_strncpy": parserGuardParserGuardRAM + uint32(a.labels["strncpy"]*4),
		"dynamic_strncpy": parserGuardParserGuardRAM + uint32(a.labels["strncpy"]*4),
		"strcat":          parserGuardParserGuardRAM + uint32(a.labels["strcat"]*4),
		"strcpy":          parserGuardParserGuardRAM + uint32(a.labels["strcpy"]*4),
		"checkedstrlen":   parserGuardParserGuardRAM + uint32(a.labels["checkedstrlen"]*4),
	}}, nil
}

func PlanManualNameLoopsOffline(retail []byte, overlays map[string][]byte, in nametables.N10OfflineTransaction) (ManualNameLoopCandidate, error) {
	var zero ManualNameLoopCandidate
	prev, err := PlanStrncpySemanticsOffline(retail, overlays, in)
	if err != nil {
		return zero, err
	}
	old, err := retailCopyPreserveRetailStrncpy(retail)
	if err != nil {
		return zero, err
	}
	newProg, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return zero, err
	}
	if len(old.code) != 328 || len(newProg.code) > len(old.code) {
		return zero, fmt.Errorf("guarded copying invalid patch space old=%d new=%d", len(old.code), len(newProg.code))
	}
	ex := bytes.Clone(prev.EnglishRendererEXE)
	at := int(parserGuardParserGuardRAM - Base)
	if !bytes.Equal(ex[at:at+len(old.code)], old.code) {
		return zero, fmt.Errorf("guarded copying parser copying preimage mismatch")
	}
	// Protect both JAL delay slots and the source provenance; originals
	// are exactly two retail strlen calls from the two manual name loops.
	for _, pc := range []uint32{parserCopyGuardFirstLoopLengthJAL, parserCopyGuardSecondLoopLengthJAL} {
		off := int(pc - Base)
		if binary.LittleEndian.Uint32(ex[off:]) != jalWord(parserCopyGuardNativeStrlen) || !bytes.Equal(ex[off+4:off+8], retail[off+4:off+8]) {
			return zero, fmt.Errorf("guarded copying source loop JAL/delay mismatch at %#x", pc)
		}
	}
	// Same owned reservation only: no fresh RAM, no untouched overlays.
	clear(ex[at : at+len(old.code)])
	copy(ex[at:], newProg.code)
	// All 32 old BIOS guard callsites are routed to the rebuilt compact entry;
	// the two manual strlen callers route to the new front-of-loop guard.
	contract, err := nametables.InspectN10ParserContract(retail)
	if err != nil {
		return zero, err
	}
	for _, site := range contract.Sites {
		off := int(site.PC - Base)
		if binary.LittleEndian.Uint32(ex[off:]) != jalWord(old.entries[site.Kind]) {
			return zero, fmt.Errorf("guarded copying existing JAL mismatch %#x", site.PC)
		}
		binary.LittleEndian.PutUint32(ex[off:], jalWord(newProg.entries[site.Kind]))
	}
	for _, pc := range []uint32{parserCopyGuardFirstLoopLengthJAL, parserCopyGuardSecondLoopLengthJAL} {
		binary.LittleEndian.PutUint32(ex[int(pc-Base):], jalWord(newProg.entries["checkedstrlen"]))
	}
	prev.EnglishRendererEXE = ex
	return ManualNameLoopCandidate{StrncpyCandidate: prev, GuardedManualLoops: 2, GuardCodeBytes: len(newProg.code), SafeToPatch: false, RuntimePass: false}, nil
}
