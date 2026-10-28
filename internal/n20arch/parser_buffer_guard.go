package n20arch

// parser guard parser-copy prototype: R3000A program with three BIOS-call entrypoints.
// It is NOT a game-boot authorization. It enforces an observed 64-byte scratch
// boundary and separate small parser buffers, but parser failure propagation,
// source address lifetime and renderer reservation ownership remain unproven.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	nametables "tokimemo/internal/namepatch"
)

const parserGuardParserGuardRAM uint32 = ShortHookSpareRAM + ShortHookSpareBytes
const parserGuardParserGuardEnd uint32 = 0x80044700

type ParserGuardCandidate struct {
	CombinedOfflineCandidate
	PatchedCalls int
	GuardBytes   int
	SafeToPatch  bool
	RuntimePass  bool
}

type parserGuardProgram struct {
	code    []byte
	entries map[string]uint32
}

func parserGuardBuildParserGuards() (parserGuardProgram, error) {
	a := &miniAsm{labels: map[string]int{}}
	// t0 scan budget; t1 cursor; t2 char; t3 expected destination;
	// t4 comparison; t5 end; t6 remaining; t7 BIOS dispatch. No s-reg use.
	a.label("strncpy")
	a.w(0x27ab02a4) // addiu t3,sp,676
	a.w(0x008b602b) // sltu t4,a0,t3
	a.b(5, 12, 0, "fail")
	a.w(0x256d0040) // bne t4,zero,fail; addiu t5,t3,64
	a.w(0x008d602b) // sltu t4,a0,t5
	a.b(4, 12, 0, "fail")
	a.w(0x01a47023) // beq t4,zero,fail; subu t6,t5,a0
	a.b(4, 6, 0, "fail")
	a.w(0)          // beq a2,zero,fail
	a.w(0x01c6602b) // sltu t4,t6,a2
	a.b(5, 12, 0, "fail")
	a.w(0x00c04021) // bne t4,zero,fail; addu t0,a2,zero
	a.w(0x3c0f800a)
	a.w(0x35efE090) // t7 = BIOS strncpy
	a.j("scan")
	a.w(0)

	a.label("strcat")
	a.w(0x27ab02a4) // t3=sp+676
	a.b(5, 4, 11, "fail")
	a.w(0x256d0040) // bne a0,t3,fail; t5=t3+64
	a.w(0x00804821) // addu t1,a0,zero
	a.label("dstscan")
	a.w(0x912c0000) // lbu t4,0(t1)
	a.w(0)          // load delay
	a.b(4, 12, 0, "dstok")
	a.w(0x25290001) // beq t4,zero,dstok; t1++
	a.w(0x012d602b) // sltu t4,t1,t5
	a.b(5, 12, 0, "dstscan")
	a.w(0) // bne t4,zero,dstscan
	a.j("fail")
	a.w(0)
	a.label("dstok")
	a.w(0x01a94023) // subu t0,t5,t1
	a.w(0x25080001) // dstscan increments in branch-delay: restore NUL budget
	a.w(0x3c0f800a)
	a.w(0x35efE100) // BIOS strcat
	a.j("scan")
	a.w(0)

	a.label("strcpy")
	// return PC discriminates 2 local preamble buffers and 4 branch tokens.
	a.w(0x3c0b8008)
	a.w(0x256b1250) // t3=0x80081250
	a.b(4, 31, 11, "first")
	a.w(0)
	a.w(0x256b000c) // t3+=12 -> 0x8008125c
	a.b(4, 31, 11, "second")
	a.w(0)
	for _, delta := range []uint32{0x5dc, 0x17c, 0x7c0, 0x17c} {
		a.w(0x256b0000 | delta)
		a.b(4, 31, 11, "small")
		a.w(0)
	}
	a.j("fail")
	a.w(0)
	a.label("first")
	a.w(0x27ab0084) // t3=sp+132
	a.j("copypre")
	a.w(0x24080008) // branch delay sets 8-byte limit
	a.label("second")
	a.w(0x27ab008c) // t3=sp+140
	a.j("copypre")
	a.w(0x24080008) // branch delay sets 8-byte limit
	a.label("small")
	a.w(0x27ab028c) // t3=sp+652
	a.w(0x24080018) // t0=24 until scratch at sp+676
	a.label("copypre")
	a.b(5, 4, 11, "fail")
	a.w(0)
	a.w(0x3c0f800a)
	a.w(0x35efE0F0) // BIOS strcpy
	a.j("scan")
	a.w(0)

	a.label("scan")
	a.w(0x00a04821) // t1 = a1
	a.label("srcloop")
	a.w(0x912a0000) // lbu t2,0(t1)
	a.w(0)          // R3000A load delay
	a.b(4, 10, 0, "success")
	a.w(0x25290001) // if NUL -> success
	a.w(0x2508ffff) // budget--
	a.b(5, 8, 0, "srcloop")
	a.w(0)
	a.label("fail")
	a.w(0x03e00008)
	a.w(0x00801021) // jr ra; v0=a0 in delay slot
	a.label("success")
	a.w(0x01e00008)
	a.w(0) // jr t7 (no new link register)
	a.resolve()
	a.resolveJLabels(parserGuardParserGuardRAM)
	start := parserGuardParserGuardRAM
	out := parserGuardProgram{code: words(a.words...), entries: map[string]uint32{
		"initial_strncpy": start + uint32(a.labels["strncpy"]*4),
		"dynamic_strncpy": start + uint32(a.labels["strncpy"]*4),
		"strcat":          start + uint32(a.labels["strcat"]*4),
		"strcpy":          start + uint32(a.labels["strcpy"]*4),
	}}
	if start+uint32(len(out.code)) > parserGuardParserGuardEnd {
		return parserGuardProgram{}, fmt.Errorf("parser guard guard program %d B does not fit verified renderer reservation %d B", len(out.code), parserGuardParserGuardEnd-start)
	}
	return out, nil
}

// PlanGuardedParserOffline only stages a CPU-testable implementation in
// host memory; it does not change the parser relocation public runtime safety gate.
func PlanGuardedParserOffline(retail []byte, overlays map[string][]byte, in nametables.N10OfflineTransaction) (ParserGuardCandidate, error) {
	var zero ParserGuardCandidate
	base, err := PlanN10N20Offline(retail, overlays, in)
	if err != nil {
		return zero, err
	}
	prog, err := parserGuardBuildParserGuards()
	if err != nil {
		return zero, err
	}
	contract, err := nametables.InspectN10ParserContract(retail)
	if err != nil {
		return zero, err
	}
	ex := bytes.Clone(base.EnglishRendererEXE)
	start := int(parserGuardParserGuardRAM - Base)
	if !bytes.Equal(ex[start:start+len(prog.code)], make([]byte, len(prog.code))) {
		return zero, fmt.Errorf("parser guard parser guard reservation occupied")
	}
	copy(ex[start:], prog.code)
	for _, site := range contract.Sites {
		off := int(site.PC - Base)
		if binary.LittleEndian.Uint32(ex[off:]) != site.JAL || binary.LittleEndian.Uint32(ex[off+4:]) != site.DelaySlot {
			return zero, fmt.Errorf("parser guard parser instruction mismatch %#x", site.PC)
		}
		binary.LittleEndian.PutUint32(ex[off:], jalWord(prog.entries[site.Kind]))
	}
	base.EnglishRendererEXE = ex
	return ParserGuardCandidate{CombinedOfflineCandidate: base, PatchedCalls: len(contract.Sites), GuardBytes: len(prog.code), SafeToPatch: false, RuntimePass: false}, nil
}
