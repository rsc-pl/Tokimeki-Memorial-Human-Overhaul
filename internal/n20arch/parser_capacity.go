package n20arch

// parser capacity — restore the original parser's 512-byte script input capacity.
// parser guard/parser unwind mistakenly apply the preceding 8-byte fixed-token limit to the
// second strcpy at 0x80081254 (destination sp+0x8c). In the authenticated
// retail parser, the next separate buffer begins at sp+0x28c, leaving
// precisely 0x200 bytes. Do not rewrite any other guard or guest memory.
// This is OFFLINE ONLY and cannot prove N10/N20 runtime RAM ownership.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	nametables "tokimemo/internal/namepatch"
)

const (
	parserInputInputCopyCall    uint32 = 0x80081254
	parserInputInputBufferStart uint32 = 0x8c
	parserInputNextBufferStart  uint32 = 0x28c
	parserInputInputCapacity    uint32 = parserInputNextBufferStart - parserInputInputBufferStart
)

type ParserCapacityCandidate struct {
	ParserUnwindCandidate
	CapacityBytes uint32
	SafeToPatch   bool
	RuntimePass   bool
}

func parserInputInputCapacityProgram(retail []byte) (parserGuardProgram, uint32, error) {
	// These instructions are protected by the original SHA contract in the
	// parent planner; also pin the exact three buffer boundaries here.
	check := map[uint32]uint32{
		0x80081250: 0x27a4008c, // strcpy destination sp+0x8c
		0x80081420: 0x27b2028c, // independent 24-byte token buffer
		0x80081530: 0x27a402a4, // separate 64-byte render scratch
	}
	for pc, want := range check {
		off := int(pc - Base)
		if off < 0 || off+4 > len(retail) || binary.LittleEndian.Uint32(retail[off:]) != want {
			return parserGuardProgram{}, 0, fmt.Errorf("parser capacity parser buffer instruction mismatch at %#x", pc)
		}
	}
	if parserInputInputCapacity != 512 {
		return parserGuardProgram{}, 0, fmt.Errorf("parser capacity input layout mismatch")
	}
	prog, _, err := parserExitGuardExitGuardProgram(retail)
	if err != nil {
		return parserGuardProgram{}, 0, err
	}
	// parser guard emitted two identical 8-byte budgets: for sp+132, then sp+140.
	// Only the second one is incorrect. Require exactly two occurrences of
	// this instruction preceded by J to the common copy gate.
	eight := words(0x24080008)
	found := []int{}
	for at := 0; at+4 <= len(prog.code); at += 4 {
		if bytes.Equal(prog.code[at:at+4], eight) {
			found = append(found, at)
		}
	}
	if len(found) != 2 || found[0] < 4 || found[1] < 4 || binary.LittleEndian.Uint32(prog.code[found[0]-4:]) != binary.LittleEndian.Uint32(prog.code[found[1]-4:]) {
		return parserGuardProgram{}, 0, fmt.Errorf("parser capacity copy-limit byte pattern changed: %+v", found)
	}
	prog.code = bytes.Clone(prog.code)
	binary.LittleEndian.PutUint32(prog.code[found[1]:], 0x24080200) // addiu t0,zero,512
	return prog, parserGuardParserGuardRAM + uint32(found[1]), nil
}

// PlanParserInputCapacityOffline changes exactly one machine word after
// parser unwind, keeping all 32 original JALs, N10 long-name data and N20 routes.
func PlanParserInputCapacityOffline(retail []byte, overlays map[string][]byte, in nametables.N10OfflineTransaction) (ParserCapacityCandidate, error) {
	var zero ParserCapacityCandidate
	previous, err := PlanParserUnwindOffline(retail, overlays, in)
	if err != nil {
		return zero, err
	}
	old, _, err := parserExitGuardExitGuardProgram(retail)
	if err != nil {
		return zero, err
	}
	newer, limitPC, err := parserInputInputCapacityProgram(retail)
	if err != nil {
		return zero, err
	}
	oldAt := int(parserGuardParserGuardRAM - Base)
	ex := bytes.Clone(previous.EnglishRendererEXE)
	if !bytes.Equal(ex[oldAt:oldAt+len(old.code)], old.code) {
		return zero, fmt.Errorf("parser capacity modified parser unwind code preimage")
	}
	if len(old.code) != len(newer.code) || len(newer.code) != 328 {
		return zero, fmt.Errorf("parser capacity unexpected guard program size")
	}
	copy(ex[oldAt:oldAt+len(newer.code)], newer.code)
	wordAt := int(limitPC - Base)
	for i := range previous.EnglishRendererEXE {
		if previous.EnglishRendererEXE[i] != ex[i] && (i < wordAt || i >= wordAt+4) {
			return zero, fmt.Errorf("parser capacity out of scope byte at %#x", i)
		}
	}
	previous.EnglishRendererEXE = ex
	return ParserCapacityCandidate{ParserUnwindCandidate: previous, CapacityBytes: parserInputInputCapacity, SafeToPatch: false, RuntimePass: false}, nil
}
