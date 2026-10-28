package n20arch

// parser unwind (OFFLINE ONLY): do not resume the retail parser after a rejected
// parser guard copy. The original parser itself has an authenticated early exit:
// at 0x8008123c it branches to 0x80082734 with v0=0 in its delay slot.
// Reuse exactly that epilogue and the parser's own saved $ra/$s-registers.
// This does not prove buffer capacities, source validity or runtime RAM
// ownership. No runnable disc image is authorized.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	nametables "tokimemo/internal/namepatch"
)

const (
	parserExitGuardOriginalEarlyBranch uint32 = 0x8008123c
	parserExitGuardOriginalEpilogue    uint32 = 0x80082734
	parserExitGuardOriginalReturn      uint32 = 0x8008275c
)

type ParserUnwindCandidate struct {
	ParserGuardCandidate
	RejectBranchPC uint32
	SafeToPatch    bool
	RuntimePass    bool
}

func parserExitGuardExitGuardProgram(retail []byte) (parserGuardProgram, uint32, error) {
	var bad parserGuardProgram
	get := func(pc uint32) (uint32, error) {
		off := int(pc - Base)
		if off < 0 || off+4 > len(retail) {
			return 0, fmt.Errorf("parser unwind original instruction outside retail EXE at %#x", pc)
		}
		return binary.LittleEndian.Uint32(retail[off:]), nil
	}
	branch, err := get(parserExitGuardOriginalEarlyBranch)
	if err != nil {
		return bad, 0, err
	}
	delay, err := get(parserExitGuardOriginalEarlyBranch + 4)
	if err != nil {
		return bad, 0, err
	}
	// Original unconditional branch with zero result; check the actual target.
	target := parserExitGuardOriginalEarlyBranch + 4 + uint32(int32(int16(branch&0xffff))<<2)
	if branch != 0x1000053d || delay != 0x00001025 || target != parserExitGuardOriginalEpilogue {
		return bad, 0, fmt.Errorf("parser unwind original zero-result early-exit signature mismatch")
	}
	for pc, expected := range map[uint32]uint32{
		0x80081190:            0x27bdfd08, // 760-byte frame
		0x80081198:            0xafbf0044, // saved outer return address
		parserExitGuardOriginalEpilogue:   0x8fbf0044,
		parserExitGuardOriginalReturn:     0x03e00008, // jr ra
		parserExitGuardOriginalReturn + 4: 0x27bd02f8, // restore frame in delay slot
	} {
		w, err := get(pc)
		if err != nil || w != expected {
			return bad, 0, fmt.Errorf("parser unwind original epilogue signature mismatch at %#x", pc)
		}
	}
	program, err := parserGuardBuildParserGuards()
	if err != nil {
		return bad, 0, err
	}
	failPattern := words(0x03e00008, 0x00801021) // parser guard: jr ra; move v0,a0
	i := bytes.Index(program.code, failPattern)
	if i < 0 || bytes.Index(program.code[i+1:], failPattern) >= 0 {
		return bad, 0, fmt.Errorf("parser unwind expected exactly one parser guard failure return")
	}
	program.code = bytes.Clone(program.code)
	binary.LittleEndian.PutUint32(program.code[i:], jWord(parserExitGuardOriginalEpilogue))
	binary.LittleEndian.PutUint32(program.code[i+4:], 0x00001025) // v0=0
	return program, parserGuardParserGuardRAM + uint32(i), nil
}

func PlanParserUnwindOffline(retail []byte, overlays map[string][]byte, in nametables.N10OfflineTransaction) (ParserUnwindCandidate, error) {
	var zero ParserUnwindCandidate
	prior, err := PlanGuardedParserOffline(retail, overlays, in)
	if err != nil {
		return zero, err
	}
	program, failPC, err := parserExitGuardExitGuardProgram(retail)
	if err != nil {
		return zero, err
	}
	previousProgram, err := parserGuardBuildParserGuards()
	if err != nil {
		return zero, err
	}
	ex := bytes.Clone(prior.EnglishRendererEXE)
	off := int(parserGuardParserGuardRAM - Base)
	if !bytes.Equal(ex[off:off+len(previousProgram.code)], previousProgram.code) {
		return zero, fmt.Errorf("parser unwind parser guard guard preimage changed")
	}
	copy(ex[off:off+len(program.code)], program.code)
	prior.EnglishRendererEXE = ex
	return ParserUnwindCandidate{
		ParserGuardCandidate: prior, RejectBranchPC: failPC,
		SafeToPatch: false, RuntimePass: false,
	}, nil
}
