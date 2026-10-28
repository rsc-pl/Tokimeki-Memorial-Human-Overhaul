package n20arch

// parser copying OFFLINE: preserve the native MIPS strncpy contract at all 24 original
// callsites. parser guard-parser capacity incorrectly required a NUL within n and rejected n=0.
// Retail strncpy instead copies exactly n bytes (padding after early NUL),
// and n=0 performs no destination/source access. This guard only proves the
// destination write boundary; it does NOT prove source address validity,
// subsequent string termination or memory ownership while a scene runs.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	nametables "tokimemo/internal/namepatch"
)

type StrncpyCandidate struct {
	ParserCapacityCandidate
	RestoredCalls int
	SafeToPatch   bool
	RuntimePass   bool
}

func retailCopyPreserveRetailStrncpy(retail []byte) (parserGuardProgram, error) {
	program, _, err := parserInputInputCapacityProgram(retail)
	if err != nil {
		return parserGuardProgram{}, err
	}
	if len(program.code) != 328 {
		return parserGuardProgram{}, fmt.Errorf("parser copying unexpected parser length %d", len(program.code))
	}
	// Exactly 16 words form the shared strncpy entry. Do not disturb the
	// separately terminating strcpy/strcat source scanner, abort epilogue,
	// the 32 caller JALs, or any other executable word.
	fail, err := retailCopyFailPC(program)
	if err != nil {
		return parserGuardProgram{}, err
	}
	success := parserGuardParserGuardRAM + uint32(len(program.code)-8)
	br := func(op, rs, rt, idx, target uint32) uint32 {
		pc := parserGuardParserGuardRAM + idx*4
		delta := int32(target) - int32(pc+4)
		return op<<26 | rs<<21 | rt<<16 | uint32(uint16(delta/4))
	}
	src := []uint32{
		0x3c0f800a,              // lui t7,0x800a; original BIOS strncpy entry
		0x35efe090,              // ori t7,t7,0xe090
		br(4, 6, 0, 2, success), // beq a2,zero,success: zero-byte copy is valid
		0,
		0x27ab02a4, // t3 = sp+0x2a4
		0x008b602b, // reject destination below scratch
		br(5, 12, 0, 6, fail),
		0x256d0040, // t5 = scratch end (delay slot)
		0x008d602b, // reject destination at/after scratch end for n>0
		br(4, 12, 0, 9, fail),
		0x01a47023, // t6 = scratch end - a0 (delay slot)
		0x01c6602b, // a2 > available bytes?
		br(5, 12, 0, 12, fail),
		0,
		jWord(success), // dispatch native strncpy; no invented NUL requirement
		0,
	}
	if len(src) != 16 {
		return parserGuardProgram{}, fmt.Errorf("parser copying bad assembler prefix")
	}
	code := bytes.Clone(program.code)
	for i, w := range src {
		binary.LittleEndian.PutUint32(code[i*4:], w)
	}
	program.code = code
	return program, nil
}

func retailCopyFailPC(program parserGuardProgram) (uint32, error) {
	// parser unwind replaced the sole old jr ra; move v0,a0 failure with a two-word
	// jump to the authenticated parser epilogue. Pin its unique location.
	sig := words(jWord(parserExitGuardOriginalEpilogue), 0x00001025)
	i := bytes.Index(program.code, sig)
	if i < 64 || bytes.Index(program.code[i+1:], sig) >= 0 {
		return 0, fmt.Errorf("parser copying invalid unique early exit at %d", i)
	}
	return parserGuardParserGuardRAM + uint32(i), nil
}

func PlanStrncpySemanticsOffline(retail []byte, overlays map[string][]byte, in nametables.N10OfflineTransaction) (StrncpyCandidate, error) {
	var zero StrncpyCandidate
	prev, err := PlanParserInputCapacityOffline(retail, overlays, in)
	if err != nil {
		return zero, err
	}
	old, _, err := parserInputInputCapacityProgram(retail)
	if err != nil {
		return zero, err
	}
	replacement, err := retailCopyPreserveRetailStrncpy(retail)
	if err != nil {
		return zero, err
	}
	if len(old.code) != len(replacement.code) {
		return zero, fmt.Errorf("parser copying program expanded")
	}
	ex := bytes.Clone(prev.EnglishRendererEXE)
	off := int(parserGuardParserGuardRAM - Base)
	if !bytes.Equal(ex[off:off+len(old.code)], old.code) {
		return zero, fmt.Errorf("parser copying prior program mismatch")
	}
	if !bytes.Equal(old.code[64:], replacement.code[64:]) {
		return zero, fmt.Errorf("parser copying non-strncpy code changed")
	}
	copy(ex[off:off+64], replacement.code[:64])
	prev.EnglishRendererEXE = ex
	return StrncpyCandidate{ParserCapacityCandidate: prev, RestoredCalls: 24, SafeToPatch: false, RuntimePass: false}, nil
}
