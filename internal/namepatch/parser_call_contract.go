package namepatch

// parser-copy contract is an authenticated parser-call contract, NOT a memory/ISO patch.
// It isolates the 24 copies and the six unbounded string operations so that
// a future guard implementation cannot silently cover only the surname path.
// All information is read from a caller-provided ORIGINAL EXE in host memory.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	n10ParserStart               uint32 = 0x80081190
	n10ParserEnd                 uint32 = 0x80082760
	n10ParserScratchOffset              = 0x2a4
	n10ParserScratchWorkingLimit        = 64 // observed copy argument, NOT proven allocated capacity
	n10BIOSStrncpyJAL            uint32 = 0x0c02b824
	n10BIOSStrcatJAL             uint32 = 0x0c02b840
	n10BIOSStrcpyJAL             uint32 = 0x0c02b83c
)

var n10ParserInitialSites = [...]uint32{0x80081534, 0x80081e6c}
var n10ParserDynamicSites = [...]uint32{
	0x800815cc, 0x80081674, 0x80081724, 0x800817d4, 0x8008188c,
	0x80081950, 0x80081a08, 0x80081ab8, 0x80081b70, 0x80081c28,
	0x80081ce0, 0x80081f04, 0x80081fac, 0x80082060, 0x80082110,
	0x800821c8, 0x8008228c, 0x80082344, 0x800823f8, 0x800824b4,
	0x80082570, 0x8008262c,
}
var n10ParserConcatSites = [...]uint32{0x80081d64, 0x800826b0}
var n10ParserUnboundedCopySites = [...]uint32{
	0x80081248, 0x80081254, 0x80081830, 0x800819ac, 0x8008216c, 0x800822e8,
}

// N10ParserCallsite is the exact JAL and delay instruction to preserve when
// later routing calls to a verified, resident MIPS helper. It is NOT a patch.
type N10ParserCallsite struct {
	PC        uint32 `json:"pc"`
	Kind      string `json:"kind"`
	JAL       uint32 `json:"jal"`
	DelaySlot uint32 `json:"delay_slot"`
}

type N10ParserContract struct {
	OriginalSHA256              string              `json:"original_sha256"`
	InitialCopies               int                 `json:"initial_copies"`
	DynamicCopies               int                 `json:"dynamic_copies"`
	ConcatCalls                 int                 `json:"concat_calls"`
	UnboundedCopies             int                 `json:"unbounded_copies"`
	AllDynamicSuffixesIdentical bool                `json:"all_dynamic_suffixes_identical"`
	ScratchObservedCopyBytes    int                 `json:"scratch_observed_copy_bytes"`
	Sites                       []N10ParserCallsite `json:"sites"`
	PositiveLengthProven        bool                `json:"positive_length_proven"`
	NULTerminationProven        bool                `json:"nul_termination_proven"`
	AllocationProven            bool                `json:"allocation_proven"`
	RuntimeGuardImplemented     bool                `json:"runtime_guard_implemented"`
	SafeToPatch                 bool                `json:"safe_to_patch"`
}

// InspectN10ParserContract rejects anything except the authenticated retail
// preimage and complete expected instruction inventory. Exact signatures are
// stronger than a generic JAL scan: each dynamic copy has the same -4/+4
// instructions, including its unchanged MIPS delay slot.
func InspectN10ParserContract(retail []byte) (N10ParserContract, error) {
	fail := func(format string, args ...any) (N10ParserContract, error) {
		return N10ParserContract{}, fmt.Errorf("N10 parser-copy contract parser contract: "+format, args...)
	}
	digest := sha256.Sum256(retail)
	if fmt.Sprintf("%x", digest) != n10Phase2ImageSHA[EXE] {
		return fail("original EXE SHA mismatch")
	}
	get := func(pc uint32) uint32 { return binary.LittleEndian.Uint32(retail[int(pc-Base):]) }
	if n10ParserStart < Base || int(n10ParserEnd-Base) > len(retail) {
		return fail("parser range outside original")
	}
	if get(n10ParserStart) != 0x27bdfd08 {
		return fail("760-byte parser frame changed")
	}
	if get(0x800ae090) != 0x240a00a0 || get(0x800ae094) != 0x01400008 || get(0x800ae098) != 0x2409001a {
		return fail("BIOS A0 strncpy thunk signature changed")
	}
	wants := make(map[uint32]string, 34)
	for _, pc := range n10ParserInitialSites {
		wants[pc] = "initial_strncpy"
	}
	for _, pc := range n10ParserDynamicSites {
		wants[pc] = "dynamic_strncpy"
	}
	for _, pc := range n10ParserConcatSites {
		wants[pc] = "strcat"
	}
	for _, pc := range n10ParserUnboundedCopySites {
		wants[pc] = "strcpy"
	}
	report := N10ParserContract{
		OriginalSHA256:              fmt.Sprintf("%x", digest),
		ScratchObservedCopyBytes:    n10ParserScratchWorkingLimit,
		AllDynamicSuffixesIdentical: true,
		Sites:                       make([]N10ParserCallsite, 0, len(wants)),
	}
	for pc := n10ParserStart; pc < n10ParserEnd; pc += 4 {
		word := get(pc)
		if word != n10BIOSStrncpyJAL && word != n10BIOSStrcatJAL && word != n10BIOSStrcpyJAL {
			continue
		}
		kind, ok := wants[pc]
		if !ok {
			return fail("unexpected string call at %#x", pc)
		}
		delete(wants, pc)
		switch kind {
		case "initial_strncpy":
			if word != n10BIOSStrncpyJAL || get(pc-4) != 0x27a402a4 || get(pc+4) != 0x24060040 {
				return fail("initial strncpy signature mismatch at %#x", pc)
			}
			report.InitialCopies++
		case "dynamic_strncpy":
			if word != n10BIOSStrncpyJAL || get(pc-4) != 0x24c60040 || get(pc+4) != 0x02302021 {
				return fail("dynamic strncpy/count/delay signature mismatch at %#x", pc)
			}
			report.DynamicCopies++
		case "strcat":
			if word != n10BIOSStrcatJAL {
				return fail("strcat signature mismatch at %#x", pc)
			}
			report.ConcatCalls++
		case "strcpy":
			if word != n10BIOSStrcpyJAL {
				return fail("strcpy signature mismatch at %#x", pc)
			}
			report.UnboundedCopies++
		}
		report.Sites = append(report.Sites, N10ParserCallsite{PC: pc, Kind: kind, JAL: word, DelaySlot: get(pc + 4)})
	}
	if len(wants) != 0 || report.InitialCopies != 2 || report.DynamicCopies != 22 || report.ConcatCalls != 2 || report.UnboundedCopies != 6 || len(report.Sites) != 32 {
		return fail("string callsite inventory incomplete: missing %d (got %+v)", len(wants), report)
	}
	return report, nil
}

// CheckStagedN10ParserPreimage ensures a caller-supplied translated/renderer
// revision has NOT silently replaced any parser instruction in the contract.
// A matching caller-provided SHA is insufficient for this cross-image check.
// This checks the 32 string operations, the preceding count/destination
// instruction, their MIPS delay slots and the parser frame entry.
func CheckStagedN10ParserPreimage(retail, staged []byte, contract N10ParserContract) error {
	if len(retail) != len(staged) || len(contract.Sites) != 32 {
		return fmt.Errorf("N10 parser staged preimage: wrong image size or incomplete contract")
	}
	checkWord := func(pc uint32) error {
		at := int(pc - Base)
		if at < 0 || at+4 > len(retail) || at+4 > len(staged) {
			return fmt.Errorf("parser word %#x outside source", pc)
		}
		if binary.LittleEndian.Uint32(retail[at:]) != binary.LittleEndian.Uint32(staged[at:]) {
			return fmt.Errorf("N10 parser instruction changed at %#x", pc)
		}
		return nil
	}
	if err := checkWord(n10ParserStart); err != nil {
		return err
	}
	for _, site := range contract.Sites {
		for _, pc := range []uint32{site.PC - 4, site.PC, site.PC + 4} {
			if err := checkWord(pc); err != nil {
				return err
			}
		}
	}
	return nil
}

// N10ParserReferenceScratch is a HOST-only conservative safety model for an
// eventual *new* parser guard. It never modifies the caller's 64-byte scratch
// on rejection and does not assert that 64 bytes is a real engine allocation.
// A real MIPS implementation must additionally prove source access, stack
// ownership, parser state accounting and the six unrelated strcpy destinations.
type N10ParserReferenceScratch struct {
	Bytes [n10ParserScratchWorkingLimit]byte
}

// Copy models bounded strncpy when the source contains NUL within the claimed
// count. Request==64 is allowed only if the NUL is inside the 64 bytes. It
// preserves the original scratch on failure, including for negative/overflowed
// counts, invalid offsets and unterminated source strings.
func (s *N10ParserReferenceScratch) Copy(offset int, source []byte, requested int) error {
	if offset < 0 || offset >= len(s.Bytes) || requested <= 0 || requested > len(s.Bytes)-offset {
		return fmt.Errorf("unsafe parser copy offset=%d count=%d", offset, requested)
	}
	term := -1
	for i := 0; i < requested && i < len(source); i++ {
		if source[i] == 0 {
			term = i
			break
		}
	}
	if term < 0 {
		return fmt.Errorf("parser source not terminated within bounded count")
	}
	next := s.Bytes
	copy(next[offset:offset+term], source[:term])
	next[offset+term] = 0
	// Model strncpy's zero-padding without allowing padding beyond 64 bytes.
	for i := offset + term + 1; i < offset+requested; i++ {
		next[i] = 0
	}
	s.Bytes = next
	return nil
}

// Append models the two strcat paths. The destination and entire append
// source must contain NUL within the known 64-byte window; otherwise reject
// atomically. It is deliberately not a C/BIOS emulator.
func (s *N10ParserReferenceScratch) Append(source []byte) error {
	destTerm, sourceTerm := -1, -1
	for i, v := range s.Bytes {
		if v == 0 {
			destTerm = i
			break
		}
	}
	for i, v := range source {
		if i >= len(s.Bytes) {
			break
		}
		if v == 0 {
			sourceTerm = i
			break
		}
	}
	if destTerm < 0 || sourceTerm < 0 || destTerm+sourceTerm >= len(s.Bytes) {
		return fmt.Errorf("unsafe parser strcat bounds/termination")
	}
	next := s.Bytes
	copy(next[destTerm:], source[:sourceTerm])
	next[destTerm+sourceTerm] = 0
	s.Bytes = next
	return nil
}
