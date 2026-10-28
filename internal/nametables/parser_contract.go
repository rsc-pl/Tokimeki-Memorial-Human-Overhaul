// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	nameParserStart uint32 = 0x80081190
	nameParserEnd   uint32 = 0x80082760

	nameParserScratchWorkingLimit        = 64
	nameBIOSStrncpyJAL            uint32 = 0x0c02b824
	nameBIOSStrcatJAL             uint32 = 0x0c02b840
	nameBIOSStrcpyJAL             uint32 = 0x0c02b83c
)

var nameParserInitialSites = [...]uint32{0x80081534, 0x80081e6c}
var nameParserDynamicSites = [...]uint32{
	0x800815cc, 0x80081674, 0x80081724, 0x800817d4, 0x8008188c,
	0x80081950, 0x80081a08, 0x80081ab8, 0x80081b70, 0x80081c28,
	0x80081ce0, 0x80081f04, 0x80081fac, 0x80082060, 0x80082110,
	0x800821c8, 0x8008228c, 0x80082344, 0x800823f8, 0x800824b4,
	0x80082570, 0x8008262c,
}
var nameParserConcatSites = [...]uint32{0x80081d64, 0x800826b0}
var nameParserUnboundedCopySites = [...]uint32{
	0x80081248, 0x80081254, 0x80081830, 0x800819ac, 0x8008216c, 0x800822e8,
}

type NameParserCallsite struct {
	PC        uint32 `json:"pc"`
	Kind      string `json:"kind"`
	JAL       uint32 `json:"jal"`
	DelaySlot uint32 `json:"delay_slot"`
}
type NameParserContract struct {
	OriginalSHA256              string               `json:"original_sha256"`
	InitialCopies               int                  `json:"initial_copies"`
	DynamicCopies               int                  `json:"dynamic_copies"`
	ConcatCalls                 int                  `json:"concat_calls"`
	UnboundedCopies             int                  `json:"unbounded_copies"`
	AllDynamicSuffixesIdentical bool                 `json:"all_dynamic_suffixes_identical"`
	ScratchObservedCopyBytes    int                  `json:"scratch_observed_copy_bytes"`
	Sites                       []NameParserCallsite `json:"sites"`
	PositiveLengthProven        bool                 `json:"positive_length_proven"`
	NULTerminationProven        bool                 `json:"nul_termination_proven"`
	AllocationProven            bool                 `json:"allocation_proven"`
	RuntimeGuardImplemented     bool                 `json:"runtime_guard_implemented"`
	SafeToPatch                 bool                 `json:"safe_to_patch"`
}

func InspectNameParserContract(retail []byte) (NameParserContract, error) {
	fail := func(format string, args ...any) (NameParserContract, error) {
		return NameParserContract{}, fmt.Errorf("Name parser contract parser contract: "+format, args...)
	}
	digest := sha256.Sum256(retail)
	if fmt.Sprintf("%x", digest) != namePhase2ImageSHA[EXE] {
		return fail("original EXE SHA mismatch")
	}
	get := func(pc uint32) uint32 { return binary.LittleEndian.Uint32(retail[int(pc-Base):]) }
	if nameParserStart < Base || int(nameParserEnd-Base) > len(retail) {
		return fail("parser range outside original")
	}
	if get(nameParserStart) != 0x27bdfd08 {
		return fail("760-byte parser frame changed")
	}
	if get(0x800ae090) != 0x240a00a0 || get(0x800ae094) != 0x01400008 || get(0x800ae098) != 0x2409001a {
		return fail("BIOS A0 strncpy thunk signature changed")
	}
	wants := make(map[uint32]string, 34)
	for _, pc := range nameParserInitialSites {
		wants[pc] = "initial_strncpy"
	}
	for _, pc := range nameParserDynamicSites {
		wants[pc] = "dynamic_strncpy"
	}
	for _, pc := range nameParserConcatSites {
		wants[pc] = "strcat"
	}
	for _, pc := range nameParserUnboundedCopySites {
		wants[pc] = "strcpy"
	}
	report := NameParserContract{
		OriginalSHA256:              fmt.Sprintf("%x", digest),
		ScratchObservedCopyBytes:    nameParserScratchWorkingLimit,
		AllDynamicSuffixesIdentical: true,
		Sites:                       make([]NameParserCallsite, 0, len(wants)),
	}
	for pc := nameParserStart; pc < nameParserEnd; pc += 4 {
		word := get(pc)
		if word != nameBIOSStrncpyJAL && word != nameBIOSStrcatJAL && word != nameBIOSStrcpyJAL {
			continue
		}
		kind, ok := wants[pc]
		if !ok {
			return fail("unexpected string call at %#x", pc)
		}
		delete(wants, pc)
		switch kind {
		case "initial_strncpy":
			if word != nameBIOSStrncpyJAL || get(pc-4) != 0x27a402a4 || get(pc+4) != 0x24060040 {
				return fail("initial strncpy signature mismatch at %#x", pc)
			}
			report.InitialCopies++
		case "dynamic_strncpy":
			if word != nameBIOSStrncpyJAL || get(pc-4) != 0x24c60040 || get(pc+4) != 0x02302021 {
				return fail("dynamic strncpy/count/delay signature mismatch at %#x", pc)
			}
			report.DynamicCopies++
		case "strcat":
			if word != nameBIOSStrcatJAL {
				return fail("strcat signature mismatch at %#x", pc)
			}
			report.ConcatCalls++
		case "strcpy":
			if word != nameBIOSStrcpyJAL {
				return fail("strcpy signature mismatch at %#x", pc)
			}
			report.UnboundedCopies++
		}
		report.Sites = append(report.Sites, NameParserCallsite{PC: pc, Kind: kind, JAL: word, DelaySlot: get(pc + 4)})
	}
	if len(wants) != 0 || report.InitialCopies != 2 || report.DynamicCopies != 22 || report.ConcatCalls != 2 || report.UnboundedCopies != 6 || len(report.Sites) != 32 {
		return fail("string callsite inventory incomplete: missing %d (got %+v)", len(wants), report)
	}
	return report, nil
}

func CheckStagedNameParserPreimage(retail, staged []byte, contract NameParserContract) error {
	if len(retail) != len(staged) || len(contract.Sites) != 32 {
		return fmt.Errorf("Name parser staged preimage: wrong image size or incomplete contract")
	}
	checkWord := func(pc uint32) error {
		at := int(pc - Base)
		if at < 0 || at+4 > len(retail) || at+4 > len(staged) {
			return fmt.Errorf("parser word %#x outside source", pc)
		}
		if binary.LittleEndian.Uint32(retail[at:]) != binary.LittleEndian.Uint32(staged[at:]) {
			return fmt.Errorf("Name parser instruction changed at %#x", pc)
		}
		return nil
	}
	if err := checkWord(nameParserStart); err != nil {
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
