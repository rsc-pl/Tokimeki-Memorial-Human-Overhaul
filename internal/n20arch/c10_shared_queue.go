package n20arch

// Cover the renderer terminal queue exits and two additional authenticated
// complete-line queue exits in the same EXE renderer. This remains an explicit
// private, runtime-unverified experiment. The same cold-boot safe EXE gate and
// resident adapter are reused: NO new resident/renderer memory is allocated.
// Both sites supply a3=sp+0x2a4 and independently supply their fifth stack arg.
import (
	"encoding/binary"
	"fmt"
)

var c10AdditionalLineQueueCalls = [...]struct{ PC, Delay uint32 }{
	{0x80081DA8, 0xAFAF0010},
	{0x80081DC8, 0xAFB80010},
}

func PlanC10SharedQueueOffline(exe []byte, originals map[string][]byte) (C10DistributedCandidate, error) {
	d, err := PlanC10TerminalDistributedOffline(exe, originals)
	if err != nil {
		return d, err
	}
	if len(d.AddedEXEWords) != 5 {
		return C10DistributedCandidate{}, fmt.Errorf("expected five EXE queue redirects")
	}
	for _, s := range c10AdditionalLineQueueCalls {
		at := int(s.PC - 0x80040800)
		if at < 0 || at+8 > len(exe) ||
			binary.LittleEndian.Uint32(exe[at:]) != jalWord(optionQueueRetail) ||
			binary.LittleEndian.Uint32(d.EnglishEXE[at:]) != jalWord(optionQueueRetail) ||
			binary.LittleEndian.Uint32(exe[at+4:]) != s.Delay ||
			binary.LittleEndian.Uint32(d.EnglishEXE[at+4:]) != s.Delay {
			return C10DistributedCandidate{}, fmt.Errorf("original queue or delay-slot drift at %08x", s.PC)
		}
		newWord := jalWord(C10EXETerminalGate)
		binary.LittleEndian.PutUint32(d.EnglishEXE[at:], newWord)
		d.AddedEXEWords = append(d.AddedEXEWords, n20RelocWord{
			Owner: "SLPM_86.053", PC: s.PC, Old: jalWord(optionQueueRetail), New: newWord,
			Kind: "c10_guarded_general_line_queue",
			Role: "EXE whole-line queue: reuse cold-boot-safe terminal gate; original O32 fifth argument retained",
		})
	}
	if len(d.AddedEXEWords) != 7 || d.SafeToPatch || d.RuntimePass {
		return C10DistributedCandidate{}, fmt.Errorf("renderer queue safety/accounting drift")
	}
	return d, nil
}
