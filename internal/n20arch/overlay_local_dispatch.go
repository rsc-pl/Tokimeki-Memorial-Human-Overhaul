package n20arch

// overlay dispatch OFFLINE ONLY: verify the complete overlay-local 3800-byte C10 body
// before dispatching through the permanent EXE F1 or terminal queue gates.
// overlay allocation checked only magic and declared length. A live overlay write can leave
// those 8 bytes intact while corrupting executable instructions. This guard
// refuses simple body corruption, but it does NOT establish overlay ownership
// or protect against writes concurrent with verification/execution.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	OverlayDispatchBlocked       = true
	OverlayDispatchBlockedReason = "overlay dispatch OFFLINE ONLY: bounded XOR integrity checks detect stale/corrupt overlay-local C10 body, but 22/26 coverage, concurrent CPU/DMA/IRQ mutations, overlay slot lifetime and gameplay remain UNVERIFIED; safe_to_patch=false, runtime_pass=false."
	overlayDispatchF1Stub                    = C10EXELoaderGate
	overlayDispatchTermStub                  = C10EXELoaderGate + 12
	overlayDispatchVerifier                  = C10EXELoaderGate + 24
)

type OverlayDispatchIntegrityCandidate struct {
	OverlayLocalCandidate
	BodyIntegrityGuarded bool
}

// An entire 180-byte existing EXE renderer reservation is used: 52-byte F1
// gate + two 12-byte paths + 64-byte shared integrity verifier + 40-byte
// terminal gate. No additional executable destination or RAM reservation.
// t6/t7 carry the target/retail addresses; t0..t4 are verifier scratch.
// a0-a3, v0/v1, s0-s7, ra, sp are unmodified. This cannot prevent races.
func buildIntegrityGates(f1, terminal []byte) ([]byte, error) {
	if len(f1) != 52 || len(terminal) != 40 || overlayDispatchVerifier+64 != C10EXETerminalGate {
		return nil, fmt.Errorf("overlay dispatch renderer gate geometry drift")
	}
	// Explicitly validate the actual overlay allocation local guard sources before patching.
	f1Want, err := BuildC10EXEGuardF1()
	if err != nil {
		return nil, err
	}
	termWant, err := BuildC10EXETerminalGate()
	if err != nil {
		return nil, err
	}
	f1Want, err = residentRelocationRelocateGuard(f1Want, C10F1Entry, OverlayBase+C10ResidentGuardBytes)
	if err != nil {
		return nil, err
	}
	termWant, err = residentRelocationRelocateGuard(termWant, C10QueueAdapterEntry, OverlayBase+16)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(f1, f1Want) || !bytes.Equal(terminal, termWant) {
		return nil, fmt.Errorf("overlay dispatch pre-existing overlay allocation gate mismatch")
	}
	out := make([]byte, C10EXEGuardTailBytes)
	copy(out, f1)
	copy(out[C10EXETerminalGate-C10EXEGuardF1:], terminal)
	word := func(i int, w uint32) { binary.LittleEndian.PutUint32(out[i:i+4], w) }
	f1entry := OverlayBase + C10ResidentGuardBytes
	terminalentry := OverlayBase + 16
	// F1 delay slots were NOP. Earlier header/length failure still jumps
	// straight to original retail, before any checksum scan.
	word(32, olLUI(14, f1entry))
	word(36, jWord(overlayDispatchF1Stub))
	word(40, olLUI(15, OLOriginalSpeaker))
	termOff := int(C10EXETerminalGate - C10EXEGuardF1)
	word(termOff+20, olLUI(14, terminalentry))
	word(termOff+24, jWord(overlayDispatchTermStub))
	word(termOff+28, olLUI(15, optionQueueRetail))
	stub := func(at int, target, retail uint32) {
		word(at, olORI(14, 14, target&0xffff))
		word(at+4, jWord(overlayDispatchVerifier))
		word(at+8, olORI(15, 15, retail&0xffff))
	}
	stub(int(overlayDispatchF1Stub-C10EXEGuardF1), f1entry, OLOriginalSpeaker)
	stub(int(overlayDispatchTermStub-C10EXEGuardF1), terminalentry, optionQueueRetail)
	// 16 instructions. A single 950-word bounded scan, not a full memory
	// owner proof. Read expected XOR from relocated overlay allocation header +12, preserve
	// the MIPS-I load delay. XOR is a corruption sentinel, not cryptographic.
	base := int(overlayDispatchVerifier - C10EXEGuardF1)
	words16 := []uint32{
		olLUI(8, 0x80160000),
		olADDIU(8, 8, -256), // t0=OverlayBase+256=0x8015FF00
		olLW(12, 8, -244),   // header XOR at image +12
		olADDIU(9, 0, C10ResidentBodyBytes/4),
		olAddu(10, 0, 0),
		olLW(11, 8, 0),
		olADDIU(8, 8, 4), // MIPS-I load delay
		olADDIU(9, 9, -1),
		olIType(5, 9, 0, uint16(0xfffc)), // bne t1,zero -> loop LW
		olRType(10, 11, 10, 0x26),        // XOR in branch delay
		olIType(5, 10, 12, 3),            // mismatch -> jr t7
		0,
		olJR(14), 0,
		olJR(15), 0,
	}
	if len(words16)*4 != 64 {
		return nil, fmt.Errorf("overlay dispatch checksum verifier geometry")
	}
	for i, w := range words16 {
		word(base+i*4, w)
	}
	return out, nil
}

func PlanOverlayLocalIntegrityOffline(exe []byte, originals map[string][]byte) (OverlayDispatchIntegrityCandidate, error) {
	var out OverlayDispatchIntegrityCandidate
	residentRelocationStage, err := PlanOverlayLocalOffline(exe, originals)
	if err != nil {
		return out, err
	}
	out.OverlayLocalCandidate = residentRelocationStage
	off := int(C10EXEGuardF1 - 0x80040800)
	f1 := residentRelocationStage.EnglishEXE[off : off+52]
	term := residentRelocationStage.EnglishEXE[off+140 : off+180]
	gate, err := buildIntegrityGates(f1, term)
	if err != nil {
		return OverlayDispatchIntegrityCandidate{}, err
	}
	if !allZero(residentRelocationStage.EnglishEXE[off+52 : off+140]) {
		return OverlayDispatchIntegrityCandidate{}, fmt.Errorf("overlay dispatch verifier area already owned")
	}
	out.EnglishEXE = bytes.Clone(residentRelocationStage.EnglishEXE)
	copy(out.EnglishEXE[off:off+180], gate)
	out.BodyIntegrityGuarded = true
	out.Blocked, out.BlockedReason = true, OverlayDispatchBlockedReason
	out.SafeToPatch, out.RuntimePass = false, false
	return out, nil
}
