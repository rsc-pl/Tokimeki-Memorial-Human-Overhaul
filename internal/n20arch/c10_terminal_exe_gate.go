package n20arch

// EXE-tail guard for both verified renderer terminal queue exits.
// This candidate remains private: GYOZI residency, runtime overwrites and
// parser behavior require grouped game QA. Default integrated baseline is untouched.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func uint16Low(x uint32) uint16 { return uint16(x & 0xffff) }

const C10EXETerminalGate uint32 = C10EXELoaderGate + C10EXELoaderGateBytes

var c10TerminalRetailCalls = [...]uint32{0x80082700, 0x80082724}

// 40 bytes. C10Magic is committed only after verified promotion and I-cache
// flush. This minimal gate checks the marker; the adapter additionally
// verifies the resident declared body length before accessing its helpers.
func BuildC10EXETerminalGate() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	w(olLUI(8, C10ResidentGuard+0x10000))
	w(olLW(9, 8, int16(uint16Low(C10ResidentGuard))))
	w(olLUI(10, C10Magic)) // fills load delay
	w(olORI(10, 10, C10Magic&0xffff))
	a.b(5, 9, 10, "retail")
	w(0)
	w(jWord(C10QueueAdapterEntry))
	w(0)
	a.label("retail")
	w(jWord(optionQueueRetail))
	w(0)
	a.resolve()
	b := words(a.words...)
	if len(b) != 40 {
		return nil, fmt.Errorf("expected 40 B terminal gate, got %d", len(b))
	}
	if int(C10EXETerminalGate-C10EXEGuardF1)+len(b) != C10EXEGuardTailBytes {
		return nil, fmt.Errorf("EXE renderer tail budget drift")
	}
	return b, nil
}

// Compose terminal hooks only onto the fully verified
// candidate. Both source JALs and their different original delay slots are
// authenticated. It never modifies the default integrated build.
func PlanC10TerminalDistributedOffline(exe []byte, originals map[string][]byte) (C10DistributedCandidate, error) {
	d, err := PlanC10DistributedOffline(exe, originals)
	if err != nil {
		return d, err
	}
	if len(d.AddedEXEWords) != 3 {
		return C10DistributedCandidate{}, fmt.Errorf("renderer word count drift")
	}
	f1, e := BuildC10EXEGuardF1()
	if e != nil {
		return C10DistributedCandidate{}, e
	}
	bridge := d.Overlays["GYOZI.EXN"][c10BridgeFileOff : c10BridgeFileOff+c10BridgeBytes]
	loader, e := BuildC10EXELoaderGate(bridge)
	if e != nil {
		return C10DistributedCandidate{}, e
	}
	terminal, e := BuildC10EXETerminalGate()
	if e != nil {
		return C10DistributedCandidate{}, e
	}
	off := int(C10EXEGuardF1 - 0x80040800)
	if off < 0 || off+C10EXEGuardTailBytes > len(d.EnglishEXE) || !bytes.Equal(d.EnglishEXE[off:off+len(f1)], f1) || !bytes.Equal(d.EnglishEXE[off+len(f1):off+len(f1)+len(loader)], loader) || !bytes.Equal(d.EnglishEXE[off+len(f1)+len(loader):off+C10EXEGuardTailBytes], make([]byte, 40)) {
		return C10DistributedCandidate{}, fmt.Errorf("renderer tail ownership mismatch")
	}
	for _, pc := range c10TerminalRetailCalls {
		at := int(pc - 0x80040800)
		old := binary.LittleEndian.Uint32(exe[at:])
		prev := binary.LittleEndian.Uint32(d.EnglishEXE[at:])
		delay := binary.LittleEndian.Uint32(exe[at+4:])
		gotDelay := binary.LittleEndian.Uint32(d.EnglishEXE[at+4:])
		expectedDelay := uint32(0xafb80010)
		if pc == 0x80082724 {
			expectedDelay = 0xafae0010
		}
		if old != jalWord(optionQueueRetail) || prev != old || delay != expectedDelay || gotDelay != expectedDelay {
			return C10DistributedCandidate{}, fmt.Errorf("terminal queue preimage / delay mismatch at %08x", pc)
		}
	}
	copy(d.EnglishEXE[off+len(f1)+len(loader):], terminal)
	for _, pc := range c10TerminalRetailCalls {
		at := int(pc - 0x80040800)
		old := binary.LittleEndian.Uint32(exe[at:])
		newWord := jalWord(C10EXETerminalGate)
		binary.LittleEndian.PutUint32(d.EnglishEXE[at:], newWord)
		d.AddedEXEWords = append(d.AddedEXEWords, n20RelocWord{Owner: "SLPM_86.053", PC: pc, Old: old, New: newWord, Kind: "c10_guarded_terminal_queue", Role: "EXE parser terminal (cold-boot retail fallback)"})
	}
	if len(d.AddedEXEWords) != 5 || d.SafeToPatch || d.RuntimePass {
		return C10DistributedCandidate{}, fmt.Errorf("terminal safety/accounting changed")
	}
	return d, nil
}
