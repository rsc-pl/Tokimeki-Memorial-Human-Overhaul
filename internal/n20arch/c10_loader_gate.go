package n20arch

// C10's EXE-owned loader dispatch gate is distinct from the overlay bridge.
// The retail loader's indirect jalr t9 MUST NOT jump unconditionally into
// the replaceable overlay slot. This branch-delay-safe tail trampoline
// verifies the loaded overlay bridge's bounded sum32/xor32 before dispatch.
// Its absence makes an original jr t9 tail call. Its presence allows the
// bridge to verify the GYOZI source, promote, and then execute retail once.
// The bridge separately verifies GYOZI source integrity. This checksum
// is an availability guard, not proof against torn-load/IRQ/DMA races.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/graphics"
)

const (
	C10EXELoaderGate      uint32 = C10EXEGuardF1 + 52
	C10EXELoaderGateBytes        = 88
)

// BuildC10EXELoaderGate preserves a0-a3, ra, sp and t9. Calling this gate
// from the original JAL site gives the exact same ra as jalr t9 did.
func BuildC10EXELoaderGate(bridge []byte) ([]byte, error) {
	if len(bridge) != c10BridgeBytes || binary.LittleEndian.Uint32(bridge[c10BridgeBytes-4:]) != c10BridgeMarker {
		return nil, fmt.Errorf("untrusted C10 bridge input")
	}
	var sum, xor uint32
	for i := 0; i < len(bridge); i += 4 {
		word := binary.LittleEndian.Uint32(bridge[i:])
		sum += word
		xor ^= word
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	// Source lives in the 96-sector overlay slot; the loop reads exactly
	// 288 bytes, including its end marker. Zero, stale, incomplete, or
	// single-bit-corrupted bridges call original t9 instead.
	w(olLUI(8, c10BridgeRAM))
	w(olORI(8, 8, c10BridgeRAM&0xffff))
	w(olADDIU(11, 0, c10BridgeBytes/4))
	w(olAddu(9, 0, 0))
	w(olAddu(10, 0, 0))
	a.label("checksum")
	w(olLW(12, 8, 0))
	w(olADDIU(8, 8, 4))          // R3000A load delay
	w(olRType(10, 12, 10, 0x26)) // xor t2,t4,t2
	w(olADDIU(11, 11, -1))
	a.b(5, 11, 0, "checksum")
	w(olAddu(9, 9, 12)) // sum in taken/not-taken delay slot
	w(olLUI(12, sum))
	w(olORI(12, 12, sum&0xffff))
	a.b(5, 9, 12, "retail")
	w(olLUI(12, xor)) // always safe on retail branch
	w(olORI(12, 12, xor&0xffff))
	a.b(5, 10, 12, "retail")
	w(0)
	w(jWord(c10BridgeRAM))
	w(0)
	a.label("retail")
	w(olJR(25)) // original jalr t9 target; ra already correct
	w(0)
	a.resolve()
	b := words(a.words...)
	if len(b) != C10EXELoaderGateBytes {
		return nil, fmt.Errorf("loader gate expected %d bytes, got %d", C10EXELoaderGateBytes, len(b))
	}
	return b, nil
}

type C10DualGateCandidate struct {
	EnglishEXE  []byte
	GuardF1     []byte
	GuardLoader []byte
	Words       []n20RelocWord
	SafeToPatch bool
	RuntimePass bool
}

// Compose both persistent EXE guards into the authenticated English renderer
// tail. Never accept an already occupied tail or unknown retail JALR site.
// It returns only private bytes, not a game image or an installable patch.
func PlanC10DualEXEGates(originalEXE, englishEXE, bridge []byte) (C10DualGateCandidate, error) {
	var out C10DualGateCandidate
	f1, err := PlanC10EXEGuardF1(originalEXE, englishEXE)
	if err != nil {
		return out, err
	}
	gate, err := BuildC10EXELoaderGate(bridge)
	if err != nil {
		return out, err
	}
	off := int(C10EXELoaderGate - 0x80040800)
	tailStart, tail, err := graphics.ReservedNamePool(englishEXE)
	if err != nil {
		return out, err
	}
	if tailStart != int(C10EXEGuardF1-0x80040800) || len(tail) != C10EXEGuardTailBytes || off+len(gate) > tailStart+len(tail) {
		return out, fmt.Errorf("dual gate exceeds the renderer reservation")
	}
	if !bytes.Equal(f1.EnglishEXE[off:off+len(gate)], make([]byte, len(gate))) {
		return out, fmt.Errorf("loader trampoline reservation occupied")
	}
	oldOff := int(c10RetailLoaderCall - 0x80040800)
	if binary.LittleEndian.Uint32(originalEXE[oldOff:]) != 0x0320F809 ||
		binary.LittleEndian.Uint32(englishEXE[oldOff:]) != 0x0320F809 ||
		binary.LittleEndian.Uint32(originalEXE[oldOff+4:]) != 0 || binary.LittleEndian.Uint32(englishEXE[oldOff+4:]) != 0 {
		return out, fmt.Errorf("original loader jalr t9 / delay preimage mismatch")
	}
	out.EnglishEXE = bytes.Clone(f1.EnglishEXE)
	copy(out.EnglishEXE[off:], gate)
	newWord := jalWord(C10EXELoaderGate)
	binary.LittleEndian.PutUint32(out.EnglishEXE[oldOff:], newWord)
	out.GuardF1 = f1.Guard
	out.GuardLoader = gate
	out.Words = append(out.Words, f1.Words...)
	out.Words = append(out.Words, n20RelocWord{Owner: "SLPM_86.053", PC: c10RetailLoaderCall, Old: 0x0320F809, New: newWord, Kind: "c10_loader_guard", Role: "EXE loader: marker-gated overlay promotion or original jalr t9"})
	return out, nil
}
