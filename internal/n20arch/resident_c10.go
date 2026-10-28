package n20arch

// C10 physically materialises an authenticated, relocated resident *source*
// using the otherwise unused tail of GYOZI.EXN. This is a PRIVATE OFFLINE
// component test, NOT a runtime-deliverable patch. It deliberately leaves all
// EXE hooks untouched: before source promotion, an unconditional EXE call
// would jump into uninitialised persistent RAM. The 26-overlay loader bridge,
// overlay/N6-FP co-residency, GYOZI index gate, F2 and F3 remain unresolved.
// Nothing here changes the English corpus, retail EXE, saves or public builder.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	C10ResidentGuard      uint32 = 0x8012D200
	C10ResidentBody       uint32 = 0x8012D300
	C10ResidentEnd        uint32 = 0x8012E1D8
	C10ResidentGuardBytes        = 256
	C10ResidentBodyBytes         = 3800
	C10ResidentBytes             = 4056
	C10SourceGuard        uint32 = 0x80160E00
	C10SourceBody         uint32 = 0x80160F00
	C10Magic              uint32 = 0x3043314e // 'N1C0' (component-specific marker)
	C10F1Entry            uint32 = C10ResidentBody
	C10F2PEntry           uint32 = C10ResidentBody + 8
	C10F3Entry            uint32 = C10ResidentBody + 16
	C10F2GEntry           uint32 = C10ResidentBody + 24
	C10QueueAdapterEntry  uint32 = C10ResidentGuard + 16 // resident guard tail (16..255), no extra RAM
	c10ResidentRomanizer  uint32 = C10ResidentBody + 32
)

type C10SourceCandidate struct {
	SourceOverlay   []byte // GYOZI private in-memory bytes, never written by this API
	SourceImage     []byte // 4056 bytes that would be copied into persistent RAM
	F1Entry         uint32
	F2PEntry        uint32 // intentionally NOT implemented
	F3Entry         uint32 // intentionally NOT implemented
	RomanizerEntry  uint32
	ShimEntry       uint32 // resident F1 shim the EXE gate jumps to
	ShimBytes       int
	ActualBodyBytes int
	SafeToPatch     bool
	RuntimePass     bool
}

// PlanC10GyoziSource builds a real resident-addressed packed romanizer and
// guarded F1 speaker shim using source-verified zero space in GYOZI. No
// unconditional EXE hook, loader JAL replacement or executable image is made.
// Calling this a completed resident architecture would be incorrect: the
// promotion bridge and index lifetime gate have not been implemented.
func PlanC10GyoziSource(original []byte) (C10SourceCandidate, error) {
	return planC10GyoziSource(original, buildSpeakerTailShimFor)
}

// planC10GyoziSource is the shared geometry used by every C10 resident variant.
// The ONLY variant-specific input is the resident F1 shim builder; the guard,
// romanizer, suffix helper, queue adapter and checksums stay byte-identical.
// This keeps speaker bridge comparable with resident module/speaker rendering without duplicating a 100-line layout.
func planC10GyoziSource(original []byte, buildF1Shim func(uint32) ([]byte, error)) (C10SourceCandidate, error) {
	var p C10SourceCandidate
	if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA["GYOZI.EXN"] {
		return p, fmt.Errorf("C10 GYOZI authenticity failure")
	}
	if !bytes.Equal(original[OLPayloadFileOff:OLPayloadEndOff], make([]byte, OLPayloadEndOff-OLPayloadFileOff)) {
		return p, fmt.Errorf("C10 original GYOZI payload not empty")
	}
	if packedTableChecksum(original) != binary.BigEndian.Uint16(original[len(original)-4:]) {
		return p, fmt.Errorf("C10 GYOZI source checksum failure")
	}
	r, err := BuildN20PackedRomanizer(c10ResidentRomanizer)
	if err != nil {
		return p, err
	}
	if len(r.Binary) != N20PackedProgramBytes {
		return p, fmt.Errorf("C10 romanizer size %d", len(r.Binary))
	}
	shim, err := buildF1Shim(c10ResidentRomanizer)
	if err != nil {
		return p, err
	}
	shimRAM := align16(c10ResidentRomanizer + uint32(len(r.Binary)))
	if shimRAM+uint32(len(shim)) > C10ResidentEnd {
		return p, fmt.Errorf("C10 body overflow")
	}
	body := make([]byte, C10ResidentBodyBytes)
	// Eight-byte entry for F1: jump to a proven speaker wrapper, delay nop.
	binary.LittleEndian.PutUint32(body[0:4], jWord(shimRAM))
	// F2-P and F3 now expose a *bounded full-line converter*, NOT EXE hooks.
	// The caller must prove source-buffer ownership and full queue ABI.
	// F2-G remains deliberately trapped (no authenticated route yet).
	binary.LittleEndian.PutUint32(body[24:], 0x0000000D)
	copy(body[32:], r.Binary)
	copy(body[int(shimRAM-C10ResidentBody):], shim)
	actual := int(shimRAM-C10ResidentBody) + len(shim)
	// A single suffix helper serves both dynamic field owners by selector.
	suffixRAM := align16(C10ResidentBody + uint32(actual))
	suffix, err := buildC10LineSuffix(suffixRAM, c10ResidentRomanizer)
	if err != nil {
		return p, err
	}
	if suffixRAM+uint32(len(suffix)) > C10ResidentEnd {
		return p, fmt.Errorf("C10 suffix helper overflow: %d B exceeds resident body", len(suffix))
	}
	copy(body[int(suffixRAM-C10ResidentBody):], suffix)
	actual = int(suffixRAM-C10ResidentBody) + len(suffix)
	for _, route := range []struct {
		off      int
		selector int16
	}{{8, 1}, {16, 2}} {
		binary.LittleEndian.PutUint32(body[route.off:], jWord(suffixRAM))
		binary.LittleEndian.PutUint32(body[route.off+4:], olADDIU(14, 0, route.selector))
	}
	var sum, xor uint32
	for i := 0; i < len(body); i += 4 {
		w := binary.LittleEndian.Uint32(body[i:])
		sum += w
		xor ^= w
	}
	guard := make([]byte, C10ResidentGuardBytes)
	binary.LittleEndian.PutUint32(guard[0:], C10Magic)
	binary.LittleEndian.PutUint32(guard[4:], C10ResidentBodyBytes)
	binary.LittleEndian.PutUint32(guard[8:], sum)
	binary.LittleEndian.PutUint32(guard[12:], xor)
	// resident module: install the complete terminal queue ABI adapter in previously
	// unused resident *guard* bytes 16..255, outside the body checksum.
	// This consumes no new RAM or overlay source footprint. It is NOT an
	// active EXE hook and remains private until cold-boot routing is proven.
	queueAdapter, err := BuildC10TerminalQueueAdapter(C10QueueAdapterEntry)
	if err != nil {
		return C10SourceCandidate{}, err
	}
	copy(guard[16:], queueAdapter)
	p.SourceImage = append(guard, body...)
	if len(p.SourceImage) != C10ResidentBytes {
		return C10SourceCandidate{}, fmt.Errorf("bad C10 image length")
	}
	p.SourceOverlay = bytes.Clone(original)
	copy(p.SourceOverlay[OLPayloadFileOff:], p.SourceImage)
	binary.BigEndian.PutUint16(p.SourceOverlay[len(p.SourceOverlay)-4:], packedTableChecksum(p.SourceOverlay))
	p.F1Entry = C10F1Entry
	p.F2PEntry = C10F2PEntry
	p.F3Entry = C10F3Entry
	p.RomanizerEntry = c10ResidentRomanizer
	p.ShimEntry = shimRAM
	p.ShimBytes = len(shim)
	p.ActualBodyBytes = actual
	p.SafeToPatch = false
	p.RuntimePass = false
	return p, nil
}
