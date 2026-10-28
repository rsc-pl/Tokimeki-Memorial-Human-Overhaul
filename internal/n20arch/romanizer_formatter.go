package n20arch

// formatter bridge: integrate the existing four exact surname+space formatter paths with
// the already allocated terminal EXE gate, without a new global gate or
// persistent RAM module. The 512-byte pre-C10 overlay-local window is used
// only in authenticated eligible carrier overlays; the four other overlays
// retain retail behavior. This is OFFLINE ONLY: indirect writes, DMA/IRQ,
// GPU and exact narrator identity remain unproved.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	pn "tokimemo/internal/playername"
)

const (
	SlotBytes              = 512
	SlotOff                = C10DistributedSourceFileOff - SlotBytes
	SlotRAM                = OverlayBase - SlotBytes
	RouterRAM              = SlotRAM + 4
	RouterBytes            = 56
	BridgeRAM              = RouterRAM + RouterBytes
	BridgeBytes            = 444
	CheckedWords           = int((OverlayEnd - RouterRAM) / 4)
	FormatterBlockedReason = "formatter bridge offline four exact formatter JALs share the verified terminal C10 gate and a 512-byte overlay-local bridge only in 22/26 carriers. The extended 4564-byte checksum detects accidental corruption, but overlay ownership, concurrent CPU/DMA/IRQ writes and narrator route identity are NOT proven. safe_to_patch=false, runtime_pass=false"
)

type FormatterIntegratedCandidate struct {
	BoundedCandidate
	FormatterPCs     []uint32
	LocalBridgeBytes int
	GuardedBytes     int
}

func formatterBridgeRouter() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	w(olLUI(24, 0x80080000))
	w(olADDIU(25, 24, -2084)) // 0x8007F7DC
	a.b(4, 31, 25, "formatter")
	w(olADDIU(25, 24, -1888))
	a.b(4, 31, 25, "formatter")
	w(olADDIU(25, 24, -1692))
	a.b(4, 31, 25, "formatter")
	w(olADDIU(25, 24, 3128))
	a.b(4, 31, 25, "formatter")
	w(0)
	w(jWord(OverlayBase + 16))
	w(0) // original terminal queue adapter
	a.label("formatter")
	w(jWord(BridgeRAM))
	w(0)
	a.resolve()
	b := words(a.words...)
	if len(b) != RouterBytes {
		return nil, fmt.Errorf("formatter bridge router geometry %d", len(b))
	}
	return b, nil
}

func formatterBridgeSlot(romanizer uint32) ([]byte, error) {
	bridge, e := pn.BuildPS1FormatterBridgeFourRoutes(BridgeRAM, romanizer)
	if e != nil {
		return nil, e
	}
	if len(bridge.Binary) != BridgeBytes || bridge.CodeBytes != BridgeBytes || bridge.FrameBytes != 0xc0 {
		return nil, fmt.Errorf("formatter bridge bridge ABI/size drift")
	}
	router, e := formatterBridgeRouter()
	if e != nil {
		return nil, e
	}
	out := make([]byte, SlotBytes)
	copy(out[4:], router)
	copy(out[4+len(router):], bridge.Binary)
	if len(out)-(4+len(router)+len(bridge.Binary)) != 8 {
		return nil, fmt.Errorf("formatter bridge slot padding drift")
	}
	return out, nil
}

// Invert the existing reversible order-dependent recurrence over an extended,
// contiguous instruction span: router + formatter + C10 metadata/adapter/body.
// The seed at 0x8015FC00 precedes executable code, so verification includes
// every word of the local formatter bridge and all previously verified code.
func formatterBridgeSeed(content []byte) (uint32, error) {
	if len(content) != SlotBytes+C10ResidentBytes {
		return 0, fmt.Errorf("formatter bridge length drift")
	}
	var seed uint32
	for i := len(content) - 4; i >= 4; i -= 4 {
		seed = (seed - overlayFormatterIncrement) ^ binary.LittleEndian.Uint32(content[i:])
	}
	return seed, nil
}
func formatterBridgeVerified(content []byte) bool {
	if len(content) != SlotBytes+C10ResidentBytes {
		return false
	}
	v := binary.LittleEndian.Uint32(content)
	for i := 4; i < len(content); i += 4 {
		v = (v ^ binary.LittleEndian.Uint32(content[i:])) + overlayFormatterIncrement
	}
	return v == 0
}

func PlanFormatterIntegratedOffline(exe []byte, originals map[string][]byte) (FormatterIntegratedCandidate, error) {
	var empty FormatterIntegratedCandidate
	memoryOwnershipStage, e := PlanBoundedOwnershipOffline(exe, originals)
	if e != nil {
		return empty, e
	}
	out := FormatterIntegratedCandidate{BoundedCandidate: memoryOwnershipStage, GuardedBytes: int(OverlayEnd - RouterRAM)}
	bridge, e := PrepareActivityFormatterOffline(exe, memoryOwnershipStage.EnglishEXE)
	if e != nil {
		return empty, fmt.Errorf("formatter bridge old formatter provenance: %w", e)
	}
	if len(bridge.SourceQueueSites) != 4 || bridge.SafeToPatch || bridge.RuntimePass {
		return empty, fmt.Errorf("formatter bridge source route drift")
	}
	// formatter bridge expands its executable interval by 512 bytes. memory ownership's older scan
	// did not cover this interval; independently refuse authenticated
	// originals with literals or direct reads/writes into the added window.
	for name, retail := range originals {
		reads, writes := memoryOwnershipBoundedLiteralAccessesInWindowAt(retail, OverlaySlotBase, 0x24000, SlotRAM, OverlayBase)
		ptrs := 0
		for off := 0; off+4 <= len(retail); off += 4 {
			v := binary.LittleEndian.Uint32(retail[off:])
			if v >= SlotRAM && v < OverlayBase {
				ptrs++
			}
		}
		if (len(reads) + len(writes) + ptrs) > 0 {
			for _, candidate := range memoryOwnershipStage.Carriers {
				if candidate == name {
					return empty, fmt.Errorf("formatter bridge retail occupied window %s: ptr=%d read=%d write=%d", name, ptrs, len(reads), len(writes))
				}
			}
		}
	}
	reads, writes := memoryOwnershipBoundedLiteralAccessesInWindowAt(exe, 0x80040800, len(exe), SlotRAM, OverlayBase)
	if len(reads)+len(writes) > 0 {
		return empty, fmt.Errorf("formatter bridge original EXE refers to expanded executable region")
	}
	for off := 0; off+4 <= len(exe); off += 4 {
		v := binary.LittleEndian.Uint32(exe[off:])
		if v >= SlotRAM && v < OverlayBase {
			return empty, fmt.Errorf("formatter bridge EXE literal pointer into expanded executable region")
		}
	}
	local, e := formatterBridgeSlot(OverlayBase + C10ResidentGuardBytes + 32)
	if e != nil {
		return empty, e
	}
	originalVerifier := tailGuardVerifierWords()
	start := int(overlayDispatchVerifier - 0x80040800)
	out.EnglishEXE = bytes.Clone(memoryOwnershipStage.EnglishEXE)
	for i, w := range originalVerifier {
		if binary.LittleEndian.Uint32(out.EnglishEXE[start+i*4:]) != w {
			return empty, fmt.Errorf("formatter bridge expected tail guard verifier drift word %d", i)
		}
	}
	// The 64-byte verification gate still uses the identical 16 instructions;
	// change only its scanned start and word count.
	next := append([]uint32(nil), originalVerifier...)
	next[1] = olADDIU(8, 8, int16(int64(RouterRAM)-0x80160000)) // LUI 0x8016 + signed -1020 = 0x8015FC04
	next[3] = olADDIU(9, 0, int16(CheckedWords))
	for i, w := range next {
		binary.LittleEndian.PutUint32(out.EnglishEXE[start+i*4:], w)
	}
	// Retarget only the existing terminal-gate's verified success branch.
	// F1 speaker gate and retail failure branches remain byte-identical.
	stub := int(overlayDispatchTermStub - 0x80040800)
	oldTarget := olORI(14, 14, uint32(uint16Low(OverlayBase+16)))
	if binary.LittleEndian.Uint32(out.EnglishEXE[stub:]) != oldTarget {
		return empty, fmt.Errorf("formatter bridge terminal target drift")
	}
	binary.LittleEndian.PutUint32(out.EnglishEXE[stub:], olORI(14, 14, uint32(uint16Low(RouterRAM))))
	for _, pc := range bridge.SourceQueueSites {
		at := int(pc - 0x80040800)
		if binary.LittleEndian.Uint32(out.EnglishEXE[at:]) != jalWord(optionQueueRetail) || binary.LittleEndian.Uint32(out.EnglishEXE[at+4:]) != olSW(0, 29, 0x10) {
			return empty, fmt.Errorf("formatter bridge formatter original source drift at %#x", pc)
		}
		binary.LittleEndian.PutUint32(out.EnglishEXE[at:], jalWord(C10EXETerminalGate))
		out.FormatterPCs = append(out.FormatterPCs, pc)
	}
	carriers := map[string]bool{}
	for _, name := range memoryOwnershipStage.Carriers {
		carriers[name] = true
	}
	out.Overlays = make(map[string][]byte, len(memoryOwnershipStage.Overlays))
	var reference []byte
	for name, original := range originals {
		current := memoryOwnershipStage.Overlays[name]
		clone := bytes.Clone(current)
		if carriers[name] {
			// Protect occupied code/data from prior combined romanization/N20 branches, not only retail.
			if !allZero(original[SlotOff:C10DistributedSourceFileOff]) || !allZero(current[SlotOff:C10DistributedSourceFileOff]) {
				return empty, fmt.Errorf("formatter bridge proposed 512-byte code slot occupied in %s", name)
			}
			chunk := make([]byte, SlotBytes+C10ResidentBytes)
			copy(chunk, local)
			copy(chunk[SlotBytes:], current[C10DistributedSourceFileOff:C10DistributedSourceEnd])
			seed, e := formatterBridgeSeed(chunk)
			if e != nil {
				return empty, e
			}
			binary.LittleEndian.PutUint32(chunk[:4], seed)
			if !formatterBridgeVerified(chunk) {
				return empty, fmt.Errorf("formatter bridge checksum inversion failed")
			}
			if reference == nil {
				reference = bytes.Clone(chunk)
			} else if !bytes.Equal(reference, chunk) {
				return empty, fmt.Errorf("formatter bridge carrier code mismatch %s", name)
			}
			copy(clone[SlotOff:C10DistributedSourceEnd], chunk)
			binary.BigEndian.PutUint16(clone[len(clone)-4:], packedTableChecksum(clone))
		} else if !bytes.Equal(current, clone) {
			return empty, fmt.Errorf("formatter bridge fallback drift %s", name)
		}
		out.Overlays[name] = clone
	}
	if len(out.FormatterPCs) != 4 || out.GuardedBytes != CheckedWords*4 || CheckedWords != 1141 || len(carriers) != 22 || len(out.Overlays) != 26 {
		return empty, fmt.Errorf("formatter bridge layout/inventory mismatch")
	}
	out.LocalBridgeBytes = BridgeBytes + RouterBytes
	out.Blocked = true
	out.BlockedReason = FormatterBlockedReason
	out.SafeToPatch = false
	out.RuntimePass = false
	return out, nil
}
