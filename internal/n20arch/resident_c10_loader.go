package n20arch

// This loader bridge remains an OFFLINE MIPS candidate. It does not enable
// resident EXE rendering hooks. Installing EXE hooks before a proven initial
// promotion would reproduce previous version's unloaded-target failure.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	c10BridgeRAM        uint32 = 0x80161EDC
	c10BridgeFileOff           = 0x2FEDC
	c10BridgeBytes             = 288
	c10BridgeMarker     uint32 = 0x43423130 // C1BC, end-of-overlay stub commit marker
	c10BridgeMarkerRAM  uint32 = c10BridgeRAM + c10BridgeBytes - 4
	c10RetailLoaderCall uint32 = 0x800796F8
	c10Memcpy           uint32 = 0x800AE0A0
	c10Flush            uint32 = 0x80042458
)

// BuildC10PromotionBridge preserves the original jalr t9 contract, attempts
// source promotion only when the freshly loaded overlay contains the exact
// expected guarded C10 image, and calls the original t9 target exactly once.
// Its checksum test is bounded to the 3800-byte source body. Execution/ABI
// checks below are emulator tests, not runtime evidence.
func BuildC10PromotionBridge(source []byte) ([]byte, error) {
	return BuildC10PromotionBridgeAt(source, C10SourceGuard)
}

// BuildC10PromotionBridgeAt binds the source address into the authenticated
// bridge. resident module uses a disjoint 4056-byte high-tail gap in eligible overlays
// instead of the N6/N6-FP window at 0x80160E00.
func BuildC10PromotionBridgeAt(source []byte, sourceGuard uint32) ([]byte, error) {
	return buildC10PromotionBridgeAt(source, sourceGuard, 0)
}

// speaker rendering PRIVATE: the genuine state-3 loader calls a fixed original scene
// selector, not jalr $t9. This bridge restores that exact target after
// attempted promotion. It does not affect the queue routing builder.
func BuildC10PromotionBridgeAtScene3(source []byte, sourceGuard uint32) ([]byte, error) {
	return buildC10PromotionBridgeAt(source, sourceGuard, LoaderDispatchSel)
}

func buildC10PromotionBridgeAt(source []byte, sourceGuard uint32, originalTarget uint32) ([]byte, error) {
	if originalTarget != 0 && originalTarget != LoaderDispatchSel {
		return nil, fmt.Errorf("unexpected speaker rendering original target %08x", originalTarget)
	}
	if sourceGuard != C10SourceGuard && sourceGuard != C10DistributedSourceRAM {
		return nil, fmt.Errorf("unknown C10 source address %08x", sourceGuard)
	}
	sourceBody := sourceGuard + C10ResidentGuardBytes
	if len(source) != C10ResidentBytes {
		return nil, fmt.Errorf("source length %d", len(source))
	}
	magic := binary.LittleEndian.Uint32(source[0:])
	size := binary.LittleEndian.Uint32(source[4:])
	sum := binary.LittleEndian.Uint32(source[8:])
	xor := binary.LittleEndian.Uint32(source[12:])
	if magic != C10Magic || size != C10ResidentBodyBytes {
		return nil, fmt.Errorf("source header mismatch")
	}
	var calcSum, calcXor uint32
	for i := C10ResidentGuardBytes; i < len(source); i += 4 {
		w := binary.LittleEndian.Uint32(source[i:])
		calcSum += w
		calcXor ^= w
	}
	if sum != calcSum || xor != calcXor {
		return nil, fmt.Errorf("source checksum mismatch")
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	li := func(r, v uint32) { w(olLUI(r, v)); w(olORI(r, r, v&0xffff)) }
	store := func(r uint32, off int16) { w(olSW(r, 29, off)) }
	load := func(r uint32, off int16) { w(olLW(r, 29, off)) }
	w(olADDIU(29, 29, -0x70))
	store(31, 0x6c)
	store(25, 0x68)
	for i, r := range []uint32{4, 5, 6, 7} {
		store(r, int16(0x50+4*i))
	}
	// Forward caller's fifth argument, even though existing loader callers
	// currently use only four; do not repeat the nested-stack hazard.
	load(8, 0x80)
	w(0)
	store(8, 0x10)
	// Source must have the correct magic and declared length. Deliberately
	// revalidate and refresh even if a resident magic word is already present.
	li(10, C10Magic)
	li(8, sourceGuard)
	w(olLW(9, 8, 0))
	w(0)
	a.b(5, 9, 10, "finish")
	w(0)
	w(olLW(9, 8, 4))
	w(0)
	w(olADDIU(11, 0, int16(C10ResidentBodyBytes)))
	a.b(5, 9, 11, "finish")
	w(0)
	// Source checksum: 950 little-endian words, 32-bit sum and XOR.
	li(8, sourceBody)
	w(olADDIU(9, 0, C10ResidentBodyBytes/4))
	w(olAddu(10, 0, 0))
	w(olAddu(11, 0, 0))
	a.label("checksum")
	w(olLW(12, 8, 0))
	w(olADDIU(9, 9, -1)) // one-instruction R3000A load delay
	w(olAddu(10, 10, 12))
	w(olRType(11, 12, 11, 0x26))
	a.b(5, 9, 0, "checksum")
	w(olADDIU(8, 8, 4))
	li(8, sum)
	a.b(5, 10, 8, "finish")
	w(0)
	li(8, xor)
	a.b(5, 11, 8, "finish")
	w(0)
	// Revoke previously valid resident before overwriting any body bytes.
	li(8, C10ResidentGuard)
	w(olSW(0, 8, 0))
	// Copy all bytes EXCEPT magic; it is committed only after full copy.
	li(4, C10ResidentGuard+4)
	li(5, sourceGuard+4)
	w(olADDIU(6, 0, C10ResidentBytes-4))
	w(jalWord(c10Memcpy))
	w(0)
	// Publish the resident marker only AFTER flushing the copied code.
	// This does not establish IRQ/DMA atomicity, but avoids advertising
	// executable code before the required I-cache flush has occurred.
	w(jalWord(c10Flush))
	w(0)
	li(8, C10ResidentGuard)
	li(9, C10Magic)
	w(olSW(9, 8, 0))
	a.label("finish")
	for i, r := range []uint32{4, 5, 6, 7} {
		load(r, int16(0x50+4*i))
	}
	if originalTarget == 0 {
		load(25, 0x68)
		w(0) // R3000A load-delay separation before jalr t9
	} else {
		// An immediate LUI/ORI has no load-delay hazard. Replace the
		// old LW+NOP pair with LUI+ORI, preserving the 284-byte budget.
		li(25, originalTarget)
	}
	// Call original jalr t9 target and preserve its return values.
	w(olRType(25, 0, 31, 0x09))
	w(0) // jalr ra,t9
	load(31, 0x6c)
	w(olADDIU(29, 29, 0x70)) // load-delay separation; restore original frame
	w(olJR(31))
	w(0)
	a.resolve()
	b := words(a.words...)
	// Reserve the final bridge word as an entry-availability marker. It is
	// installed only in the final sector, never in the retail image.
	if len(b) > c10BridgeBytes-4 {
		return nil, fmt.Errorf("bridge requires %d bytes, have %d", len(b), c10BridgeBytes)
	}
	out := append(b, make([]byte, c10BridgeBytes-len(b))...)
	binary.LittleEndian.PutUint32(out[c10BridgeBytes-4:], c10BridgeMarker)
	return out, nil
}

// C10StubOnly overlays preserve their original payload. EVENT/TACO are
// supported without writing into their nonzero tail data.
func ApplyC10BridgeToOverlay(original []byte, bridge []byte) ([]byte, error) {
	if len(original) != OverlayLoadSectors*2048 || len(bridge) != c10BridgeBytes {
		return nil, fmt.Errorf("invalid overlay/bridge geometry")
	}
	if !bytes.Equal(original[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes], make([]byte, c10BridgeBytes)) {
		return nil, fmt.Errorf("bridge window not zero")
	}
	d := bytes.Clone(original)
	copy(d[c10BridgeFileOff:], bridge)
	binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
	return d, nil
}

// C10OfflineComposition composes integrated 426-word offline plan with a
// test-only loader bridge. The separate bridge is NOT admitted into the
// human-overhaul image builder: C10 does not yet establish first-promotion
// order, GYOZI table-index ownership, or F2/F3 suffix conversion.
type C10OfflineComposition struct {
	PatchedEXE            []byte
	PatchedOverlays       map[string][]byte
	BridgeWordPC          uint32
	OriginalBridgeWord    uint32
	BridgeWord            uint32
	SourceOwner           string
	OverlayBridgeCount    int
	ExistingH5DirectSites int
	Source                C10SourceCandidate
	SafeToPatch           bool
	RuntimePass           bool
}

func PlanC10OfflineComposition(exe []byte, overlays map[string][]byte) (C10OfflineComposition, error) {
	var p C10OfflineComposition
	h5, err := N20DirectQueueCoResident(exe, overlays)
	if err != nil {
		return p, fmt.Errorf("integrated baseline: %w", err)
	}
	src, err := PlanC10GyoziSource(overlays["GYOZI.EXN"])
	if err != nil {
		return p, err
	}
	bridge, err := BuildC10PromotionBridge(src.SourceImage)
	if err != nil {
		return p, err
	}
	if len(h5.ExtraSites) != 13 {
		return p, fmt.Errorf("integrated direct queue count %d", len(h5.ExtraSites))
	}
	p.PatchedEXE = bytes.Clone(h5.PatchedEXE)
	// Retail jalr ra,t9 -> jal bridge; the original delay slot is a nop.
	const retailJALR = 0x0320F809
	off := int(c10RetailLoaderCall - 0x80040800)
	if binary.LittleEndian.Uint32(exe[off:]) != retailJALR || binary.LittleEndian.Uint32(exe[off+4:]) != 0 ||
		binary.LittleEndian.Uint32(p.PatchedEXE[off:]) != retailJALR {
		return C10OfflineComposition{}, fmt.Errorf("loader hook preimage mismatch at %08x", c10RetailLoaderCall)
	}
	binary.LittleEndian.PutUint32(p.PatchedEXE[off:], jalWord(c10BridgeRAM))
	p.PatchedOverlays = make(map[string][]byte, len(overlays))
	if len(overlays) != len(OverlaySHA) {
		return C10OfflineComposition{}, fmt.Errorf("not all 26 originals supplied")
	}
	for name, original := range overlays {
		d := h5.PatchedOverlays[name]
		if d == nil {
			return C10OfflineComposition{}, fmt.Errorf("integrated baseline missing %s", name)
		}
		if name == "GYOZI.EXN" {
			if !bytes.Equal(d, original) {
				return C10OfflineComposition{}, fmt.Errorf("unexpected GYOZI baseline changes")
			}
			d = src.SourceOverlay
		}
		out, err := ApplyC10BridgeToOverlay(d, bridge)
		if err != nil {
			return C10OfflineComposition{}, fmt.Errorf("%s: %w", name, err)
		}
		p.PatchedOverlays[name] = out
	}
	p.BridgeWordPC = c10RetailLoaderCall
	p.OriginalBridgeWord = retailJALR
	p.BridgeWord = jalWord(c10BridgeRAM)
	p.SourceOwner = "GYOZI.EXN"
	p.Source = src
	p.OverlayBridgeCount = len(p.PatchedOverlays)
	p.ExistingH5DirectSites = len(h5.ExtraSites)
	p.SafeToPatch = false
	p.RuntimePass = false
	return p, nil
}
