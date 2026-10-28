package n20arch

// unified name entry builds ONE offline NAME_ENT overlay that preserves all six third-field input name
// presenters while coexisting byte-for-byte with the name-entry drawing-name-entry transfer keyboard glyph
// staging machinery.  Before unified name entry, the entry slot/third-field input packed romanizer overlapped
// the name-entry transfer GPU bridge in 0x23200..0x23400.  This variant relocates only the
// former into an authenticated zero-payload local window 0x24000..0x25000.
//
// This is NOT a visible romaji keyboard or a playable patch: name-entry transfer uses the
// shared font cache and has NO hooked caller. No VRAM slot ownership is proved.
// safe_to_patch:false, runtime_pass:false.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	UnifiedEntryNameEntOff   = 0x24000
	UnifiedEntryNameEntBytes = 0x1000
	UnifiedEntryRomOff       = UnifiedEntryNameEntOff + 0x100
	UnifiedEntryShimOff      = UnifiedEntryNameEntOff + 0xb00
	UnifiedEntryRomRAM       = OverlaySlotBase + UnifiedEntryRomOff
	UnifiedEntryShimRAM      = OverlaySlotBase + UnifiedEntryShimOff
)

type UnifiedNameEntCandidate struct {
	Overlay            []byte
	Romanizer          []byte
	Shim               []byte
	HookPCs            []uint32
	KeyboardDrawSites  int
	KeyboardGlyphs     int
	GPUBridgeDetached  bool
	OriginalKanaIntact bool
	SafeToPatch        bool
	RuntimePass        bool
}

func nameEntryFieldNameEntSixSites() []uint32 {
	return []uint32{
		nameEntryQueueNameEntQueuePCs[0], nameEntryQueueNameEntQueuePCs[1],
		nameEntryQueueNameEntQueuePCs[2], nameEntryQueueNameEntQueuePCs[3],
		nicknameFieldThirdFieldPCs[0], nicknameFieldThirdFieldPCs[1],
	}
}

func PlanUnifiedNameEntOffline(original []byte) (UnifiedNameEntCandidate, error) {
	var empty UnifiedNameEntCandidate
	old, err := PlanNameEntThirdFieldOffline(original)
	if err != nil {
		return empty, err
	}
	gpu, err := BuildNameEntNativeTransfer(original)
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(original[UnifiedEntryNameEntOff:UnifiedEntryNameEntOff+UnifiedEntryNameEntBytes], make([]byte, UnifiedEntryNameEntBytes)) {
		return empty, fmt.Errorf("unified name entry relocated module window is not retail-zero")
	}
	rom, err := BuildN20PackedRomanizer(UnifiedEntryRomRAM)
	if err != nil {
		return empty, err
	}
	shim, err := buildSlotDrawShim(UnifiedEntryRomRAM)
	if err != nil {
		return empty, err
	}
	if UnifiedEntryRomOff+len(rom.Binary) > UnifiedEntryShimOff || UnifiedEntryShimOff+len(shim) > UnifiedEntryNameEntOff+UnifiedEntryNameEntBytes {
		return empty, fmt.Errorf("unified name entry relocated module exceeds bounds")
	}
	// Begin with all six third-field input presenters, but retire the OLD module contents
	// before installing name-entry transfer's *different* local code at overlapping addresses.
	out := bytes.Clone(old.Overlay)
	if !bytes.Equal(original[EntrySlotNameEntOff:EntrySlotNameEntOff+EntrySlotNameEntBytes], make([]byte, EntrySlotNameEntBytes)) {
		return empty, fmt.Errorf("unified name entry historical module window not original-zero")
	}
	copy(out[EntrySlotNameEntOff:EntrySlotNameEntOff+EntrySlotNameEntBytes], original[EntrySlotNameEntOff:EntrySlotNameEntOff+EntrySlotNameEntBytes])
	// name-entry transfer can modify only bytes that are pristine in the third-field input presenter plan.
	// Reject any independent code, data, row pointer or callsite overlap.
	for i, b := range gpu.Overlay {
		if i >= len(out)-4 && i < len(out)-2 {
			continue
		} // derived checksum
		if b == original[i] {
			continue
		}
		if out[i] != original[i] {
			return empty, fmt.Errorf("unified name entry name-entry transfer/presenter overlap at +%#x", i)
		}
		out[i] = b
	}
	copy(out[UnifiedEntryRomOff:], rom.Binary)
	copy(out[UnifiedEntryShimOff:], shim)
	for _, pc := range nameEntryFieldNameEntSixSites() {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out[off:]) != jalWord(EntrySlotShimRAM) ||
			binary.LittleEndian.Uint32(out[off+4:]) != olSW(0, 29, 0x10) {
			return empty, fmt.Errorf("unified name entry old presenter hook drift at %#x", pc)
		}
		binary.LittleEndian.PutUint32(out[off:], jalWord(UnifiedEntryShimRAM))
	}
	if !bytes.Equal(out[nameEntryGridGridStart:nameEntryGridGridEnd], original[nameEntryGridGridStart:nameEntryGridGridEnd]) ||
		!bytes.Equal(out[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+nameEntryGridGridRows*4], original[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+nameEntryGridGridRows*4]) {
		return empty, fmt.Errorf("unified name entry modified original selectable kana data")
	}
	// name-entry transfer's GPU bridge must stay detached. The original retail queue calls
	// on all 42 keyboard rows remain unchanged, preserving shared font cache.
	routes, err := nameEntryDrawScanDrawRoutes(original)
	if err != nil {
		return empty, err
	}
	for _, r := range routes {
		off := int(r.QueuePC - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out[off:]) != nameEntryDrawRetailQueueWord {
			return empty, fmt.Errorf("unified name entry keyboard queue unexpectedly hooked %#x", r.QueuePC)
		}
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return UnifiedNameEntCandidate{
		Overlay: out, Romanizer: rom.Binary, Shim: shim, HookPCs: nameEntryFieldNameEntSixSites(),
		KeyboardDrawSites: len(routes), KeyboardGlyphs: GlyphCount,
		GPUBridgeDetached: true, OriginalKanaIntact: true, SafeToPatch: false, RuntimePass: false,
	}, nil
}

// Compose against the COMPLETE third-field input English candidate, never substitute a
// pristine-only overlay and thereby erase the existing N6/C10 source/bridge.
func PlanCombinedUnifiedOffline(exe []byte, originals map[string][]byte) (TELCandidate, UnifiedNameEntCandidate, error) {
	var zero TELCandidate
	baseline, _, err := PlanCombinedThirdFieldOffline(exe, originals)
	if err != nil {
		return zero, UnifiedNameEntCandidate{}, err
	}
	orig, ok := originals["NAME_ENT.EXN"]
	if !ok {
		return zero, UnifiedNameEntCandidate{}, fmt.Errorf("unified name entry missing NAME_ENT")
	}
	old, err := PlanNameEntThirdFieldOffline(orig)
	if err != nil {
		return zero, UnifiedNameEntCandidate{}, err
	}
	next, err := PlanUnifiedNameEntOffline(orig)
	if err != nil {
		return zero, UnifiedNameEntCandidate{}, err
	}
	actual := baseline.Overlays["NAME_ENT.EXN"]
	if len(actual) != len(old.Overlay) || len(actual) != len(next.Overlay) {
		return zero, UnifiedNameEntCandidate{}, fmt.Errorf("unified name entry overlay length mismatch")
	}
	merged := bytes.Clone(actual)
	for i, b := range next.Overlay {
		if i >= len(merged)-4 && i < len(merged)-2 {
			continue
		}
		if b == old.Overlay[i] {
			continue
		}
		if merged[i] != old.Overlay[i] {
			return zero, UnifiedNameEntCandidate{}, fmt.Errorf("unified name entry conflicts with telephone at +%#x", i)
		}
		merged[i] = b
	}
	binary.BigEndian.PutUint16(merged[len(merged)-4:], packedTableChecksum(merged))
	baseline.Overlays["NAME_ENT.EXN"] = merged
	baseline.SafeToPatch = false
	baseline.RuntimePass = false
	return baseline, next, nil
}
