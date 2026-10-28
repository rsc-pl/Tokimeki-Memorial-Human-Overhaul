package n20arch

// overlay loading: authenticated, bounded CPU-side NAME_ENT overlay-load preflight.
// This is not a proof of DMA/IRQ/cache/GPU lifetime or runtime playability.
// Both the scene selector and the 96-sector read must be verified against
// the retail executable before treating local NAME_ENT code as load-backed.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	NameEntLBA uint32 = 0x95EA
	OptionLBA  uint32 = 0x976A
	OLHLBA     uint32 = 0x96AA
)

type NameEntLoadAudit struct {
	SectorCount           int
	OverlayBytes          int
	LoadBase              uint32
	LoadEnd               uint32
	NameEntScenes         []byte
	ActivityOptionScenes  []byte
	ActivityOLHScene      byte
	KeyboardCalls         int
	LocalCodeWithinLoad   bool
	OriginalKanaUnchanged bool
	CPUOnly               bool
	RuntimePass           bool
	SafeToPatch           bool
}

func AuditNameEntLoadBoundary(exe, original, candidate []byte) (NameEntLoadAudit, error) {
	var a NameEntLoadAudit
	if _, err := VerifyRetailEXE(exe); err != nil {
		return a, fmt.Errorf("overlay loading original EXE: %w", err)
	}
	if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA["NAME_ENT.EXN"] {
		return a, fmt.Errorf("overlay loading unauthenticated NAME_ENT source")
	}
	if len(candidate) != len(original) {
		return a, fmt.Errorf("overlay loading candidate load length mismatch")
	}
	// Source-grounded loader: the NAME_ENT case sets LBA=0x95EA,
	// 96 sectors at 0x800B6D38, and joins the common CD-read state machine.
	for _, witness := range []struct{ pc, word uint32 }{
		{0x80078E88, 0x340695EA}, // ori a2,zero,0x95EA (prior branch delay)
		{0x80078E8C, 0x240C0060}, // addiu t4,zero,96
		{0x80078E90, 0x3C01800B}, // lui at,0x800B
		{0x80078E94, 0xA02C6D38}, // sb t4,0x6D38(at)
		{0x80078E98, 0x1000003B}, // join the common request path
		{0x80078F8C, 0x24040060}, // read request size = 96
		{0x80078FBC, 0x0C0118C6}, // CD read
		{0x8007902C, 0x0C0118DB}, // completion polling
		{0x80079044, 0x0C010916}, // cache flush
		{0x80078A74, 0x0C01E41C}, // state-3 scene dispatch
		{0x80078C74, 0xAC2E6D3C}, // physical overlay destination
	} {
		if got := wordAt(exe, witness.pc); got != witness.word {
			return a, fmt.Errorf("overlay loading loader witness drift at %#x: %#x, expected %#x", witness.pc, got, witness.word)
		}
	}
	scenes := SceneSlots(exe)
	expected := map[byte]uint32{17: NameEntLBA, 19: NameEntLBA, 20: NameEntLBA, 21: NameEntLBA,
		32: OptionLBA, 33: OptionLBA, 34: OptionLBA, 58: OLHLBA}
	for _, s := range scenes {
		lba, has := expected[s.Scene]
		if !has {
			continue
		}
		if !s.Loads || s.LBA != lba || s.Entry < OverlaySlotBase || s.Entry >= OverlaySlotEnd {
			return a, fmt.Errorf("overlay loading scene %d maps to %#x, loads=%v, entry=%#x", s.Scene, s.LBA, s.Loads, s.Entry)
		}
		switch s.Scene {
		case 17, 19, 20, 21:
			a.NameEntScenes = append(a.NameEntScenes, s.Scene)
		case 32, 33, 34:
			a.ActivityOptionScenes = append(a.ActivityOptionScenes, s.Scene)
		case 58:
			a.ActivityOLHScene = s.Scene
		}
	}
	if len(a.NameEntScenes) != 4 || len(a.ActivityOptionScenes) != 3 || a.ActivityOLHScene != 58 {
		return a, fmt.Errorf("overlay loading scene mapping incomplete")
	}
	a.SectorCount = OverlayLoadSectors
	a.OverlayBytes = len(original)
	a.LoadBase = OverlaySlotBase
	a.LoadEnd = OverlaySlotBase + uint32(len(original))
	// These are the installed local regions actually consumed by the native name entry
	// keyboard path and unified name entry presenters. Never infer safety from zero bytes.
	regions := [][2]int{
		{nameEntryDrawGlyphAtlasFileOff, nameEntryDrawGlyphAtlasFileOff + GlyphCount*18},
		{UnifiedEntryNameEntOff, UnifiedEntryNameEntOff + UnifiedEntryNameEntBytes},
		{AliasResolverOff, SelectorOff + 0x100},
	}
	for _, region := range regions {
		if region[0] < 0 || region[1] > len(candidate) || region[0] >= region[1] {
			return a, fmt.Errorf("overlay loading local code/data outside full CD extent [%#x,%#x)", region[0], region[1])
		}
	}
	shadow, err := BuildNameEntDrawShadow(original)
	if err != nil {
		return a, err
	}
	for _, r := range shadow.Routes {
		i := int(r.QueuePC - OverlaySlotBase)
		if i < 0 || i+4 > len(candidate) || binary.LittleEndian.Uint32(candidate[i:]) != jalWord(QueueRAM) {
			return a, fmt.Errorf("overlay loading local keyboard JAL not installed at %#x", r.QueuePC)
		}
	}
	a.KeyboardCalls = len(shadow.Routes)
	if a.KeyboardCalls != 42 {
		return a, fmt.Errorf("overlay loading keyboard callsites %d != 42", a.KeyboardCalls)
	}
	if !bytes.Equal(candidate[nameEntryGridGridStart:nameEntryGridGridEnd], original[nameEntryGridGridStart:nameEntryGridGridEnd]) ||
		!bytes.Equal(candidate[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+nameEntryGridGridRows*4], original[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+nameEntryGridGridRows*4]) {
		return a, fmt.Errorf("overlay loading selectable kana modified")
	}
	a.OriginalKanaUnchanged = true
	a.LocalCodeWithinLoad = true
	a.CPUOnly = true
	a.SafeToPatch = false
	a.RuntimePass = false
	return a, nil
}
