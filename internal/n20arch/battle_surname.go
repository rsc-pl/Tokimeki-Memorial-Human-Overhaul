package n20arch

// The battle overlay uses a separate authenticated saved-surname copy path.
// Its adapter occupies an independently guarded code region and is composed
// only after source verification. CPU, DMA and IRQ ownership remain unproved.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	RPGCopyPC             uint32 = 0x801334FC
	RPGOriginalCopy       uint32 = 0x800AE0F0
	RPGBuffer             uint32 = 0x8015E828
	RPGNextBuffer         uint32 = 0x8015E850
	RPGMaxBytes                  = int(RPGNextBuffer - RPGBuffer)
	rpgStatusNamePC       uint32 = 0x801525CC
	rpgStatusCachedNamePC uint32 = 0x801597C4
	rpgStatusCachedName   uint32 = 0x8015E0D8
	rpgStatusDraw         uint32 = 0x8013E934
	rpgStatusStub         uint32 = OLGuardBase + 0xe0
)

type RPGOverlayPlan struct {
	Overlay            []byte
	WrapperRAM         uint32
	WrapperBytes       int
	StatusWrapperRAM   uint32
	StatusWrapperBytes int
	SafeToPatch        bool
	RuntimePass        bool
	BlockedReason      string
}

// The native status-name helper takes x, y, and a string pointer. The first
// player row has two original callers: one uses the saved surname directly;
// the other uses a short scene-local cache. The latter is eligible only when
// its complete eight-byte value equals the currently saved surname. The
// adjacent NPC row and original drawing coordinates remain unchanged.
func rpgStatusNameWrapper(romanizer uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	beq := func(x, y uint32, l string) { a.b(4, x, y, l); w(0) }
	bne := func(x, y uint32, l string) { a.b(5, x, y, l); w(0) }
	add(29, 29, -0x50)
	w(olSW(31, 29, 0x4c))
	w(olSW(4, 29, 0x40))
	w(olSW(5, 29, 0x44))
	w(olSW(6, 29, 0x48))
	add(8, 0, 0xb1)
	bne(4, 8, "retail")
	add(8, 0, 0xb3)
	bne(5, 8, "retail")
	w(olLUI(8, OLA0SurnameField))
	w(olORI(8, 8, OLA0SurnameField))
	// The direct source is already the saved field. Other pointers are
	// never trusted unless they are exactly the second retail player row.
	a.b(4, 6, 8, "convert")
	w(0)
	w(olLUI(9, rpgStatusCachedName))
	w(olORI(9, 9, rpgStatusCachedName&0xffff))
	bne(6, 9, "retail")
	w(olLW(10, 8, 0))
	w(olLW(11, 6, 0))
	w(0) // R3000A load delay before comparison.
	bne(10, 11, "retail")
	w(olLW(10, 8, 4))
	w(olLW(11, 6, 4))
	w(0) // R3000A load delay before comparison.
	bne(10, 11, "retail")
	w(0)
	a.label("convert")
	w(olAddu(4, 8, 0)) // Always convert current saved surname, never the cache.
	add(5, 29, 0x20)
	add(6, 0, 16)
	w(jalWord(romanizer))
	add(7, 0, 3)
	// Count includes NUL; accept only 2..14 Latin glyph bytes in pairs.
	add(8, 2, -1)
	w(olSLTIU(9, 8, 2))
	bne(9, 0, "retail")
	w(olSLTIU(9, 8, 15))
	beq(9, 0, "retail")
	w(olIType(0x0c, 8, 9, 1))
	bne(9, 0, "retail")
	add(10, 29, 0x20)
	a.label("pairs")
	w(olLBU(11, 10, 0))
	add(10, 10, 1)
	add(11, 11, -0xa0)
	w(olSLTIU(9, 11, 0x5b))
	beq(9, 0, "retail")
	add(8, 8, -1)
	bne(8, 0, "pairs")
	w(olLBU(9, 10, 0))
	w(0)
	bne(9, 0, "retail")
	add(6, 29, 0x20)
	beq(0, 0, "draw")
	a.label("retail")
	w(olLW(6, 29, 0x48))
	w(0)
	a.label("draw")
	w(olLW(4, 29, 0x40))
	w(olLW(5, 29, 0x44))
	w(jalWord(rpgStatusDraw))
	w(0)
	w(olLW(31, 29, 0x4c))
	w(0)
	w(olJR(31))
	add(29, 29, 0x50)
	a.resolve()
	return words(a.words...)
}

// The guest has already formed a0=0x8015E828 and a1=0x800E6354.
// The converter never writes to the shared RPG buffer on failure: it writes
// to this adapter's stack-local staging area, validates NUL and length,
// then copies at most 32 bytes (including NUL) into the 40-byte slot.
func rpgSavedSurnameRPGCopyWrapper(romanizer uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	bne := func(x, y uint32, l string) { a.b(5, x, y, l); w(0) }
	beq := func(x, y uint32, l string) { a.b(4, x, y, l); w(0) }
	jump := func(l string) { beq(0, 0, l) }
	add(29, 29, -0x80)
	w(olSW(31, 29, 0x7c))
	w(olSW(16, 29, 0x70))
	w(olSW(17, 29, 0x74))
	w(olSW(18, 29, 0x78))
	mov(16, 4)
	mov(17, 5)
	w(olLUI(8, RPGBuffer))
	w(olORI(8, 8, RPGBuffer))
	bne(16, 8, "fallback")
	w(olLUI(8, OLA0SurnameField))
	w(olORI(8, 8, OLA0SurnameField))
	bne(17, 8, "fallback")
	mov(4, 17)
	add(5, 29, 0x20)
	add(6, 0, 0x20)
	add(7, 0, 3)
	w(jalWord(romanizer))
	w(0)
	beq(2, 0, "fallback")
	mov(18, 2)
	w(olSLTIU(8, 18, 33))
	beq(8, 0, "fallback")
	// An encoded surname must be at least one complete glyph pair followed
	// by NUL. The return count includes NUL, hence it must be odd (3..31).
	// This also prevents a NUL-only or partially packed output from
	// replacing the live battle name with a blank or malformed string.
	add(8, 18, -1)
	w(olSLTIU(9, 8, 2))
	bne(9, 0, "fallback")
	w(olIType(0x0c, 8, 9, 1))
	bne(9, 0, "fallback")
	add(8, 29, 0x20)
	w(olAddu(8, 8, 18))
	w(olLBU(9, 8, -1))
	w(0)
	bne(9, 0, "fallback")
	// Validate the entire paired Latin glyph alphabet before committing
	// anything into the 40-byte retail battle slot. An unexpected byte
	// is a retail fallback, never a partially written translated name.
	add(10, 29, 0x20)
	add(8, 18, -1)
	a.label("validate")
	w(olLBU(11, 10, 0))
	w(0) // R3000A load delay
	add(11, 11, -0xa0)
	w(olSLTIU(9, 11, 0x5b))
	beq(9, 0, "fallback")
	add(10, 10, 1)
	add(8, 8, -1)
	bne(8, 0, "validate")
	mov(10, 0)
	a.label("copy")
	beq(10, 18, "success")
	w(olAddu(8, 29, 10))
	w(olLBU(9, 8, 0x20))
	w(0)
	w(olAddu(8, 16, 10))
	w(olSB(9, 8, 0))
	add(10, 10, 1)
	jump("copy")
	a.label("success")
	mov(2, 16)
	jump("restore")
	a.label("fallback")
	mov(4, 16)
	mov(5, 17)
	w(jalWord(RPGOriginalCopy))
	w(0)
	a.label("restore")
	w(olLW(18, 29, 0x78))
	w(0)
	w(olLW(17, 29, 0x74))
	w(0)
	w(olLW(16, 29, 0x70))
	w(0)
	w(olLW(31, 29, 0x7c))
	w(0)
	w(olJR(31))
	add(29, 29, 0x80)
	a.resolve()
	return words(a.words...), nil
}

// PlanRPGSurnameOverlay composes the supplied English RPG
// overlay only after validating its original callsite, its original writable
// name slot and its *already installed* formatter bridge C10 carrier. Both modules occupy
// disjoint original-zero regions. No save, translation or other overlay edits.
func PlanRPGSurnameOverlay(retailRPG, currentRPG []byte) (RPGOverlayPlan, error) {
	var out RPGOverlayPlan
	if len(retailRPG) != OverlayLoadSectors*2048 || sha(retailRPG) != OverlaySHA["RPG_BAT.EXN"] {
		return out, fmt.Errorf("battle surname original RPG_BAT authentication failed")
	}
	if len(currentRPG) != len(retailRPG) || binary.BigEndian.Uint16(currentRPG[len(currentRPG)-4:]) != packedTableChecksum(currentRPG) {
		return out, fmt.Errorf("battle surname current RPG_BAT size/checksum invalid")
	}
	off := int(RPGCopyPC - OverlaySlotBase)
	if binary.LittleEndian.Uint32(retailRPG[off:]) != jalWord(RPGOriginalCopy) ||
		binary.LittleEndian.Uint32(retailRPG[off+4:]) != 0x02002025 ||
		!bytes.Equal(retailRPG[off-16:off], currentRPG[off-16:off]) ||
		!bytes.Equal(retailRPG[off:off+8], currentRPG[off:off+8]) {
		return out, fmt.Errorf("battle surname original RPG surname strcpy ABI/preimage drift")
	}
	statusOff := int(rpgStatusNamePC - OverlaySlotBase)
	cachedOff := int(rpgStatusCachedNamePC - OverlaySlotBase)
	drawOff := int(rpgStatusDraw - OverlaySlotBase)
	// The first call is the saved surname, the second is an indexed
	// NPC name at y+16. The original draw helper forwards a2 to a3
	// and immediately calls the resident text queue with mode zero.
	if !bytes.Equal(retailRPG[statusOff-20:statusOff+8], currentRPG[statusOff-20:statusOff+8]) ||
		!bytes.Equal(retailRPG[statusOff-20:statusOff+8], words(0x3c01800e, 0x3c06800e, 0xa02062ba, 0x24c66354, 0x240400b1, jalWord(rpgStatusDraw), 0x240500b3)) {
		return out, fmt.Errorf("battle status name caller preimage drift")
	}
	// The second player row renders an eight-byte cached name at precisely
	// the same position. The cache can differ from the current save; the
	// wrapper checks exact equality at runtime and falls back on mismatch.
	if !bytes.Equal(retailRPG[cachedOff-12:cachedOff+8], currentRPG[cachedOff-12:cachedOff+8]) ||
		!bytes.Equal(retailRPG[cachedOff-12:cachedOff+8], words(
			0x3c068016, 0x24c6e0d8, 0x240400b1, jalWord(rpgStatusDraw), 0x240500b3)) ||
		binary.LittleEndian.Uint32(retailRPG[cachedOff+4:]) != 0x240500b3 ||
		!bytes.Equal(retailRPG[cachedOff+8:cachedOff+0x4c], currentRPG[cachedOff+8:cachedOff+0x4c]) {
		return out, fmt.Errorf("battle cached status-name caller or adjacent NPC row drift")
	}
	if !bytes.Equal(retailRPG[drawOff:drawOff+0x48], currentRPG[drawOff:drawOff+0x48]) ||
		!bytes.Equal(retailRPG[statusOff+8:statusOff+0x4c], currentRPG[statusOff+8:statusOff+0x4c]) {
		return out, fmt.Errorf("battle status name draw helper or adjacent NPC row drift")
	}
	if !allZero(retailRPG[OLPayloadFileOff:OLPayloadEndOff]) || !allZero(currentRPG[OLPayloadFileOff:OLPayloadEndOff]) ||
		bytes.IndexByte(retailRPG[RPGBuffer-OverlaySlotBase:RPGNextBuffer-OverlaySlotBase], 0) < 0 {
		return out, fmt.Errorf("battle surname code reserve occupied or 40-byte RPG name-buffer not terminated")
	}
	if !formatterBridgeVerified(currentRPG[SlotOff:C10DistributedSourceEnd]) {
		return out, fmt.Errorf("battle surname requires authenticated formatter bridge resident C10 carrier")
	}
	module, err := BuildOverlayLocalModule()
	if err != nil {
		return out, err
	}
	if len(module.Body)%16 != 0 {
		return out, fmt.Errorf("battle surname N6 body not aligned")
	}
	out.WrapperRAM = OLBodyBase + uint32(len(module.Body))
	helper, err := rpgSavedSurnameRPGCopyWrapper(OLBodyBase)
	if err != nil {
		return out, err
	}
	out.WrapperBytes = len(helper)
	module.Body = append(module.Body, helper...)
	for len(module.Body)%16 != 0 {
		module.Body = append(module.Body, 0)
	}
	out.StatusWrapperRAM = OLBodyBase + uint32(len(module.Body))
	statusHelper := rpgStatusNameWrapper(OLBodyBase)
	out.StatusWrapperBytes = len(statusHelper)
	module.Body = append(module.Body, statusHelper...)
	for len(module.Body)%16 != 0 {
		module.Body = append(module.Body, 0)
	}
	if len(module.Body) > OLBodyCapacity {
		return out, fmt.Errorf("battle surname wrapper cannot fit in RPG N6 code reserve: %d > %d", len(module.Body), OLBodyCapacity)
	}
	module.BodyLen = len(module.Body)
	module.Sum32 = 0
	module.XOR32 = 0
	for i := 0; i < len(module.Body); i += 4 {
		v := binary.LittleEndian.Uint32(module.Body[i:])
		module.Sum32 += v
		module.XOR32 ^= v
	}
	binary.LittleEndian.PutUint32(module.Guard[4:], uint32(module.BodyLen))
	binary.LittleEndian.PutUint32(module.Guard[8:], module.Sum32)
	binary.LittleEndian.PutUint32(module.Guard[12:], module.XOR32)
	v, err := buildOverlayVerifier(module.Sum32, module.XOR32, uint32(module.BodyLen))
	if err != nil {
		return out, err
	}
	if len(v) != module.VerifierBytes {
		return out, fmt.Errorf("battle surname N6 verifier length drift")
	}
	copy(module.Guard[OLVerifierRAM-OLGuardBase:], v)
	stub, err := buildDispatchStub(RPGOriginalCopy, out.WrapperRAM)
	if err != nil {
		return out, err
	}
	copy(module.Guard[OLStubRAM-OLGuardBase:], stub)
	statusStub, err := buildDispatchStub(rpgStatusDraw, out.StatusWrapperRAM)
	if err != nil || OLVerifierRAM+uint32(len(v)) != rpgStatusStub ||
		len(statusStub) > int(OLBodyBase-rpgStatusStub) ||
		!allZero(module.Guard[rpgStatusStub-OLGuardBase:]) {
		return out, fmt.Errorf("battle status name verified guard tail does not fit: %v", err)
	}
	copy(module.Guard[rpgStatusStub-OLGuardBase:], statusStub)
	out.Overlay = bytes.Clone(currentRPG)
	copy(out.Overlay[OLPayloadFileOff:OLGuardFileEnd], module.Guard)
	copy(out.Overlay[OLBodyFileOff:OLBodyFileOff+len(module.Body)], module.Body)
	binary.LittleEndian.PutUint32(out.Overlay[off:], jalWord(OLStubRAM))
	binary.LittleEndian.PutUint32(out.Overlay[statusOff:], jalWord(rpgStatusStub))
	binary.LittleEndian.PutUint32(out.Overlay[cachedOff:], jalWord(rpgStatusStub))
	binary.BigEndian.PutUint16(out.Overlay[len(out.Overlay)-4:], packedTableChecksum(out.Overlay))
	for i := range out.Overlay {
		if out.Overlay[i] == currentRPG[i] {
			continue
		}
		if (i >= OLPayloadFileOff && i < OLPayloadEndOff) || (i >= off && i < off+4) || (i >= statusOff && i < statusOff+4) || (i >= cachedOff && i < cachedOff+4) || (i >= len(out.Overlay)-4 && i < len(out.Overlay)-2) {
			continue
		}
		return RPGOverlayPlan{}, fmt.Errorf("battle surname unowned RPG byte changed %#x", i)
	}
	out.BlockedReason = "battle surname adapter: verified per-overlay code and 40B source buffer, but live display/CPU/DMA/IRQ ownership and exact battle frame still unverified; safe_to_patch=false, runtime_pass=false"
	return out, nil
}
