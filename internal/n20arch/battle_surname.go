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
	RPGCopyPC       uint32 = 0x801334FC
	RPGOriginalCopy uint32 = 0x800AE0F0
	RPGBuffer       uint32 = 0x8015E828
	RPGNextBuffer   uint32 = 0x8015E850
	RPGMaxBytes            = int(RPGNextBuffer - RPGBuffer)
)

type RPGPrivateCandidate struct {
	Overlay       []byte
	WrapperRAM    uint32
	WrapperBytes  int
	SafeToPatch   bool
	RuntimePass   bool
	BlockedReason string
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
	add(8, 29, 0x20)
	w(olAddu(8, 8, 18))
	w(olLBU(9, 8, -1))
	w(0)
	bne(9, 0, "fallback")
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

// PlanRPGPrivateSurname integrates into the actual private English RPG
// overlay only after validating its original callsite, its original writable
// name slot and its *already installed* formatter bridge C10 carrier. Both modules occupy
// disjoint original-zero regions. No save, translation or other overlay edits.
func PlanRPGPrivateSurname(retailRPG, currentRPG []byte) (RPGPrivateCandidate, error) {
	var out RPGPrivateCandidate
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
	out.Overlay = bytes.Clone(currentRPG)
	copy(out.Overlay[OLPayloadFileOff:OLGuardFileEnd], module.Guard)
	copy(out.Overlay[OLBodyFileOff:OLBodyFileOff+len(module.Body)], module.Body)
	binary.LittleEndian.PutUint32(out.Overlay[off:], jalWord(OLStubRAM))
	binary.BigEndian.PutUint16(out.Overlay[len(out.Overlay)-4:], packedTableChecksum(out.Overlay))
	for i := range out.Overlay {
		if out.Overlay[i] == currentRPG[i] {
			continue
		}
		if (i >= OLPayloadFileOff && i < OLPayloadEndOff) || (i >= off && i < off+4) || (i >= len(out.Overlay)-4 && i < len(out.Overlay)-2) {
			continue
		}
		return RPGPrivateCandidate{}, fmt.Errorf("battle surname unowned RPG byte changed %#x", i)
	}
	out.BlockedReason = "battle surname private battle surname adapter: verified per-overlay code and 40B source buffer, but live display/CPU/DMA/IRQ ownership and exact battle frame still unverified; safe_to_patch=false, runtime_pass=false"
	return out, nil
}
