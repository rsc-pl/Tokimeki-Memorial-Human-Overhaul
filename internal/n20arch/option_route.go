package n20arch

// N20-OPTION: source-authenticated, overlay-owned activity/name UI route.
// This is an OFFLINE candidate. OPTION has two name-label groups whose queue
// callsites directly pass the saved surname/given as a3. Both groups share a
// single in-overlay guarded romanizer; nickname calls remain untouched.
// Nothing in this file edits a retail image, modifies the public builder, or
// asserts that the queue copies its argument synchronously in actual gameplay.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	optionQueueRetail uint32 = 0x8004E788
	optionMagic       uint32 = 0x00004F4E // "NO" distinct from N6/NF
	optionShimFrame   int16  = 0x60
	optionScratchOff  int16  = 0x20
	optionRAOff       int16  = 0x5c
)

// Each source JAL passes the pointer loaded by the two preceding instructions.
// The second group uses a different window code, not a different name source.
var optionNameSites = []struct {
	Off    int
	Source uint32
}{
	{0x878C, OLA0SurnameField}, {0x87A8, OLFieldPrepSavedGiv},
	{0x8EB0, OLA0SurnameField}, {0x8ECC, OLFieldPrepSavedGiv},
}

// OptionNameCandidate is separate from the integrated N20 planner until its
// queue lifetime and runtime behavior have been verified. It must NOT be
// silently added to the human-overhaul image builder merely because it fits.
type OptionNameCandidate struct {
	Guard     []byte
	Body      []byte
	Overlay   []byte
	Words     []n20RelocWord
	BodyBytes int
	SHA       string
}

func buildOptionQueueShim(romanizer uint32) ([]byte, error) {
	return buildOptionQueueShimVariant(romanizer, false)
}

// nickname opt-in variation; baseline telephone bytes remain exactly unchanged.
func buildOptionQueueShimVariant(romanizer uint32, includeNickname bool) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	add := func(d, s uint32, v int16) { w(olADDIU(d, s, v)) }
	save := func(r uint32, off int16) { w(olSW(r, 29, off)) }
	load := func(r uint32, off int16) { w(olLW(r, 29, off)) }
	luiAddr := func(r, addr uint32) { w(olLUI(r, addr)); w(olORI(r, r, addr&0xffff)) }
	add(29, 29, -optionShimFrame)
	save(31, optionRAOff)
	for i, r := range []uint32{16, 17, 18, 19, 20} {
		save(r, int16(0x40+4*i))
	}
	mov(16, 4)
	mov(17, 5)
	mov(18, 6)
	mov(19, 7)
	// This is an exact pointer gate, not a generic queue hook. Never change
	// nickname or unrelated dialogue strings that happen to use this queue.
	luiAddr(8, OLA0SurnameField)
	a.b(4, 19, 8, "convert")
	w(0)
	luiAddr(8, OLFieldPrepSavedGiv)
	if includeNickname {
		a.b(4, 19, 8, "convert")
		w(0)
		// Exact third player field only: independent nickname, no dialog scan.
		luiAddr(8, 0x800E6364)
	}
	a.b(5, 19, 8, "retail")
	w(0)
	a.label("convert")
	mov(4, 19)
	add(5, 29, optionScratchOff)
	add(6, 0, 16)
	add(7, 0, 3) // exactly three saved kana, no guessed honorific
	w(jalWord(romanizer))
	w(0)
	a.b(4, 2, 0, "retail")
	w(0)
	w(olSLTIU(1, 2, 16))
	a.b(4, 1, 0, "retail")
	w(0)
	add(20, 29, optionScratchOff)
	a.b(4, 0, 0, "queue")
	w(0)
	a.label("retail")
	mov(20, 19)
	a.label("queue")
	mov(4, 16)
	mov(5, 17)
	mov(6, 18)
	mov(7, 20)
	// The retail callsite delay slot stores the fifth argument (zero) at
	// old_sp+0x10. The nested queue call uses OUR sp, so reproduce it.
	// Otherwise retail queue observes arbitrary shim-frame contents.
	w(olSW(0, 29, 0x10))
	w(jalWord(optionQueueRetail))
	w(0)
	save(2, 0x38)
	save(3, 0x3c)
	load(31, optionRAOff)
	for i, r := range []uint32{16, 17, 18, 19, 20} {
		load(r, int16(0x40+4*i))
	}
	load(2, 0x38)
	load(3, 0x3c)
	w(olJR(31))
	add(29, 29, optionShimFrame)
	a.resolve()
	return words(a.words...), nil
}

func PlanOptionNameCandidate(option []byte) (OptionNameCandidate, error) {
	var p OptionNameCandidate
	if len(option) != OverlayLoadSectors*2048 || sha(option) != OverlaySHA["OPTION.EXN"] {
		return p, fmt.Errorf("OPTION original authenticity refused")
	}
	if option[len(option)-2] != 0x12 || option[len(option)-1] != 0x10 || packedTableChecksum(option) != binary.BigEndian.Uint16(option[len(option)-4:]) {
		return p, fmt.Errorf("OPTION trailer/checksum refused")
	}
	if !bytes.Equal(option[OLPayloadFileOff:OLPayloadEndOff], make([]byte, OLPayloadEndOff-OLPayloadFileOff)) {
		return p, fmt.Errorf("OPTION module slot is not empty")
	}
	for _, site := range optionNameSites {
		if binary.LittleEndian.Uint32(option[site.Off:]) != jalWord(optionQueueRetail) || binary.LittleEndian.Uint32(option[site.Off+4:]) != 0xAFA00010 {
			return p, fmt.Errorf("OPTION queue/delay mismatch at %x", site.Off)
		}
		if binary.LittleEndian.Uint32(option[site.Off-16:]) != olADDIU(7, 7, int16(site.Source&0xffff)) || binary.LittleEndian.Uint32(option[site.Off-20:]) != olLUI(7, site.Source) {
			return p, fmt.Errorf("OPTION a3 name source mismatch at %x", site.Off)
		}
	}
	r, err := BuildN20PackedRomanizer(OLBodyBase)
	if err != nil {
		return p, err
	}
	shimRAM := align16(OLBodyBase + uint32(len(r.Binary)))
	s, err := buildOptionQueueShim(OLBodyBase)
	if err != nil {
		return p, err
	}
	p.Body = make([]byte, int(shimRAM-OLBodyBase)+len(s))
	copy(p.Body, r.Binary)
	copy(p.Body[int(shimRAM-OLBodyBase):], s)
	for len(p.Body)%16 != 0 {
		p.Body = append(p.Body, 0)
	}
	if len(p.Body) > OLBodyCapacity {
		return OptionNameCandidate{}, fmt.Errorf("OPTION module %d exceeds overlay-owned %d", len(p.Body), OLBodyCapacity)
	}
	p.BodyBytes = len(p.Body)
	var sum, xor uint32
	for off := 0; off < len(p.Body); off += 4 {
		x := binary.LittleEndian.Uint32(p.Body[off:])
		sum += x
		xor ^= x
	}
	p.Guard = make([]byte, OLGuardBytes)
	binary.LittleEndian.PutUint32(p.Guard[0:], optionMagic)
	binary.LittleEndian.PutUint32(p.Guard[4:], uint32(len(p.Body)))
	binary.LittleEndian.PutUint32(p.Guard[8:], sum)
	binary.LittleEndian.PutUint32(p.Guard[12:], xor)
	stub, err := buildDispatchStub(optionQueueRetail, shimRAM)
	if err != nil {
		return OptionNameCandidate{}, err
	}
	verifier, err := buildOverlayVerifierMagic(optionMagic, sum, xor, uint32(len(p.Body)))
	if err != nil {
		return OptionNameCandidate{}, err
	}
	if int(OLVerifierRAM-OLGuardBase)+len(verifier) > OLGuardBytes {
		return OptionNameCandidate{}, fmt.Errorf("OPTION verifier out of guard")
	}
	copy(p.Guard[OLStubRAM-OLGuardBase:], stub)
	copy(p.Guard[OLVerifierRAM-OLGuardBase:], verifier)
	p.Overlay = bytes.Clone(option)
	copy(p.Overlay[OLPayloadFileOff:], p.Guard)
	copy(p.Overlay[OLBodyFileOff:], p.Body)
	for _, site := range optionNameSites {
		old := binary.LittleEndian.Uint32(p.Overlay[site.Off:])
		nw := jalWord(OLStubRAM)
		binary.LittleEndian.PutUint32(p.Overlay[site.Off:], nw)
		p.Words = append(p.Words, n20RelocWord{Owner: "OPTION.EXN", PC: OverlaySlotBase + uint32(site.Off), Old: old, New: nw, Kind: "overlay_local_option_name", Role: fmt.Sprintf("direct a3 source 0x%08x", site.Source)})
	}
	binary.BigEndian.PutUint16(p.Overlay[len(p.Overlay)-4:], packedTableChecksum(p.Overlay))
	p.SHA = sha(p.Overlay)
	return p, nil
}

// DirectSavedNameQueueSite is an independently decoded overlay-owned JAL
// whose immediately preceding basic-block instructions load saved player-name
// bytes into a3. This is NOT a claim that the visible scene is reached or
// that the original queue owns/copies any replacement buffer.
type DirectSavedNameQueueSite struct {
	Overlay string `json:"overlay"`
	PC      uint32 `json:"pc"`
	Source  uint32 `json:"source"`
	Field   string `json:"field"`
	Delay   uint32 `json:"delay_word"`
}

func ScanDirectSavedNameQueueSites(overlays map[string][]byte) ([]DirectSavedNameQueueSite, error) {
	if len(overlays) != len(OverlaySHA) {
		return nil, fmt.Errorf("expected %d authenticated overlays, got %d", len(OverlaySHA), len(overlays))
	}
	keys := make([]string, 0, len(OverlaySHA))
	for name := range OverlaySHA {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	var sites []DirectSavedNameQueueSite
	for _, name := range keys {
		data, ok := overlays[name]
		if !ok || len(data) != OverlayLoadSectors*2048 || sha(data) != OverlaySHA[name] {
			return nil, fmt.Errorf("unauthenticated %s", name)
		}
		for off := 20; off < 0x2D000-8; off += 4 {
			if binary.LittleEndian.Uint32(data[off:]) != jalWord(optionQueueRetail) {
				continue
			}
			if binary.LittleEndian.Uint32(data[off-20:]) != olLUI(7, OLA0SurnameField) {
				continue
			}
			w := binary.LittleEndian.Uint32(data[off-16:])
			var field string
			var address uint32
			switch w {
			case olADDIU(7, 7, int16(OLA0SurnameField&0xffff)):
				field = "surname"
				address = OLA0SurnameField
			case olADDIU(7, 7, int16(OLFieldPrepSavedGiv&0xffff)):
				field = "given"
				address = OLFieldPrepSavedGiv
			case olADDIU(7, 7, 0x6364):
				field = "nickname"
				address = 0x800E6364
			default:
				continue
			}
			sites = append(sites, DirectSavedNameQueueSite{Overlay: name, PC: OverlaySlotBase + uint32(off), Source: address, Field: field, Delay: binary.LittleEndian.Uint32(data[off+4:])})
		}
	}
	return sites, nil
}
