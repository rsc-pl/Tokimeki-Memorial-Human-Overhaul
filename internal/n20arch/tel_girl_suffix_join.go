package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// These caller-owned fields are composed by the original character-name
// producer, not by the resident G/P script expansion. The three authenticated
// callers use two distinct 32-byte local fields; neither saved player names
// nor the generic NPC renderer is modified.
const (
	telGirlSuffixShimOffset       = 0x900
	telGirlSuffixShim             = telPAddressShim + telGirlSuffixShimOffset
	telGirlSuffixFrame      int16 = 0x40
)

type telGirlSuffixSite struct {
	pc, fragment, rendered uint32
	delay                  uint32
	destination            int16
}

var telGirlSuffixSites = [...]telGirlSuffixSite{
	{0x80133fcc, 0x8013ea60, 0x80134010, 0x2405000c, 0x3c},
	{0x80133fe0, 0x8013ea60, 0x80134010, 0x00c02825, 0x3c},
	{0x8013b204, 0x8013fbe4, 0x8013b230, 0x00402825, 0x34},
}

func telGirlSuffixSource(retail []byte) error {
	if len(retail) != 196608 || sha(retail) != OverlaySHA["TEL.EXN"] {
		return fmt.Errorf("TEL character name: source identity mismatch")
	}
	at := func(pc uint32) int { return int(pc - OverlaySlotBase) }
	for _, s := range telGirlSuffixSites {
		if binary.LittleEndian.Uint32(retail[at(s.pc):]) != jalWord(0x80051438) ||
			binary.LittleEndian.Uint32(retail[at(s.pc)+4:]) != s.delay ||
			binary.LittleEndian.Uint32(retail[at(s.rendered):]) != jalWord(map[bool]uint32{true: 0x80050e8c, false: 0x80051010}[s.destination == 0x34]) {
			return fmt.Errorf("TEL character name: producer/consumer drift at %#x", s.pc)
		}
		if s.fragment != 0 {
			data := retail[at(s.fragment):]
			if len(data) < 4 || data[0] != 0x82 && s.fragment == 0x8013ea60 {
				return fmt.Errorf("TEL character name: source fragment drift at %#x", s.fragment)
			}
		}
	}
	for pc, word := range map[uint32]uint32{
		0x80133ff8: 0x3c058014, 0x80133ffc: 0x24a5ea60,
		0x80134000: jalWord(0x800ae100), 0x80134004: 0x02002025,
		0x8013b1e8: 0x3c058014, 0x8013b1ec: 0x24a5fbe4,
		0x8013b210: jalWord(0x800ae100), 0x8013b214: 0x27a50034,
		0x8013b218: 0x3c058014, 0x8013b21c: 0x24a5fc00,
		0x8013b220: jalWord(0x800ae100),
	} {
		if binary.LittleEndian.Uint32(retail[at(pc):]) != word {
			return fmt.Errorf("TEL character name: adjacent source flow drift at %#x", pc)
		}
	}
	return nil
}

// The native producer already chose the correct character and honorific.
// Only a complete odd-width Latin name followed by its pair-font pad,
// encoded -san and NUL is normalized. The pad is rotated behind the suffix
// in the same buffer; no length, relationship or native fallback is changed.
func telGirlSuffixPayload() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	lw := func(d, b uint32, n int16) { w(olLW(d, b, n)); w(0) }
	lbu := func(d, b uint32, n int16) { w(olLBU(d, b, n)); w(0) }
	sw := func(d, b uint32, n int16) { w(olSW(d, b, n)) }
	sb := func(d, b uint32, n int16) { w(olSB(d, b, n)) }
	beq := func(r, s uint32, l string) { a.b(4, r, s, l); w(0) }
	bne := func(r, s uint32, l string) { a.b(5, r, s, l); w(0) }
	add(29, 29, -telGirlSuffixFrame)
	sw(31, 29, 0x20)
	sw(4, 29, 0x24)
	w(jalWord(0x80051438))
	w(0)
	sw(2, 29, 0x28)
	sw(3, 29, 0x2c)
	lw(8, 29, 0x20) // caller return PC authenticated independently
	lw(9, 29, 0x24) // destination originally passed to the producer
	for i, s := range telGirlSuffixSites {
		w(olLUI(10, s.pc+8))
		w(olORI(10, 10, (s.pc+8)&0xffff))
		bne(8, 10, fmt.Sprintf("next_%d", i))
		add(10, 29, int16(telGirlSuffixFrame+s.destination))
		bne(9, 10, "return")
		beq(0, 0, "scan_start")
		a.label(fmt.Sprintf("next_%d", i))
	}
	beq(0, 0, "return")
	a.label("scan_start")
	w(olAddu(8, 9, 0)) // scan pointer
	add(10, 0, 0)      // number of Latin letters
	a.label("scan")
	lbu(11, 8, 0)
	add(12, 0, 0xa0)
	beq(11, 12, "pad")
	// Case-fold the game's one-byte Latin glyphs and accept A-Z only.
	w(olIType(0x0c, 11, 12, 0xdf))
	add(12, 12, -0xc1)
	w(olSLTIU(13, 12, 26))
	beq(13, 0, "return")
	add(10, 10, 1)
	w(olSLTIU(13, 10, 16))
	beq(13, 0, "return")
	add(8, 8, 1)
	beq(0, 0, "scan")
	a.label("pad")
	beq(10, 0, "return")
	w(olIType(0x0c, 10, 13, 1))
	beq(13, 0, "return")
	for i, want := range []uint8{0xa0, 0xad, 0xf3, 0xe1, 0xee, 0} {
		lbu(11, 8, int16(i))
		add(12, 0, int16(want))
		bne(11, 12, "return")
	}
	for i, value := range []uint8{0xad, 0xf3, 0xe1, 0xee, 0xa0} {
		add(11, 0, int16(value))
		sb(11, 8, int16(i))
	}
	a.label("return")
	lw(2, 29, 0x28)
	lw(3, 29, 0x2c)
	lw(31, 29, 0x20)
	w(olJR(31))
	add(29, 29, telGirlSuffixFrame)
	a.resolve()
	a.resolveJLabels(telGirlSuffixShim)
	result := words(a.words...)
	if len(result) > telPAddressWindow-telGirlSuffixShimOffset {
		return nil, fmt.Errorf("TEL character name: local reservation exceeded: %d", len(result))
	}
	return result, nil
}

func telGirlSuffixPatch(original, composed []byte) error {
	if err := telGirlSuffixSource(original); err != nil {
		return err
	}
	if len(composed) != len(original) {
		return fmt.Errorf("TEL character name: carrier size mismatch")
	}
	for _, site := range telGirlSuffixSites {
		off := int(site.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(0x80051438) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != site.delay {
			return fmt.Errorf("TEL character name: staged preimage drift at %#x", site.pc)
		}
		binary.LittleEndian.PutUint32(composed[off:], jalWord(telGirlSuffixShim))
	}
	return nil
}

func telGirlSuffixVerify(original, composed []byte) error {
	if err := telGirlSuffixSource(original); err != nil {
		return err
	}
	for _, site := range telGirlSuffixSites {
		off := int(site.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telGirlSuffixShim) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != site.delay {
			return fmt.Errorf("TEL character name: installed call drift at %#x", site.pc)
		}
	}
	body, err := telGirlSuffixPayload()
	if err != nil {
		return err
	}
	start := telPAddressFileOff + telGirlSuffixShimOffset
	if !bytes.Equal(composed[start:start+len(body)], body) {
		return fmt.Errorf("TEL character name: installed body drift")
	}
	return nil
}
