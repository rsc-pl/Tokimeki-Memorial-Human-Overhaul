package n20arch

// entry slot: private, offline-only exact-site NAME_ENT screen-field conversion.
// The authenticated game has two alternative views, each drawing a pair of
// 8-byte player-name fields through retail 0x8004E788. entry slot redirects ONLY
// those four calls to an overlay-local converter; the third field on each
// view, all selectable kana and all memory-card source records stay intact.
// No C10 residency, original EXE change, save write or global font hook.
// This source-level candidate does not authorize a game image.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	EntrySlotNameEntOff   = 0x23000
	EntrySlotNameEntBytes = 0x1000
	EntrySlotRomOff       = EntrySlotNameEntOff + 0x100
	EntrySlotShimOff      = EntrySlotNameEntOff + 0xb00
	EntrySlotRomRAM       = OverlaySlotBase + EntrySlotRomOff
	EntrySlotShimRAM      = OverlaySlotBase + EntrySlotShimOff
)

type SlotDrawCandidate struct {
	Overlay                   []byte
	Shim                      []byte
	Romanizer                 []byte
	HookPCs                   []uint32
	ThirdFieldUntouched       bool
	OriginalNameDataUntouched bool
	SafeToPatch               bool
	RuntimePass               bool
}

var nameEntryQueueNameEntQueuePCs = []uint32{
	0x80139D3C, // first screen: displayed field A (0x800E8598 + 8*index)
	0x80139D6C, // first screen: displayed field B (0x800E8618 + 8*index)
	0x80139E60, // second screen: slot record+0x29C
	0x80139E98, // second screen: slot record+0x2A4
}

func buildSlotDrawShim(romanizer uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, v int16) { w(olADDIU(d, s, v)) }
	mv := func(d, s uint32) { w(olAddu(d, s, 0)) }
	sv := func(r uint32, o int16) { w(olSW(r, 29, o)) }
	ld := func(r uint32, o int16) { w(olLW(r, 29, o)); w(0) }
	// O32 outgoing args = 0..0x1F, separate 32B text = 0x20..0x3F;
	// saved s0-s4, output v0/v1 and ra all outside of those regions.
	add(29, 29, -0x70)
	sv(31, 0x5c)
	for i := uint32(0); i < 5; i++ {
		sv(16+i, int16(0x40+i*4))
	}
	mv(16, 4)
	mv(17, 5)
	mv(18, 6)
	mv(19, 7)
	// Suffix selector zero. Max source three CP932 kana; never rewrite src.
	mv(4, 19)
	add(5, 29, 0x20)
	add(6, 0, 32)
	add(7, 0, 3)
	w(jalWord(romanizer))
	w(0)
	a.b(4, 2, 0, "old")
	w(0)
	w(olSLTIU(8, 2, 33))
	a.b(4, 8, 0, "old")
	w(0)
	add(20, 29, 0x20)
	a.b(4, 0, 0, "call")
	w(0)
	a.label("old")
	mv(20, 19)
	a.label("call")
	mv(4, 16)
	mv(5, 17)
	mv(6, 18)
	mv(7, 20)
	w(olSW(0, 29, 0x10)) // preserve authenticated fifth queue argument
	w(jalWord(optionQueueRetail))
	w(0)
	sv(2, 0x54)
	sv(3, 0x58)
	for i := uint32(0); i < 5; i++ {
		ld(16+i, int16(0x40+i*4))
	}
	ld(2, 0x54)
	ld(3, 0x58)
	ld(31, 0x5c)
	w(olJR(31))
	add(29, 29, 0x70)
	a.resolve()
	v := words(a.words...)
	if len(v) > 0x200 {
		return nil, fmt.Errorf("entry slot adapter exceeds 512B: %d", len(v))
	}
	return v, nil
}

func PlanNameEntSlotDrawOffline(original []byte) (SlotDrawCandidate, error) {
	var out SlotDrawCandidate
	if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA["NAME_ENT.EXN"] {
		return out, fmt.Errorf("entry slot needs authenticated original NAME_ENT.EXN")
	}
	if !bytes.Equal(original[EntrySlotNameEntOff:EntrySlotNameEntOff+EntrySlotNameEntBytes], make([]byte, EntrySlotNameEntBytes)) {
		return out, fmt.Errorf("entry slot candidate local code window is not zero")
	}
	// These are four already-proven retail queue callsites. The authentic
	// surrounding instructions must match their DIFFERENT source layouts.
	// Both layouts have the exact same queue ABI (including delay slot).
	for _, pc := range nameEntryQueueNameEntQueuePCs {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(original[off:]) != jalWord(optionQueueRetail) ||
			binary.LittleEndian.Uint32(original[off+4:]) != olSW(0, 29, 0x10) {
			return out, fmt.Errorf("entry slot queue ABI drift at %#x", pc)
		}
	}
	// First view computes a3 from 8-byte stride and 0x800E7D10 base.
	// Second view computes a3 from 0xF00-byte save-slot record stride.
	for _, p := range []struct {
		pc   uint32
		lui  uint32
		addu uint32
	}{
		{0x80139D3C, 0x3c0a800e, 0x012a3821},
		{0x80139D6C, 0x3c0e800e, 0x01ae3821},
		{0x80139E60, 0x3c198012, 0x03193821},
		{0x80139E98, 0x3c0b8012, 0x014b3821},
	} {
		// source register and source address arithmetic are authenticated,
		// rather than trusting the JAL word by itself.
		off := int(p.pc - OverlaySlotBase)
		foundLUI, foundADD := false, false
		for at := off - 56; at < off; at += 4 {
			v := binary.LittleEndian.Uint32(original[at:])
			if v == p.lui {
				foundLUI = true
			}
			if v == p.addu {
				foundADD = true
			}
		}
		if !foundLUI || !foundADD {
			return out, fmt.Errorf("entry slot a3 provenance drift %#x", p.pc)
		}
	}
	r, e := BuildN20PackedRomanizer(EntrySlotRomRAM)
	if e != nil {
		return out, e
	}
	shim, e := buildSlotDrawShim(EntrySlotRomRAM)
	if e != nil {
		return out, e
	}
	if EntrySlotRomOff+len(r.Binary) > EntrySlotShimOff || EntrySlotShimOff+len(shim) > EntrySlotNameEntOff+EntrySlotNameEntBytes {
		return out, fmt.Errorf("entry slot local module exceeds source window")
	}
	d := bytes.Clone(original)
	copy(d[EntrySlotRomOff:], r.Binary)
	copy(d[EntrySlotShimOff:], shim)
	for _, pc := range nameEntryQueueNameEntQueuePCs {
		binary.LittleEndian.PutUint32(d[int(pc-OverlaySlotBase):], jalWord(EntrySlotShimRAM))
	}
	for _, pc := range []uint32{0x80139D9C, 0x80139ED0} {
		if binary.LittleEndian.Uint32(d[int(pc-OverlaySlotBase):]) != jalWord(optionQueueRetail) {
			return out, fmt.Errorf("entry slot nickname/third field changed %#x", pc)
		}
	}
	binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
	out = SlotDrawCandidate{Overlay: d, Shim: shim, Romanizer: r.Binary, HookPCs: append([]uint32(nil), nameEntryQueueNameEntQueuePCs...), ThirdFieldUntouched: true, OriginalNameDataUntouched: true, SafeToPatch: false, RuntimePass: false}
	return out, nil
}

// PlanCombinedTELAndNameEntOffline proves that the new screen-local module
// can coexist with telephone's complete private English+N20 composition. This is
// strictly an in-memory candidate; the default QA/image builder is unchanged.
func PlanCombinedTELAndNameEntOffline(exe []byte, original map[string][]byte) (TELCandidate, SlotDrawCandidate, error) {
	var empty TELCandidate
	c, err := PlanTELFullnameOffline(exe, original)
	if err != nil {
		return empty, SlotDrawCandidate{}, err
	}
	s, err := PlanNameEntSlotDrawOffline(original["NAME_ENT.EXN"])
	if err != nil {
		return empty, SlotDrawCandidate{}, err
	}
	base := c.Overlays["NAME_ENT.EXN"]
	pristine := original["NAME_ENT.EXN"]
	if len(base) != len(s.Overlay) {
		return empty, SlotDrawCandidate{}, fmt.Errorf("entry slot telephone name entry size mismatch")
	}
	out := bytes.Clone(base)
	for i, v := range s.Overlay {
		if v == pristine[i] || (i >= len(pristine)-4 && i < len(pristine)-2) {
			continue
		}
		if base[i] != pristine[i] {
			return empty, SlotDrawCandidate{}, fmt.Errorf("entry slot overlapping telephone edit at NAME_ENT+%#x", i)
		}
		out[i] = v
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	c.Overlays["NAME_ENT.EXN"] = out
	c.SafeToPatch = false
	c.RuntimePass = false
	return c, s, nil
}
