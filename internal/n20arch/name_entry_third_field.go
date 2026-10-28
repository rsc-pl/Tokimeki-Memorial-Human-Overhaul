package n20arch

// third-field input: two additional original NAME_ENT *presentation* callsites, offline only.
// These draw a third field after the entry slot pair (the first screen uses a
// distinct 16-byte record stride, unlike A/B and the other screen). Field identity (nickname versus another UI role) is NOT inferred from
// adjacency alone; this is a bounded kana-only conversion with retail fallback.
// The entry slot converter already exists and is reused without code, RAM, or VRAM
// growth. Never touch original slot storage, memory cards, the third field
// writer, visible input grid, or any generic dialogue queue.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var nicknameFieldThirdFieldPCs = []uint32{0x80139D9C, 0x80139ED0}

type NameEntThirdFieldCandidate struct {
	Overlay           []byte
	HookPCs           []uint32
	ReusesShim        bool
	SemanticsVerified bool
	SafeToPatch       bool
	RuntimePass       bool
}

func PlanNameEntThirdFieldOffline(original []byte) (NameEntThirdFieldCandidate, error) {
	var zero NameEntThirdFieldCandidate
	// entry slot establishes the whole original source, buffer ownership, local
	// implementation, queue calling convention, and four existing hooks.
	prior, err := PlanNameEntSlotDrawOffline(original)
	if err != nil {
		return zero, err
	}

	// Exact original producer instructions and original queue ABI for each
	// third-field display. These are not writes/serialization functions.
	// First: index*16 + 0x800E7D10 + 0x988 -> 0x800E8698+index*16.
	// Second: index*0xF00 + 0x80123120 + 0x2AC.
	for _, p := range []struct {
		pc           uint32
		instructions [8]uint32
	}{
		{0x80139D9C, [8]uint32{0x91ef7d36, 0x3c08800e, 0x000fc100, 0x27190988, 0x25087d10, 0x03283821, 0x24040020, 0x2405ffc5}},
		{0x80139ED0, [8]uint32{0x918c7397, 0x3c0f8012, 0x000c6900, 0x01ac6823, 0x000d6a00, 0x25ae02ac, 0x25ef3120, 0x01cf3821}},
	} {
		off := int(p.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(original[off:]) != jalWord(optionQueueRetail) ||
			binary.LittleEndian.Uint32(original[off+4:]) != olSW(0, 29, 0x10) {
			return zero, fmt.Errorf("third-field input retail third-field queue drift %#x", p.pc)
		}
		// Look backward for each individual producer word (ordered), not a
		// single JAL signature. Exact original overlay SHA is also mandatory.
		needle := 0
		for at := off - 44; at < off; at += 4 {
			if binary.LittleEndian.Uint32(original[at:]) == p.instructions[needle] {
				needle++
				if needle == len(p.instructions) {
					break
				}
			}
		}
		if needle != len(p.instructions) {
			return zero, fmt.Errorf("third-field input third-field provenance mismatch %#x (%d/8)", p.pc, needle)
		}
	}
	d := bytes.Clone(prior.Overlay)
	for _, pc := range nicknameFieldThirdFieldPCs {
		binary.LittleEndian.PutUint32(d[int(pc-OverlaySlotBase):], jalWord(EntrySlotShimRAM))
	}
	binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
	for i := range d {
		if d[i] == prior.Overlay[i] {
			continue
		}
		ok := (i >= len(d)-4 && i < len(d)-2)
		for _, pc := range nicknameFieldThirdFieldPCs {
			off := int(pc - OverlaySlotBase)
			if i >= off && i < off+4 {
				ok = true
			}
		}
		if !ok {
			return zero, fmt.Errorf("third-field input unowned change NAME_ENT+%#x", i)
		}
	}
	return NameEntThirdFieldCandidate{Overlay: d, HookPCs: append([]uint32(nil), nicknameFieldThirdFieldPCs...), ReusesShim: true, SemanticsVerified: false, SafeToPatch: false, RuntimePass: false}, nil
}

// Compose on the complete telephone + entry slot + nickname English candidate; modify only two
// NAME_ENT JALs and its derived checksum, never an overlay replacement.
func PlanCombinedThirdFieldOffline(exe []byte, orig map[string][]byte) (TELCandidate, NameEntThirdFieldCandidate, error) {
	var empty TELCandidate
	c, _, _, err := PlanCombinedNicknameOffline(exe, orig)
	if err != nil {
		return empty, NameEntThirdFieldCandidate{}, err
	}
	third, err := PlanNameEntThirdFieldOffline(orig["NAME_ENT.EXN"])
	if err != nil {
		return empty, NameEntThirdFieldCandidate{}, err
	}
	prior, err := PlanNameEntSlotDrawOffline(orig["NAME_ENT.EXN"])
	if err != nil {
		return empty, NameEntThirdFieldCandidate{}, err
	}
	base := c.Overlays["NAME_ENT.EXN"]
	if len(base) != len(prior.Overlay) || len(base) != len(third.Overlay) {
		return empty, NameEntThirdFieldCandidate{}, fmt.Errorf("third-field input overlay length")
	}
	// The combined telephone/nickname NAME_ENT also carries separate C10 source/bridge
	// bytes, which must not be erased by a pristine-entry slot overlay replacement.
	// Validate only the six relevant original and already-retargeted routes.
	for _, pc := range nameEntryQueueNameEntQueuePCs {
		off := int(pc - OverlaySlotBase)
		if !bytes.Equal(base[off:off+8], prior.Overlay[off:off+8]) {
			return empty, NameEntThirdFieldCandidate{}, fmt.Errorf("third-field input previous NAME_ENT JAL drift %#x", pc)
		}
	}
	for _, pc := range nicknameFieldThirdFieldPCs {
		off := int(pc - OverlaySlotBase)
		if !bytes.Equal(base[off:off+8], prior.Overlay[off:off+8]) {
			return empty, NameEntThirdFieldCandidate{}, fmt.Errorf("third-field input new NAME_ENT JAL drift %#x", pc)
		}
	}
	if !bytes.Equal(base[EntrySlotNameEntOff:EntrySlotNameEntOff+EntrySlotNameEntBytes], prior.Overlay[EntrySlotNameEntOff:EntrySlotNameEntOff+EntrySlotNameEntBytes]) {
		return empty, NameEntThirdFieldCandidate{}, fmt.Errorf("third-field input previous romanizer overwritten")
	}
	out := bytes.Clone(base)
	for _, pc := range nicknameFieldThirdFieldPCs {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out[off:]) != jalWord(optionQueueRetail) {
			return empty, NameEntThirdFieldCandidate{}, fmt.Errorf("third-field input combined unexpected third JAL %#x", pc)
		}
		copy(out[off:off+4], third.Overlay[off:off+4])
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	for i := range out {
		if out[i] == base[i] {
			continue
		}
		allowed := i >= len(out)-4 && i < len(out)-2
		for _, pc := range nicknameFieldThirdFieldPCs {
			off := int(pc - OverlaySlotBase)
			if i >= off && i < off+4 {
				allowed = true
			}
		}
		if !allowed {
			return empty, NameEntThirdFieldCandidate{}, fmt.Errorf("third-field input combined unowned mutation +%#x", i)
		}
	}
	c.Overlays["NAME_ENT.EXN"] = out
	c.SafeToPatch = false
	c.RuntimePass = false
	return c, third, nil
}
