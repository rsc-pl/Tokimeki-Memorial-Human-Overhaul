package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Scene-owned literal labels bypass the normal field-preparation producer.
// Keep their original source and selector, but write the renderer's actual
// name buffer. Dynamic saved-name copies are deliberately not in this set.
var contextSpeakerSites = [...]struct {
	overlay        string
	pc, hi, source uint32
	slot           int
}{
	{"BUNKAKEN.EXN", 0x80146494, 0x80146488, 0x80154bf8, 4},
	{"BUNKASAI.EXN", 0x80151114, 0x80151108, 0x8015f148, 4},
	{"ENDING.EXN", 0x8013396c, 0x8013395c, 0x8013bfb0, 8},
	{"ENDING.EXN", 0x801339e0, 0x801339d0, 0x8013bfb8, 8},
	{"ENDING.EXN", 0x80133a20, 0x80133a10, 0x8013bfc0, 16},
	{"OMIMAI.EXN", 0x801327ec, 0x801327dc, 0x801348b8, 8},
	{"SHUGAKU.EXN", 0x801341bc, 0x801341ac, 0x8013ad70, 16},
}

// PlanContextSpeakers is transactional: validate all original/current
// preimages before returning any changed overlay. The resident renderer and
// its measured byte count must already use the relocated sixteen-byte A.
func PlanContextSpeakers(retailEXE, currentEXE []byte, originals, current map[string][]byte) (map[string][]byte, error) {
	if sha(retailEXE) != OriginalEXESHA || len(currentEXE) != len(retailEXE) {
		return nil, fmt.Errorf("contextual label: executable identity")
	}
	for _, route := range npcNameQueueNPCNameQueues {
		word := func(pc uint32) uint32 { return binary.LittleEndian.Uint32(currentEXE[pc-Base:]) }
		if word(route.FormatPC-16) != 0x3c06800b || word(route.FormatPC-8) != 0x24c635a4 ||
			word(route.FormatPC+8)&0xffe0ffff != 0x2440ffff {
			return nil, fmt.Errorf("contextual label: renderer source/count drift")
		}
	}
	out := map[string][]byte{}
	for _, s := range contextSpeakerSites {
		o, c := originals[s.overlay], current[s.overlay]
		if len(o) != 196608 || len(c) != len(o) || sha(o) != OverlaySHA[s.overlay] {
			return nil, fmt.Errorf("contextual label: source identity %s", s.overlay)
		}
		off, hi, src := int(s.pc-OverlaySlotBase), int(s.hi-OverlaySlotBase), int(s.source-OverlaySlotBase)
		word := func(i int) uint32 { return binary.LittleEndian.Uint32(o[i:]) }
		sourceHi := uint32((s.source + 0x8000) >> 16)
		// The source LUI follows the destination LUI; an intervening native
		// selector store may precede the ADDIU. Keep every original word.
		if word(hi) != 0x3c04800d || word(hi+4) != 0x3c050000|sourceHi ||
			word(off-4) != 0x24a50000|uint32(uint16(s.source)) ||
			word(off) != jalWord(0x800ae0f0) || word(off+4) != 0x2484a188 ||
			!bytes.Equal(o[hi:off+8], c[hi:off+8]) {
			return nil, fmt.Errorf("contextual label: caller drift %s %#x", s.overlay, s.pc)
		}
		originalEnd := bytes.IndexByte(o[src:src+s.slot], 0)
		end := bytes.IndexByte(c[src:src+s.slot], 0)
		if originalEnd <= 0 || originalEnd%2 != 0 || end < 0 || end%2 != 0 || end >= 16 {
			return nil, fmt.Errorf("contextual label: source boundary %s %#x", s.overlay, s.source)
		}
		d := out[s.overlay]
		if d == nil {
			d = bytes.Clone(c)
			out[s.overlay] = d
		}
		binary.LittleEndian.PutUint32(d[hi:], 0x3c04800b)
		binary.LittleEndian.PutUint32(d[off+4:], 0x248435a4)
	}
	for _, d := range out {
		binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
	}
	return out, nil
}

// PlanSchoolTripSurname redirects the school trip's direct saved-name copy
// to the freshly prepared working surname and the active speaker label.
// The immediately preceding field-preparation call has both a converted
// path and a retail fallback; both populate the same relocated source.
// No separate conversion, storage or selector is introduced here.
func PlanSchoolTripSurname(retailEXE, currentEXE, original, current []byte) ([]byte, error) {
	if sha(retailEXE) != OriginalEXESHA || len(currentEXE) != len(retailEXE) ||
		sha(original) != OverlaySHA["SHUGAKU.EXN"] || len(current) != len(original) {
		return nil, fmt.Errorf("school trip label: source identity")
	}
	word := func(d []byte, pc, base uint32) uint32 {
		return binary.LittleEndian.Uint32(d[pc-base:])
	}
	for _, route := range npcNameQueueNPCNameQueues {
		if word(currentEXE, route.FormatPC-16, Base) != 0x3c06800b ||
			word(currentEXE, route.FormatPC-8, Base) != 0x24c635a4 ||
			word(currentEXE, route.FormatPC+8, Base)&0xffe0ffff != 0x2440ffff {
			return nil, fmt.Errorf("school trip label: renderer source/count")
		}
	}
	// Verify the actual retail fallback first copies both saved names into
	// the relocated working fields, before the guarded conversion runs.
	for i, w := range []uint32{0x3c048013, 0x3c05800e, 0x24a56354, 0x0c02b83c, 0x2484b500,
		0x3c048013, 0x3c05800e, 0x24a5635c, 0x0c02b83c, 0x2484b510} {
		if word(currentEXE, 0x800847c4+uint32(i*4), Base) != w {
			return nil, fmt.Errorf("school trip label: relocated field preparation")
		}
	}
	module, err := buildOverlayFieldPrepModuleAtWithGivenKun(N20RelocFamilyAddr, N20RelocGivenAddr, N20RelocSlotBytes, true)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(current[OLPayloadFileOff:OLGuardFileEnd], module.Guard) ||
		!bytes.Equal(current[OLBodyFileOff:OLBodyFileOff+len(module.Body)], module.Body) {
		return nil, fmt.Errorf("school trip label: field preparation guard/body")
	}
	const start = 0x80137e20
	want := []uint32{jalWord(OLFieldPrepOriginal), 0x00002025, 0x3c04800d, 0x3c05800e,
		0x24a56354, 0x0c02b83c, 0x2484a188, 0x0c04d8e0, 0}
	for i, w := range want {
		pc := uint32(start + i*4)
		if word(original, pc, OverlaySlotBase) != w {
			return nil, fmt.Errorf("school trip label: native window")
		}
		if i == 0 {
			w = jalWord(OLStubRAM)
		}
		if word(current, pc, OverlaySlotBase) != w {
			return nil, fmt.Errorf("school trip label: composed window")
		}
	}
	out := bytes.Clone(current)
	for _, w := range []struct{ pc, value uint32 }{
		{0x80137e28, 0x3c04800b}, {0x80137e2c, 0x3c058013},
		{0x80137e30, 0x24a5b500}, {0x80137e38, 0x248435a4},
	} {
		binary.LittleEndian.PutUint32(out[w.pc-OverlaySlotBase:], w.value)
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return out, nil
}
