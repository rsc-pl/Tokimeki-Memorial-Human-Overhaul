package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// This route relocates only the original P string, leaving the two saved
// names and the adjacent retail suffix fields unchanged. It is staged on
// authenticated originals and does not establish exclusive runtime BSS access.
const pFieldRetail uint32 = 0x800ca17c

type pFieldRelocPair struct {
	owner    string
	lui, add uint32
	role     string
}

var pFieldPairs = [...]pFieldRelocPair{
	{"EXE", 0x800813f8, 0x8008140c, "renderer P input"},
	{"EXE", 0x800847f0, 0x800847fc, "field-preparation P destination"},
	{"DATE2.EXN", 0x80132f18, 0x80132f24, "DATE2 P producer A"},
	{"DATE2.EXN", 0x801335b0, 0x801335b8, "DATE2 P producer B"},
	{"SHOUGATU.EXN", 0x8013b0ac, 0x8013b0c4, "holiday P producer"},
}

func pFieldSourceWords(exe []byte, overlays map[string][]byte) ([]N20ManifestWord, error) {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA || len(overlays) != len(OverlaySHA) {
		return nil, fmt.Errorf("P field source identity mismatch")
	}
	for name, want := range OverlaySHA {
		if len(overlays[name]) != 196608 || sha(overlays[name]) != want {
			return nil, fmt.Errorf("P field source overlay mismatch %s", name)
		}
	}
	target := givenKunExtended
	if target < BootBSSStart || target+16 > BootBSSEnd || target+16 > OverlaySlotBase || target+16 > N20RelocBSSLastWord {
		return nil, fmt.Errorf("P field destination outside source-inspected BSS slack")
	}
	// Independent reference inventory: precisely these five effective addresses,
	// and zero embedded pointer literals. Unexpected readers/writers are fatal.
	seen := map[string]bool{}
	count := 0
	readRefs := func(owner string, d []byte, base uint32) {
		for _, r := range scanN20RelocRefs(d, base, owner, pFieldRetail, pFieldRetail+1) {
			if r.Kind != "op09" && r.Kind != "op0d" {
				count = -10000
				continue
			}
			seen[fmt.Sprintf("%s:%08x", owner, r.PC)] = true
			count++
		}
	}
	readRefs("EXE", exe[0x800:], 0x80041000)
	for name, src := range overlays {
		readRefs(name, src, OverlaySlotBase)
	}
	if count != len(pFieldPairs) || len(seen) != len(pFieldPairs) {
		return nil, fmt.Errorf("P field source reference count %d/%d expected %d", count, len(seen), len(pFieldPairs))
	}
	for _, pair := range pFieldPairs {
		if !seen[fmt.Sprintf("%s:%08x", pair.owner, pair.add)] {
			return nil, fmt.Errorf("P field missing source reference %s:%08x", pair.owner, pair.add)
		}
	}
	// The new BSS location has no direct static references in the original
	// EXE or any original overlay; the adjacent original data word is outside the 16B slot.
	if len(scanN20RelocRefs(exe[0x800:], 0x80041000, "EXE", target, target+16)) != 0 {
		return nil, fmt.Errorf("P field BSS destination referenced by EXE")
	}
	for name, src := range overlays {
		if refs := scanN20RelocRefs(src, OverlaySlotBase, name, target, target+16); len(refs) != 0 {
			return nil, fmt.Errorf("P field BSS destination referenced by %s", name)
		}
	}
	out := make([]N20ManifestWord, 0, 2*len(pFieldPairs))
	for _, pair := range pFieldPairs {
		src := exe
		base := uint32(0x80040800)
		if pair.owner != "EXE" {
			src = overlays[pair.owner]
			base = OverlaySlotBase
		}
		a, b := int(pair.lui-base), int(pair.add-base)
		if a < 0 || b < 0 || a+4 > len(src) || b+4 > len(src) {
			return nil, fmt.Errorf("P field invalid patch offset %s", pair.owner)
		}
		oldHi, oldLo := binary.LittleEndian.Uint32(src[a:]), binary.LittleEndian.Uint32(src[b:])
		rt := (oldHi >> 16) & 31
		if oldHi>>26 != 15 || oldHi&0xffff != 0x800d || oldLo>>26 != 9 || (oldLo>>21)&31 != rt || (oldLo>>16)&31 != rt || oldLo&0xffff != 0xa17c {
			return nil, fmt.Errorf("P field site changed %s:%08x/%08x", pair.owner, pair.lui, pair.add)
		}
		newHi, newLo := n20RelocLUIWord(oldHi, target), n20RelocADDIUWord(oldLo, target)
		out = append(out, N20ManifestWord{Owner: pair.owner, PC: pair.lui, Old: oldHi, New: newHi, Kind: "lui", Role: pair.role, Reason: "P field pointer relocated to 16-byte BSS slot"}, N20ManifestWord{Owner: pair.owner, PC: pair.add, Old: oldLo, New: newLo, Kind: "addiu", Role: pair.role, Reason: "P field pointer relocated to 16-byte BSS slot"})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner == out[j].Owner {
			return out[i].PC < out[j].PC
		}
		return out[i].Owner < out[j].Owner
	})
	return out, nil
}

func applyPFieldRelocation(exe []byte, overlays map[string][]byte, records []N20ManifestWord) ([]byte, map[string][]byte, error) {
	destEXE := bytes.Clone(exe)
	destOverlays := make(map[string][]byte, len(overlays))
	for name, b := range overlays {
		destOverlays[name] = bytes.Clone(b)
	}
	for _, w := range records {
		b := destEXE
		base := uint32(0x80040800)
		if w.Owner != "EXE" {
			b = destOverlays[w.Owner]
			base = OverlaySlotBase
		}
		idx := int(w.PC - base)
		if idx < 0 || idx+4 > len(b) || binary.LittleEndian.Uint32(b[idx:]) != w.Old {
			return nil, nil, fmt.Errorf("P field collision %s:%08x", w.Owner, w.PC)
		}
		binary.LittleEndian.PutUint32(b[idx:], w.New)
	}
	for _, owner := range []string{"DATE2.EXN", "SHOUGATU.EXN"} {
		b := destOverlays[owner]
		ck := packedTableChecksum(b)
		b[0x2fffc], b[0x2fffd] = byte(ck>>8), byte(ck)
	}
	return destEXE, destOverlays, nil
}
