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

// The holiday setup formats the explicit saved surname and san after its
// normal field-preparation call. A second guarded call with selector 14
// bypasses the native selector table, leaving the formatted P and A fields
// intact while applying the existing exact-content conversion. Consolidate
// the pointer loads below the local initializer to fit that call in place.
const holidayPRefreshPC uint32 = 0x8013b0d0

func holidayPRefreshWords(original []byte) ([]N20ManifestWord, error) {
	const name = "SHOUGATU.EXN"
	if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA[name] {
		return nil, fmt.Errorf("holiday P refresh source identity mismatch")
	}
	old := [...]uint32{
		0x3c098014, 0x8d294db0, 0x3c018014, 0x3c0a8014,
		0x8d4a4dd4, 0xac294dfc, 0x3c018014, 0x3c0b8014,
		0x8d6b4df8, 0xac2a4e00, 0x3c018014, 0x0c010a13, 0xac2b4e04,
	}
	next := [...]uint32{
		jalWord(OLStubRAM), 0x2404000e, 0x3c018014, 0x8c294db0,
		0x8c2a4dd4, 0xac294dfc, 0x8c2b4df8, 0,
		0, 0xac2a4e00, 0x3c018014, 0x0c010a13, 0xac2b4e04,
	}
	var records []N20ManifestWord
	for i, w := range old {
		pc := holidayPRefreshPC + uint32(i*4)
		if binary.LittleEndian.Uint32(original[pc-OverlaySlotBase:]) != w {
			return nil, fmt.Errorf("holiday P refresh instruction mismatch at %#x", pc)
		}
		if w != next[i] {
			kind := "word"
			if i == 0 {
				kind = "jal"
			}
			records = append(records, N20ManifestWord{
				Owner: name, PC: pc, Old: w, New: next[i], Kind: kind,
				Role: "holiday formatted P conversion", Reason: "retain explicit native surname and suffix; reuse guarded field preparation before the scheduler",
			})
		}
	}
	return records, nil
}

func applyHolidayPRefresh(original, staged []byte) ([]N20ManifestWord, error) {
	records, err := holidayPRefreshWords(original)
	if err != nil {
		return nil, err
	}
	if len(staged) != len(original) {
		return nil, fmt.Errorf("holiday P refresh image size mismatch")
	}
	// Check the entire block, including the retained initializer, scheduler,
	// delay stores and unmodified pointer instructions before the first write.
	start, end := int(holidayPRefreshPC-OverlaySlotBase)-8, int(0x8013b104-OverlaySlotBase)
	if !bytes.Equal(original[start:end], staged[start:end]) {
		return nil, fmt.Errorf("holiday P refresh composition collision")
	}
	for _, w := range records {
		binary.LittleEndian.PutUint32(staged[w.PC-OverlaySlotBase:], w.New)
	}
	ck := packedTableChecksum(staged)
	staged[0x2fffc], staged[0x2fffd] = byte(ck>>8), byte(ck)
	return records, nil
}
