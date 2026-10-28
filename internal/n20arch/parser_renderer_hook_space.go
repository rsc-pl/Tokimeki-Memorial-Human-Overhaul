package n20arch

// parser relocation PRIVATE OFFLINE ONLY. Move previous version N10's *already authenticated* compact
// 132-byte surname strings from the overlapping English renderer FONT tail into
// the renderer HOOK reservation, after its actual glyph scratch. The N20 fixed
// executable guards remain entirely in the font tail. The two reservations
// are independent parts of the existing authenticated renderer installation.
//
// This transforms a private, staged N10 candidate, never a retail image or
// installed patch. It is NOT an authorization to boot: N10's 32 parser string
// operations are unguarded, the hook scratch/range lifetime is unverified in
// the running game and N20 overlay-local C10 has unresolved CPU/DMA ownership.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/graphics"
	nametables "tokimemo/internal/namepatch"
)

const (
	ShortHookSpareRAM   uint32 = 0x80044530
	ShortHookSpareBytes        = 132
	ShortOldRAM         uint32 = 0x8004BA78
	Base                uint32 = 0x80040800
)

type RelocationEvidence struct {
	OldStart               uint32 `json:"old_start"`
	NewStart               uint32 `json:"new_start"`
	Bytes                  int    `json:"bytes"`
	Pointers               int    `json:"pointers"`
	RetargetedAddressPairs int    `json:"retargeted_address_pairs"`
	FullEnglishPreserved   bool   `json:"full_english_preserved"`
	SafeToPatch            bool   `json:"safe_to_patch"`
	RuntimePass            bool   `json:"runtime_pass"`
}

type compactRelocationPair struct {
	name         string
	upper, lower int
	idx          int
}

var compactRelocationFixedPairs = [...]compactRelocationPair{
	{"SLPM_86.053", 0x3ffb4, 0x3ffbc, 0},
	{"SLPM_86.053", 0x3ffe4, 0x3ffe8, 0},
	{"SLPM_86.053", 0x40088, 0x4008c, 0},
	{"SLPM_86.053", 0x3ff94, 0x40068, 0},
	{"GEKO.EXN", 0xf468, 0xf46c, 11},
}

func compactRelocationRetargetAddressPair(b []byte, p compactRelocationPair, old, target uint32) error {
	if p.upper < 0 || p.lower < 0 || p.upper+4 > len(b) || p.lower+4 > len(b) {
		return fmt.Errorf("%s pair outside file", p.name)
	}
	hi := binary.LittleEndian.Uint32(b[p.upper:])
	lo := binary.LittleEndian.Uint32(b[p.lower:])
	rt := (hi >> 16) & 31
	if hi>>26 != 15 || lo>>26 != 9 || rt == 0 || (lo>>21)&31 != rt || (lo>>16)&31 != rt {
		return fmt.Errorf("%s invalid LUI/ADDIU at %#x/%#x", p.name, p.upper, p.lower)
	}
	address := uint32(int64(uint32(hi&0xffff)<<16) + int64(int16(lo&0xffff)))
	if address != old {
		return fmt.Errorf("%s unexpected old target %#x at %#x, want %#x", p.name, address, p.upper, old)
	}
	newhi := ((target + 0x8000) >> 16) & 0xffff
	if uint32(int64(newhi<<16)+int64(int16(target&0xffff))) != target {
		return fmt.Errorf("unrepresentable new target")
	}
	binary.LittleEndian.PutUint32(b[p.upper:], hi&0xffff0000|newhi)
	binary.LittleEndian.PutUint32(b[p.lower:], lo&0xffff0000|target&0xffff)
	return nil
}

// compactRelocationRelocateN10ShortOffline accepts the exact in-memory previous version transaction
// output. N20 base is passed independently so preimage and ownership can be
// tested against the ACTUAL integrated formatter bridge candidate instead of assumptions.
// Every change is staged on clones and checked before returning anything.
func compactRelocationRelocateN10ShortOffline(n10 map[string][]byte, formatterBridgeEXE []byte) (map[string][]byte, RelocationEvidence, error) {
	fail := func(f string, args ...any) (map[string][]byte, RelocationEvidence, error) {
		return nil, RelocationEvidence{}, fmt.Errorf("parser relocation N10/formatter bridge relocation: "+f, args...)
	}
	original := n10["SLPM_86.053"]
	geko := n10["GEKO.EXN"]
	if len(original) != len(formatterBridgeEXE) || len(original) < nametables.PointerTable+64 || len(geko) < 0xf484 {
		return fail("invalid source images")
	}
	_, code, _, scratch, err := graphics.RendererBuild()
	if err != nil {
		return fail("renderer: %v", err)
	}
	const hookStart uint32 = 0x8004443c
	const hookEnd uint32 = hookStart + 708
	if scratch != 0x8004451c || uint32(len(code)) > scratch-hookStart || ShortHookSpareRAM < (scratch+18+3)&^uint32(3) || ShortHookSpareRAM+ShortHookSpareBytes > hookEnd {
		return fail("renderer/scratch geometry mismatch")
	}
	newAt := int(ShortHookSpareRAM - Base)
	oldAt := int(ShortOldRAM - Base)
	if oldAt+180 > len(original) || newAt+ShortHookSpareBytes > len(original) {
		return fail("out-of-file compact table")
	}
	if !bytes.Equal(original[oldAt+132:oldAt+180], make([]byte, 48)) {
		return fail("old N10 compact tail has unexpected suffix bytes")
	}
	if !bytes.Equal(formatterBridgeEXE[newAt:newAt+ShortHookSpareBytes], make([]byte, ShortHookSpareBytes)) || !bytes.Equal(original[newAt:newAt+ShortHookSpareBytes], make([]byte, ShortHookSpareBytes)) {
		return fail("renderer hook spare already used")
	}
	// Reject a foreign or altered renderer installation at its executable entry
	// and scratch. Only the newly selected unused reservation is writable.
	hookOff := int(hookStart - Base)
	if !bytes.Equal(original[hookOff:hookOff+len(code)], code) || !bytes.Equal(formatterBridgeEXE[hookOff:hookOff+len(code)], code) || !bytes.Equal(original[int(scratch-Base):int(scratch-Base)+18], formatterBridgeEXE[int(scratch-Base):int(scratch-Base)+18]) {
		return fail("renderer hook or scratch changed")
	}
	// 16 encoded short strings must be exactly consecutive, NUL terminated,
	// and match all 16 currently published N10 short-table pointers.
	offs := [nametables.Entries]int{}
	pos := 0
	for i := range offs {
		if pos >= ShortHookSpareBytes {
			return fail("missing short string %d", i)
		}
		end := bytes.IndexByte(original[oldAt+pos:oldAt+ShortHookSpareBytes], 0)
		if end <= 0 {
			return fail("N10 short name %d not NUL-terminated", i)
		}
		addr := binary.LittleEndian.Uint32(original[nametables.PointerTable+4*i:])
		if addr != ShortOldRAM+uint32(pos) {
			return fail("N10 pointer %d = %#x, want %#x", i, addr, ShortOldRAM+uint32(pos))
		}
		offs[i] = pos
		pos += end + 1
	}
	if pos > ShortHookSpareBytes || !bytes.Equal(original[oldAt+pos:oldAt+ShortHookSpareBytes], make([]byte, ShortHookSpareBytes-pos)) {
		return fail("compact pool has nonzero slack after %d bytes", pos)
	}
	out := make(map[string][]byte, len(n10))
	for name, b := range n10 {
		out[name] = bytes.Clone(b)
	}
	ex := out["SLPM_86.053"]
	copy(ex[newAt:newAt+ShortHookSpareBytes], original[oldAt:oldAt+ShortHookSpareBytes])
	clear(ex[oldAt : oldAt+ShortHookSpareBytes])
	for i, off := range offs {
		binary.LittleEndian.PutUint32(ex[nametables.PointerTable+4*i:], ShortHookSpareRAM+uint32(off))
	}
	for _, p := range compactRelocationFixedPairs {
		old := ShortOldRAM + uint32(offs[p.idx])
		next := ShortHookSpareRAM + uint32(offs[p.idx])
		if err := compactRelocationRetargetAddressPair(out[p.name], p, old, next); err != nil {
			return fail("%v", err)
		}
	}
	// GEKO G2 may either be an explicit dedicated `-san` string in the full
	// split area or the unsuffixed index 11 alias; do NOT choose policy here.
	g2 := compactRelocationPair{"GEKO.EXN", 0xf47c, 0xf480, 11}
	hi := binary.LittleEndian.Uint32(out[g2.name][g2.upper:])
	lo := binary.LittleEndian.Uint32(out[g2.name][g2.lower:])
	if hi>>26 != 15 || lo>>26 != 9 {
		return fail("GEKO G2 opcode changed")
	}
	actual := uint32(int64(uint32(hi&0xffff)<<16) + int64(int16(lo&0xffff)))
	if actual == ShortOldRAM+uint32(offs[11]) {
		if err := compactRelocationRetargetAddressPair(out[g2.name], g2, ShortOldRAM+uint32(offs[11]), ShortHookSpareRAM+uint32(offs[11])); err != nil {
			return fail("GEKO G2: %v", err)
		}
	} else if actual != nametables.N10Phase2G2 {
		return fail("GEKO G2 target %#x not verified", actual)
	}
	// NOTE: legacy N10 direct-consumer inventory is finite; do not infer
	// hidden pointer coverage or runtime safety from these 5+1 sites.
	return out, RelocationEvidence{OldStart: ShortOldRAM, NewStart: ShortHookSpareRAM, Bytes: ShortHookSpareBytes, Pointers: nametables.Entries, RetargetedAddressPairs: len(compactRelocationFixedPairs), SafeToPatch: false, RuntimePass: false}, nil
}

// CombinedOfflineCandidate is an independently byte-merged host-memory
// research artifact. It cannot be passed to the public disc builder: the N10
// parser is unguarded and no runtime owner proof exists for either reservation.
// The caller must retain the current EN translation corpus separately; this
// function composes the physical N10/N20 layers on authenticated JP sources.
type CombinedOfflineCandidate struct {
	EnglishRendererEXE []byte
	Overlays           map[string][]byte
	N10Report          nametables.N10OfflineTransactionReport
	Relocation         RelocationEvidence
	ConflictBytes      int
	SafeToPatch        bool
	RuntimePass        bool
	ImageBuilt         bool
}

// PlanN10N20Offline performs the previous version N10 transaction and formatter bridge N20 full
// overlay plan against the same authenticated original bytes, then merges both
// sets only where their original preimage ownership does not conflict. The
// renderer hook spare is the ONLY N10 short pool relocation. No files/ROMs are
// written and it refuses independently modified or conflicting sources.
func PlanN10N20Offline(retailEXE []byte, overlays map[string][]byte, input nametables.N10OfflineTransaction) (CombinedOfflineCandidate, error) {
	var zero CombinedOfflineCandidate
	if !bytes.Equal(input.Originals["SLPM_86.053"], retailEXE) {
		return zero, fmt.Errorf("parser relocation N10 original EXE differs from N20 authenticated original")
	}
	for _, name := range []string{"GEKO.EXN", "SHUGAKU.EXN", "SHOUGATU.EXN"} {
		if !bytes.Equal(input.Originals[name], overlays[name]) {
			return zero, fmt.Errorf("parser relocation %s retail originals differ", name)
		}
	}
	n20, e := PlanFormatterIntegratedOffline(retailEXE, overlays)
	if e != nil {
		return zero, fmt.Errorf("parser relocation N20: %w", e)
	}
	n10, n10r, e := nametables.ComposeN10Phase2Offline(input)
	if e != nil {
		return zero, fmt.Errorf("parser relocation N10: %w", e)
	}
	if n20.SafeToPatch || n20.RuntimePass || n10r.SafeToPatch || n10r.ParserGuarded || n10r.RuntimeVerified {
		return zero, fmt.Errorf("parser relocation unexpectedly authorized a runtime variant")
	}
	staged, rel, e := compactRelocationRelocateN10ShortOffline(n10, n20.EnglishEXE)
	if e != nil {
		return zero, e
	}
	renderer, e := graphics.InstallRenderer(retailEXE)
	if e != nil {
		return zero, fmt.Errorf("parser relocation renderer: %w", e)
	}
	merged := bytes.Clone(n20.EnglishEXE)
	conflict := 0
	for i, v := range staged["SLPM_86.053"] {
		base := renderer[i]
		other := n20.EnglishEXE[i]
		if v == base {
			continue
		}
		if other != base && other != v {
			conflict++
			continue
		}
		merged[i] = v
	}
	ovs := make(map[string][]byte, len(overlays))
	for name, original := range overlays {
		current, ok := n20.Overlays[name]
		if !ok || len(current) != len(original) {
			return zero, fmt.Errorf("parser relocation N20 overlay absent %s", name)
		}
		result := bytes.Clone(current)
		if stage, ok := staged[name]; ok {
			if len(stage) != len(original) {
				return zero, fmt.Errorf("parser relocation N10 overlay size mismatch %s", name)
			}
			for i, v := range stage {
				if v == original[i] {
					continue
				}
				if current[i] != original[i] && current[i] != v {
					conflict++
					continue
				}
				result[i] = v
			}
		}
		ovs[name] = result
	}
	if conflict != 0 {
		return zero, fmt.Errorf("parser relocation %d conflicting N10/N20 bytes after relocation", conflict)
	}
	start := int(C10EXEGuardF1 - Base)
	if !bytes.Equal(merged[start:start+180], n20.EnglishEXE[start:start+180]) {
		return zero, fmt.Errorf("parser relocation damaged N20 EXE gate")
	}
	if bytes.Equal(merged, n20.EnglishEXE) {
		return zero, fmt.Errorf("parser relocation N10 unexpectedly absent")
	}
	rel.FullEnglishPreserved = false // owner's *current* translation corpus not supplied to this planner
	return CombinedOfflineCandidate{EnglishRendererEXE: merged, Overlays: ovs, N10Report: n10r, Relocation: rel, SafeToPatch: false, RuntimePass: false, ImageBuilt: false}, nil
}
