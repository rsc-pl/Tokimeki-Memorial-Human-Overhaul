package n20arch

// native name entry: source-stage, NAME_ENT-only private copy of three source-authenticated
// retail routines. Unlike glyph aliasing this does not overwrite already submitted VRAM
// slots. It delegates the ordinary alias slot assignment / LoadImage path to
// the native retail instructions and replaces only the input 96-byte bitmap
// before the original transfer. It is an OFFLINE candidate, not a proof of
// overlay lifetime, DMA/IRQ/cache or real display behavior.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	QueueOff           = 0x23500
	ParserOff          = 0x23600
	UploadOff          = 0x23700
	SelectorOff        = 0x23900
	QueueRAM    uint32 = OverlaySlotBase + QueueOff
	ParserRAM   uint32 = OverlaySlotBase + ParserOff
	UploadRAM   uint32 = OverlaySlotBase + UploadOff
	SelectorRAM uint32 = OverlaySlotBase + SelectorOff
)

type NativeChainCandidate struct {
	Overlay                 []byte
	QueueCalls              []uint32
	SourceStageOnly         bool
	UsesNativeVRAMAllocator bool
	ChangesRetailEXE        bool
	OriginalInputIntact     bool
	RuntimePass             bool
	SafeToPatch             bool
}

// Selector has the same a0 (index), a1 (staging destination) arguments as
// original 0x8004f4f0. Foreign indices use retail; aliases use alias resolution.
func BuildGlyphSelector() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	br := func(op, rs, rt uint32, label string) { a.b(op, rs, rt, label); w(0) }
	add(29, 29, -0x28)
	w(olSW(31, 29, 0x24))
	w(olSW(4, 29, 0x10))
	w(olSW(5, 29, 0x14))
	add(8, 4, -AliasFirstGlyphIndex)
	w(olSLTIU(9, 8, AliasGlyphCount))
	br(4, 9, 0, "original")
	w(jalWord(AliasResolverRAM))
	w(0)
	add(8, 0, 96)
	br(5, 2, 8, "original") // alias resolution refused staging: never upload stale scratch.
	br(4, 0, 0, "done")
	a.label("original")
	w(olLW(4, 29, 0x10))
	w(0)
	w(olLW(5, 29, 0x14))
	w(0)
	w(jalWord(RetailGlyphExpand))
	w(0)
	a.label("done")
	w(olLW(4, 29, 0x10))
	w(0)
	w(olLW(5, 29, 0x14))
	w(0)
	w(olLW(31, 29, 0x24))
	w(0)
	w(olJR(31))
	add(29, 29, 0x28)
	a.resolve()
	out := words(a.words...)
	if len(out) > 0x100 {
		return nil, fmt.Errorf("native name entry selector %d > 256", len(out))
	}
	return out, nil
}

// previous version: only the exact authenticated R3000A control-flow shape may be cloned.
// The source is SHA checked by the caller, but validating the shape as well
// prevents a future source-layout change from silently making an unsafe copy.
// In particular indirect jumps, branch-likely/COP branches and control-flow
// instructions in delay slots are not justified by relative-branch relocation.
func nameEntryCloneFlowValidateCloneFlow(out []byte, start, end uint32) error {
	if start >= end || (end-start)%4 != 0 || len(out) != int(end-start) {
		return fmt.Errorf("previous version invalid clone span %#x..%#x", start, end)
	}
	expected := map[uint32]map[uint32]uint32{
		0x8004e788: {0x8004e82c: 0x8004f268},
		0x8004f268: {0x8004f2e8: 0x800ae0b0, 0x8004f32c: 0x8004f364},
		0x8004f364: {0x8004f390: 0x8004f4f0, 0x8004f400: 0x8004435c,
			0x8004f468: 0x8004435c, 0x8004f4c0: 0x8004435c,
			0x8004f4c8: 0x8009c674},
	}[start]
	if expected == nil {
		return fmt.Errorf("previous version unknown clone source %#x", start)
	}
	seen := map[uint32]bool{}
	delaySlot := false
	jrCount := 0
	for pc := start; pc < end; pc += 4 {
		w := binary.LittleEndian.Uint32(out[pc-start:])
		op, fn, rs := w>>26, w&63, (w>>21)&31
		control, delay := false, false
		switch {
		case op == 0 && (fn == 8 || fn == 9): // JR/JALR
			control, delay = true, true
			if fn != 8 || rs != 31 || pc != end-8 || w != olJR(31) {
				return fmt.Errorf("previous version unsafe indirect jump at %#x: %08x", pc, w)
			}
			jrCount++
		case op == 0 && (fn == 12 || fn == 13): // SYSCALL/BREAK
			return fmt.Errorf("previous version exception instruction at %#x: %08x", pc, w)
		case op == 2 || op == 3: // absolute J or JAL
			control, delay = true, true
			target := (pc & 0xf0000000) | ((w & 0x03ffffff) << 2)
			if op != 3 || expected[pc] != target {
				return fmt.Errorf("previous version unexpected jump at %#x to %#x", pc, target)
			}
			seen[pc] = true
		case op == 1 || (op >= 4 && op <= 7): // regular relative branches
			control, delay = true, true
			if op == 1 && (w>>16)&31 > 1 { // disallow link and unrecognized REGIMM modes
				return fmt.Errorf("previous version unsupported REGIMM at %#x", pc)
			}
			offset := int32(int16(w & 0xffff))
			target := uint32(int64(pc) + 4 + int64(offset)*4)
			if target < start || target >= end {
				return fmt.Errorf("previous version branch exits clone at %#x to %#x", pc, target)
			}
		case op >= 20 && op <= 23: // MIPS-II branch-likely, invalid for PS1 R3000A
			return fmt.Errorf("previous version branch-likely at %#x", pc)
		case op >= 16 && op <= 19 && rs == 8: // coprocessor conditional branch
			return fmt.Errorf("previous version COP branch at %#x", pc)
		}
		if delaySlot && control {
			return fmt.Errorf("previous version control instruction in delay slot at %#x", pc)
		}
		if delay && pc+4 >= end {
			return fmt.Errorf("previous version unterminated delay slot at %#x", pc)
		}
		delaySlot = delay
	}
	if jrCount != 1 || len(seen) != len(expected) {
		return fmt.Errorf("previous version flow mismatch: return=%d callsites=%d/%d", jrCount, len(seen), len(expected))
	}
	return nil
}

// Clone authenticated instruction bytes with the exact original branch
// displacements. For these three source blocks, previous version requires every indirect
// return, JAL target and relative branch to remain within the proved shape.
func nameEntryCloneCloneAuthenticated(exe []byte, start, end, base uint32) ([]byte, error) {
	if start >= end || (end-start)%4 != 0 || base&3 != 0 || (start&0xf0000000) != (base&0xf0000000) {
		return nil, fmt.Errorf("bad clone range or base")
	}
	out := make([]byte, end-start)
	for pc := start; pc < end; pc += 4 {
		word, err := RetailPCWord(exe, pc)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(out[pc-start:], word)
	}
	if err := nameEntryCloneFlowValidateCloneFlow(out, start, end); err != nil {
		return nil, err
	}
	return out, nil
}

func PlanLocalNativeGlyphChainOffline(exe, original []byte) (NativeChainCandidate, error) {
	var zero NativeChainCandidate
	prev, err := PlanAliasSourceOffline(exe, original)
	if err != nil {
		return zero, err
	}
	const limit = 0x23a00
	if !bytes.Equal(original[QueueOff:limit], make([]byte, limit-QueueOff)) {
		return zero, fmt.Errorf("native name entry native chain window occupied")
	}
	q, err := nameEntryCloneCloneAuthenticated(exe, 0x8004e788, 0x8004e884, QueueRAM)
	if err != nil {
		return zero, err
	}
	p, err := nameEntryCloneCloneAuthenticated(exe, 0x8004f268, 0x8004f364, ParserRAM)
	if err != nil {
		return zero, err
	}
	u, err := nameEntryCloneCloneAuthenticated(exe, 0x8004f364, 0x8004f4f0, UploadRAM)
	if err != nil {
		return zero, err
	}
	selector, err := BuildGlyphSelector()
	if err != nil {
		return zero, err
	}
	if len(q) > 0x100 || len(p) > 0x100 || len(u) > 0x200 {
		return zero, fmt.Errorf("retail clones exceed planned windows")
	}
	// The three exact internal JAL relocations, with unchanged delay slots.
	patch := func(b []byte, pc, start uint32, sourceDest, newDest uint32) error {
		i := pc - start
		if int(i)+4 > len(b) || binary.LittleEndian.Uint32(b[i:]) != jalWord(sourceDest) {
			return fmt.Errorf("source JAL at %#x drift", pc)
		}
		binary.LittleEndian.PutUint32(b[i:], jalWord(newDest))
		return nil
	}
	if err = patch(q, 0x8004e82c, 0x8004e788, 0x8004f268, ParserRAM); err != nil {
		return zero, err
	}
	if err = patch(p, 0x8004f32c, 0x8004f268, 0x8004f364, UploadRAM); err != nil {
		return zero, err
	}
	if err = patch(u, 0x8004f390, 0x8004f364, 0x8004f4f0, SelectorRAM); err != nil {
		return zero, err
	}
	out := bytes.Clone(prev.Overlay)
	copy(out[QueueOff:], q)
	copy(out[ParserOff:], p)
	copy(out[UploadOff:], u)
	copy(out[SelectorOff:], selector)
	draws, err := nameEntryDrawScanDrawRoutes(original)
	if err != nil {
		return zero, err
	}
	sites := make([]uint32, 0, len(draws))
	for _, r := range draws {
		i := int(r.QueuePC - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out[i:]) != nameEntryDrawRetailQueueWord {
			return zero, fmt.Errorf("queue hook drift at %#x", r.QueuePC)
		}
		binary.LittleEndian.PutUint32(out[i:], jalWord(QueueRAM))
		sites = append(sites, r.QueuePC)
	}
	if !bytes.Equal(out[nameEntryGridGridStart:nameEntryGridGridEnd], original[nameEntryGridGridStart:nameEntryGridGridEnd]) ||
		!bytes.Equal(out[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4], original[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4]) {
		return zero, fmt.Errorf("native name entry touched selectable input")
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	// overlay loading guards scene provenance and the full 96-sector CPU load boundary
	// before even an offline candidate is returned. This does not approve GPU
	// or live RAM lifetime, but catches drift that glyph-only tests miss.
	if _, err := AuditNameEntLoadBoundary(exe, original, out); err != nil {
		return zero, fmt.Errorf("overlay loading NAME_ENT load boundary: %w", err)
	}
	return NativeChainCandidate{Overlay: out, QueueCalls: sites, SourceStageOnly: true, UsesNativeVRAMAllocator: true,
		ChangesRetailEXE: false, OriginalInputIntact: true, SafeToPatch: false, RuntimePass: false}, nil
}

// Compose against glyph aliasing's existing FULL private English carrier, not a bare
// NAME_ENT overlay. Only the authenticated renderer-local delta is permitted.
func PlanCombinedNativeGlyphChainOffline(exe []byte, originals map[string][]byte) (TELCandidate, NativeChainCandidate, error) {
	var empty TELCandidate
	prior, nameEntryAliasStage, err := PlanCombinedAliasesOffline(exe, originals)
	if err != nil {
		return empty, NativeChainCandidate{}, err
	}
	nameEntryCloneStage, err := PlanLocalNativeGlyphChainOffline(exe, originals["NAME_ENT.EXN"])
	if err != nil {
		return empty, NativeChainCandidate{}, err
	}
	merged := bytes.Clone(prior.Overlays["NAME_ENT.EXN"])
	if len(merged) != len(nameEntryAliasStage.Overlay) || len(merged) != len(nameEntryCloneStage.Overlay) {
		return empty, NativeChainCandidate{}, fmt.Errorf("merge size mismatch")
	}
	hooks := map[int]bool{}
	for _, pc := range nameEntryCloneStage.QueueCalls {
		hooks[int(pc-OverlaySlotBase)] = true
	}
	for i, v := range nameEntryCloneStage.Overlay {
		if i >= len(merged)-4 && i < len(merged)-2 {
			continue
		}
		if v == nameEntryAliasStage.Overlay[i] {
			continue
		}
		inHook := false
		for d := 0; d < 4; d++ {
			if hooks[i-d] {
				inHook = true
				break
			}
		}
		if !(inHook || (i >= AliasResolverOff && i < 0x23a00)) || merged[i] != nameEntryAliasStage.Overlay[i] {
			return empty, NativeChainCandidate{}, fmt.Errorf("foreign native name entry overlay merge change +%#x", i)
		}
		merged[i] = v
	}
	binary.BigEndian.PutUint16(merged[len(merged)-4:], packedTableChecksum(merged))
	prior.Overlays["NAME_ENT.EXN"] = merged
	prior.SafeToPatch = false
	prior.RuntimePass = false
	return prior, nameEntryCloneStage, nil
}
