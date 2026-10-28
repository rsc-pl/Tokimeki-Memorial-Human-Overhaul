package n20arch

// loop guards: OFFLINE-only exhaustive first-entry guards for the retail parser's
// 22 structurally authenticated manual name-byte loops. This reuses guarded copying's
// checkedstrlen entry and 308-byte renderer-resident module; no new RAM.
// Protecting a single iteration's JAL is too late because its delay slot
// has already executed an sb, so only each loop's INITIAL strlen is hooked.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	nametables "tokimemo/internal/namepatch"
)

type manualNameCopyManualLoop struct{ InitialJAL, ManualStore uint32 }

// Independently pinned retail source locations. The pairs are deliberately
// explicit, not discovered from arbitrary opcode matches on modded images.
var manualNameCopyRetailManualLoops = [...]manualNameCopyManualLoop{
	{0x80081578, 0x800815a4}, {0x80081620, 0x8008164c},
	{0x800816cc, 0x800816fc}, {0x80081780, 0x800817ac},
	{0x80081838, 0x80081864}, {0x800818fc, 0x80081928},
	{0x800819b4, 0x800819e0}, {0x80081a60, 0x80081a90},
	{0x80081b18, 0x80081b48}, {0x80081bd0, 0x80081c00},
	{0x80081c88, 0x80081cb8}, {0x80081eb0, 0x80081edc},
	{0x80081f58, 0x80081f84}, {0x80082004, 0x80082038},
	{0x800820bc, 0x800820e8}, {0x80082174, 0x800821a0},
	{0x80082238, 0x80082264}, {0x800822f0, 0x8008231c},
	{0x8008239c, 0x800823d0}, {0x80082458, 0x8008248c},
	{0x80082514, 0x80082548}, {0x800825d0, 0x80082604},
}

type AllManualLoopsCandidate struct {
	ManualNameLoopCandidate
	TotalGuardedManualLoops  int
	AddedManualLoopJALs      int
	FixedLongNameCopySources int
	SafeToPatch              bool
	RuntimePass              bool
}

// Verify the original first-length call, authentic second-length call and its
// unguardable sb delay slot. In every permitted loop, destination must be
// formed as original s1+signed-copy-index before that second call.
func manualNameCopyValidateRetailLoop(retail []byte, loop manualNameCopyManualLoop) error {
	at := func(pc uint32) (uint32, error) {
		off := int(pc - Base)
		if pc < Base || off+4 > len(retail) {
			return 0, fmt.Errorf("out-of-bounds retail instruction %#x", pc)
		}
		return binary.LittleEndian.Uint32(retail[off:]), nil
	}
	first, err := at(loop.InitialJAL)
	if err != nil {
		return err
	}
	second, err := at(loop.ManualStore - 4)
	if err != nil {
		return err
	}
	store, err := at(loop.ManualStore)
	if err != nil {
		return err
	}
	if first != jalWord(parserCopyGuardNativeStrlen) || second != jalWord(parserCopyGuardNativeStrlen) || store>>26 != 0x28 || store&0xffff != 0 {
		return fmt.Errorf("retail manual loop opcode mismatch %#x/%#x", loop.InitialJAL, loop.ManualStore)
	}
	// A guard immediately after the second JAL would run after its store.
	// Require its destination register to have been formed from s1+s0.
	dst := (store >> 21) & 31
	formed := false
	for pc := loop.InitialJAL + 8; pc < loop.ManualStore-4; pc += 4 {
		w, e := at(pc)
		if e != nil {
			return e
		}
		if w>>26 == 0 && w&63 == 0x21 && (w>>11)&31 == dst &&
			(((w>>21)&31 == 17 && (w>>16)&31 == 16) || ((w>>21)&31 == 16 && (w>>16)&31 == 17)) {
			formed = true
		}
	}
	if !formed {
		return fmt.Errorf("no retail s1+s0 copy destination at %#x", loop.ManualStore)
	}
	return nil
}

// manualNameCopyRepairN10StrlenVersusCopySource fixes one actual long-NPC name
// relocation bug: N10 retargeted the loop's initial strlen to the new table
// while its inline lbu still read the OLD table. A long surname then used
// the new length with old bytes. Pin five fixed-source candidates and refuse
// all unexpected alias mismatches, writing only the two authentic consumer
// instructions for the one demonstrated mismatch.
func manualNameCopyRepairN10StrlenVersusCopySource(ex, retail []byte) (int, error) {
	pairs := [...]struct{ first, lui, lbu uint32 }{
		{0x80082004, 0x80082010, 0x8008201c},
		{0x8008239c, 0x800823a8, 0x800823b4},
		{0x80082458, 0x80082464, 0x80082470},
		{0x80082514, 0x80082520, 0x8008252c},
		{0x800825d0, 0x800825dc, 0x800825e8},
	}
	word := func(image []byte, pc uint32) uint32 { return binary.LittleEndian.Uint32(image[int(pc-Base):]) }
	patched := 0
	for _, p := range pairs {
		hi, lo := word(ex, p.first-4), word(ex, p.first+4)
		oldHi, oldLo := word(ex, p.lui), word(ex, p.lbu)
		if hi>>26 != 15 || (hi>>16)&31 != 4 || lo>>26 != 9 || (lo>>21)&31 != 4 || (lo>>16)&31 != 4 ||
			oldHi>>26 != 15 || oldLo>>26 != 0x24 || (oldHi>>16)&31 != (oldLo>>21)&31 || (oldLo>>16)&31 != (oldLo>>21)&31 {
			return 0, fmt.Errorf("loop guards unrecognized native inline copy source %#x", p.first)
		}
		source := uint32(int64((hi&0xffff)<<16) + int64(int16(lo&0xffff)))
		copied := uint32(int64((oldHi&0xffff)<<16) + int64(int16(oldLo&0xffff)))
		if source == copied {
			continue
		}
		if p.first != 0x80082004 || !bytes.Equal(ex[int(p.lui-Base):int(p.lui-Base)+4], retail[int(p.lui-Base):int(p.lui-Base)+4]) ||
			!bytes.Equal(ex[int(p.lbu-Base):int(p.lbu-Base)+4], retail[int(p.lbu-Base):int(p.lbu-Base)+4]) ||
			copied != 0x800ca190 || source != 0x800b35b4 {
			return 0, fmt.Errorf("loop guards unexpected relocated source %#x: strlen %#x != copy %#x", p.first, source, copied)
		}
		newHi := (source + 0x8000) >> 16
		if uint32(int64(newHi<<16)+int64(int16(source&0xffff))) != source {
			return 0, fmt.Errorf("loop guards unrepresentable source %#x", source)
		}
		binary.LittleEndian.PutUint32(ex[int(p.lui-Base):], oldHi&0xffff0000|(newHi&0xffff))
		binary.LittleEndian.PutUint32(ex[int(p.lbu-Base):], oldLo&0xffff0000|(source&0xffff))
		patched++
	}
	if patched != 1 {
		return 0, fmt.Errorf("loop guards unexpected number of long-NPC source repairs: %d", patched)
	}
	return patched, nil
}

func PlanAllManualLoopsOffline(retail []byte, overlays map[string][]byte, in nametables.N10OfflineTransaction) (AllManualLoopsCandidate, error) {
	var zero AllManualLoopsCandidate
	prev, err := PlanManualNameLoopsOffline(retail, overlays, in)
	if err != nil {
		return zero, err
	}
	prog, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return zero, err
	}
	result := bytes.Clone(prev.EnglishRendererEXE)
	added := 0
	for i, loop := range manualNameCopyRetailManualLoops {
		if err := manualNameCopyValidateRetailLoop(retail, loop); err != nil {
			return zero, err
		}
		off := int(loop.InitialJAL - Base)
		want := jalWord(parserCopyGuardNativeStrlen)
		if i < 2 {
			want = jalWord(prog.entries["checkedstrlen"])
		}
		if binary.LittleEndian.Uint32(result[off:]) != want {
			return zero, fmt.Errorf("loop guards callsite mismatch at %#x current=%#x expected=%#x", loop.InitialJAL, binary.LittleEndian.Uint32(result[off:]), want)
		}
		// parser relocation N10 legitimately retargeted some caller LUI/ADDIU source
		// pairs to the long-NPC string tables. Preserve those bytes intact.
		// The earlier authenticated composer owns their exact values.
		newDelay := binary.LittleEndian.Uint32(result[off+4:])
		oldDelay := binary.LittleEndian.Uint32(retail[off+4:])
		if newDelay != oldDelay {
			prior := binary.LittleEndian.Uint32(result[off-4:])
			if newDelay>>26 != 9 || (newDelay>>21)&31 != 4 || (newDelay>>16)&31 != 4 || prior>>26 != 15 || (prior>>16)&31 != 4 {
				return zero, fmt.Errorf("loop guards altered unexpected delay at %#x", loop.InitialJAL)
			}
		}
		if i >= 2 {
			binary.LittleEndian.PutUint32(result[off:], jalWord(prog.entries["checkedstrlen"]))
			added++
		}
	}
	if len(manualNameCopyRetailManualLoops) != 22 || added != 20 {
		return zero, fmt.Errorf("loop guards unexpected loop coverage")
	}
	repaired, err := manualNameCopyRepairN10StrlenVersusCopySource(result, retail)
	if err != nil {
		return zero, err
	}
	prev.EnglishRendererEXE = result
	return AllManualLoopsCandidate{ManualNameLoopCandidate: prev, TotalGuardedManualLoops: 22, AddedManualLoopJALs: added, FixedLongNameCopySources: repaired, SafeToPatch: false, RuntimePass: false}, nil
}
