package graphics

import (
	"bytes"

	"fmt"
	"hash/crc32"
	"tokimemo/internal/mips"
)

const (
	exeBase           uint32 = 0x80040800
	hookSite          uint32 = 0x8004f2cc
	hookSource        uint32 = 0x8004443c
	hookSize                 = 708
	narrowSource      uint32 = 0x8004b778
	narrowSize               = 948
	scratchGlyph      uint32 = 0x8004451c
	originalHookCRC   uint32 = 0x95CF8D48
	originalNarrowCRC uint32 = 0xC57F80EA
)

var originalSite = []byte{0x0b, 0x80, 0x09, 0x3c, 0x2c, 0x40, 0x29, 0x95}

// RendererBuild assembles the original hook source in native Go and creates
// the 5x12 English pair-font table. No preassembled binary is needed at runtime.
func RendererBuild() (site, hook, narrow []byte, scratch uint32, err error) {
	symbols := map[string]int64{
		"HOOK_RESUME": 0x8004F2D8, "LAYOUT_LOOP": 0x8004F294,
		"RENDER_GLYPH": 0x8004F364, "NARROW": int64(narrowSource),
		"SCRATCH": 0, "SCRATCH_INDEX": 0,
	}
	preliminary, e := mips.Assemble(hookAssembly, hookSource, symbols)
	if e != nil {
		err = fmt.Errorf("renderer first assembly: %w", e)
		return
	}
	// Scratch must be aligned to the game's 18-byte font-glyph stride.
	scratch = hookSource + uint32(len(preliminary))
	for (int64(scratch)-0x800B6D50)%18 != 0 {
		scratch++
	}
	symbols["SCRATCH"] = int64(scratch)
	symbols["SCRATCH_INDEX"] = int64(uint32((int64(scratch) - 0x800B6D50) / 18))
	hook, err = mips.Assemble(hookAssembly, hookSource, symbols)
	if err != nil {
		err = fmt.Errorf("renderer final assembly: %w", err)
		return
	}
	site, err = mips.Assemble("j hook\nandi t0, v1, 0xffff", hookSite, map[string]int64{"hook": int64(hookSource)})
	if err != nil {
		return
	}
	narrow, err = NarrowFont()
	if err != nil {
		return
	}
	if len(site) != len(originalSite) || len(hook) > hookSize || len(narrow) > narrowSize || scratch+18 > hookSource+hookSize {
		err = fmt.Errorf("renderer patch exceeds reserved regions")
	}
	return
}

func region(exe []byte, addr uint32, length int) ([]byte, error) {
	if addr < exeBase {
		return nil, fmt.Errorf("invalid executable address %08x", addr)
	}
	start := uint64(addr - exeBase)
	if start+uint64(length) > uint64(len(exe)) {
		return nil, fmt.Errorf("executable lacks guarded region at %08x", addr)
	}
	return exe[start : start+uint64(length)], nil
}

type rendererGuards struct{ HookCRC, FontCRC uint32 }

// InstallRenderer patches a copy of the PlayStation the Best SLPM_86.053 image.
// It refuses an unknown executable or an already modified renderer region.
func InstallRenderer(original []byte) ([]byte, error) {
	return installRenderer(original, rendererGuards{originalHookCRC, originalNarrowCRC})
}
func installRenderer(original []byte, guards rendererGuards) ([]byte, error) {
	site, err := region(original, hookSite, len(originalSite))
	if err != nil {
		return nil, err
	}
	hook, err := region(original, hookSource, hookSize)
	if err != nil {
		return nil, err
	}
	narrow, err := region(original, narrowSource, narrowSize)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(site, originalSite) {
		return nil, fmt.Errorf("renderer site does not match unmodified SLPM_86.053")
	}
	if crc32.ChecksumIEEE(hook) != guards.HookCRC || crc32.ChecksumIEEE(narrow) != guards.FontCRC {
		return nil, fmt.Errorf("renderer reserved executable regions have unexpected CRC32")
	}
	siteCode, hookCode, font, scratch, err := RendererBuild()
	if err != nil {
		return nil, err
	}
	if scratch != scratchGlyph {
		return nil, fmt.Errorf("renderer scratch address changed")
	}
	result := append([]byte(nil), original...)
	toSite, _ := region(result, hookSite, len(originalSite))
	copy(toSite, siteCode)
	toHook, _ := region(result, hookSource, hookSize)
	clear(toHook)
	copy(toHook, hookCode)
	toNarrow, _ := region(result, narrowSource, narrowSize)
	clear(toNarrow)
	copy(toNarrow, font)
	return result, nil
}

// GlyphOffset finds an original 12x12 font glyph by its Shift-JIS code.
func GlyphOffset(exe []byte, code uint16) (int, error) {
	const rangeBegin uint32 = 0x800b402c
	const rangeEnd uint32 = 0x800b40e4
	const fontStart uint32 = 0x800b6d50
	table, err := region(exe, rangeBegin, int(rangeEnd-rangeBegin))
	if err != nil {
		return 0, err
	}
	if crc32.ChecksumIEEE(table) != 0x3cc19ff3 {
		return 0, fmt.Errorf("unsupported font range table")
	}
	index := -1
	for pos := 0; pos+4 <= len(table); pos += 4 {
		first := uint16(table[pos]) | uint16(table[pos+1])<<8
		base := uint16(table[pos+2]) | uint16(table[pos+3])<<8
		if code >= first {
			index = int(base) + int(code-first)
		}
	}
	if index < 0 || index >= 3418 {
		return 0, fmt.Errorf("glyph %04x is absent", code)
	}
	off := int(fontStart-exeBase) + index*18
	if off < 0 || off+18 > len(exe) {
		return 0, fmt.Errorf("glyph %04x lies outside executable", code)
	}
	return off, nil
}

// RendererNameTail verifies the complete installed renderer hook and font, then
// returns a detached copy of its 180-byte reserved tail. Callers MUST audit
// ownership of any occupied bytes; this routine does not claim spare RAM.
func RendererNameTail(patched []byte) (start int, tail []byte, err error) {
	site, hook, font, scratch, e := RendererBuild()
	if e != nil {
		return 0, nil, e
	}
	if scratch != scratchGlyph {
		return 0, nil, fmt.Errorf("unexpected renderer scratch")
	}
	src, e := region(patched, hookSite, len(site))
	if e != nil {
		return 0, nil, e
	}
	if !bytes.Equal(src, site) {
		return 0, nil, fmt.Errorf("renderer site not installed as expected")
	}
	code, e := region(patched, hookSource, hookSize)
	if e != nil {
		return 0, nil, e
	}
	if !bytes.Equal(code[:len(hook)], hook) || !allZero(code[len(hook):int(scratch-hookSource)]) || !allZero(code[int(scratch-hookSource)+18:]) {
		return 0, nil, fmt.Errorf("renderer hook reservation changed")
	}
	narrow, e := region(patched, narrowSource, narrowSize)
	if e != nil {
		return 0, nil, e
	}
	if !bytes.Equal(narrow[:len(font)], font) {
		return 0, nil, fmt.Errorf("renderer font changed")
	}
	return int(narrowSource-exeBase) + len(font), append([]byte(nil), narrow[len(font):]...), nil
}

// ReservedNamePool returns the as-yet-unused trailing portion of the already
// guarded renderer font reservation. The original renderer installation clears
// the entire 948-byte region, and only the first 768 bytes contain font glyphs.
// This is a candidate for EXE static string storage ONLY. It does not enlarge
// runtime name-copy destinations or prove that longer names are safe in game.
// It refuses an uninstalled, partially changed, or foreign renderer.
func ReservedNamePool(patched []byte) (start int, before []byte, err error) {
	start, before, err = RendererNameTail(patched)
	if err != nil {
		return 0, nil, err
	}
	if !allZero(before) {
		return 0, nil, fmt.Errorf("renderer font tail is occupied")
	}
	return start, before, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
