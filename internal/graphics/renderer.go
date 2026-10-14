package graphics

import (
	"bytes"
	"embed"
	"fmt"
	"hash/crc32"
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

//go:embed renderer_hook.bin renderer_site.bin
var rendererBlobs embed.FS

// RendererBuild returns the preassembled PS1 hook bytes, with a native-Go font table.
// The embedded MIPS code is checked against the Python assembler in tests.
func RendererBuild() (site, hook, narrow []byte, scratch uint32, err error) {
	site, err = rendererBlobs.ReadFile("renderer_site.bin")
	if err != nil {
		return
	}
	hook, err = rendererBlobs.ReadFile("renderer_hook.bin")
	if err != nil {
		return
	}
	narrow, err = NarrowFont()
	if err != nil {
		return
	}
	scratch = scratchGlyph
	if len(site) != len(originalSite) || len(hook) > hookSize || len(narrow) > narrowSize || scratchGlyph+18 > hookSource+hookSize {
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
