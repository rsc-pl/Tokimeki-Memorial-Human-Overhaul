package n20arch

// name-entry glyphs verifies the 18-byte NAME_ENT romaji candidates against the actual
// retail R3000A 12x12 1bpp -> 4bpp glyph expander. It DOES NOT hook the
// renderer, alter a shared font table, or establish a runtime-safe overlay
// memory lifetime. The 96-byte result is the raster payload consumed by the
// original VRAM upload path, not a complete executable glyph router.
import "fmt"

const (
	RetailGlyphBank      uint32 = 0x800B6D50
	RetailGlyphExpand    uint32 = 0x8004F4F0
	RetailQueueDraw      uint32 = 0x8004E788
	RetailQueueGlyphs    uint32 = 0x8004F268
	RetailGlyphUpload    uint32 = 0x8004F364
	RetailLoadImage      uint32 = 0x8004435C
	RetailFontGlyphBytes        = 18
	ExpandedGlyphBytes          = 96
)

// ExpandMask18 models the observable bit ordering of retail
// 0x8004F4F0: MSB-first in source, lower nibble first in the destination.
// The parity test independently executes the real PS1 instructions.
func ExpandMask18(mask []byte) ([ExpandedGlyphBytes]byte, error) {
	var out [ExpandedGlyphBytes]byte
	if len(mask) != RetailFontGlyphBytes {
		return out, fmt.Errorf("expected an 18-byte retail 12x12 glyph, got %d", len(mask))
	}
	for pixel := 0; pixel < 144; pixel++ {
		bit := (mask[pixel/8] >> uint(7-(pixel&7))) & 1
		if pixel&1 == 0 {
			out[(pixel/12)*8+(pixel%12)/2] |= bit
		} else {
			out[(pixel/12)*8+(pixel%12)/2] |= bit << 4
		}
	}
	return out, nil
}

// RetailPCWord uses the authenticated PS-X EXE header's text offset:
// on this disc, text RAM 0x80041000 starts at file offset 0x800.
// Never treat the header as executable code or use 0x80010000 as text base.
func RetailPCWord(exe []byte, pc uint32) (uint32, error) {
	if len(exe) < 0x800 || string(exe[:8]) != "PS-X EXE" {
		return 0, fmt.Errorf("not a PS-X EXE")
	}
	load := uint32(exe[0x18]) | uint32(exe[0x19])<<8 | uint32(exe[0x1a])<<16 | uint32(exe[0x1b])<<24
	size := uint32(exe[0x1c]) | uint32(exe[0x1d])<<8 | uint32(exe[0x1e])<<16 | uint32(exe[0x1f])<<24
	if pc&3 != 0 || pc < load || pc-load+4 > size {
		return 0, fmt.Errorf("PC %#x outside authenticated executable text", pc)
	}
	off := int(pc-load) + 0x800
	if off+4 > len(exe) {
		return 0, fmt.Errorf("truncated PS-X EXE at %#x", pc)
	}
	return uint32(exe[off]) | uint32(exe[off+1])<<8 | uint32(exe[off+2])<<16 | uint32(exe[off+3])<<24, nil
}
