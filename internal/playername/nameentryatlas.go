package playername

// A NAME_ENT-only raster candidate compatible in size with the 12x12, 18-byte
// 1bpp source glyphs documented in the original PS1 renderer. Its BIT ORDER is
// a host convention until compared with the retail font's original bitmap
// loader at 0x8004F4F0. Never install it globally or over gameplay kana.
import (
	"encoding/hex"
	"errors"
	"fmt"
)

type NameEntryGlyphCandidate struct {
	SourceCP932 string `json:"source_cp932"`
	Kana        string `json:"kana"`
	Label       string `json:"label"`
	SmallKana   bool   `json:"small_kana"`
	Mask18Hex   string `json:"candidate_1bpp_18_bytes_hex"`
	// This is not a proven drawable PS1 atlas slot; no hook or replacement exists.
}

func PackKeyboardMask18(mask [12]uint16) ([18]byte, error) {
	var packed [18]byte
	for y, row := range mask {
		if row & ^uint16(0xfff) != 0 {
			return packed, fmt.Errorf("row %d exceeds 12px", y)
		}
		for x := 0; x < 12; x++ {
			if row&(1<<uint(11-x)) == 0 {
				continue
			}
			bit := y*12 + x
			packed[bit>>3] |= 1 << uint(7-(bit&7))
		}
	}
	return packed, nil
}

func UnpackKeyboardMask18(packed [18]byte) [12]uint16 {
	var mask [12]uint16
	for y := 0; y < 12; y++ {
		for x := 0; x < 12; x++ {
			bit := y*12 + x
			if (packed[bit>>3] & (1 << uint(7-(bit&7)))) != 0 {
				mask[y] |= 1 << uint(11-x)
			}
		}
	}
	return mask
}

func BuildNameEntryGlyphCandidates(rows []KeyboardRow) ([]NameEntryGlyphCandidate, error) {
	if len(rows) == 0 {
		return nil, errors.New("missing keyboard rows")
	}
	var out []NameEntryGlyphCandidate
	cache := map[string]NameEntryGlyphCandidate{}
	for _, row := range rows {
		if len(row.Cells) == 0 {
			return nil, fmt.Errorf("empty keyboard row %s", row.OverlayOffset)
		}
		for _, cell := range row.Cells {
			_, mask, err := RenderRomajiKeyboardGlyph(cell.Kana)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", row.OverlayOffset, cell.Kana, err)
			}
			b, err := PackKeyboardMask18(mask)
			if err != nil {
				return nil, err
			}
			got := NameEntryGlyphCandidate{SourceCP932: cell.SourceCP932, Kana: cell.Kana, Label: cell.Label, SmallKana: cell.SmallKana, Mask18Hex: hex.EncodeToString(b[:])}
			if old, exists := cache[cell.SourceCP932]; exists && old != got {
				return nil, fmt.Errorf("duplicate CP932 %s has conflicting display glyph", cell.SourceCP932)
			}
			cache[cell.SourceCP932] = got
			out = append(out, got)
		}
	}
	return out, nil
}
