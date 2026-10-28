package playername

// Name-entry keyboard display model. In NAME_ENT the kana character is
// the GAME INPUT CODE, not a display-only label. Always keep the original
// selected CP932 bytes separate from its romaji label. This module does not
// patch the game and never changes a saved name.
import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

type KeyboardCell struct {
	Kana                 string `json:"kana"`
	Label                string `json:"label"`
	SourceCP932          string `json:"source_cp932"`
	LatinGlyphCells      int    `json:"latin_pair_glyph_cells"`
	FitsOneOriginalGlyph bool   `json:"fits_one_original_glyph"`
	SmallKana            bool   `json:"small_kana"`
}

// KanaKeyboardLabel uses the authenticated entry-grid convention: normal kana are
// uppercase Latin syllables (KA, SHI, TSU), small composing kana are lowercase
// (a, ya, tsu). Neither labels nor their rendered pixels are saved as a name.
// This differs from the display name's ordinary title case (Mumei, Kya).
func KanaKeyboardLabel(kana string) (string, error) {
	rr := []rune(kana)
	if len(rr) != 1 {
		return "", errors.New("one keyboard cell must be one kana character")
	}
	r := hira(rr[0])
	if r == 'ー' {
		return "-", nil
	}
	if r == '～' {
		return "~", nil
	}
	if r == '　' {
		return "SP", nil
	}
	if r == '・' {
		return ".", nil
	}
	special := map[rune]string{
		'ぁ': "a", 'ぃ': "i", 'ぅ': "u", 'ぇ': "e", 'ぉ': "o",
		'ゃ': "ya", 'ゅ': "yu", 'ょ': "yo", 'っ': "tsu",
		'ゎ': "wa", 'ゕ': "ka", 'ゖ': "ke",
	}
	if v, ok := special[r]; ok {
		return v, nil
	}
	if r == 'を' {
		return "WO", nil
	} // distinct keyboard character from お
	if v, ok := syllables[r]; ok {
		return strings.ToUpper(v), nil
	}
	if r == 'ゐ' {
		return "WI", nil
	}
	if r == 'ゑ' {
		return "WE", nil
	}
	if r == 'ゔ' {
		return "VU", nil
	}
	return "", fmt.Errorf("unsupported keyboard kana %U", rr[0])
}

// NameFieldDisplay works for any saved kana name; it capitalizes actual name
// segments but never forces capitalization on the grid labels.
func NameFieldDisplay(rawCP932 []byte) (string, error) {
	source, err := DecodeCP932Kana(rawCP932)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(source) == "" {
		return "", errors.New("empty saved name")
	}
	return RomanizeKana(source)
}

// ParseNameEntryKeyboardRows scans only the documented NAME_ENT.EXN keyboard
// string window [0x19150,0x192D8), without ever writing to it. A string is
// listed only when all its characters have explicit mappings; non-kana data
// and conversion tables are not interpreted as display text. Rows preserve
// their original source-byte positions to allow later code/data xref checks.
func ParseNameEntryKeyboardRows(overlay []byte) ([]KeyboardRow, error) {
	const begin = 0x19150
	const end = 0x192D8
	if len(overlay) != 196608 {
		return nil, fmt.Errorf("NAME_ENT.EXN size %d, expected 196608", len(overlay))
	}
	var rows []KeyboardRow
	for p := begin; p < end; {
		first := p
		for p < end && overlay[p] != 0 {
			p++
		}
		raw := overlay[first:p]
		// NAME_ENT can append one ASCII 0x20 alignment pad after five
		// CP932 glyphs (the Katakana SA row). This byte is NOT a key.
		// Do not strip internal spaces or hide malformed multi-byte rows.
		if len(raw)%2 == 1 && len(raw) > 0 && raw[len(raw)-1] == 0x20 {
			raw = bytes.TrimSuffix(raw, []byte{0x20})
		}
		if len(raw) >= 6 && len(raw) <= 48 && len(raw)%2 == 0 {
			var cells []KeyboardCell
			good := true
			for i := 0; i < len(raw); i += 2 {
				s, err := DecodeCP932Kana(raw[i : i+2])
				if err != nil {
					good = false
					break
				}
				label, err := KanaKeyboardLabel(s)
				if err != nil {
					good = false
					break
				}
				// Source is two bytes. Names stay encoded with precisely this
				// pair no matter what appears on screen.
				cells = append(cells, KeyboardCell{Kana: s, Label: label, SourceCP932: fmt.Sprintf("%02x%02x", raw[i], raw[i+1]), LatinGlyphCells: (len(label) + 1) / 2, FitsOneOriginalGlyph: len(label) <= 2, SmallKana: label != strings.ToUpper(label)})
			}
			if good && len(cells) >= 3 {
				rows = append(rows, KeyboardRow{OverlayOffset: fmt.Sprintf("0x%05X", first), Cells: cells})
			}
		}
		if p == end {
			break
		}
		p++
	}
	if len(rows) == 0 {
		return nil, errors.New("no unambiguous NAME_ENT kana rows; no modification")
	}
	return rows, nil
}

type KeyboardRow struct {
	OverlayOffset string         `json:"overlay_offset"`
	Cells         []KeyboardCell `json:"cells"`
}
