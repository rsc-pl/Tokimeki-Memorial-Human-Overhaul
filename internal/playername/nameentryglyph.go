package playername

// Compact 12x12 monochrome name-entry key-label raster. One kana cell
// still selects its original CP932 value. We do not modify the global kana
// font atlas: it is shared by the rest of the game. The caller must arrange
// display-only drawing exclusively on the NAME_ENT keyboard screen.
import "fmt"

// Uppercase 3x5 glyphs are drawn at full cell height. Lowercase glyphs
// use a separate shorter baseline; uppercase and lowercase labels MUST be
// distinguishable in the actual pixels (not merely in Go strings).
var gridFont3x5 = map[byte][5]uint8{
	'~': {0, 5, 2, 0, 0}, 'a': {0, 3, 5, 7, 5}, 'b': {6, 5, 6, 5, 6}, 'c': {3, 4, 4, 4, 3}, 'd': {6, 5, 5, 5, 6},
	'e': {7, 4, 6, 4, 7}, 'f': {7, 4, 6, 4, 4}, 'g': {3, 4, 5, 5, 3}, 'h': {5, 5, 7, 5, 5},
	'i': {7, 2, 2, 2, 7}, 'j': {1, 1, 1, 5, 2}, 'k': {5, 5, 6, 5, 5}, 'l': {4, 4, 4, 4, 7},
	'm': {5, 7, 7, 5, 5}, 'n': {5, 7, 7, 7, 5}, 'o': {2, 5, 5, 5, 2}, 'p': {6, 5, 6, 4, 4},
	'q': {0, 2, 5, 3, 1}, 'r': {0, 6, 5, 4, 4}, 's': {0, 3, 6, 3, 6}, 't': {2, 7, 2, 2, 1},
	'u': {0, 5, 5, 5, 7}, 'v': {0, 5, 5, 5, 2}, 'w': {0, 5, 7, 7, 5}, 'x': {0, 5, 2, 2, 5},
	'y': {0, 5, 5, 3, 1}, 'z': {0, 7, 1, 2, 7}, '-': {0, 0, 7, 0, 0}, '.': {0, 0, 0, 0, 2},
	'A': {2, 5, 7, 5, 5}, 'B': {6, 5, 6, 5, 6}, 'C': {3, 4, 4, 4, 3}, 'D': {6, 5, 5, 5, 6},
	'E': {7, 4, 6, 4, 7}, 'F': {7, 4, 6, 4, 4}, 'G': {3, 4, 5, 5, 3}, 'H': {5, 5, 7, 5, 5},
	'I': {7, 2, 2, 2, 7}, 'J': {1, 1, 1, 5, 2}, 'K': {5, 5, 6, 5, 5}, 'L': {4, 4, 4, 4, 7},
	'M': {5, 7, 7, 5, 5}, 'N': {5, 7, 7, 7, 5}, 'O': {2, 5, 5, 5, 2}, 'P': {6, 5, 6, 4, 4},
	'Q': {2, 5, 5, 3, 1}, 'R': {6, 5, 6, 5, 5}, 'S': {3, 4, 2, 1, 6}, 'T': {7, 2, 2, 2, 2},
	'U': {5, 5, 5, 5, 7}, 'V': {5, 5, 5, 5, 2}, 'W': {5, 5, 7, 7, 5}, 'X': {5, 5, 2, 5, 5},
	'Y': {5, 5, 2, 2, 2}, 'Z': {7, 1, 2, 4, 7},
}

// 12 bits per scanline, high bit is x=0. This is a *host raster sample*,
// not an already-installed PS1 texture or a screenshot QA result.
func RenderRomajiKeyboardGlyph(kana string) (label string, mask [12]uint16, err error) {
	label, err = KanaKeyboardLabel(kana)
	if err != nil {
		return "", mask, err
	}
	n := len(label)
	if n == 0 || n > 4 {
		return "", mask, fmt.Errorf("keyboard label exceeds 4 glyphs: %q", label)
	}
	gap := 1
	if n == 4 {
		gap = 0
	}
	used := 3*n + gap*(n-1)
	if used > 12 {
		return "", mask, fmt.Errorf("label overflow %s", label)
	}
	start := (12 - used) / 2
	for k := 0; k < n; k++ {
		glyph, ok := gridFont3x5[label[k]]
		if !ok {
			return "", mask, fmt.Errorf("missing compact glyph %q", label[k])
		}
		x := start + k*(3+gap)
		for dy := 0; dy < 5; dy++ {
			bits := glyph[dy]
			for dx := 0; dx < 3; dx++ {
				if bits&(1<<(2-dx)) != 0 {
					mask[dy+3] |= uint16(1) << uint(11-(x+dx))
				}
			}
		}
	}
	return label, mask, nil
}
