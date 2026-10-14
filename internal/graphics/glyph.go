package graphics

import (
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed glyphs.json
var glyphFile embed.FS

type glyphDef struct {
	Top  int      `json:"top"`
	Rows []string `json:"rows"`
}

var glyphs map[string]glyphDef
var glyphOnce sync.Once
var glyphErr error

func loadGlyphs() error {
	glyphOnce.Do(func() {
		data, e := glyphFile.ReadFile("glyphs.json")
		if e != nil {
			glyphErr = e
			return
		}
		glyphErr = json.Unmarshal(data, &glyphs)
		if glyphErr != nil {
			return
		}
		for ch, def := range glyphs {
			if len(ch) != 1 || def.Top < 0 || def.Top > 12 || def.Top+len(def.Rows) > 12 {
				glyphErr = fmt.Errorf("invalid glyph %q", ch)
				return
			}
			for _, row := range def.Rows {
				if len(row) != 5 {
					glyphErr = fmt.Errorf("invalid glyph width %q", ch)
					return
				}
				for _, pix := range row {
					if pix != '.' && pix != '#' {
						glyphErr = fmt.Errorf("invalid glyph pixel %q", ch)
						return
					}
				}
			}
		}
	})
	return glyphErr
}

// Supported reports whether a character has a narrow letter glyph.
func Supported(ch byte) bool {
	if loadGlyphs() != nil {
		return false
	}
	_, ok := glyphs[string(ch)]
	return ok
}

// LetterRows returns twelve five-bit rows, leftmost pixel at bit 4.
func LetterRows(ch byte) ([12]byte, error) {
	var rows [12]byte
	if err := loadGlyphs(); err != nil {
		return rows, err
	}
	def, ok := glyphs[string(ch)]
	if !ok {
		return rows, fmt.Errorf("unsupported character %q", ch)
	}
	for y, row := range def.Rows {
		for x, v := range row {
			if v == '#' {
				rows[def.Top+y] |= byte(0x10 >> x)
			}
		}
	}
	return rows, nil
}

// RenderPair creates the game's 18-byte 12x12 MSB-first packed glyph.
func RenderPair(left, right byte) ([18]byte, error) {
	var out [18]byte
	a, e := LetterRows(left)
	if e != nil {
		return out, e
	}
	b, e := LetterRows(right)
	if e != nil {
		return out, e
	}
	for y := 0; y < 12; y++ {
		bits := uint16(a[y])<<7 | uint16(b[y])
		for x := 0; x < 12; x++ {
			if bits&(1<<(11-x)) != 0 {
				index := y*12 + x
				out[index/8] |= 0x80 >> uint(index%8)
			}
		}
	}
	return out, nil
}

// NarrowFont emits the 96 ASCII table entries consumed by the PS1 renderer hook.
func NarrowFont() ([]byte, error) {
	if err := loadGlyphs(); err != nil {
		return nil, err
	}
	out := make([]byte, 96*8)
	for c := 32; c < 128; c++ {
		var rows [12]byte
		if Supported(byte(c)) {
			rows, _ = LetterRows(byte(c))
		}
		var words [2]uint32
		for y, v := range rows {
			words[y/6] |= uint32(v) << uint(5*(y%6))
		}
		binary.LittleEndian.PutUint32(out[(c-32)*8:], words[0])
		binary.LittleEndian.PutUint32(out[(c-32)*8+4:], words[1])
	}
	return out, nil
}
