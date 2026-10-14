package graphics

import (
	"fmt"
	"hash/crc32"
	"math"
)

// Rect selects an area of the PNG, whose origin is placed at (X,Y) in the destination bitmap.
type Rect struct{ X, Y, W, H int }

// Patch holds raw-bitmap geometry and the checksum of the original pixels in the selected rectangles.
type Patch struct {
	Offset        int
	Stride        int
	X, Y          int
	BPP           int
	Rects         []Rect
	OriginalCRC32 uint32
}

type writePixel struct {
	offset int
	shift  uint
	value  byte
}

// ApplyPatch returns a new buffer. On any error, the input is unchanged.
// 4bpp uses the low nibble for the left pixel, matching the original patcher.
func ApplyPatch(input []byte, im Indexed, p Patch) ([]byte, error) {
	if err := im.Validate(); err != nil {
		return nil, err
	}
	if p.BPP != 4 && p.BPP != 8 {
		return nil, fmt.Errorf("unsupported bitmap depth %d", p.BPP)
	}
	if p.Offset < 0 || p.Stride <= 0 || p.X < 0 || p.Y < 0 || p.Offset > len(input) {
		return nil, fmt.Errorf("invalid bitmap geometry")
	}
	rowPixels := int64(p.Stride) * 8 / int64(p.BPP)
	if rowPixels > math.MaxInt32 {
		return nil, fmt.Errorf("bitmap stride too large")
	}
	expected := make([]byte, 0)
	planned := make([]writePixel, 0)
	if len(p.Rects) == 0 {
		return nil, fmt.Errorf("no image rectangles")
	}
	for _, r := range p.Rects {
		if r.X < 0 || r.Y < 0 || r.W <= 0 || r.H <= 0 || r.X > im.Width-r.W || r.Y > im.Height-r.H || int64(p.X)+int64(r.X)+int64(r.W) > rowPixels {
			return nil, fmt.Errorf("image rectangle %+v is out of bounds", r)
		}
		if int64(r.W)*int64(r.H) > int64(len(input))*8 || len(planned)+r.W*r.H > 32<<20 {
			return nil, fmt.Errorf("image patch exceeds safe size")
		}
		for row := r.Y; row < r.Y+r.H; row++ {
			for col := r.X; col < r.X+r.W; col++ {
				x, y := int64(p.X)+int64(col), int64(p.Y)+int64(row)
				at := int64(p.Offset) + y*int64(p.Stride) + x/(8/int64(p.BPP))
				if at < 0 || at >= int64(len(input)) {
					return nil, fmt.Errorf("target pixel (%d,%d) is outside bitmap", x, y)
				}
				var shift uint
				if p.BPP == 4 {
					shift = uint((x & 1) * 4)
				}
				value := im.Pixels[row*im.Width+col]
				if p.BPP == 4 && value > 15 {
					return nil, fmt.Errorf("pixel (%d,%d) has palette index %d (> 15)", col, row, value)
				}
				old := input[int(at)]
				if p.BPP == 4 {
					old = (old >> shift) & 15
				}
				expected = append(expected, old)
				planned = append(planned, writePixel{int(at), shift, value})
			}
		}
	}
	if actual := crc32.ChecksumIEEE(expected); actual != p.OriginalCRC32 {
		return nil, fmt.Errorf("original pixels CRC32 %08x does not match expected %08x", actual, p.OriginalCRC32)
	}
	result := append([]byte(nil), input...)
	for _, v := range planned {
		if p.BPP == 8 {
			result[v.offset] = v.value
		} else {
			result[v.offset] = (result[v.offset] & ^byte(15<<v.shift)) | (v.value << v.shift)
		}
	}
	return result, nil
}
