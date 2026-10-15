package duckstation

import (
	"fmt"
	"image/color"
	"image/png"
	"os"
)

type ScreenStats struct {
	Width         int     `json:"width"`
	Height        int     `json:"height"`
	WhiteFraction float64 `json:"white_fraction"`
	PinkFraction  float64 `json:"pink_fraction"`
}

// AnalyzeScreen follows the legacy DuckStation title-screen detector's exact
// center-area RGB thresholds and 8-pixel sampling grid. PNG decode is native
// Go and also supports formats the historical minimal PNG decoder did not.
func AnalyzeScreen(filename string) (ScreenStats, error) {
	f, err := os.Open(filename)
	if err != nil {
		return ScreenStats{}, err
	}
	defer f.Close()
	im, err := png.Decode(f)
	if err != nil {
		return ScreenStats{}, fmt.Errorf("decode screenshot PNG: %w", err)
	}
	b := im.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 16 || h < 8 {
		return ScreenStats{}, fmt.Errorf("screenshot too small: %dx%d", w, h)
	}
	var white, pink, total int
	for y := 0; y < h; y += 8 {
		for x := w / 6; x < w*5/6; x += 8 {
			pix := color.NRGBAModel.Convert(im.At(b.Min.X+x, b.Min.Y+y)).(color.NRGBA)
			// The Python reference checks raw RGB even for RGBA PNGs.
			r8, g8, b8 := uint32(pix.R), uint32(pix.G), uint32(pix.B)
			total++
			if r8 > 230 && g8 > 230 && b8 > 230 {
				white++
			}
			if r8 > 200 && g8 < 120 && b8 > 120 {
				pink++
			}
		}
	}
	if total == 0 {
		return ScreenStats{}, fmt.Errorf("no screenshot sample points")
	}
	return ScreenStats{w, h, float64(white) / float64(total), float64(pink) / float64(total)}, nil
}
func (s ScreenStats) IsTitle() bool { return s.WhiteFraction > 0.5 && s.PinkFraction > 0.01 }
