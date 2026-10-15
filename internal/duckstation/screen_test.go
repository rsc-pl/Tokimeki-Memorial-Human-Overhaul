package duckstation

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func fixtureScreenshot(t *testing.T, pinkLogo bool) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "shot.png")
	im := image.NewNRGBA(image.Rect(0, 0, 192, 96))
	for y := 0; y < 96; y++ {
		for x := 0; x < 192; x++ {
			col := color.NRGBA{255, 255, 255, 255}
			if pinkLogo && x >= 55 && x < 80 && y < 24 {
				col = color.NRGBA{255, 30, 180, 255}
			}
			im.SetNRGBA(x, y, col)
		}
	}
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err = png.Encode(f, im); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return filename
}
func TestTitleScreenshotNativeDetector(t *testing.T) {
	s, err := AnalyzeScreen(fixtureScreenshot(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsTitle() {
		t.Fatalf("expected title: %+v", s)
	}
	s, err = AnalyzeScreen(fixtureScreenshot(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if s.IsTitle() {
		t.Fatalf("accepted blank white fade: %+v", s)
	}
}
func TestScreenshotRejectsBrokenPNG(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.png")
	if err := os.WriteFile(p, []byte("not PNG"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AnalyzeScreen(p); err == nil {
		t.Fatal("accepted malformed PNG")
	}
}
