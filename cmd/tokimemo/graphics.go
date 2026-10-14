package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/graphics"
)

type imageProbe struct {
	Source string   `json:"source"`
	PNG    string   `json:"png"`
	BPP    int      `json:"bpp"`
	Stride int      `json:"stride"`
	X      int      `json:"x"`
	Y      int      `json:"y"`
	Rects  [][4]int `json:"rects"`
	Seed   int      `json:"seed"`
}
type imageResult struct {
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	PixelsSHA string `json:"pixels_sha256"`
	OutputSHA string `json:"output_sha256"`
}

func hexSHA(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

func collectImageProbes(root string) ([]imageProbe, error) {
	paths, e := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if e != nil {
		return nil, e
	}
	sort.Strings(paths)
	result := []imageProbe{}
	for _, path := range paths {
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		var d struct {
			Images []struct {
				PNG    string   `json:"png"`
				BPP    int      `json:"bpp"`
				Stride int      `json:"stride"`
				X      int      `json:"x"`
				Y      int      `json:"y"`
				Rects  [][4]int `json:"rects"`
			} `json:"images"`
		}
		if e = json.Unmarshal(b, &d); e != nil {
			return nil, fmt.Errorf("%s: %w", path, e)
		}
		for _, p := range d.Images {
			bpp := p.BPP
			if bpp == 0 {
				bpp = 8
			}
			result = append(result, imageProbe{Source: filepath.Base(path), PNG: filepath.Join(filepath.Dir(path), p.PNG), BPP: bpp, Stride: p.Stride, X: p.X, Y: p.Y, Rects: p.Rects, Seed: len(result)})
		}
	}
	return result, nil
}
func imageProbeGo(p imageProbe) (imageResult, error) {
	im, e := graphics.ReadIndexedFile(p.PNG)
	if e != nil {
		return imageResult{}, e
	}
	var roundTrip bytes.Buffer
	if e = graphics.WriteIndexed(&roundTrip, im); e != nil {
		return imageResult{}, e
	}
	decoded, e := graphics.ReadIndexed(roundTrip.Bytes())
	if e != nil {
		return imageResult{}, e
	}
	if decoded.Width != im.Width || decoded.Height != im.Height || !bytes.Equal(decoded.Pixels, im.Pixels) {
		return imageResult{}, errors.New("indexed PNG round-trip changed palette indices")
	}
	length := int64(p.Stride) * int64(p.Y+im.Height+2)
	if length <= 0 || length > 16<<20 {
		return imageResult{}, fmt.Errorf("invalid synthetic bitmap length %d", length)
	}
	data := make([]byte, int(length))
	for i := range data {
		data[i] = byte((i*73 + p.Seed*19 + 31) & 255)
	}
	before := make([]byte, 0)
	rects := make([]graphics.Rect, 0, len(p.Rects))
	for _, rect := range p.Rects {
		rx, ry, rw, rh := rect[0], rect[1], rect[2], rect[3]
		rects = append(rects, graphics.Rect{X: rx, Y: ry, W: rw, H: rh})
		if rx < 0 || ry < 0 || rw <= 0 || rh <= 0 || rx+rw > im.Width || ry+rh > im.Height {
			return imageResult{}, errors.New("invalid rect")
		}
		for y := ry; y < ry+rh; y++ {
			for x := rx; x < rx+rw; x++ {
				destX, destY := p.X+x, p.Y+y
				at := destY*p.Stride + destX*p.BPP/8 // 4bpp division is handled separately below
				if p.BPP == 4 {
					at = destY*p.Stride + destX/2
				}
				if at < 0 || at >= len(data) {
					return imageResult{}, errors.New("source pixel outside synthetic buffer")
				}
				val := data[at]
				if p.BPP == 4 {
					val = (val >> uint(4*(destX&1))) & 15
				}
				before = append(before, val)
			}
		}
	}
	patched, e := graphics.ApplyPatch(data, im, graphics.Patch{Offset: 0, Stride: p.Stride, X: p.X, Y: p.Y, BPP: p.BPP, Rects: rects, OriginalCRC32: crc32.ChecksumIEEE(before)})
	if e != nil {
		return imageResult{}, e
	}
	if !bytes.Equal(data, func() []byte {
		orig := make([]byte, len(data))
		for i := range orig {
			orig[i] = byte((i*73 + p.Seed*19 + 31) & 255)
		}
		return orig
	}()) {
		return imageResult{}, errors.New("source mutated")
	}
	return imageResult{Width: im.Width, Height: im.Height, PixelsSHA: hexSHA(im.Pixels), OutputSHA: hexSHA(patched)}, nil
}
func cmdGraphicsCheck(root string, args []string) error {
	fs := flag.NewFlagSet("graphics-check", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	compare := fs.Bool("compare-python", false, "compare PNG indices and synthetic 4/8bpp patches against Python")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo graphics-check [--compare-python]")
	}
	probes, e := collectImageProbes(root)
	if e != nil {
		return e
	}
	if len(probes) == 0 {
		return errors.New("no graphics patches in current translation")
	}
	results := make([]imageResult, len(probes))
	counts := map[int]int{}
	for i, p := range probes {
		result, e := imageProbeGo(p)
		if e != nil {
			return fmt.Errorf("%s (%s): %w", p.Source, filepath.Base(p.PNG), e)
		}
		results[i] = result
		counts[p.BPP]++
	}
	say("Graphics", fmt.Sprintf("%d image entries (4bpp: %d, 8bpp: %d)", len(results), counts[4], counts[8]))
	say("PNG roundtrip", "Go indexed read/write: PASS")
	say("Patch pixels", "Go synthetic 4/8bpp: PASS")
	if !*compare {
		return nil
	}
	data, e := json.Marshal(probes)
	if e != nil {
		return e
	}
	python := os.Getenv("TOKIMEMO_PYTHON")
	if python == "" {
		python = "python3"
	}
	command := exec.Command(python, filepath.Join(root, "legacy_scripts", "tools", "graphics_reference.py"))
	command.Dir = root
	command.Env = pythonEnv(root)
	command.Stdin = bytes.NewReader(data)
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	command.Stdout = stdout
	command.Stderr = stderr
	if e = command.Run(); e != nil {
		return fmt.Errorf("Python graphic oracle: %w: %s", e, stderr.String())
	}
	var expected []imageResult
	if e = json.Unmarshal(stdout.Bytes(), &expected); e != nil {
		return fmt.Errorf("invalid Python oracle output: %w: %s", e, stderr.String())
	}
	if len(expected) != len(results) {
		return fmt.Errorf("Python yielded %d entries for %d probes", len(expected), len(results))
	}
	for i := range results {
		if results[i] != expected[i] {
			return fmt.Errorf("graphics mismatch at %d: %s/%s: Go %v / Python %v", i, probes[i].Source, strconv.Quote(probes[i].PNG), results[i], expected[i])
		}
	}
	say("Python parity", fmt.Sprintf("%d/%d byte-identical patched synthetic buffers and indexed pixels", len(results), len(results)))
	return nil
}
