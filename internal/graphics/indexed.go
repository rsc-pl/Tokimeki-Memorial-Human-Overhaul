package graphics

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
)

// Indexed is an uncompressed, row-major 8-bit palette-indexed image.
type Indexed struct {
	Width, Height int
	Pixels        []byte
	Palette       [][3]uint8
	Alpha         []uint8
}

// ReadIndexed reads an 8-bit, noninterlaced, palette-indexed PNG without changing indices.
func ReadIndexed(data []byte) (Indexed, error) {
	if len(data) < 33 || !bytes.Equal(data[:8], []byte("\x89PNG\r\n\x1a\n")) || !bytes.Equal(data[12:16], []byte("IHDR")) {
		return Indexed{}, fmt.Errorf("invalid PNG signature or IHDR")
	}
	if data[24] != 8 || data[25] != 3 || data[26] != 0 || data[27] != 0 || data[28] != 0 {
		return Indexed{}, fmt.Errorf("PNG must use 8-bit indexed color without interlacing")
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return Indexed{}, err
	}
	pal, ok := img.(*image.Paletted)
	if !ok {
		return Indexed{}, fmt.Errorf("PNG decoder returned %T instead of an indexed image", img)
	}
	bounds := pal.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 || width > 32768 || height > 32768 || int64(width)*int64(height) > 128<<20 {
		return Indexed{}, fmt.Errorf("invalid or excessively large PNG dimensions")
	}
	result := Indexed{Width: width, Height: height, Pixels: make([]byte, width*height), Palette: make([][3]uint8, len(pal.Palette)), Alpha: make([]uint8, len(pal.Palette))}
	for y := 0; y < height; y++ {
		copy(result.Pixels[y*width:(y+1)*width], pal.Pix[y*pal.Stride:y*pal.Stride+width])
	}
	for i, c := range pal.Palette {
		rgba := color.NRGBAModel.Convert(c).(color.NRGBA)
		result.Palette[i] = [3]uint8{rgba.R, rgba.G, rgba.B}
		result.Alpha[i] = rgba.A
	}
	return result, nil
}

func ReadIndexedFile(path string) (Indexed, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Indexed{}, e
	}
	return ReadIndexed(b)
}

// WriteIndexed emits a noninterlaced 8-bit indexed PNG without remapping indices.
func WriteIndexed(w io.Writer, im Indexed) error {
	if err := im.Validate(); err != nil {
		return err
	}
	if len(im.Palette) == 0 || len(im.Palette) > 256 {
		return fmt.Errorf("indexed PNG requires 1..256 colors")
	}
	for _, idx := range im.Pixels {
		if int(idx) >= len(im.Palette) {
			return fmt.Errorf("palette index %d is unavailable", idx)
		}
	}
	output := new(bytes.Buffer)
	output.Write([]byte("\x89PNG\r\n\x1a\n"))
	chunk := func(kind string, data []byte) {
		var u32 [4]byte
		binary.BigEndian.PutUint32(u32[:], uint32(len(data)))
		output.Write(u32[:])
		output.WriteString(kind)
		output.Write(data)
		sum := crc32.ChecksumIEEE(append([]byte(kind), data...))
		binary.BigEndian.PutUint32(u32[:], sum)
		output.Write(u32[:])
	}
	header := make([]byte, 13)
	binary.BigEndian.PutUint32(header[0:], uint32(im.Width))
	binary.BigEndian.PutUint32(header[4:], uint32(im.Height))
	header[8] = 8
	header[9] = 3
	chunk("IHDR", header)
	if len(im.Alpha) != 0 && len(im.Alpha) != len(im.Palette) {
		return fmt.Errorf("palette alpha has incorrect length")
	}
	palette := make([]byte, 0, 3*len(im.Palette))
	for _, c := range im.Palette {
		palette = append(palette, c[:]...)
	}
	chunk("PLTE", palette)
	last := 0
	for i, a := range im.Alpha {
		if a < 255 {
			last = i + 1
		}
	}
	if last > 0 {
		chunk("tRNS", im.Alpha[:last])
	}
	var compressed bytes.Buffer
	zw, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if err != nil {
		return err
	}
	for y := 0; y < im.Height; y++ {
		if _, err = zw.Write([]byte{0}); err != nil {
			return err
		}
		if _, err = zw.Write(im.Pixels[y*im.Width : (y+1)*im.Width]); err != nil {
			return err
		}
	}
	if err = zw.Close(); err != nil {
		return err
	}
	chunk("IDAT", compressed.Bytes())
	chunk("IEND", nil)
	_, err = output.WriteTo(w)
	return err
}

func (im Indexed) Validate() error {
	if im.Width <= 0 || im.Height <= 0 || im.Width > 32768 || im.Height > 32768 || int64(im.Width)*int64(im.Height) > 128<<20 {
		return fmt.Errorf("invalid image dimensions")
	}
	if len(im.Pixels) != im.Width*im.Height {
		return fmt.Errorf("pixel count %d does not match %dx%d", len(im.Pixels), im.Width, im.Height)
	}
	return nil
}
