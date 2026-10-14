package patchplan

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/graphics"
	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/script"
)

// Batch holds patch operations in the same order as the legacy patcher.
type Batch struct {
	Strings  []script.InPlaceString
	Images   []ImageEdit
	Bytes    []script.BytesPatch
	Dialogue []script.DialogueBlock
	Files    int
}
type ImageEdit struct {
	File, Source, PNG string
	Patch             graphics.Patch
}
type number int64

func (n *number) UnmarshalJSON(b []byte) error {
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	switch v := value.(type) {
	case float64:
		if v < 0 || v > 1<<53 || v != float64(int64(v)) {
			return fmt.Errorf("invalid nonnegative integer %s", b)
		}
		*n = number(v)
	case string:
		i, e := strconv.ParseInt(v, 0, 64)
		if e != nil || i < 0 {
			return fmt.Errorf("invalid numeric string %q", v)
		}
		*n = number(i)
	default:
		return fmt.Errorf("expected integer or numeric string: %s", b)
	}
	return nil
}
func discFile(raw string) (string, error) {
	p := strings.ToUpper(strings.TrimLeft(raw, "/"))
	if p == "" || strings.ContainsAny(p, "\\:") || strings.HasPrefix(raw, "//") || filepath.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.HasPrefix(p, "./") {
		return "", fmt.Errorf("invalid disc path %q", raw)
	}
	return p, nil
}
func nonnegative(v number) (int, error) {
	if v < 0 || int64(v) > int64(^uint(0)>>1) {
		return 0, fmt.Errorf("offset out of range: %d", v)
	}
	return int(v), nil
}

// Load parses current translation JSON as read-only inputs. Missing schema values
// are rejected rather than guessed, and image paths cannot escape their root.
func Load(root string, provided []string) (Batch, error) {
	var out Batch
	paths := append([]string(nil), provided...)
	if len(paths) == 0 {
		var err error
		paths, err = filepath.Glob(filepath.Join(root, "translation", "*.json"))
		if err != nil {
			return out, err
		}
		sort.Strings(paths)
	}
	if len(paths) == 0 {
		return out, fmt.Errorf("no translation JSON files")
	}
	for _, filename := range paths {
		raw, err := os.ReadFile(filename)
		if err != nil {
			return out, err
		}
		var doc struct {
			Strings []struct {
				File, Original, Text, Encoding string
				Offset                         number
				Slot                           *number
			} `json:"strings"`
			Images []struct {
				File, PNG     string
				Pixels        number
				Stride, X, Y  int
				Rects         [][4]int
				OriginalCRC32 number `json:"original_crc32"`
				BPP           int
			} `json:"images"`
			Bytes []struct {
				File, Original, Replacement string
				Offset                      number
			} `json:"bytes"`
			Dialogue []struct {
				File           string
				Base           number
				MaxCells       int  `json:"max_cells"`
				ShareIdentical bool `json:"share_identical"`
				Lines          []struct {
					Offset         number
					Original, Text string
				}
			} `json:"dialogue"`
		}
		if err = json.Unmarshal(raw, &doc); err != nil {
			return out, fmt.Errorf("%s: %w", filename, err)
		}
		source := filepath.Base(filename)
		for _, v := range doc.Strings {
			f, e := discFile(v.File)
			if e != nil {
				return out, e
			}
			at, e := nonnegative(v.Offset)
			if e != nil {
				return out, e
			}
			p := script.InPlaceString{File: f, Source: source, Offset: at, Original: v.Original, Text: v.Text, Encoding: v.Encoding}
			if v.Slot != nil {
				x, er := nonnegative(*v.Slot)
				if er != nil || x < 2 {
					return out, fmt.Errorf("%s: invalid slot", source)
				}
				p.Slot = &x
			}
			out.Strings = append(out.Strings, p)
		}
		for _, v := range doc.Images {
			f, e := discFile(v.File)
			if e != nil {
				return out, e
			}
			at, e := nonnegative(v.Pixels)
			if e != nil {
				return out, e
			}
			if v.PNG == "" || filepath.IsAbs(v.PNG) {
				return out, fmt.Errorf("%s: invalid PNG path", source)
			}
			base := filepath.Dir(filename)
			resolved := filepath.Clean(filepath.Join(base, v.PNG))
			rel, e := filepath.Rel(base, resolved)
			if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return out, fmt.Errorf("%s: PNG leaves translation directory", source)
			}
			bpp := v.BPP
			if bpp == 0 {
				bpp = 8
			}
			patch := graphics.Patch{Offset: at, Stride: v.Stride, X: v.X, Y: v.Y, BPP: bpp, OriginalCRC32: uint32(v.OriginalCRC32)}
			if int64(v.OriginalCRC32) > 0xffffffff {
				return out, fmt.Errorf("%s: invalid image CRC", source)
			}
			for _, r := range v.Rects {
				patch.Rects = append(patch.Rects, graphics.Rect{X: r[0], Y: r[1], W: r[2], H: r[3]})
			}
			out.Images = append(out.Images, ImageEdit{File: f, Source: source, PNG: resolved, Patch: patch})
		}
		for _, v := range doc.Bytes {
			f, e := discFile(v.File)
			if e != nil {
				return out, e
			}
			at, e := nonnegative(v.Offset)
			if e != nil {
				return out, e
			}
			old, e := hex.DecodeString(v.Original)
			if e != nil {
				return out, fmt.Errorf("%s bytes original: %w", source, e)
			}
			newBytes, e := hex.DecodeString(v.Replacement)
			if e != nil {
				return out, fmt.Errorf("%s bytes replacement: %w", source, e)
			}
			if len(old) != len(newBytes) {
				return out, fmt.Errorf("%s: byte replacement changed length", source)
			}
			out.Bytes = append(out.Bytes, script.BytesPatch{File: f, Source: source, Offset: at, Original: old, Replacement: newBytes})
		}
		for _, v := range doc.Dialogue {
			f, e := discFile(v.File)
			if e != nil {
				return out, e
			}
			if int64(v.Base) > 0xffffffff {
				return out, fmt.Errorf("%s: base address too large", source)
			}
			p := script.DialogueBlock{File: f, Source: source, Base: uint32(v.Base), MaxCells: v.MaxCells, ShareIdentical: v.ShareIdentical}
			for _, l := range v.Lines {
				at, er := nonnegative(l.Offset)
				if er != nil {
					return out, er
				}
				p.Lines = append(p.Lines, script.DialogueLine{Offset: at, Original: l.Original, Text: l.Text})
			}
			out.Dialogue = append(out.Dialogue, p)
		}
		out.Files++
	}
	return out, nil
}
