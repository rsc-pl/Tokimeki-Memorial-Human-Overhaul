package script

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"strings"
)

// The mapping tables are generated from the legacy Python Shift-JIS codec.
// Runtime encoding/decoding is pure Go and does not need Python or x/text.
// Each record is an (rune uint32, code uint16) or the reverse, little-endian.
//
//go:embed sjis_encode.tbl
var encodeTable []byte

//go:embed sjis_decode.tbl
var decodeTable []byte

var toJIS = func() map[rune]uint16 {
	out := make(map[rune]uint16, len(encodeTable)/6)
	for i := 0; i+6 <= len(encodeTable); i += 6 {
		out[rune(binary.LittleEndian.Uint32(encodeTable[i:]))] = binary.LittleEndian.Uint16(encodeTable[i+4:])
	}
	return out
}()
var fromJIS = func() map[uint16]rune {
	out := make(map[uint16]rune, len(decodeTable)/6)
	for i := 0; i+6 <= len(decodeTable); i += 6 {
		out[binary.LittleEndian.Uint16(decodeTable[i:])] = rune(binary.LittleEndian.Uint32(decodeTable[i+2:]))
	}
	return out
}()

func encodeJIS(s string) ([]byte, error) {
	var b bytes.Buffer
	for _, r := range s {
		if r <= 0x7f {
			b.WriteByte(byte(r))
			continue
		}
		code, ok := toJIS[r]
		if !ok {
			return nil, fmt.Errorf("character %U cannot be encoded as Shift-JIS", r)
		}
		if code <= 255 {
			b.WriteByte(byte(code))
		} else {
			b.WriteByte(byte(code >> 8))
			b.WriteByte(byte(code))
		}
	}
	return b.Bytes(), nil
}
func decodeJIS(data []byte) (string, error) {
	var b strings.Builder
	for i := 0; i < len(data); {
		code := uint16(data[i])
		i++
		if isLead(byte(code)) {
			if i >= len(data) {
				return "", fmt.Errorf("truncated Shift-JIS character at %d", i-1)
			}
			code = (code << 8) | uint16(data[i])
			i++
		}
		r, ok := fromJIS[code]
		if !ok {
			return "", fmt.Errorf("invalid Shift-JIS code %#x", code)
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}
func isLead(c byte) bool { return c >= 0x81 && c <= 0x9f || c >= 0xe0 && c <= 0xea }

// EncodeFullwidth preserves Python text.encode's ASCII substitutions and its
// additional game-font lead-byte restriction. It is not dialogue pair encoding.
func EncodeFullwidth(s string) ([]byte, error) {
	const asciiFirst, asciiLast = '!', '~'
	special := map[rune]rune{' ': '　', '\'': '’', '"': '”', '-': '−', '~': '〜', '\\': '＼'}
	var converted strings.Builder
	for _, r := range s {
		if mapped, ok := special[r]; ok {
			converted.WriteRune(mapped)
		} else if r >= asciiFirst && r <= asciiLast {
			converted.WriteRune(r + 0xFEE0)
		} else {
			converted.WriteRune(r)
		}
	}
	data, e := encodeJIS(converted.String())
	if e != nil {
		return nil, e
	}
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) || !(data[i] >= 0x81 && data[i] <= 0x84 || data[i] >= 0x88 && data[i] <= 0x9f || data[i] >= 0xe0 && data[i] <= 0xea) {
			return nil, fmt.Errorf("text contains a character not displayable by the fullwidth game font at byte %d", i)
		}
	}
	return data, nil
}
