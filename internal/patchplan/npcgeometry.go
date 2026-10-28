package patchplan

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

// FirstLineNPCGeometry is a source-name-aware, exact-preimage transformation of
// the six ordinary NPC dialogue speaker/quotation pairs. It operates on a
// caller-owned copy after the formatter's temporary buffer and parser X have
// been coordinated. It does not allocate executable memory, change other
// speaker routes, or authorize a disc release.
//
// This is deliberately independent of the build launcher: the normal build
// must supply a fully composed executable and the current 16 translated names.
// Calling it on an unprepared retail executable is an error, not a silent no-op.
func FirstLineNPCGeometry(retail, composed []byte, names []string) ([]byte, error) {
	const base uint32 = 0x80040800
	const size = 667648
	const originalSHA = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	if len(retail) != size || len(composed) != size || len(names) != 16 {
		return nil, errors.New("invalid executable or source-name table dimensions")
	}
	if fmt.Sprintf("%x", sha256.Sum256(retail)) != originalSHA {
		return nil, errors.New("unrecognized original executable")
	}
	encoder := &script.PairEncoder{}
	for i, name := range names {
		if len(name) < 2 || len(name) > 38 {
			return nil, fmt.Errorf("name %d exceeds authenticated formatter capacity", i)
		}
		for _, c := range name {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
				return nil, fmt.Errorf("name %d contains unsupported characters", i)
			}
		}
		encoded, err := encoder.Encode(name)
		if err != nil || len(encoded) < len(name) || len(encoded) > len(name)+1 || len(encoded)%2 != 0 || len(encoded) > 38 {
			return nil, fmt.Errorf("name %d has invalid encoded layout: %v", i, err)
		}
		n := len(encoded)
		glyph, err := graphics.RenderPair(encoded[n-2]&0x7f, encoded[n-1]&0x7f)
		if err != nil {
			return nil, fmt.Errorf("last name glyph %d: %w", i, err)
		}
		inkWidth := 0
		for y := 0; y < 12; y++ {
			for x := 0; x < 12; x++ {
				if glyph[(y*12+x)/8]&(0x80>>uint((y*12+x)%8)) != 0 && x+1 > inkWidth {
					inkWidth = x + 1
				}
			}
		}
		speakerX, quoteX := -98-4*n, -102+4*n
		for _, stride := range [...]int{14, 16} {
			if quoteX < speakerX+(n/2-1)*stride+inkWidth {
				return nil, fmt.Errorf("name %d overlaps dialogue at glyph advance %d", i, stride)
			}
		}
	}
	// The two coordinates must move together. The parser uses the quote X
	// prepared by its preceding coordinated layout stage; never edit only X.
	sites := [...]struct{ name, quote uint32 }{
		{0x8007FBAC, 0x8007FBD4 + 0x20},
		{0x8007FC6C, 0x8007FC94 + 0x20},
		{0x8007FE70, 0x8007FE98 + 0x20},
		{0x800800C8, 0x800800F0 + 0x20},
		{0x80080188, 0x800801B0 + 0x20},
		{0x80081060, 0x80081088 + 0x20},
	}
	get := func(b []byte, pc uint32) uint32 { return binary.LittleEndian.Uint32(b[pc-base:]) }
	for i, s := range sites {
		original := get(retail, s.name)
		if original>>26 != 9 || original&0xffff != 0xff98 ||
			get(composed, s.name) != original&0xffff0000|0xff9b ||
			get(composed, s.quote) != 0x2484ff97 {
			return nil, fmt.Errorf("NPC route %d lacks the coordinated name/quote preimage", i)
		}
	}
	result := append([]byte(nil), composed...)
	for _, s := range sites {
		original := get(retail, s.name)
		binary.LittleEndian.PutUint32(result[s.name-base:], original&0xffff0000|0xff9e)
		binary.LittleEndian.PutUint32(result[s.quote-base:], 0x2484ff9a)
	}
	return result, nil
}
