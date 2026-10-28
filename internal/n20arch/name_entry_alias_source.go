package n20arch

// alias resolution replaces the glyph aliasing post-upload VRAM overwrite hypothesis with a detached,
// overlay-local, source-stage alias-to-romaji resolver. glyph aliasing's 162 authenticated
// glyph aliases map to consecutive ORIGINAL glyph indices 3179..3340. The
// resolver maps that index directly to name-entry drawing's local 18-byte glyph mask and
// calls the already verified name-entry glyphs expander, leaving retail font RAM, GPU slots,
// user kana and saves untouched. It is NOT yet connected to the original font
// parser/queue. In particular, no EXE-wide source hook is authorized.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	AliasFirstGlyphIndex        = 3179
	AliasGlyphCount             = 162
	AliasResolverOff            = 0x23400 // glyph aliasing only; unused in the unified name entry/glyph aliasing lineage
	AliasResolverRAM     uint32 = OverlaySlotBase + AliasResolverOff
	AliasResolverMax            = 256
)

type AliasSourceCandidate struct {
	Overlay                  []byte
	Code                     []byte
	Entry                    uint32
	FirstIndex               int
	LastIndex                int
	AllAliasesContiguous     bool
	OriginalSelectionIntact  bool
	SourceOnlyNoGPUOverwrite bool
	RendererHookInstalled    bool
	SafeToPatch              bool
	RuntimePass              bool
}

// O32: a0=retail decoded glyph INDEX; a1=caller-owned 96B destination;
// v0=96 on conversion, or 0 on failure. a0/a1, s0..s7 and ra/sp preserved.
func BuildAliasSourceResolver() ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	br := func(op, rs, rt uint32, label string) { a.b(op, rs, rt, label); w(0) }
	add(29, 29, -0x30)
	w(olSW(31, 29, 0x2c))
	w(olSW(4, 29, 0x20))
	w(olSW(5, 29, 0x24))
	add(8, 4, -AliasFirstGlyphIndex)
	w(olSLTIU(9, 8, AliasGlyphCount))
	br(4, 9, 0, "fail")
	// Fail closed on caller-owned 96B destination outside real guest RAM.
	// Unlike the source bank, the destination is not trusted implicitly.
	w(olIType(0x0c, 5, 11, 3)) // andi t3,a1,3
	br(5, 11, 0, "fail")
	w(olLUI(10, 0x80010000))
	w(olRType(5, 10, 11, 0x2b)) // sltu t3,a1,minimum
	br(5, 11, 0, "fail")
	w(olLUI(10, 0x801f0000))
	w(olORI(10, 10, 0xffa0))
	w(olRType(10, 5, 11, 0x2b)) // sltu t3,max,a1
	br(5, 11, 0, "fail")
	w(olRType(0, 8, 10, 0) | (4 << 6)) // t2=index*16
	w(olRType(0, 8, 11, 0) | (1 << 6)) // t3=index*2
	w(olAddu(10, 10, 11))
	src := OverlaySlotBase + uint32(nameEntryDrawGlyphAtlasFileOff)
	w(olLUI(4, src))
	w(olORI(4, 4, src&0xffff))
	w(olAddu(4, 4, 10))
	w(jalWord(LocalExpanderRAM))
	w(0)
	br(4, 0, 0, "done")
	a.label("fail")
	add(2, 0, 0)
	a.label("done")
	w(olLW(4, 29, 0x20))
	w(0)
	w(olLW(5, 29, 0x24))
	w(0)
	w(olLW(31, 29, 0x2c))
	w(0)
	w(olJR(31))
	add(29, 29, 0x30)
	a.resolve()
	code := words(a.words...)
	if len(code) > AliasResolverMax {
		return nil, fmt.Errorf("alias resolution resolver %d > %d", len(code), AliasResolverMax)
	}
	return code, nil
}

func PlanAliasSourceOffline(exe, original []byte) (AliasSourceCandidate, error) {
	var empty AliasSourceCandidate
	nameEntryAliasStage, err := PlanKeyboardCacheAliasesOffline(exe, original)
	if err != nil {
		return empty, err
	}
	if len(nameEntryAliasStage.Aliases) != AliasGlyphCount {
		return empty, fmt.Errorf("glyph aliasing alias count drift")
	}
	// Original EXE font source base begins at RAM 0x800B6D50.
	const origFontRAM uint32 = 0x800b6d50
	const origExeTextBase uint32 = 0x80041000
	const origExeHeader = 0x800
	fontFileBase := int(origFontRAM-origExeTextBase) + origExeHeader
	for i, a := range nameEntryAliasStage.Aliases {
		want := fontFileBase + (AliasFirstGlyphIndex+i)*18
		if a.RetailFontOffset != want || a.Cell != i || a.RomajiMaskOffset != nameEntryDrawGlyphAtlasFileOff+i*18 {
			return empty, fmt.Errorf("alias mapping not consecutive at %d: font=%#x want=%#x", i, a.RetailFontOffset, want)
		}
	}
	code, err := BuildAliasSourceResolver()
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(nameEntryAliasStage.Overlay[AliasResolverOff:AliasResolverOff+AliasResolverMax], make([]byte, AliasResolverMax)) {
		return empty, fmt.Errorf("alias resolution source-stage code space occupied")
	}
	out := bytes.Clone(nameEntryAliasStage.Overlay)
	copy(out[AliasResolverOff:], code)
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	if !bytes.Equal(out[nameEntryGridGridStart:nameEntryGridGridEnd], original[nameEntryGridGridStart:nameEntryGridGridEnd]) ||
		!bytes.Equal(out[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4], original[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4]) {
		return empty, fmt.Errorf("alias resolution modified original selectable kana")
	}
	return AliasSourceCandidate{Overlay: out, Code: code, Entry: AliasResolverRAM,
		FirstIndex: AliasFirstGlyphIndex, LastIndex: AliasFirstGlyphIndex + AliasGlyphCount - 1,
		AllAliasesContiguous: true, OriginalSelectionIntact: true, SourceOnlyNoGPUOverwrite: true,
		RendererHookInstalled: false, SafeToPatch: false, RuntimePass: false}, nil
}
