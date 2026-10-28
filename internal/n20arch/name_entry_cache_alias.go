package n20arch

// glyph aliasing investigates a CACHE-MANAGED alternative to the unsafe name-entry transfer direct-slot
// upload. Each display-only keyboard cell receives a distinct source-supported
// Shift-JIS font code, so the retail glyph cache -- rather than a new patch --
// chooses the texture slot. The original source kana, input pointers and all
// selectors are unchanged. IMPORTANT: the retail glyphs for these codes are
// NOT romaji; the screen-local font-source substitution is still missing.
// This is an OFFLINE dataflow candidate, never a playable image.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/graphics"
	pn "tokimemo/internal/playername"
)

type FontAlias struct {
	Cell             int    `json:"cell"`
	Row              int    `json:"row"`
	Column           int    `json:"column"`
	Code             uint16 `json:"code"`
	RetailFontOffset int    `json:"retail_font_offset"`
	RomajiMaskOffset int    `json:"romaji_mask_offset"`
	Label            string `json:"label"`
}

type KeyboardAliasCandidate struct {
	Overlay                   []byte
	Aliases                   []FontAlias
	DistinctRetailGlyphs      bool
	CacheSlotsReserved        bool
	RomajiFontSourceInstalled bool
	OriginalSelectionIntact   bool
	SafeToPatch               bool
	RuntimePass               bool
}

func PlanKeyboardCacheAliasesOffline(exe, original []byte) (KeyboardAliasCandidate, error) {
	var empty KeyboardAliasCandidate
	if _, err := VerifyRetailEXE(exe); err != nil {
		return empty, fmt.Errorf("retail EXE: %w", err)
	}
	nameEntryCacheStage, err := PlanUnifiedNameEntOffline(original)
	if err != nil {
		return empty, err
	}
	rows, err := pn.ParseNameEntryKeyboardRows(original)
	if err != nil {
		return empty, err
	}
	if len(rows) != 34 {
		return empty, fmt.Errorf("unexpected row count %d", len(rows))
	}
	// 0x9740..0x9872 is in the AUTHENTIC font range table. Select only
	// legal Shift-JIS trails and check every glyph via the original table.
	type alias struct {
		code uint16
		off  int
	}
	codes := make([]alias, 0, 162)
	seenOffsets := map[int]bool{}
	for hi := uint16(0x97); hi <= 0x98 && len(codes) < 162; hi++ {
		for lo := uint16(0x40); lo <= 0xfc && len(codes) < 162; lo++ {
			if lo == 0x7f || (hi == 0x98 && lo > 0x72) {
				continue
			}
			code := (hi << 8) | lo
			off, e := graphics.GlyphOffset(exe, code)
			if e != nil || seenOffsets[off] {
				continue
			}
			seenOffsets[off] = true
			codes = append(codes, alias{code, off})
		}
	}
	if len(codes) != 162 {
		return empty, fmt.Errorf("only %d/162 cache-manager aliases", len(codes))
	}
	out := bytes.Clone(nameEntryCacheStage.Overlay)
	aliases := make([]FontAlias, 0, 162)
	cell := 0
	shadowStart := nameEntryDrawShadowFileOff
	for row, r := range rows {
		sourcePtr := binary.LittleEndian.Uint32(original[nameEntryGridGridPtrFileOff+row*4:])
		if sourcePtr < OverlaySlotBase || sourcePtr >= OverlaySlotBase+uint32(len(original)) {
			return empty, fmt.Errorf("row %d pointer out of bounds", row)
		}
		source := int(sourcePtr - OverlaySlotBase)
		if source < 0 || source+len(r.Cells)*2 >= nameEntryGridGridEnd {
			return empty, fmt.Errorf("row %d source overflow", row)
		}
		// name-entry drawing wrote a byte-identical row into a private display shadow.
		for col, c := range r.Cells {
			p := shadowStart + 2*col
			if !bytes.Equal(out[p:p+2], original[source+col*2:source+col*2+2]) {
				return empty, fmt.Errorf("name-entry drawing row %d col %d shadow drift", row, col)
			}
			if cell >= 162 {
				return empty, fmt.Errorf("cell overflow")
			}
			a := codes[cell]
			out[p], out[p+1] = byte(a.code>>8), byte(a.code)
			aliases = append(aliases, FontAlias{Cell: cell, Row: row, Column: col, Code: a.code,
				RetailFontOffset: a.off, RomajiMaskOffset: nameEntryDrawGlyphAtlasFileOff + 18*cell, Label: c.Label})
			cell++
		}
		// Respect the original row NUL and the one known ASCII pad.
		size := 2 * len(r.Cells)
		if original[source+size] == 0x20 {
			size++
		}
		if original[source+size] != 0 {
			return empty, fmt.Errorf("row %d terminator missing", row)
		}
		if !bytes.Equal(out[shadowStart+2*len(r.Cells):shadowStart+size+1],
			original[source+2*len(r.Cells):source+size+1]) {
			return empty, fmt.Errorf("row %d tail drift", row)
		}
		shadowStart += size + 1
	}
	if cell != 162 || shadowStart > nameEntryDrawShadowFileEnd {
		return empty, fmt.Errorf("shadow geometry %d cells end %x", cell, shadowStart)
	}
	if !bytes.Equal(out[nameEntryGridGridStart:nameEntryGridGridEnd], original[nameEntryGridGridStart:nameEntryGridGridEnd]) ||
		!bytes.Equal(out[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4], original[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4]) {
		return empty, fmt.Errorf("original input rows changed")
	}
	for _, pc := range nameEntryFieldNameEntSixSites() {
		if binary.LittleEndian.Uint32(out[pc-OverlaySlotBase:]) != jalWord(UnifiedEntryShimRAM) {
			return empty, fmt.Errorf("presenter overwritten %#x", pc)
		}
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return KeyboardAliasCandidate{Overlay: out, Aliases: aliases, DistinctRetailGlyphs: true,
		CacheSlotsReserved: false, RomajiFontSourceInstalled: false, OriginalSelectionIntact: true,
		SafeToPatch: false, RuntimePass: false}, nil
}

// Compose only the keyboard shadow delta against the FULL unified name entry private English
// candidate. Deliberately no production writer, font-source hook, or VRAM edits.
func PlanCombinedAliasesOffline(exe []byte, originals map[string][]byte) (TELCandidate, KeyboardAliasCandidate, error) {
	var empty TELCandidate
	prior, nameEntryCacheStage, err := PlanCombinedUnifiedOffline(exe, originals)
	if err != nil {
		return empty, KeyboardAliasCandidate{}, err
	}
	alias, err := PlanKeyboardCacheAliasesOffline(exe, originals["NAME_ENT.EXN"])
	if err != nil {
		return empty, KeyboardAliasCandidate{}, err
	}
	merged := bytes.Clone(prior.Overlays["NAME_ENT.EXN"])
	if len(merged) != len(nameEntryCacheStage.Overlay) || len(merged) != len(alias.Overlay) {
		return empty, KeyboardAliasCandidate{}, fmt.Errorf("overlay size drift")
	}
	for i, v := range alias.Overlay {
		if i >= len(merged)-4 && i < len(merged)-2 {
			continue
		}
		if v == nameEntryCacheStage.Overlay[i] {
			continue
		}
		if i < nameEntryDrawShadowFileOff || i >= nameEntryDrawShadowFileEnd || merged[i] != nameEntryCacheStage.Overlay[i] {
			return empty, KeyboardAliasCandidate{}, fmt.Errorf("glyph aliasing overlay merge conflict +%#x", i)
		}
		merged[i] = v
	}
	binary.BigEndian.PutUint16(merged[len(merged)-4:], packedTableChecksum(merged))
	prior.Overlays["NAME_ENT.EXN"] = merged
	prior.SafeToPatch = false
	prior.RuntimePass = false
	return prior, alias, nil
}
