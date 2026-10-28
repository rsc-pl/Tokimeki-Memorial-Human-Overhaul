package n20arch

// name-entry drawing: authenticate and isolate the NAME_ENT row DRAW clients from the
// original input-selection pointer table. This candidate is deliberately
// *visually identical*: the shadow rows contain the exact original CP932
// bytes. It establishes a narrow display-only future edit surface; no
// Latin art, font replacement, or production patch is installed here.
//
// Original input is read elsewhere through 0x80134480 / 0x801346B4. These
// original selection consumers and 34 table pointers MUST remain unchanged.
import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	pn "tokimemo/internal/playername"
)

const (
	nameEntryDrawShadowFileOff            = 0x22000
	nameEntryDrawShadowFileEnd            = 0x22200
	nameEntryDrawGlyphAtlasFileOff        = 0x22400
	nameEntryDrawGlyphAtlasBytes          = 162 * 18
	nameEntryDrawShadowBase        uint32 = OverlaySlotBase + nameEntryDrawShadowFileOff
	nameEntryDrawRetailQueueWord   uint32 = 0x0c0139e2 // JAL 0x8004E788
)

type DrawRoute struct {
	RowIndex  int    `json:"row_index"`
	LoadPC    uint32 `json:"load_pc"`
	QueuePC   uint32 `json:"queue_pc"`
	ShadowRAM uint32 `json:"shadow_ram"`
}

type DrawShadow struct {
	ShadowOverlay                    []byte
	Routes                           []DrawRoute
	SourceRows                       int
	ShadowBytes                      int
	GlyphAtlasBytes                  int
	GlyphCount                       int
	OriginalInputPreserved           bool
	OriginalRetailDrawCallsPreserved bool
	VisuallyIdentical                bool
	SafeToPatch                      bool
	RuntimePass                      bool
}

func nameEntryDrawScanDrawRoutes(original []byte) ([]DrawRoute, error) {
	routes := make([]DrawRoute, 0, 42)
	seen := make(map[uint32]bool)
	counts := [nameEntryGridGridRows]int{}
	// Original executable code stops before the 0x19150 input row literals.
	// The pattern is intentionally strict: a3 loads one of the exact 34
	// original row pointers, followed by the authenticated retail draw queue.
	for off := 4; off+120 < nameEntryGridGridStart; off += 4 {
		w := binary.LittleEndian.Uint32(original[off:])
		if (w>>26) != 0x23 || ((w>>21)&31) != 7 || ((w>>16)&31) != 7 {
			continue
		}
		imm := int(w & 0xffff)
		if imm < 0xcd28 || imm > 0xcdac || (imm-0xcd28)%4 != 0 {
			continue
		}
		idx := (imm - 0xcd28) / 4
		// $a3 must have been initialized to 0x80150000 immediately before
		// the pointer load, or earlier in the same straight-line block.
		lui := false
		for back := 4; back <= 12 && back <= off; back += 4 {
			if binary.LittleEndian.Uint32(original[off-back:]) == 0x3c078015 {
				lui = true
				break
			}
		}
		if !lui {
			continue
		}
		var q uint32
		for future := off + 4; future < off+120; future += 4 {
			cur := binary.LittleEndian.Uint32(original[future:])
			if cur == nameEntryDrawRetailQueueWord {
				q = OverlaySlotBase + uint32(future)
				break
			}
			// Refuse intervening writes to the argument register, rather than
			// matching unrelated later text calls.
			op, rt := cur>>26, (cur>>16)&31
			if rt == 7 && (op == 0x09 || op == 0x0f || op == 0x23 || op == 0x21 || op == 0x24 || op == 0x20) {
				break
			}
		}
		if q == 0 {
			continue
		}
		pc := OverlaySlotBase + uint32(off)
		if seen[pc] {
			return nil, fmt.Errorf("duplicate display route %#x", pc)
		}
		seen[pc] = true
		counts[idx]++
		routes = append(routes, DrawRoute{RowIndex: idx, LoadPC: pc, QueuePC: q})
	}
	if len(routes) != 42 {
		return nil, fmt.Errorf("NAME_ENT draw-route census changed: %d/42", len(routes))
	}
	for i, c := range counts {
		if c < 1 {
			return nil, fmt.Errorf("NAME_ENT row %d has no verified draw call", i)
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].LoadPC < routes[j].LoadPC })
	return routes, nil
}

func BuildNameEntDrawShadow(original []byte) (DrawShadow, error) {
	var out DrawShadow
	if _, e := AuditNameEntryGrid(original); e != nil {
		return out, e
	}
	if !bytes.Equal(original[nameEntryDrawShadowFileOff:nameEntryDrawShadowFileEnd], make([]byte, nameEntryDrawShadowFileEnd-nameEntryDrawShadowFileOff)) ||
		!bytes.Equal(original[nameEntryDrawGlyphAtlasFileOff:nameEntryDrawGlyphAtlasFileOff+nameEntryDrawGlyphAtlasBytes], make([]byte, nameEntryDrawGlyphAtlasBytes)) {
		return out, fmt.Errorf("NAME_ENT shadow destination is not authenticated zero source")
	}
	routes, e := nameEntryDrawScanDrawRoutes(original)
	if e != nil {
		return out, e
	}
	d := bytes.Clone(original)
	rows, err := pn.ParseNameEntryKeyboardRows(original)
	if err != nil {
		return out, err
	}
	glyphs, err := pn.BuildNameEntryGlyphCandidates(rows)
	if err != nil || len(glyphs) != 162 {
		return out, fmt.Errorf("name-entry drawing glyph source not exactly 162 candidates: %v", err)
	}
	for i, g := range glyphs {
		one, e := hex.DecodeString(g.Mask18Hex)
		if e != nil || len(one) != 18 {
			return out, fmt.Errorf("name-entry drawing glyph %d malformed: %v", i, e)
		}
		copy(d[nameEntryDrawGlyphAtlasFileOff+i*18:], one)
	}
	newPointers := [nameEntryGridGridRows]uint32{}
	used := 0
	for i := 0; i < nameEntryGridGridRows; i++ {
		p := binary.LittleEndian.Uint32(original[nameEntryGridGridPtrFileOff+i*4:])
		if p < OverlaySlotBase || p >= OverlaySlotBase+uint32(nameEntryGridGridStart+0x1000) {
			return out, fmt.Errorf("source row %d out of range", i)
		}
		off := int(p - OverlaySlotBase)
		end := off
		for end < nameEntryGridGridEnd && original[end] != 0 {
			end++
		}
		if end >= nameEntryGridGridEnd {
			return out, fmt.Errorf("unterminated row %d", i)
		}
		size := end - off + 1
		if used+size > nameEntryDrawShadowFileEnd-nameEntryDrawShadowFileOff {
			return out, fmt.Errorf("shadow overflow")
		}
		copy(d[nameEntryDrawShadowFileOff+used:], original[off:end+1])
		newPointers[i] = nameEntryDrawShadowBase + uint32(used)
		used += size
	}
	for i := range routes {
		r := &routes[i]
		pcOff := int(r.LoadPC - OverlaySlotBase)
		ptr := newPointers[r.RowIndex]
		// The old pointer table is addressed through $a3=0x80150000.
		// Replace ONLY 'lw a3,offset(a3)' with 'addiu a3,a3,offset';
		// $a3 now points to a byte-for-byte identical shadow row.
		if (ptr&0xffff) >= 0x8000 || ptr>>16 != 0x8015 {
			return out, fmt.Errorf("unrepresentable shadow address %#x", ptr)
		}
		old := binary.LittleEndian.Uint32(d[pcOff:])
		if old != (0x8ce7cd28 + uint32(4*r.RowIndex)) {
			return out, fmt.Errorf("unexpected draw load at %#x", r.LoadPC)
		}
		binary.LittleEndian.PutUint32(d[pcOff:], 0x24e70000|(ptr&0xffff))
		r.ShadowRAM = ptr
	}
	if !bytes.Equal(d[nameEntryGridGridStart:nameEntryGridGridEnd], original[nameEntryGridGridStart:nameEntryGridGridEnd]) ||
		!bytes.Equal(d[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+nameEntryGridGridRows*4], original[nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+nameEntryGridGridRows*4]) {
		return out, fmt.Errorf("input selection bytes changed")
	}
	for _, r := range routes {
		off := int(r.QueuePC - OverlaySlotBase)
		if binary.LittleEndian.Uint32(d[off:]) != nameEntryDrawRetailQueueWord {
			return out, fmt.Errorf("draw queue changed %#x", r.QueuePC)
		}
	}
	binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
	out = DrawShadow{ShadowOverlay: d, Routes: routes, SourceRows: 34, ShadowBytes: used, GlyphAtlasBytes: nameEntryDrawGlyphAtlasBytes, GlyphCount: len(glyphs),
		OriginalInputPreserved: true, OriginalRetailDrawCallsPreserved: true,
		VisuallyIdentical: true, SafeToPatch: false, RuntimePass: false}
	return out, nil
}
