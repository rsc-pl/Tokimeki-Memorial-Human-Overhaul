package n20arch

// name-entry grid: authenticated read-only NAME_ENT grid-producer provenance. This does
// not draw romanized labels, patch a disk, or change selected/stored kana.
// It separates the actual two 17-row original data page consumers from the
// unproved screen-specific renderer/texture producer.
import (
	"encoding/binary"
	"fmt"
	pn "tokimemo/internal/playername"
)

const (
	nameEntryGridGridRows               = 34
	nameEntryGridGridPtrFileOff         = 0x1ad28
	nameEntryGridGridStart              = 0x19150
	nameEntryGridGridEnd                = 0x192d8
	nameEntryGridGridPage0Caller uint32 = 0x80134480
	nameEntryGridGridPage1Caller uint32 = 0x801346b4
)

type NameEntryRow struct {
	Index            int  `json:"index"`
	Page             int  `json:"page"`
	ByteOffset       int  `json:"byte_offset"`
	Cells            int  `json:"cells"`
	TrailingASCIIPad bool `json:"trailing_ascii_pad"`
}
type NameEntryAudit struct {
	Name                   string         `json:"name"`
	Rows                   int            `json:"rows"`
	Cells                  int            `json:"cells"`
	CellsByPage            [2]int         `json:"cells_by_page"`
	TableRAM               uint32         `json:"table_ram"`
	PageConsumers          [2]uint32      `json:"page_consumers"`
	RowsInfo               []NameEntryRow `json:"rows_info"`
	DisplayLabels          [][]string     `json:"display_labels"`
	CandidateGlyphs        int            `json:"candidate_glyphs"`
	RasterBitOrderVerified bool           `json:"raster_bit_order_verified"`
	Status                 string         `json:"status"`
}

func AuditNameEntryGrid(original []byte) (NameEntryAudit, error) {
	var report NameEntryAudit
	if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA["NAME_ENT.EXN"] {
		return report, fmt.Errorf("name-entry grid NAME_ENT not authenticated retail overlay")
	}
	report.Name = "NAME_ENT.EXN"
	report.TableRAM = OverlaySlotBase + nameEntryGridGridPtrFileOff
	report.PageConsumers = [2]uint32{nameEntryGridGridPage0Caller, nameEntryGridGridPage1Caller}
	// Original code uses LUI $v1,0x8015 + ADDIU $v1,$v1,0xCD28
	// on the first page, and the matching 0xCD6C on the second.
	for page, pc := range report.PageConsumers {
		off := int(pc - OverlaySlotBase)
		expected := uint32(0x2463cd28 + page*0x44)
		if binary.LittleEndian.Uint32(original[off:]) != 0x3c038015 ||
			binary.LittleEndian.Uint32(original[off+8:]) != expected {
			return NameEntryAudit{}, fmt.Errorf("name-entry grid NAME_ENT page %d caller pair drift at %#x", page, pc)
		}
	}
	for idx := 0; idx < nameEntryGridGridRows; idx++ {
		ptr := binary.LittleEndian.Uint32(original[nameEntryGridGridPtrFileOff+idx*4:])
		if ptr < OverlaySlotBase+nameEntryGridGridStart || ptr >= OverlaySlotBase+nameEntryGridGridEnd {
			return NameEntryAudit{}, fmt.Errorf("grid pointer %d outside authenticated data rows", idx)
		}
		off := int(ptr - OverlaySlotBase)
		if idx == 0 && off != nameEntryGridGridStart {
			return NameEntryAudit{}, fmt.Errorf("grid source start drift")
		}
		if idx > 0 && off <= report.RowsInfo[idx-1].ByteOffset {
			return NameEntryAudit{}, fmt.Errorf("out-of-order grid pointer %d", idx)
		}
		stop := nameEntryGridGridEnd
		if idx < nameEntryGridGridRows-1 {
			next := binary.LittleEndian.Uint32(original[nameEntryGridGridPtrFileOff+(idx+1)*4:])
			if next < OverlaySlotBase || next > OverlaySlotBase+nameEntryGridGridEnd {
				return NameEntryAudit{}, fmt.Errorf("bad next grid pointer %d", idx)
			}
			stop = int(next - OverlaySlotBase)
		}
		if stop <= off || stop-off > 16 {
			return NameEntryAudit{}, fmt.Errorf("row %d has impossible stride", idx)
		}
		chunk := original[off:stop]
		term := -1
		for j, b := range chunk {
			if b == 0 {
				term = j
				break
			}
		}
		if term < 0 {
			return NameEntryAudit{}, fmt.Errorf("unterminated row %d", idx)
		}
		body := chunk[:term]
		pad := len(body)%2 != 0
		if pad {
			if len(body) < 1 || body[len(body)-1] != 0x20 || idx != 19 {
				return NameEntryAudit{}, fmt.Errorf("unexpected row padding %d", idx)
			}
			body = body[:len(body)-1]
		}
		if len(body)%2 != 0 || len(body) < 6 || len(body) > 10 {
			return NameEntryAudit{}, fmt.Errorf("invalid two-byte kana row %d", idx)
		}
		for j := 0; j < len(body); j += 2 {
			if body[j] != 0x82 && body[j] != 0x83 && !(idx == 11 && j == 8 && body[j] == 0x81) && !(idx == 28 && j == 8 && body[j] == 0x81) {
				return NameEntryAudit{}, fmt.Errorf("row %d has non-kana/control value at %d", idx, j)
			}
		}
		row := NameEntryRow{Index: idx, Page: idx / 17, ByteOffset: off, Cells: len(body) / 2, TrailingASCIIPad: pad}
		report.RowsInfo = append(report.RowsInfo, row)
		report.Cells += row.Cells
		report.CellsByPage[row.Page] += row.Cells
	}
	report.Rows = len(report.RowsInfo)
	if report.Rows != 34 || report.Cells != 162 || report.CellsByPage != [2]int{81, 81} {
		return NameEntryAudit{}, fmt.Errorf("unexpected grid completeness %d/%d/%v", report.Rows, report.Cells, report.CellsByPage)
	}
	hostRows, err := pn.ParseNameEntryKeyboardRows(original)
	if err != nil || len(hostRows) != report.Rows {
		return NameEntryAudit{}, fmt.Errorf("grid host label decoding incomplete: %v rows %d", err, len(hostRows))
	}
	for idx, row := range hostRows {
		if len(row.Cells) != report.RowsInfo[idx].Cells {
			return NameEntryAudit{}, fmt.Errorf("grid label count drift at %d", idx)
		}
		var labels []string
		for _, cell := range row.Cells {
			labels = append(labels, cell.Label)
		}
		report.DisplayLabels = append(report.DisplayLabels, labels)
	}
	glyphs, err := pn.BuildNameEntryGlyphCandidates(hostRows)
	if err != nil || len(glyphs) != report.Cells {
		return NameEntryAudit{}, fmt.Errorf("glyph candidate assembly incomplete: %v count %d", err, len(glyphs))
	}
	report.CandidateGlyphs = len(glyphs)
	report.RasterBitOrderVerified = false // The retail 1bpp font path is NOT yet resolved.
	report.Status = "ORIGINAL_ROW_SOURCES_AUTHENTICATED__DRAW_HOOK_NOT_PROVEN"
	return report, nil
}
