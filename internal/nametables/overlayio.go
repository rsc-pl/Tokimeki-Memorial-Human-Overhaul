package nametables

// G42: exact, read-only linkage of original executable LBA selector words to
// the original ISO9660 geometry, plus narrowly bounded follow-up opcodes.
// Matching argument registers to ISO extents is NOT a dynamic I/O or DMA proof.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const N10OwnerG41TraceSHA = "506962e69e8d856a05b10e7257893aac91ef5b0340a602de11012d0e2245b2e9"

type N10IOSelectorMatch struct {
	Path        string `json:"path"`
	LBA         int64  `json:"lba"`
	FileOffset  int    `json:"file_offset"`
	SectorCount int64  `json:"sector_count"`
}
type N10IOLoaderReview struct {
	Status                           string               `json:"status"`
	OriginalEXESHA                   string               `json:"original_exe_sha256"`
	OwnerG41TraceSHA                 string               `json:"owner_g41_trace_sha256"`
	OwnerG36GeometrySHA              string               `json:"owner_g36_geometry_sha256"`
	OwnerReportedG41FlowPresent      bool                 `json:"owner_report_contains_g41_static_flow"`
	OwnerReportedStatus              string               `json:"owner_report_status"`
	SourceWordsVerified              bool                 `json:"original_source_words_verified"`
	SelectorMatches                  []N10IOSelectorMatch `json:"selector_matches"`
	EXNNotInThisSelector             []string             `json:"exn_not_found_in_this_selector"`
	ExtraISOPayloadNotInThisSelector string               `json:"extra_iso_payload_not_in_this_selector"`
	SelectedSectorCount              int                  `json:"sector_count_argument"`
	DestinationFromOriginalSelector  string               `json:"destination_pointer_hypothesis"`
	IOCallTarget                     string               `json:"candidate_io_function"`
	IOCallFileOffset                 int                  `json:"candidate_io_call_file_offset"`
	IOFunctionImplementationVerified bool                 `json:"io_function_implementation_verified"`
	RuntimeIOVerified                bool                 `json:"runtime_io_verified"`
	RAMWriteOwnershipVerified        bool                 `json:"ram_write_ownership_verified"`
	SafeToPatch                      bool                 `json:"safe_to_patch"`
	Windows                          []N10TraceWindow     `json:"new_code_windows"`
	Limitations                      []string             `json:"limitations"`
}

type n10IOWindowSpec struct {
	label      string
	start, end int
}

func n10IOWindowSpecs() []n10IOWindowSpec {
	ramOff := func(a uint32) int { return int(a - n10FileToRAM) }
	return []n10IOWindowSpec{
		{"candidate-sector-reader-and-neighboring-calls", ramOff(0x80046080), ramOff(0x800465C0)},
		{"pre-overlay-device-state-0x8009C5E0", ramOff(0x8009C5A0), ramOff(0x8009C750)},
		{"transition-helper-0x80042808", ramOff(0x800427D0), ramOff(0x800429B0)},
		{"transition-helper-0x80042458", ramOff(0x80042420), ramOff(0x800425B0)},
	}
}

// Resolve the 24 selector immediates against G36 verified ISO extents. The
// complete range comes from the owner's G41 static word window, not guesswork.
func ReviewN10OverlaySelectorG42(old N10DispatchTraceReport, geo GeometryReport) (N10IOLoaderReview, error) {
	r := N10IOLoaderReview{Status: "G42_STATIC_IO_SELECTOR_NOT_RUNTIME_N10_DO_NOT_BOOT", OriginalEXESHA: N10OriginalEXESHA, OwnerG41TraceSHA: N10OwnerG41TraceSHA, OwnerG36GeometrySHA: "72452fe1df5ab2c9f0e5819946ae5402529a11272516a40f00541089878da024", OwnerReportedG41FlowPresent: old.StaticFlow != nil, OwnerReportedStatus: old.Status, IOCallTarget: "0x80046318", IOCallFileOffset: int(0x80079638 - n10FileToRAM), SelectedSectorCount: 96, DestinationFromOriginalSelector: "0x80132000 via [0x800B6D3C] (static)", ExtraISOPayloadNotInThisSelector: "CDROM/EXEDIR/O.BIN LBA 38474 (separate G37/G38 original-disc evidence)", SelectorMatches: []N10IOSelectorMatch{}, EXNNotInThisSelector: []string{}, Windows: []N10TraceWindow{}, Limitations: []string{
		"Static MIPS instruction/register and ISO LBA matching is not proof a transfer executes or completes",
		"0x80046318 must be separately inspected; even a sector-read implementation does not establish runtime BSS, bounds or RAM ownership",
		"This selector is not an exhaustive catalog of all code paths loading EVENT.EXN, GYOZI.EXN, or O.BIN",
		"Owner-supplied report has G40 lexical status without G41 static_flow; valid source words but do not claim the G41 flow ran",
		"No translation, ROM, CUE, Git, production builder or patch change; all 16 N10 edits HOLD / DO_NOT_BOOT",
	}}
	if !old.OriginalSourceVerified || old.OriginalEXESHA256 != N10OriginalEXESHA || old.DispatcherPointerSlot != "0x80123110" || old.PointerReadFileOffset != 233200 || old.SourceWindowBytes != 5888 || len(old.Windows) != 4 || old.SafeToPatch || geo.FilesVerified != 27 || len(geo.Sources) != 27 || geo.SafeToPatch {
		return r, errors.New("missing/replaced original G41 trace or G36 geometry evidence")
	}
	ins := map[int]uint32{}
	for _, w := range old.Windows {
		for _, v := range w.Instructions {
			if v.FileOffset%4 != 0 || len(v.Word) != 8 {
				return r, errors.New("bad instruction word")
			}
			var n uint32
			if _, e := fmt.Sscanf(v.Word, "%X", &n); e != nil {
				return r, e
			}
			if oldv, ok := ins[v.FileOffset]; ok && oldv != n {
				return r, errors.New("duplicate conflicting instruction")
			}
			ins[v.FileOffset] = n
		}
	}
	// Verify both halves of the actual call and destination preparation, not
	// lexical decode strings (which may differ across Go toolchain versions).
	anchors := map[int]uint32{
		233000: 0x34099A6A, 233004: 0x8CA56D3C, 233008: 0xAC296D40,
		233012: 0x24040060, 233016: 0x0C0118C6, 233020: 0x34069A6A,
		233148: 0x3C0B8014, 233152: 0x256BE850, 233160: 0xAC2B3110,
		233200: 0x8F393110, 233208: 0x0320F809,
		230500: 0x3C0E8013, 230504: 0x35CE2000, 230516: 0xAC2E6D3C,
	}
	for o, v := range anchors {
		if got, ok := ins[o]; !ok || got != v {
			return r, fmt.Errorf("G41 original code anchor mismatch 0x%X", o)
		}
	}
	paths := map[int64]GeometrySource{}
	for _, s := range geo.Sources {
		if strings.HasSuffix(s.Path, ".EXN") {
			if s.ISOExtentSectors != 96 || s.FileBytes != 196608 || !s.SourceIdentityVerified {
				return r, errors.New("bad EXN geometry")
			}
			if _, ok := paths[s.ISOExtentLBA]; ok {
				return r, errors.New("duplicate LBA")
			}
			paths[s.ISOExtentLBA] = s
		}
	}
	if len(paths) != 26 {
		return r, errors.New("expected 26 EXN extents")
	}
	seen := map[int64]bool{}
	// Every immediate here is an explicit ori $a2,$zero,LBA within the one
	// primary selection region. The other two excluded files may be loaded by
	// other routines; count is scoped, never global consumer closure.
	for o := 230800; o <= 231300; o += 4 {
		w, ok := ins[o]
		if !ok {
			return r, fmt.Errorf("missing selector word %d", o)
		}
		if w>>26 != 13 || ((w>>21)&31) != 0 || ((w>>16)&31) != 6 {
			continue
		}
		lba := int64(w & 0xffff)
		s, found := paths[lba]
		if !found || seen[lba] {
			continue
		}
		seen[lba] = true
		r.SelectorMatches = append(r.SelectorMatches, N10IOSelectorMatch{Path: s.Path, LBA: lba, FileOffset: o, SectorCount: s.ISOExtentSectors})
	}
	sort.Slice(r.SelectorMatches, func(i, j int) bool { return r.SelectorMatches[i].LBA < r.SelectorMatches[j].LBA })
	for _, s := range geo.Sources {
		if strings.HasSuffix(s.Path, ".EXN") && !seen[s.ISOExtentLBA] {
			r.EXNNotInThisSelector = append(r.EXNNotInThisSelector, s.Path)
		}
	}
	sort.Strings(r.EXNNotInThisSelector)
	if len(r.SelectorMatches) != 24 || len(r.EXNNotInThisSelector) != 2 || r.EXNNotInThisSelector[0] != "CDROM/EXEDIR/EVENT.EXN" || r.EXNNotInThisSelector[1] != "CDROM/EXEDIR/GYOZI.EXN" {
		return r, fmt.Errorf("G41 selector invariant: matches=%d omitted=%v", len(r.SelectorMatches), r.EXNNotInThisSelector)
	}
	r.SourceWordsVerified = true
	return r, nil
}

// The only operation requiring original EXE bytes is the subsequent targeted
// capture. The owner G41/G36 static review itself runs without their ROM.
func CaptureN10OverlayIOG42(exe []byte, review N10IOLoaderReview) (N10IOLoaderReview, error) {
	if !review.SourceWordsVerified {
		return review, errors.New("missing source report provenance")
	}
	if len(exe) != 667648 || hex.EncodeToString(sha256Sum(exe)) != N10OriginalEXESHA {
		return review, errors.New("original EXE identity mismatch")
	}
	for _, spec := range n10IOWindowSpecs() {
		if spec.start < 2048 || spec.end > len(exe) || spec.start >= spec.end || spec.start%4 != 0 || spec.end%4 != 0 || spec.end-spec.start > 2048 {
			return review, errors.New("unsafe IO window")
		}
		w := N10TraceWindow{Label: spec.label, Reason: "original EXE verified only; no execution or RAM write asserted", StartFileOffset: spec.start, EndFileOffsetExclusive: spec.end, Instructions: []N10TraceInstruction{}}
		for pos := spec.start; pos < spec.end; pos += 4 {
			inst := binary.LittleEndian.Uint32(exe[pos : pos+4])
			ram := n10FileToRAM + uint32(pos)
			dec, target := decodeN10Word(inst, ram)
			w.Instructions = append(w.Instructions, N10TraceInstruction{FileOffset: pos, RAM: fmt.Sprintf("0x%08X", ram), Word: fmt.Sprintf("%08X", inst), LexicalDecode: dec, ControlTarget: target})
		}
		review.Windows = append(review.Windows, w)
	}
	return review, nil
}
func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
