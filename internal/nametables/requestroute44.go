package nametables

// G44: original-disc request jump-table routing, read-only. A table word and
// lexical instructions do not prove the selected branch executes or that DMA
// writes into writable, long-lived overlay memory.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
)

const N10OwnerG43TransferSHA = "9def7ae8737d28384299ed2c849eddd94d720fe78546e2d26769321d645c5248"
const n10RequestTableStart uint32 = 0x800AF810
const n10RequestEntries = 28

type N10RequestRouteEntryG44 struct {
	Operation          int    `json:"operation"`
	TableAddress       string `json:"table_address"`
	FileOffset         int    `json:"file_offset"`
	WordLittleEndian   string `json:"word_little_endian"`
	InMainEXECodeRange bool   `json:"in_main_exe_code_range"`
	Aligned            bool   `json:"aligned"`
}

type N10RequestRouteReviewG44 struct {
	Status                            string                    `json:"status"`
	OwnerG43SHA256                    string                    `json:"owner_g43_sha256"`
	OriginalEXESHA256                 string                    `json:"original_exe_sha256"`
	OwnerSourceVerified               bool                      `json:"owner_source_verified"`
	OriginalEXEVerified               bool                      `json:"original_exe_verified"`
	RequestedOperation                int                       `json:"requested_operation"`
	DispatchTableBase                 string                    `json:"dispatch_table_base"`
	DispatchTableLength               int                       `json:"dispatch_table_length"`
	Operation6EntryAddress            string                    `json:"operation_6_entry_address"`
	Operation6Target                  string                    `json:"operation_6_target,omitempty"`
	Operation6TargetInMainEXECode     bool                      `json:"operation_6_target_in_main_exe_code"`
	Operation6IsCandidate45494        bool                      `json:"operation_6_is_0x80045494"`
	Operation6BranchRuntimeVerified   bool                      `json:"operation_6_branch_runtime_verified"`
	Callee45318ImplementationVerified bool                      `json:"callee_0x80045318_implementation_verified"`
	SectorTransferVerified            bool                      `json:"sector_transfer_verified"`
	OverlayRAMBoundsVerified          bool                      `json:"overlay_ram_bounds_verified"`
	SafeToPatch                       bool                      `json:"safe_to_patch"`
	Entries                           []N10RequestRouteEntryG44 `json:"jump_table_entries"`
	NewCodeWindows                    []N10TraceWindow          `json:"new_code_windows"`
	Limitations                       []string                  `json:"limitations"`
}

type n10Route44Window struct {
	label      string
	start, end uint32
}

func n10G44Windows() []n10Route44Window {
	return []n10Route44Window{
		{"request-handler-0x80045318", 0x800452C0, 0x800453D0},
		{"indirect-device-helper-0x8008A1E0", 0x8008A160, 0x8008A360},
		{"request-command-helper-0x800879D0", 0x80087930, 0x80087A80},
		{"setup-called-function-0x8009C93C", 0x8009C900, 0x8009CB00},
	}
}

// The proof includes the entire G43 code-window geometry (not isolated search
// hits), exact source metadata and all source words needed to derive operation 6.
func ReviewN10RequestRouteG44(owner N10DescriptorReviewG43) (N10RequestRouteReviewG44, error) {
	r := N10RequestRouteReviewG44{
		Status:         "G44_STATIC_REQUEST_DISPATCH_TABLE_EXE_ONLY_N10_HOLD",
		OwnerG43SHA256: N10OwnerG43TransferSHA, OriginalEXESHA256: N10OriginalEXESHA,
		RequestedOperation: 6, DispatchTableBase: fmt.Sprintf("0x%08X", n10RequestTableStart),
		DispatchTableLength: n10RequestEntries, Operation6EntryAddress: fmt.Sprintf("0x%08X", n10RequestTableStart+6*4),
		Entries: []N10RequestRouteEntryG44{}, NewCodeWindows: []N10TraceWindow{},
		Limitations: []string{
			"The request jump-table target comes from original EXE data, not executed-PC evidence",
			"A handler being selected does not prove CD read, DMA or completion",
			"Packed descriptor 0x60132000 is NOT a direct virtual RAM pointer",
			"No original RAM ownership, overlay lifetime, BSS/heap alias or renderer-name capacity is established",
			"No writes to translation, BIN/CUE, Git, production builder or saves; all 16 N10 surname edits HOLD / DO_NOT_BOOT",
		},
	}
	if owner.Status != "G43_ORIGINAL_MIPS_PACKED_REQUEST_STATIC_ONLY_DO_NOT_BOOT" ||
		owner.OwnerG42SHA != N10OwnerG42IOSHA || owner.OriginalEXESHA != N10OriginalEXESHA || !owner.SourceVerified ||
		owner.AddressBeforePacking != "0x80132000 (G41/G42 static selector hypothesis)" ||
		owner.Sectors != 96 || owner.PackedDescriptor != "0x60132000" || owner.PackedBytePattern != "00 20 13 60" ||
		owner.DescriptorStackOffset != 40 || owner.RequestConsumer != "0x80045414" || owner.RequestOperation != 6 ||
		owner.SectorTransferVerified || owner.CalleeDescriptorInterpretationVerified || owner.OverlayRAMBoundsVerified || owner.SafeToPatch ||
		len(owner.NewCodeWindows) != 4 {
		return r, fmt.Errorf("G43 source metadata/status mismatch")
	}
	words := make(map[uint32]uint32)
	for _, win := range owner.NewCodeWindows {
		if win.StartFileOffset < 2048 || win.EndFileOffsetExclusive > 667648 ||
			win.EndFileOffsetExclusive <= win.StartFileOffset ||
			(win.EndFileOffsetExclusive-win.StartFileOffset)%4 != 0 ||
			len(win.Instructions) != (win.EndFileOffsetExclusive-win.StartFileOffset)/4 {
			return r, fmt.Errorf("G43 original code geometry mismatch")
		}
		for i, x := range win.Instructions {
			off := win.StartFileOffset + i*4
			addr := n10FileToRAM + uint32(off)
			if x.FileOffset != off || x.RAM != fmt.Sprintf("0x%08X", addr) || len(x.Word) != 8 {
				return r, fmt.Errorf("G43 original code continuity mismatch")
			}
			w, e := strconv.ParseUint(x.Word, 16, 32)
			if e != nil {
				return r, fmt.Errorf("G43 original opcode malformed")
			}
			if _, exists := words[addr]; exists {
				return r, fmt.Errorf("duplicate G43 source address")
			}
			words[addr] = uint32(w)
		}
	}
	anchors := map[uint32]uint32{
		0x80045414: 0x3C010004, 0x80045418: 0x3421AB51,
		0x80045420: 0x308E00FF, 0x80045424: 0x00A1082B,
		0x80045430: 0x14200003, 0x80045434: 0x00A03825,
		0x80045438: 0x3C070004, 0x8004543C: 0x34E7AB50,
		0x80045440: 0x2C81001C, 0x80045448: 0x00047880,
		0x8004544C: 0x3C01800B, 0x80045450: 0x002F0821,
		0x80045454: 0x8C2FF810, 0x8004545C: 0x01E00008, 0x80045460: 0,
		0x80045494: 0x3C01800B, 0x80045498: 0xAC273D6C,
		0x8004549C: 0x24040006, 0x800454A0: 0x0C0114C6,
		0x800454A4: 0x00E02825,
	}
	for addr, want := range anchors {
		if got, ok := words[addr]; !ok || got != want {
			return r, fmt.Errorf("G43 MIPS anchor %08X mismatch", addr)
		}
	}
	r.OwnerSourceVerified = true
	return r, nil
}

func CaptureN10RequestRouteG44(exe []byte, r N10RequestRouteReviewG44) (N10RequestRouteReviewG44, error) {
	if !r.OwnerSourceVerified || r.Status != "G44_STATIC_REQUEST_DISPATCH_TABLE_EXE_ONLY_N10_HOLD" ||
		r.SafeToPatch || r.SectorTransferVerified || r.OverlayRAMBoundsVerified || r.Operation6BranchRuntimeVerified ||
		len(exe) != 667648 || fmt.Sprintf("%x", sha256.Sum256(exe)) != N10OriginalEXESHA {
		return r, fmt.Errorf("G44 requires original SHA-verified EXE + verified G43 source")
	}
	return captureG44Original(exe, r)
}

func captureG44Original(exe []byte, r N10RequestRouteReviewG44) (N10RequestRouteReviewG44, error) {
	if !r.OwnerSourceVerified || r.SafeToPatch || len(r.Entries) != 0 || len(r.NewCodeWindows) != 0 {
		return r, fmt.Errorf("G44 invalid source/safety status or repeated capture")
	}
	for i := 0; i < n10RequestEntries; i++ {
		at := n10RequestTableStart + uint32(i*4)
		off := int(at - n10FileToRAM)
		if off < 2048 || off+4 > len(exe) {
			return r, fmt.Errorf("G44 table out of bounds")
		}
		value := binary.LittleEndian.Uint32(exe[off : off+4])
		entry := N10RequestRouteEntryG44{
			Operation: i, TableAddress: fmt.Sprintf("0x%08X", at), FileOffset: off,
			WordLittleEndian: fmt.Sprintf("0x%08X", value),
			Aligned:          value%4 == 0, InMainEXECodeRange: value >= 0x80041000 && value < 0x800E3800,
		}
		r.Entries = append(r.Entries, entry)
		if i == 6 {
			r.Operation6Target = entry.WordLittleEndian
			r.Operation6TargetInMainEXECode = entry.InMainEXECodeRange && entry.Aligned
			r.Operation6IsCandidate45494 = value == 0x80045494
		}
	}
	for _, spec := range n10G44Windows() {
		if spec.start < n10FileToRAM+2048 || spec.end <= spec.start || spec.end > n10FileToRAM+uint32(len(exe)) ||
			spec.start%4 != 0 || spec.end%4 != 0 || spec.end-spec.start > 2048 {
			return r, fmt.Errorf("invalid G44 scoped window")
		}
		start := int(spec.start - n10FileToRAM)
		end := int(spec.end - n10FileToRAM)
		win := N10TraceWindow{Label: spec.label, Reason: "SHA-verified original code words; static only, not live execution", StartFileOffset: start, EndFileOffsetExclusive: end, Instructions: []N10TraceInstruction{}}
		for off := start; off < end; off += 4 {
			word := binary.LittleEndian.Uint32(exe[off : off+4])
			addr := n10FileToRAM + uint32(off)
			dec, target := decodeN10Word(word, addr)
			win.Instructions = append(win.Instructions, N10TraceInstruction{FileOffset: off, RAM: fmt.Sprintf("0x%08X", addr), Word: fmt.Sprintf("%08X", word), LexicalDecode: dec, ControlTarget: target})
		}
		r.NewCodeWindows = append(r.NewCodeWindows, win)
	}
	r.OriginalEXEVerified = true
	return r, nil
}
