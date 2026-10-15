package nametables

// G39: classifies only the owner-authenticated G38 static MIPS word windows.
// Selecting an overlay entry pointer does NOT prove how an EXN file is loaded,
// when memory is cleared, or whether a surname buffer is safe to relocate.

import (
	"errors"
	"fmt"
	"strconv"
)

type N10DispatchArm struct {
	FileOffset          int    `json:"file_offset"`
	PointerValue        string `json:"pointer_value"`
	StoredAt            string `json:"stored_at"`
	StoreFileOffset     int    `json:"store_file_offset"`
	UnconditionalBranch bool   `json:"unconditional_branch"`
	JoinFileOffset      int    `json:"join_file_offset"`
}

type N10DispatchReview struct {
	Status                      string           `json:"status"`
	InputReportSHA256           string           `json:"input_report_sha256"`
	InputSourceVerified         bool             `json:"input_source_verified"`
	OddBINDirectABC             int              `json:"odd_bin_direct_abc"`
	OddBINDirectCPlus64         int              `json:"odd_bin_direct_c_plus_64"`
	OddBINJALLikeWords          int              `json:"odd_bin_jal_like_words"`
	RawOverlayRangeJALCount     int              `json:"raw_overlay_range_jal_count"`
	DataLikeJALOffsets          []int            `json:"data_like_jal_offsets"`
	DataLikeJALInterpretation   string           `json:"data_like_jal_interpretation"`
	AllAddressPairs             int              `json:"all_address_pairs"`
	DispatchArms                []N10DispatchArm `json:"dispatch_arms"`
	DispatchJoinFileOffset      int              `json:"dispatch_join_file_offset"`
	DispatchJoinRAM             string           `json:"dispatch_join_ram"`
	DispatchSlot                string           `json:"dispatch_slot"`
	SeparateAnchorOffsets       []int            `json:"separate_anchor_offsets"`
	SeparateAnchorValues        []string         `json:"separate_anchor_values"`
	FollowupPointerReadObserved bool             `json:"followup_pointer_read_observed"`
	FollowupPointerReadOffset   int              `json:"followup_pointer_read_file_offset"`
	RuntimeLoaderVerified       bool             `json:"runtime_loader_verified"`
	WritableRAMVerified         bool             `json:"writable_ram_verified"`
	SafeToPatch                 bool             `json:"safe_to_patch"`
	Limitations                 []string         `json:"limitations"`
}

func n10At(w N10RawWordWindow, off int) (uint32, bool) {
	for _, v := range w.Words {
		if v.Offset == off {
			n, err := strconv.ParseUint(v.Hex, 16, 32)
			if err == nil {
				return uint32(n), true
			}
		}
	}
	return 0, false
}

func n10InstructionAt(w N10RawWordWindow, off int) (uint32, error) {
	word, ok := n10At(w, off)
	if !ok {
		return 0, fmt.Errorf("missing instruction at offset %d", off)
	}
	return word, nil
}

// ReviewN10OverlayDispatch can process the previously collected owner G38
// report without rescanning a ROM. The CLI separately authenticates its SHA.
func ReviewN10OverlayDispatch(r N10LoaderFollowupReport, sha string) (N10DispatchReview, error) {
	if len(sha) != 64 || r.Status != "G38_ORIGINAL_ODD_BIN_AND_MAIN_LOADER_ANCHORS_STATIC_ONLY_DO_NOT_BOOT" ||
		!r.OriginalSourcesVerified || r.RuntimeLoaderVerified || r.FullControlFlowVerified ||
		r.BSSAndWritableMemoryVerified || r.SafeToPatch || len(r.MainDirectOverlayJAL) != 2 ||
		len(r.MainOverlayAddressPairs) != 48 || r.OddBINABCUniqueSites != 0 || r.OddBINCPlus64DirectSites != 0 || r.OddBINStaticSelfJALCount != 4 {
		return N10DispatchReview{}, errors.New("G38 report missing required original-source provenance, sites or HOLD status")
	}
	o := N10DispatchReview{
		Status:            "G39_STATIC_OVERLAY_ENTRY_DISPATCH_REVIEW_N10_HOLD_DO_NOT_BOOT",
		InputReportSHA256: sha, InputSourceVerified: true,
		OddBINDirectABC: r.OddBINABCUniqueSites, OddBINDirectCPlus64: r.OddBINCPlus64DirectSites,
		OddBINJALLikeWords:        r.OddBINStaticSelfJALCount,
		RawOverlayRangeJALCount:   len(r.MainDirectOverlayJAL),
		DataLikeJALOffsets:        []int{483800, 648276},
		DataLikeJALInterpretation: "data-like neighborhoods; neither is a demonstrated executed call; CFG still unverified",
		AllAddressPairs:           len(r.MainOverlayAddressPairs),
		DispatchArms:              []N10DispatchArm{},
		DispatchJoinFileOffset:    232604, DispatchJoinRAM: "0x8007949C", DispatchSlot: "0x80123110",
		SeparateAnchorOffsets: []int{}, SeparateAnchorValues: []string{},
		RuntimeLoaderVerified: false, WritableRAMVerified: false, SafeToPatch: false,
		Limitations: []string{
			"Entry pointer selection is not disc I/O: loader implementation and RAM/BSS writes remain unverified",
			"G38 data-like JAL words are likely static-scan false positives, not independently CFG-disproved",
			"Only exact G38 bounded windows reviewed; pointer aliases/indirect consumers and overlay lifetime remain open",
			"No N10 code patch, boot authorization, string length/append bound or UI-fit proof",
		},
	}
	for i, c := range r.MainDirectOverlayJAL {
		if c.FileOffset != o.DataLikeJALOffsets[i] {
			return N10DispatchReview{}, errors.New("unexpected static JAL site")
		}
	}
	for _, w := range r.MainOverlayAddressPairs {
		off := w.FileOffset
		if off < 231664 || off > 232592 {
			o.SeparateAnchorOffsets = append(o.SeparateAnchorOffsets, off)
			o.SeparateAnchorValues = append(o.SeparateAnchorValues, w.Target)
			continue
		}
		low, err := n10InstructionAt(w, off)
		if err != nil {
			return N10DispatchReview{}, err
		}
		hi, err := n10InstructionAt(w, off-4)
		if err != nil {
			return N10DispatchReview{}, err
		}
		at, err := n10InstructionAt(w, off+4)
		if err != nil {
			return N10DispatchReview{}, err
		}
		next, err := n10InstructionAt(w, off+8)
		if err != nil {
			return N10DispatchReview{}, err
		}
		reg := (low >> 16) & 31
		if hi>>26 != 15 || ((hi>>16)&31) != reg || (low>>26 != 9 && low>>26 != 13) || (low>>21)&31 != reg || at != 0x3C018012 {
			return N10DispatchReview{}, fmt.Errorf("offset %d does not construct a local pointer in expected register", off)
		}
		storeOff := off + 8
		branch := false
		if (next>>26) == 4 && (next&0x03ff0000) == 0 { // beq $zero,$zero, imm
			branch = true
			imm := int16(next & 0xffff)
			join := off + 8 + 4 + int(imm)*4
			if join != o.DispatchJoinFileOffset {
				return N10DispatchReview{}, fmt.Errorf("branch at %d has different join %d", off+8, join)
			}
			storeOff += 4 // branch delay slot executes before jumping
		} else if off != 232592 {
			return N10DispatchReview{}, fmt.Errorf("early arm at %d lacks common-exit branch", off)
		}
		store, err := n10InstructionAt(w, storeOff)
		if err != nil {
			return N10DispatchReview{}, err
		}
		expected := uint32(0xAC200000) | (reg << 16) | 0x3110 // SW reg,0x3110($at)
		if store != expected {
			return N10DispatchReview{}, fmt.Errorf("bad pointer store at %d", storeOff)
		}
		o.DispatchArms = append(o.DispatchArms, N10DispatchArm{FileOffset: off, PointerValue: w.Target, StoredAt: o.DispatchSlot, StoreFileOffset: storeOff, UnconditionalBranch: branch, JoinFileOffset: o.DispatchJoinFileOffset})
	}
	if len(o.DispatchArms) != 45 || len(o.SeparateAnchorOffsets) != 3 || o.SeparateAnchorOffsets[0] != 4200 || o.SeparateAnchorOffsets[1] != 230504 || o.SeparateAnchorOffsets[2] != 233152 {
		return N10DispatchReview{}, fmt.Errorf("unexpected dispatch arm/separate site partition %d/%d", len(o.DispatchArms), len(o.SeparateAnchorOffsets))
	}
	for i, a := range o.DispatchArms {
		if i < 44 && !a.UnconditionalBranch || i == 44 && a.UnconditionalBranch {
			return N10DispatchReview{}, errors.New("unexpected terminal arm behavior")
		}
	}
	// The third separate site shows an actual read of the chosen entry slot
	// in its bounded context: LUI $t9,0x8012; LW $t9,0x3110($t9).
	for _, w := range r.MainOverlayAddressPairs {
		if w.FileOffset != 233152 {
			continue
		}
		a, yesA := n10At(w, 233196)
		b, yesB := n10At(w, 233200)
		if yesA && yesB && a == 0x3C198012 && b == 0x8F393110 {
			o.FollowupPointerReadObserved = true
			o.FollowupPointerReadOffset = 233200
		}
	}
	if !o.FollowupPointerReadObserved {
		return N10DispatchReview{}, errors.New("G38 followup pointer read context changed")
	}
	return o, nil
}
