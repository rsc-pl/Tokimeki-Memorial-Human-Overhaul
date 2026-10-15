package nametables

// G37: bounded, read-only examination of the standard PS-X EXE header and
// possible call/pointer constructions from the original retail main EXE.
// A header field and static MIPS words NEVER establish observed overlay-loader
// behavior, runtime BSS clearing, safe writable lifetime or N10 patch approval.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	psxHeaderBytes = 0x800
	psxMaxRAM      = 0x80200000
	psxMinRAM      = 0x80000000
)

type N10LoadHeader struct {
	EntryPC                        string `json:"entry_pc"`
	GlobalPointer                  string `json:"global_pointer"`
	TextAddress                    string `json:"text_address"`
	TextSize                       uint32 `json:"text_size"`
	DataAddress                    string `json:"data_address"`
	DataSize                       uint32 `json:"data_size"`
	BSSAddress                     string `json:"bss_address"`
	BSSSize                        uint32 `json:"bss_size"`
	StackAddress                   string `json:"stack_address"`
	StackSize                      uint32 `json:"stack_size"`
	TextRangeIfHonored             string `json:"text_range_if_header_honored"`
	BSSRangeIfHonored              string `json:"bss_range_if_header_honored,omitempty"`
	FileOffsetToRAMBase            string `json:"file_offset_to_ram_base_for_text"`
	LegacyMainBaseAgrees           bool   `json:"legacy_main_file_base_agrees_with_header"`
	DeclaredTextFitsFile           bool   `json:"declared_text_fits_file_payload"`
	TextRangeIsWithin2MiBRAM       bool   `json:"text_range_is_within_ps1_2mib_ram"`
	BSSRangeIsWithin2MiBRAM        bool   `json:"bss_range_is_within_ps1_2mib_ram"`
	RendererTailInsideDeclaredText bool   `json:"renderer_tail_inside_declared_text"`
	ScratchABCInsideDeclaredBSS    bool   `json:"scratch_abc_inside_declared_bss"`
	RendererTailInsideDeclaredBSS  bool   `json:"renderer_tail_inside_declared_bss"`
}

type N10StaticTarget struct {
	FileOffset   int    `json:"file_offset"`
	Target       string `json:"target"`
	Kind         string `json:"kind"`
	AnchorOffset int    `json:"anchor_offset,omitempty"`
}

type N10ISOGapOccupant struct {
	Path        string `json:"path"`
	LBA         int64  `json:"lba"`
	Sectors     int64  `json:"sectors"`
	Size        int64  `json:"size"`
	IsDirectory bool   `json:"is_directory"`
}

type N10LoaderHeaderReport struct {
	UnscannedEXNInventoryGapStartLBA        int64               `json:"exn_inventory_gap_start_lba"`
	UnscannedEXNInventoryGapEndExclusiveLBA int64               `json:"exn_inventory_gap_end_exclusive_lba"`
	ISOExtentsOverlappingGap                []N10ISOGapOccupant `json:"iso_extents_overlapping_gap"`
	Status                                  string              `json:"status"`
	OwnerG36GeometrySHA256                  string              `json:"owner_g36_geometry_sha256"`
	OriginalEXESHA256                       string              `json:"original_exe_sha256"`
	Header                                  N10LoadHeader       `json:"header"`
	StaticDirectOverlayJALCount             int                 `json:"static_direct_overlay_jal_count"`
	StaticDirectOverlayJALExamples          []N10StaticTarget   `json:"static_direct_overlay_jal_examples"`
	StaticOverlayAddressPairCount           int                 `json:"static_overlay_address_pair_count"`
	StaticOverlayAddressPairExamples        []N10StaticTarget   `json:"static_overlay_address_pair_examples"`
	OriginalSourceIdentityVerified          bool                `json:"original_source_identity_verified"`
	HeaderParsed                            bool                `json:"header_parsed"`
	RuntimeLoaderVerified                   bool                `json:"runtime_loader_verified"`
	RuntimeBSSClearVerified                 bool                `json:"runtime_bss_clear_verified"`
	OverlayLifetimeVerified                 bool                `json:"overlay_lifetime_verified"`
	SafeToPatch                             bool                `json:"safe_to_patch"`
	Limitations                             []string            `json:"limitations"`
}

// AnalyzeN10LoadHeader verifies original EXE identity against the owner's
// G36 original-disc report before interpreting PS-X EXE header fields. It
// derives text's file-offset conversion from the header (which may disagree
// with legacy tools) and catalogs bounded static references to the overlay
// address window. No execution or loader disassembly is claimed.
func AnalyzeN10LoadHeader(exe []byte, geo GeometryReport, ownerSHA string) (N10LoaderHeaderReport, error) {
	if geo.Status != "STATIC_DISC_GEOMETRY_ONLY_UNVERIFIED_RAM_AND_BSS_DO_NOT_BOOT" {
		return N10LoaderHeaderReport{}, errors.New("unreviewed G36 report status")
	}
	if geo.FilesVerified != 27 || geo.TotalBytes != 5779456 || geo.SafeToPatch || geo.RuntimeLoaderVerified ||
		geo.BSSRangeVerified || geo.WritableRAMOwnershipVerified || len(geo.Sources) != 27 ||
		!strings.EqualFold(ownerSHA, "72452fe1df5ab2c9f0e5819946ae5402529a11272516a40f00541089878da024") {
		return N10LoaderHeaderReport{}, errors.New("wrong or unsafe original owner G36 geometry provenance")
	}
	var sourceSHA string
	for _, src := range geo.Sources {
		if src.Path == EXE && src.SourceIdentityVerified && src.PSXExeSignature && src.FileBytes == 667648 {
			sourceSHA = src.SourceSHA256
			break
		}
	}
	h := sha256.Sum256(exe)
	sha := fmt.Sprintf("%x", h)
	if sourceSHA == "" || !strings.EqualFold(sourceSHA, sha) || len(exe) != 667648 || len(exe)%4 != 0 || len(exe) < psxHeaderBytes || string(exe[:8]) != "PS-X EXE" {
		return N10LoaderHeaderReport{}, errors.New("original owner retail PS-X EXE SHA/signature mismatch")
	}
	out := inspectPSXHeaderAndAnchors(exe)
	out.OwnerG36GeometrySHA256 = ownerSHA
	out.OriginalEXESHA256 = sha
	out.OriginalSourceIdentityVerified = true
	return out, nil
}

// Structural parsing is deliberately independent of provenance so synthetic
// unit tests can cover field/offset/delay-slot arithmetic without using ROM.
func inspectPSXHeaderAndAnchors(exe []byte) N10LoaderHeaderReport {
	u := func(off int) uint32 { return binary.LittleEndian.Uint32(exe[off:]) }
	f := func(a uint32) string { return fmt.Sprintf("0x%08X", a) }
	entry, gp, tAddr, tSize := u(0x10), u(0x14), u(0x18), u(0x1c)
	dAddr, dSize, bAddr, bSize := u(0x20), u(0x24), u(0x28), u(0x2c)
	sAddr, sSize := u(0x30), u(0x34)
	// Arithmetic intentionally remains in uint64: malformed headers cannot
	// wrap an interval back into RAM and be incorrectly marked safe.
	tEnd := uint64(tAddr) + uint64(tSize)
	bEnd := uint64(bAddr) + uint64(bSize)
	textRAM := tSize > 0 && uint64(tAddr) >= psxMinRAM && tEnd <= psxMaxRAM
	bssRAM := bSize > 0 && uint64(bAddr) >= psxMinRAM && bEnd <= psxMaxRAM
	header := N10LoadHeader{
		EntryPC: f(entry), GlobalPointer: f(gp), TextAddress: f(tAddr), TextSize: tSize,
		DataAddress: f(dAddr), DataSize: dSize, BSSAddress: f(bAddr), BSSSize: bSize,
		StackAddress: f(sAddr), StackSize: sSize,
		TextRangeIfHonored:       fmt.Sprintf("[%s,0x%08X)", f(tAddr), tEnd),
		FileOffsetToRAMBase:      f(tAddr - psxHeaderBytes),
		LegacyMainBaseAgrees:     uint64(tAddr) == uint64(LegacyEXEBase)+psxHeaderBytes,
		DeclaredTextFitsFile:     tSize > 0 && uint64(tSize) <= uint64(len(exe)-psxHeaderBytes),
		TextRangeIsWithin2MiBRAM: textRAM, BSSRangeIsWithin2MiBRAM: bssRAM,
		RendererTailInsideDeclaredText: textRAM && uint64(tAddr) <= uint64(rendererTailFirst) && uint64(rendererTailEnd) <= tEnd,
		ScratchABCInsideDeclaredBSS:    bssRAM && uint64(bAddr) <= 0x800ca188 && 0x800ca19c+1 <= bEnd,
		RendererTailInsideDeclaredBSS:  bssRAM && uint64(bAddr) <= uint64(rendererTailFirst) && uint64(rendererTailEnd) <= bEnd,
	}
	if bSize > 0 {
		header.BSSRangeIfHonored = fmt.Sprintf("[%s,0x%08X)", f(bAddr), bEnd)
	}
	out := N10LoaderHeaderReport{
		Status:                         "PSX_EXE_HEADER_AND_STATIC_MAIN_ANCHORS_ONLY_N10_DO_NOT_BOOT",
		Header:                         header,
		StaticDirectOverlayJALExamples: []N10StaticTarget{}, StaticOverlayAddressPairExamples: []N10StaticTarget{},
		OriginalSourceIdentityVerified: false, HeaderParsed: true,
		RuntimeLoaderVerified: false, RuntimeBSSClearVerified: false, OverlayLifetimeVerified: false, SafeToPatch: false,
		Limitations: []string{
			"PS-X EXE header fields are declared metadata, not a runtime read/write/zeroing observation",
			"Declared BSS can omit heap, dynamic allocations, overlay initialization and manual clearing",
			"Overlay .EXN lacks PS-X EXE header; overlay static address anchors are not the loader's RAM writes",
			"Static JAL/address-pair words can be data, unused branches or dynamic call sites; no CFG or loader proof",
			"A/B/C pointer aliases, renderer-tail write ownership, strcat lengths, game UI and actual runtime remain unverified",
			"Owner original executable source remains unchanged; no N10 runtime or build patch is authorized",
		},
	}
	// Only scan *declared executable payload* if the declared size is sane;
	// otherwise scan the bounded file payload as a heuristic, still no CFG.
	end := len(exe)
	if header.DeclaredTextFitsFile {
		end = psxHeaderBytes + int(tSize)
	}
	// Standard J/JAL targets use the caller PC's upper nibble. In the PS1
	// KSEG0 region the high nibble is 8, so the resulting target preserves it.
	// We do not know if every word is executable code.
	for off := psxHeaderBytes; off+4 <= end; off += 4 {
		w := u(off)
		if (w >> 26) == 3 { // JAL only, not J
			target := uint32(0x80000000) | ((w & 0x03ffffff) << 2)
			if target >= LegacyOverlayBase && target < LegacyOverlayBase+0x30000 {
				out.StaticDirectOverlayJALCount++
				if len(out.StaticDirectOverlayJALExamples) < 32 {
					out.StaticDirectOverlayJALExamples = append(out.StaticDirectOverlayJALExamples, N10StaticTarget{FileOffset: off, Target: f(target), Kind: "JAL-to-hypothetical-overlay-range"})
				}
			}
		}
		// Detect LUI+ADDIU/ORI to the same destination register, no intervening
		// instruction. Wider register propagation is purposefully excluded.
		if (w>>26) != 0x0f || off+8 > end {
			continue
		}
		rt := (w >> 16) & 0x1f
		next := u(off + 4)
		op, rs, dest := next>>26, (next>>21)&0x1f, (next>>16)&0x1f
		if (op != 0x09 && op != 0x0d) || rt != rs || rt != dest {
			continue
		}
		imm := uint32(next & 0xffff)
		if op == 0x09 && imm >= 0x8000 {
			imm -= 0x10000
		}
		addr := uint32((w&0xffff)<<16) + imm
		if addr >= LegacyOverlayBase && addr < LegacyOverlayBase+0x30000 {
			out.StaticOverlayAddressPairCount++
			if len(out.StaticOverlayAddressPairExamples) < 32 {
				out.StaticOverlayAddressPairExamples = append(out.StaticOverlayAddressPairExamples, N10StaticTarget{FileOffset: off + 4, AnchorOffset: off, Target: f(addr), Kind: "adjacent-LUI-ADDIU-ORI"})
			}
		}
	}
	return out
}
