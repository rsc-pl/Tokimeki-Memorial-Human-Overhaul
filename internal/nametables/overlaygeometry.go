package nametables

// G36 is a read-only, original-disc file/ISO geometry check. In particular,
// a byte interval inferred from a legacy source-address convention is NOT
// an observed dynamic load range, a BSS boundary, or writable RAM ownership.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	LegacyEXEBase     uint32 = 0x80040800 // legacy_scripts/tools/exn_words.py
	LegacyOverlayBase uint32 = 0x80132000 // source convention, NOT measured loader
	rendererTailFirst uint32 = 0x8004bafc
	rendererTailEnd   uint32 = 0x8004bb2c
)

type GeometryInput struct {
	Path string
	LBA  int64
	Data []byte
}
type GeometrySelfCall struct {
	Offset int    `json:"file_offset"`
	Target string `json:"target"`
}
type GeometrySource struct {
	Path                   string             `json:"path"`
	SourceSHA256           string             `json:"source_sha256"`
	ISOExtentLBA           int64              `json:"iso_extent_lba"`
	ISOExtentSectors       int64              `json:"iso_extent_sectors"`
	FileBytes              int                `json:"file_bytes"`
	LegacyFileBase         string             `json:"legacy_file_base_hypothesis"`
	LegacyFileEndExclusive string             `json:"legacy_file_end_exclusive_hypothesis"`
	PSXExeSignature        bool               `json:"ps_x_exe_signature_at_file_zero"`
	StaticSelfJALSites     int                `json:"static_self_jal_sites"`
	SelfJALExamples        []GeometrySelfCall `json:"self_jal_examples"`
	SourceIdentityVerified bool               `json:"source_identity_verified"`
}
type GeometryReport struct {
	Status                                      string           `json:"status"`
	OwnerG34ContextSHA256                       string           `json:"owner_g34_context_sha256"`
	FilesVerified                               int              `json:"files_verified"`
	TotalBytes                                  int64            `json:"total_bytes"`
	SourceConvention                            string           `json:"source_convention"`
	MainFileImageRange                          string           `json:"main_file_image_range_hypothesis"`
	OverlayFileImageRange                       string           `json:"overlay_file_image_range_hypothesis"`
	RendererTailInsideMainFileHypothesis        bool             `json:"renderer_tail_inside_main_file_hypothesis"`
	HypothesizedOverlayFileOverlapsRendererTail bool             `json:"hypothesized_overlay_file_overlaps_renderer_tail"`
	StaticSelfJALSites                          int              `json:"static_self_jal_sites"`
	Sources                                     []GeometrySource `json:"sources"`
	RuntimeLoaderVerified                       bool             `json:"runtime_loader_verified"`
	BSSRangeVerified                            bool             `json:"bss_range_verified"`
	WritableRAMOwnershipVerified                bool             `json:"writable_ram_ownership_verified"`
	SafeToPatch                                 bool             `json:"safe_to_patch"`
	Limitations                                 []string         `json:"limitations"`
}

// BuildN10OverlayGeometry verifies every original source against the exact
// SHA inventory in the owner's G34 report. ISO LBA is caller-supplied metadata
// (read by the CLI from the original-disc ISO9660 directory), not RAM mapping.
func BuildN10OverlayGeometry(ctx OverlayContextReport, ctxSHA string, files []GeometryInput) (GeometryReport, error) {
	if ctx.Status != "STATIC_MIPS_CONTEXT_REVIEW_ONLY_DO_NOT_BOOT" ||
		!ctx.VerifiedAgainstFreshScan || ctx.CallerCoverageComplete || ctx.RuntimeSafe ||
		ctx.UniqueSites != 211 || len(ctx.Sources) != 27 || len(files) != len(ctx.Sources) {
		return GeometryReport{}, errors.New("owner G34 inventory is missing or is not the reviewed 27-source / 211-site census")
	}
	expected := map[string]OverlayContextSource{}
	for _, s := range ctx.Sources {
		if !N10DiscCodeCandidate(s.Path, false) || s.Size <= 0 || s.Size > 16<<20 || len(s.SHA256) != 64 {
			return GeometryReport{}, errors.New("untrusted inventory source")
		}
		if _, seen := expected[s.Path]; seen {
			return GeometryReport{}, errors.New("duplicate inventory source")
		}
		expected[s.Path] = s
	}
	if _, ok := expected[EXE]; !ok {
		return GeometryReport{}, errors.New("missing main executable")
	}
	if _, ok := expected[Geko]; !ok {
		return GeometryReport{}, errors.New("missing GEKO")
	}
	seen := map[string]bool{}
	report := GeometryReport{
		Status:                "STATIC_DISC_GEOMETRY_ONLY_UNVERIFIED_RAM_AND_BSS_DO_NOT_BOOT",
		OwnerG34ContextSHA256: ctxSHA,
		SourceConvention:      "legacy_scripts/tools/exn_words.py base_of() (hypothesis; not an overlay-loader observation)",
		Sources:               make([]GeometrySource, 0, len(files)),
		RuntimeLoaderVerified: false, BSSRangeVerified: false, WritableRAMOwnershipVerified: false, SafeToPatch: false,
		Limitations: []string{
			"The legacy per-file base is an address-resolution convention; no runtime PC or loader writes were measured",
			"ISO9660 LBA/sector extents describe disc positions, not memory or BSS ownership",
			"Static JAL targets can be data or unreachable code and do not prove dynamic overlay load base",
			"Overlay initialization may clear additional ranges, allocate BSS or use DMA; this report does not inspect those actions",
			"Mapped file-image separation is only conditional on the legacy base convention; indirect A/B/C users and renderer-tail liveness remain unknown",
		},
	}
	var main, overlayMax uint32
	for _, f := range files {
		e, ok := expected[f.Path]
		if !ok || seen[f.Path] {
			return GeometryReport{}, fmt.Errorf("unexpected/duplicate executable %s", f.Path)
		}
		seen[f.Path] = true
		if f.LBA < 0 || len(f.Data) != e.Size || len(f.Data)%4 != 0 || len(f.Data) > 16<<20 {
			return GeometryReport{}, fmt.Errorf("invalid original file size/LBA: %s", f.Path)
		}
		sum := sha256.Sum256(f.Data)
		sha := hex.EncodeToString(sum[:])
		if !strings.EqualFold(sha, e.SHA256) {
			return GeometryReport{}, fmt.Errorf("owner G34 SHA mismatch: %s", f.Path)
		}
		base := LegacyOverlayBase
		if f.Path == EXE {
			base = LegacyEXEBase
		}
		size := uint32(len(f.Data))
		if size > 0x200000 || base > 0xffffffff-size {
			return GeometryReport{}, errors.New("candidate mapping arithmetic overflow")
		}
		end := base + size
		source := GeometrySource{Path: f.Path, SourceSHA256: sha, ISOExtentLBA: f.LBA,
			ISOExtentSectors: (int64(len(f.Data)) + 2047) / 2048, FileBytes: len(f.Data),
			LegacyFileBase: fmt.Sprintf("0x%08X", base), LegacyFileEndExclusive: fmt.Sprintf("0x%08X", end),
			PSXExeSignature: len(f.Data) >= 8 && string(f.Data[:8]) == "PS-X EXE", SourceIdentityVerified: true,
			SelfJALExamples: []GeometrySelfCall{},
		}
		// Derive a bounded *static* indicator from MIPS JAL words. Do not
		// classify any word as certainly executable or a measured load call.
		for off := 0; off+4 <= len(f.Data); off += 4 {
			w := binary.LittleEndian.Uint32(f.Data[off:])
			if w>>26 != 3 {
				continue
			}
			target := uint32(0x80000000) | ((w & 0x3ffffff) << 2)
			if target < base || target >= end {
				continue
			}
			source.StaticSelfJALSites++
			if len(source.SelfJALExamples) < 5 {
				source.SelfJALExamples = append(source.SelfJALExamples, GeometrySelfCall{off, fmt.Sprintf("0x%08X", target)})
			}
		}
		report.Sources = append(report.Sources, source)
		report.StaticSelfJALSites += source.StaticSelfJALSites
		report.TotalBytes += int64(len(f.Data))
		if f.Path == EXE {
			main = end
		} else if end > overlayMax {
			overlayMax = end
		}
	}
	if len(seen) != len(expected) || main == 0 || overlayMax == 0 {
		return GeometryReport{}, errors.New("incomplete source coverage")
	}
	report.FilesVerified = len(seen)
	report.MainFileImageRange = fmt.Sprintf("[0x%08X,0x%08X)", LegacyEXEBase, main)
	report.OverlayFileImageRange = fmt.Sprintf("[0x%08X,0x%08X)", LegacyOverlayBase, overlayMax)
	report.RendererTailInsideMainFileHypothesis = LegacyEXEBase <= rendererTailFirst && rendererTailEnd <= main
	report.HypothesizedOverlayFileOverlapsRendererTail = LegacyOverlayBase < rendererTailEnd && rendererTailFirst < overlayMax
	sort.Slice(report.Sources, func(i, j int) bool { return report.Sources[i].Path < report.Sources[j].Path })
	return report, nil
}
