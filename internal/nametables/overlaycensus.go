package nametables

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// OverlayA_B_CWindow is the union of the original game surname scratch
// buffers (A/B/C); the runtime ownership of these addresses is NOT proven.
const (
	N10WindowStart uint32 = 0x800ca180
	N10WindowEnd   uint32 = 0x800ca1c0
)

// OverlayPointerEvidence is a possible *static* use, not proof of execution.
// Offset is relative to the start of the named disc file, never to the ISO.
// The scan includes false positives from data and can miss dynamically loaded
// addresses. Never use this as an automatic rewrite list.
type OverlayPointerEvidence struct {
	Offset       int    `json:"offset"`
	AnchorOffset int    `json:"anchor_offset,omitempty"`
	Address      uint32 `json:"address"`
	Type         string `json:"type"`
	Buffer       string `json:"buffer"`
}

type OverlaySourceCensus struct {
	Path                   string                   `json:"path"`
	Size                   int                      `json:"size"`
	Evidence               []OverlayPointerEvidence `json:"evidence"`
	DirectPairs            int                      `json:"direct_pairs"`
	DerivedCandidates      int                      `json:"derived_candidates"`
	AlignedPointerWords    int                      `json:"aligned_pointer_words"`
	StaticCandidates       int                      `json:"static_candidates"`
	CallerCoverageComplete bool                     `json:"caller_coverage_complete"`
	RuntimeSafe            bool                     `json:"runtime_safe"`
}

type OverlayDiscCensus struct {
	Status                     string                `json:"status"`
	Scope                      string                `json:"scope"`
	TotalFiles                 int                   `json:"total_files"`
	TotalBytes                 int64                 `json:"total_bytes"`
	SourcesWithCandidates      int                   `json:"sources_with_candidates"`
	OtherSourcesWithCandidates int                   `json:"other_sources_with_candidates"`
	CompleteDiscCodeCoverage   bool                  `json:"complete_disc_code_coverage"`
	SafeToRelocate             bool                  `json:"safe_to_relocate"`
	Sources                    []OverlaySourceCensus `json:"sources"`
	Limitations                []string              `json:"limitations"`
}

func N10BufferForAddress(addr uint32) string {
	switch {
	case addr >= 0x800ca188 && addr < 0x800ca190:
		return "A-or-adjacent"
	case addr >= 0x800ca190 && addr < 0x800ca19c:
		return "B-or-adjacent"
	case addr >= 0x800ca19c && addr < 0x800ca1c0:
		return "C-or-adjacent"
	default:
		return "adjacent-scratch-unknown"
	}
}

// N10DiscCodeCandidate confines enumeration to the original main EXE and
// executable overlay extensions. Other game code may be stored in differently
// named files, ROM data, RAM or overlays; the census is explicitly incomplete.
func N10DiscCodeCandidate(path string, isDir bool) bool {
	if isDir {
		return false
	}
	upper := strings.ToUpper(path)
	return upper == EXE || strings.HasSuffix(upper, ".EXN") || strings.HasSuffix(upper, ".EXE")
}

// ScanN10ExecutableSource combines simple LUI-derived pairs, bounded
// register-provenance candidates and aligned in-data pointer words. Inputs
// must be aligned MIPS file lengths. Repeated equivalent constructions are
// coalesced, but distinct *types* of evidence remain visible.
func ScanN10ExecutableSource(path string, data []byte) (OverlaySourceCensus, error) {
	if len(data) == 0 || len(data)%4 != 0 || len(data) > 16<<20 {
		return OverlaySourceCensus{}, fmt.Errorf("%s: invalid source size %d (must be aligned and <=16 MiB)", path, len(data))
	}
	direct, err := FindRAMReferences(data, N10WindowStart, N10WindowEnd)
	if err != nil {
		return OverlaySourceCensus{}, err
	}
	derived, err := FindDerivedLiteralReferences(data, N10WindowStart, N10WindowEnd, 32)
	if err != nil {
		return OverlaySourceCensus{}, err
	}
	s := OverlaySourceCensus{Path: path, Size: len(data), Evidence: make([]OverlayPointerEvidence, 0), DirectPairs: len(direct), DerivedCandidates: len(derived)}
	keys := map[string]bool{}
	add := func(offset, anchor int, addr uint32, kind string) {
		if offset < 0 || offset+4 > len(data) || offset%4 != 0 || addr < N10WindowStart || addr >= N10WindowEnd {
			return
		}
		k := fmt.Sprintf("%d/%d/%08x/%s", offset, anchor, addr, kind)
		if keys[k] {
			return
		}
		keys[k] = true
		s.Evidence = append(s.Evidence, OverlayPointerEvidence{Offset: offset, AnchorOffset: anchor, Address: addr, Type: kind, Buffer: N10BufferForAddress(addr)})
	}
	for _, x := range direct {
		add(x.UseOffset, x.UpperOffset, x.Address, "lui-"+x.Kind)
	}
	for _, x := range derived {
		add(x.UseOffset, x.AnchorOffset, x.Address, "register-derived-"+x.Action)
	}
	for off := 0; off+4 <= len(data); off += 4 {
		v := binary.LittleEndian.Uint32(data[off:])
		if v >= N10WindowStart && v < N10WindowEnd {
			s.AlignedPointerWords++
			add(off, off, v, "aligned-pointer-word")
		}
	}
	sort.Slice(s.Evidence, func(i, j int) bool {
		a, b := s.Evidence[i], s.Evidence[j]
		if a.Offset != b.Offset {
			return a.Offset < b.Offset
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Type < b.Type
	})
	// Bound memory and report size; do not silently truncate evidence and then
	// accidentally present an artificially low candidate count.
	if len(s.Evidence) > 16384 {
		return OverlaySourceCensus{}, fmt.Errorf("%s: too many static candidates (%d)", path, len(s.Evidence))
	}
	s.StaticCandidates = len(s.Evidence)
	return s, nil
}

// BuildN10DiscCensus constructs a deterministic fail-closed report from the
// caller's *complete* selected executable file set. Missing/read-failed files
// must be treated as errors by the disc reader, never omitted from the input.
func BuildN10DiscCensus(sources []OverlaySourceCensus) (OverlayDiscCensus, error) {
	if len(sources) == 0 {
		return OverlayDiscCensus{}, fmt.Errorf("empty executable source set")
	}
	out := OverlayDiscCensus{Status: "STATIC_OTHER_OVERLAY_A_B_C_CENSUS_NOT_GAMEPLAY_PROOF", Scope: "original EXE plus all ISO9660 files ending in .EXN/.EXE", Sources: append([]OverlaySourceCensus(nil), sources...), Limitations: []string{
		"Only ISO9660 file names selected by extension, not executable code embedded in other resources",
		"MIPS byte scans cannot distinguish code from data, or exhaust dynamic and indirect pointer propagation",
		"No overlay load/unload lifetimes, writable RAM ownership, BSS geometry, runtime strlen or display-fit evidence",
		"All source files must come from the owner-verified original disc; no N10 research candidate may be booted on this report",
	}}
	sort.Slice(out.Sources, func(i, j int) bool { return out.Sources[i].Path < out.Sources[j].Path })
	seen := map[string]bool{}
	main, geko := false, false
	for _, s := range out.Sources {
		if seen[s.Path] || !N10DiscCodeCandidate(s.Path, false) {
			return OverlayDiscCensus{}, fmt.Errorf("invalid or duplicate candidate file %q", s.Path)
		}
		seen[s.Path] = true
		if s.Path == EXE {
			main = true
		}
		if s.Path == Geko {
			geko = true
		}
		out.TotalFiles++
		out.TotalBytes += int64(s.Size)
		if s.StaticCandidates > 0 {
			out.SourcesWithCandidates++
			if s.Path != EXE && s.Path != Geko {
				out.OtherSourcesWithCandidates++
			}
		}
	}
	if !main || !geko {
		return OverlayDiscCensus{}, fmt.Errorf("original main EXE and GEKO must both be present (main=%v geko=%v)", main, geko)
	}
	return out, nil
}
