package nametables

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
)

// OverlayContextWord is a *raw* MIPS-aligned file word, not a disassembled
// instruction or evidence that the bytes are ever executed.
type OverlayContextWord struct {
	Offset    int    `json:"offset"`
	Hex       string `json:"hex"`
	Anchor    bool   `json:"anchor,omitempty"`
	Candidate bool   `json:"candidate,omitempty"`
}

type OverlayContextSite struct {
	Path          string               `json:"path"`
	Offset        int                  `json:"offset"`
	AnchorOffset  int                  `json:"anchor_offset"`
	Address       uint32               `json:"address"`
	Buffer        string               `json:"buffer"`
	EvidenceTypes []string             `json:"evidence_types"`
	Words         []OverlayContextWord `json:"words"`
}

type OverlayContextSource struct {
	Path        string `json:"path"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	UniqueSites int    `json:"unique_sites"`
}

type OverlayContextReport struct {
	Status                   string                 `json:"status"`
	CensusSHA256             string                 `json:"census_sha256"`
	VerifiedAgainstFreshScan bool                   `json:"verified_against_fresh_scan"`
	Sources                  []OverlayContextSource `json:"sources"`
	UniqueSites              int                    `json:"unique_sites"`
	OtherOverlayUniqueSites  int                    `json:"other_overlay_unique_sites"`
	UniqueByAddress          map[string]int         `json:"unique_by_address"`
	Sites                    []OverlayContextSite   `json:"sites"`
	CallerCoverageComplete   bool                   `json:"caller_coverage_complete"`
	RuntimeSafe              bool                   `json:"runtime_safe"`
	Limitations              []string               `json:"limitations"`
}

// BuildN10OverlayContext checks the exact source census against a fresh byte
// scan before exposing any bounded, per-site context. A duplicate detection
// method at the same file offset/address appears only once in the result.
// File reads, main/GEKO retail hash checks and safe output paths are the CLI's
// responsibility. This function never alters its inputs.
func BuildN10OverlayContext(census OverlayDiscCensus, censusBytes []byte, sources map[string][]byte) (OverlayContextReport, error) {
	if census.Status != "STATIC_OTHER_OVERLAY_A_B_C_CENSUS_NOT_GAMEPLAY_PROOF" ||
		census.SafeToRelocate || census.CompleteDiscCodeCoverage || census.TotalFiles != len(census.Sources) ||
		census.TotalFiles != len(sources) || census.TotalFiles == 0 {
		return OverlayContextReport{}, fmt.Errorf("invalid or unsafe/stale G31 census header")
	}
	fresh := make([]OverlaySourceCensus, 0, len(sources))
	for path, buf := range sources {
		s, err := ScanN10ExecutableSource(path, buf)
		if err != nil {
			return OverlayContextReport{}, err
		}
		fresh = append(fresh, s)
	}
	rebuilt, err := BuildN10DiscCensus(fresh)
	if err != nil {
		return OverlayContextReport{}, err
	}
	// All offsets, evidence types and per-file totals must match, not merely
	// the aggregate candidate counts. Refuse mutated or incompatible input.
	if !reflect.DeepEqual(census, rebuilt) {
		return OverlayContextReport{}, fmt.Errorf("G31 census differs from a fresh scan of the supplied original executables")
	}
	h := sha256.Sum256(censusBytes)
	out := OverlayContextReport{
		Status: "STATIC_MIPS_CONTEXT_REVIEW_ONLY_DO_NOT_BOOT", CensusSHA256: hex.EncodeToString(h[:]),
		VerifiedAgainstFreshScan: true, Sources: make([]OverlayContextSource, 0, len(rebuilt.Sources)),
		UniqueByAddress: map[string]int{}, Sites: []OverlayContextSite{},
		CallerCoverageComplete: false, RuntimeSafe: false,
		Limitations: []string{
			"Raw aligned words only: bytes may be data, not instructions; no full control-flow analysis",
			"Context windows do not prove a read, write, buffer length, pointer lifetime, residency or BSS ownership",
			"Indirect pointers, code stored outside .EXN/.EXE, overlays loaded later and UI text fit remain unknown",
			"All surname patch candidates remain HOLD/DO_NOT_BOOT; do not rewrite any addresses using this output",
		},
	}
	for _, source := range rebuilt.Sources {
		buf := sources[source.Path]
		sum := sha256.Sum256(buf)
		src := OverlayContextSource{Path: source.Path, Size: len(buf), SHA256: hex.EncodeToString(sum[:])}
		type key struct {
			off, anchor int
			addr        uint32
		}
		grouped := map[key]map[string]bool{}
		for _, e := range source.Evidence {
			k := key{e.Offset, e.AnchorOffset, e.Address}
			if grouped[k] == nil {
				grouped[k] = map[string]bool{}
			}
			grouped[k][e.Type] = true
		}
		keys := make([]key, 0, len(grouped))
		for k := range grouped {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			if a.off != b.off {
				return a.off < b.off
			}
			if a.addr != b.addr {
				return a.addr < b.addr
			}
			return a.anchor < b.anchor
		})
		for _, k := range keys {
			types := make([]string, 0, len(grouped[k]))
			for t := range grouped[k] {
				types = append(types, t)
			}
			sort.Strings(types)
			start := k.anchor - 8*4
			if start < 0 {
				start = 0
			}
			end := k.off + 17*4 // candidate plus 16 following words
			if end > len(buf) {
				end = len(buf)
			}
			// The old analyzer bounds LUI-to-use at 32 instructions; cap
			// context as an additional guard against unexpected input changes.
			if end-start > 180 {
				return OverlayContextReport{}, fmt.Errorf("unexpectedly wide MIPS context in %s at %#x", source.Path, k.off)
			}
			words := make([]OverlayContextWord, 0, (end-start)/4)
			for p := start; p+4 <= end; p += 4 {
				v := binary.LittleEndian.Uint32(buf[p:])
				words = append(words, OverlayContextWord{Offset: p, Hex: fmt.Sprintf("%08X", v), Anchor: p == k.anchor, Candidate: p == k.off})
			}
			out.Sites = append(out.Sites, OverlayContextSite{Path: source.Path, Offset: k.off, AnchorOffset: k.anchor,
				Address: k.addr, Buffer: N10BufferForAddress(k.addr), EvidenceTypes: types, Words: words})
			src.UniqueSites++
			out.UniqueSites++
			out.UniqueByAddress[fmt.Sprintf("0x%08X", k.addr)]++
			if source.Path != EXE && source.Path != Geko {
				out.OtherOverlayUniqueSites++
			}
		}
		out.Sources = append(out.Sources, src)
	}
	return out, nil
}
