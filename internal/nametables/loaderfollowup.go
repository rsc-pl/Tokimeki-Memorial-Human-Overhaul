package nametables

// G38: read-only, source-bound follow-up to the actual owner G37 PS-X EXE
// report. Static bytes and ISO file extents are NOT observed runtime loader
// behavior, proof of free RAM/BSS, or authorization to boot an N10 patch.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const N10OddBinPath = "CDROM/EXEDIR/O.BIN"

type N10RawWordWindow struct {
	FileOffset int                  `json:"file_offset"`
	Kind       string               `json:"kind"`
	Target     string               `json:"target,omitempty"`
	Words      []OverlayContextWord `json:"words"`
}

type N10AddressRun struct {
	FirstFileOffset int    `json:"first_file_offset"`
	LastFileOffset  int    `json:"last_file_offset"`
	Count           int    `json:"count"`
	Stride20Pairs   int    `json:"adjacent_20_byte_steps"`
	Interpretation  string `json:"interpretation"`
}

type N10OddSite struct {
	FileOffset    int                  `json:"file_offset"`
	AnchorOffset  int                  `json:"anchor_offset"`
	Address       string               `json:"address"`
	EvidenceTypes []string             `json:"evidence_types"`
	Words         []OverlayContextWord `json:"words"`
}

type N10LoaderFollowupReport struct {
	Status                       string             `json:"status"`
	OwnerG37ReportSHA256         string             `json:"owner_g37_report_sha256"`
	OwnerOriginalEXESHA256       string             `json:"owner_original_exe_sha256"`
	OddBINPath                   string             `json:"odd_bin_path"`
	OddBINLBA                    int64              `json:"odd_bin_lba"`
	OddBINSize                   int                `json:"odd_bin_size"`
	OddBINSHA256                 string             `json:"odd_bin_sha256"`
	OddBINSignature              string             `json:"odd_bin_signature"`
	OddBINLooksLikePSXEXE        bool               `json:"odd_bin_looks_like_psx_exe"`
	OddBINStaticSelfJALCount     int                `json:"odd_bin_static_self_jal_count"`
	OddBINABCUniqueSites         int                `json:"odd_bin_abc_unique_sites"`
	OddBINCPlus64DirectSites     int                `json:"odd_bin_c_plus_64_direct_sites"`
	OddBINABCSites               []N10OddSite       `json:"odd_bin_abc_sites"`
	OddBINCPlus64Sites           []N10OddSite       `json:"odd_bin_c_plus_64_sites"`
	MainDirectOverlayJAL         []N10RawWordWindow `json:"main_direct_overlay_jal"`
	MainOverlayAddressPairs      []N10RawWordWindow `json:"main_overlay_address_pairs"`
	MainAddressPairRuns          []N10AddressRun    `json:"main_address_pair_runs"`
	OriginalSourcesVerified      bool               `json:"original_sources_verified"`
	FullControlFlowVerified      bool               `json:"full_control_flow_verified"`
	RuntimeLoaderVerified        bool               `json:"runtime_loader_verified"`
	BSSAndWritableMemoryVerified bool               `json:"bss_and_writable_memory_verified"`
	SafeToPatch                  bool               `json:"safe_to_patch"`
	Limitations                  []string           `json:"limitations"`
}

func oddWords(b []byte, center, left, right int) []OverlayContextWord {
	start := center - left*4
	if start < 0 {
		start = 0
	}
	end := center + (right+1)*4
	if end > len(b) {
		end = len(b)
	}
	out := make([]OverlayContextWord, 0, (end-start)/4)
	for p := start; p+4 <= end; p += 4 {
		out = append(out, OverlayContextWord{Offset: p, Hex: fmt.Sprintf("%08X", binary.LittleEndian.Uint32(b[p:])), Candidate: p == center})
	}
	return out
}

func scanMainOverlayAnchorOffsets(exe []byte) ([]N10StaticTarget, []N10StaticTarget) {
	var calls, pairs []N10StaticTarget
	u := func(off int) uint32 { return binary.LittleEndian.Uint32(exe[off:]) }
	for off := 0x800; off+4 <= len(exe); off += 4 {
		w := u(off)
		if w>>26 == 3 {
			target := uint32(0x80000000) | ((w & 0x03ffffff) << 2)
			if target >= LegacyOverlayBase && target < LegacyOverlayBase+0x30000 {
				calls = append(calls, N10StaticTarget{FileOffset: off, Target: fmt.Sprintf("0x%08X", target), Kind: "JAL-to-hypothetical-overlay-range"})
			}
		}
		if w>>26 != 0x0f || off+8 > len(exe) {
			continue
		}
		rt := (w >> 16) & 31
		next := u(off + 4)
		op, rs, dst := next>>26, (next>>21)&31, (next>>16)&31
		if (op != 0x09 && op != 0x0d) || rt != rs || rt != dst {
			continue
		}
		imm := uint32(next & 0xffff)
		if op == 0x09 && imm >= 0x8000 {
			imm -= 0x10000
		}
		addr := uint32((w&0xffff)<<16) + imm
		if addr >= LegacyOverlayBase && addr < LegacyOverlayBase+0x30000 {
			pairs = append(pairs, N10StaticTarget{FileOffset: off + 4, AnchorOffset: off, Target: fmt.Sprintf("0x%08X", addr), Kind: "adjacent-LUI-ADDIU-ORI"})
		}
	}
	return calls, pairs
}

func CheckN10FollowupInputs(g37 N10LoaderHeaderReport, g37sha string, exe, odd []byte, oddLBA int64) error {
	if len(g37sha) != 64 || g37.Status != "PSX_EXE_HEADER_AND_STATIC_MAIN_ANCHORS_ONLY_N10_DO_NOT_BOOT" ||
		!g37.OriginalSourceIdentityVerified || !g37.HeaderParsed || g37.SafeToPatch || g37.RuntimeLoaderVerified ||
		g37.RuntimeBSSClearVerified || g37.OverlayLifetimeVerified || g37.StaticDirectOverlayJALCount != 2 || g37.StaticOverlayAddressPairCount != 48 {
		return errors.New("G37 original-disc report provenance, count or safety flags not verified")
	}
	if len(exe) != 667648 || string(exe[:8]) != "PS-X EXE" || fmt.Sprintf("%x", sha256.Sum256(exe)) != g37.OriginalEXESHA256 || !strings.EqualFold(g37.OriginalEXESHA256, "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae") {
		return errors.New("original EXE identity mismatch")
	}
	if len(odd) != 196608 || oddLBA != 38474 || len(odd)%4 != 0 {
		return errors.New("O.BIN extent/size from retail ISO does not match owner G37")
	}
	found := false
	for _, s := range g37.ISOExtentsOverlappingGap {
		if s.Path == N10OddBinPath && s.LBA == 38474 && s.Sectors == 96 && s.Size == 196608 && !s.IsDirectory {
			found = true
		}
	}
	if !found {
		return errors.New("G37 did not attest O.BIN at LBA 38474")
	}
	return nil
}

// BuildN10LoaderFollowup is a static byte inspection of two verified files.
// Its reports are NEVER eligible as patch/ROM mutation inputs.
func BuildN10LoaderFollowup(g37 N10LoaderHeaderReport, g37sha string, exe, odd []byte, oddLBA int64) (N10LoaderFollowupReport, error) {
	if err := CheckN10FollowupInputs(g37, g37sha, exe, odd, oddLBA); err != nil {
		return N10LoaderFollowupReport{}, err
	}
	return buildN10LoaderFollowupVerified(g37, g37sha, exe, odd, oddLBA)
}

// Only test fixtures can call this branch without source authentication; real
// users always pass the strict BuildN10LoaderFollowup provenance gate above.
func buildN10LoaderFollowupVerified(g37 N10LoaderHeaderReport, g37sha string, exe, odd []byte, oddLBA int64) (N10LoaderFollowupReport, error) {
	calls, pairs := scanMainOverlayAnchorOffsets(exe)
	if len(calls) != 2 || len(pairs) != 48 {
		return N10LoaderFollowupReport{}, errors.New("main EXE static anchor census differs from G37")
	}
	for i, sample := range g37.StaticDirectOverlayJALExamples {
		if i >= len(calls) || sample.FileOffset != calls[i].FileOffset || sample.Target != calls[i].Target {
			return N10LoaderFollowupReport{}, errors.New("G37 static JAL example mismatch")
		}
	}
	for i, sample := range g37.StaticOverlayAddressPairExamples {
		if i >= len(pairs) || sample.FileOffset != pairs[i].FileOffset || sample.Target != pairs[i].Target || sample.AnchorOffset != pairs[i].AnchorOffset {
			return N10LoaderFollowupReport{}, errors.New("G37 static address pair example mismatch")
		}
	}
	report := N10LoaderFollowupReport{
		Status:               "G38_ORIGINAL_ODD_BIN_AND_MAIN_LOADER_ANCHORS_STATIC_ONLY_DO_NOT_BOOT",
		OwnerG37ReportSHA256: g37sha, OwnerOriginalEXESHA256: g37.OriginalEXESHA256,
		OddBINPath: N10OddBinPath, OddBINLBA: oddLBA, OddBINSize: len(odd),
		OddBINSHA256:          fmt.Sprintf("%x", sha256.Sum256(odd)),
		OddBINSignature:       fmt.Sprintf("%X", odd[:min(8, len(odd))]),
		OddBINLooksLikePSXEXE: string(odd[:8]) == "PS-X EXE",
		OddBINABCSites:        []N10OddSite{}, OddBINCPlus64Sites: []N10OddSite{},
		MainDirectOverlayJAL: []N10RawWordWindow{}, MainOverlayAddressPairs: []N10RawWordWindow{}, MainAddressPairRuns: []N10AddressRun{},
		OriginalSourcesVerified: true, FullControlFlowVerified: false, RuntimeLoaderVerified: false, BSSAndWritableMemoryVerified: false, SafeToPatch: false,
		Limitations: []string{
			"O.BIN is a 96-sector original-disc file omitted from the extension-filtered G31 executable inventory; its runtime purpose is not established",
			"Self-range JAL or A/B/C raw words in O.BIN can be data, not executed MIPS code; zero hits do not close indirect consumers",
			"G37 main code/anchor contexts are local windows, not a complete CFG or demonstrated loader implementation",
			"PS-X EXE BSS=0 is header metadata only; custom clear/heap/overlay initialization remain unmeasured",
			"No RAM write ownership, overlay lifetime, indirect alias, append bound, UI-fit or N10 patch approval is established",
		},
	}
	for _, c := range calls {
		report.MainDirectOverlayJAL = append(report.MainDirectOverlayJAL, N10RawWordWindow{FileOffset: c.FileOffset, Kind: c.Kind, Target: c.Target, Words: oddWords(exe, c.FileOffset, 16, 28)})
	}
	for _, p := range pairs {
		report.MainOverlayAddressPairs = append(report.MainOverlayAddressPairs, N10RawWordWindow{FileOffset: p.FileOffset, Kind: p.Kind, Target: p.Target, Words: oddWords(exe, p.FileOffset, 8, 12)})
	}
	// Runs are structural clustering, not an assertion that the bytes form a
	// dispatch/loader table. 20-byte spacing is only a pattern to investigate.
	for i := 0; i < len(pairs); {
		j := i + 1
		steps := 0
		for j < len(pairs) && pairs[j].FileOffset-pairs[j-1].FileOffset <= 36 {
			if pairs[j].FileOffset-pairs[j-1].FileOffset == 20 {
				steps++
			}
			j++
		}
		if j-i >= 3 {
			report.MainAddressPairRuns = append(report.MainAddressPairRuns, N10AddressRun{FirstFileOffset: pairs[i].FileOffset, LastFileOffset: pairs[j-1].FileOffset, Count: j - i, Stride20Pairs: steps, Interpretation: "structural-cluster-possible-table-or-code-not-proven"})
		}
		i = j
	}
	oddCensus, err := ScanN10ExecutableSource(N10OddBinPath, odd)
	if err != nil {
		return N10LoaderFollowupReport{}, err
	}
	type siteKey struct {
		off, anchor int
		addr        uint32
	}
	sites := map[siteKey]map[string]bool{}
	for _, e := range oddCensus.Evidence {
		key := siteKey{e.Offset, e.AnchorOffset, e.Address}
		if sites[key] == nil {
			sites[key] = map[string]bool{}
		}
		sites[key][e.Type] = true
	}
	keys := make([]siteKey, 0, len(sites))
	for k := range sites {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].off != keys[j].off {
			return keys[i].off < keys[j].off
		}
		return keys[i].addr < keys[j].addr
	})
	for _, k := range keys {
		types := make([]string, 0, len(sites[k]))
		for t := range sites[k] {
			types = append(types, t)
		}
		sort.Strings(types)
		report.OddBINABCSites = append(report.OddBINABCSites, N10OddSite{FileOffset: k.off, AnchorOffset: k.anchor, Address: fmt.Sprintf("0x%08X", k.addr), EvidenceTypes: types, Words: oddWords(odd, k.off, 8, 16)})
	}
	report.OddBINABCUniqueSites = len(keys)
	// The exact adjacent region omitted by G31 is a second separate scan.
	cplus, err := FindRAMReferences(odd, 0x800CA1DC, 0x800CA1E0)
	if err != nil {
		return N10LoaderFollowupReport{}, err
	}
	seenPlus := map[string]bool{}
	for _, p := range cplus {
		k := fmt.Sprintf("%d/%d/%08x", p.UseOffset, p.UpperOffset, p.Address)
		if seenPlus[k] {
			continue
		}
		seenPlus[k] = true
		report.OddBINCPlus64Sites = append(report.OddBINCPlus64Sites, N10OddSite{FileOffset: p.UseOffset, AnchorOffset: p.UpperOffset, Address: fmt.Sprintf("0x%08X", p.Address), EvidenceTypes: []string{"lui-" + p.Kind}, Words: oddWords(odd, p.UseOffset, 8, 16)})
	}
	report.OddBINCPlus64DirectSites = len(report.OddBINCPlus64Sites)
	for off := 0; off+4 <= len(odd); off += 4 {
		w := binary.LittleEndian.Uint32(odd[off:])
		if w>>26 == 3 {
			target := uint32(0x80000000) | ((w & 0x03ffffff) << 2)
			if target >= LegacyOverlayBase && target < LegacyOverlayBase+0x30000 {
				report.OddBINStaticSelfJALCount++
			}
		}
	}
	return report, nil
}
