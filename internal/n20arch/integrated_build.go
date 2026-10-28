package n20arch

// N20 integrated private build (offline only).
//
// This file is the single consolidated planner for the N20 prototype. It
// composes, in one in-memory plan:
//
//   (a) the rebuilt packed romanizer (inside both module bodies),
//   (b) the N6 overlay-local speaker module (3 carriers, 136 callsites),
//   (c) the N6-FP overlay-local field-prep module with the relocated 12-byte
//       shim (14 carriers, 235 callsites, family 0x8012B500, given 0x8012B510,
//       gate v0<12, all-or-nothing fallback),
//   (d) all 15 EXE relocation pairs (30 words) and all 6 overlay relocation
//       pairs (12 words) in private copies,
//   (e) integrity guards, retail fallback and a complete per-word manifest.
//
// The planner fails closed. It cannot return success without exactly 15 EXE
// pairs, exactly 6 overlay pairs, the two v0<12 gates and an exact byte-delta
// audit against the authenticated originals. The EXE is no longer untouched:
// it carries 30 relocation words and zero entry hooks. That distinction is
// explicit in the manifest and in every consumer of this plan.
//
// No file, image, save, emulator or guest memory is written. safe_to_patch
// remains false and runtime_pass remains false.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// N20ManifestWord is one changed 32-bit instruction word in the integrated
// build. PC is the loaded address; Old is the authenticated original word.
type N20ManifestWord struct {
	Owner  string `json:"owner"`
	PC     uint32 `json:"pc"`
	Old    uint32 `json:"old"`
	New    uint32 `json:"new"`
	Kind   string `json:"kind"`
	Role   string `json:"role"`
	Reason string `json:"reason"`
}

// N20ManifestRegion is one contiguous payload range installed into a formerly
// zero overlay window. It is byte-accounted by length and SHA-256 rather than
// expanded into thousands of unchanged-zero words.
type N20ManifestRegion struct {
	Owner   string `json:"owner"`
	RAMAddr uint32 `json:"ram_addr"`
	FileOff int    `json:"file_off"`
	Bytes   int    `json:"bytes"`
	SHA256  string `json:"sha256"`
	Kind    string `json:"kind"`
	Role    string `json:"role"`
	Reason  string `json:"reason"`
}

// N20GateProof records the relocated slot gate found in the actual shim bytes.
type N20GateProof struct {
	SlotBytes      int      `json:"slot_bytes"`
	GateWord       uint32   `json:"gate_word"`
	Count          int      `json:"count"`
	PCs            []uint32 `json:"pcs"`
	AcceptsV0      int      `json:"accepts_v0_inclusive_max"`
	RejectsV0      int      `json:"rejects_v0"`
	EightByteGates int      `json:"eight_byte_gates"`
	AllOrNothing   bool     `json:"all_or_nothing"`
	DestinationLUI []uint32 `json:"destination_lui_words"`
}

// N20ChangeAccounting replaces the misleading "EXE changed words = 0" label.
// The N6/N6-FP entry-hook count really is zero, but the integrated EXE changes
// 30 relocation words. Both facts are stated separately and a legacy field is
// kept only with an explicit label for older readers.
type N20ChangeAccounting struct {
	EXEEntryHooks          int    `json:"exe_entry_hooks"`
	EXERelocationPairs     int    `json:"exe_relocation_pairs"`
	EXERelocationWords     int    `json:"exe_relocation_words"`
	OverlayRelocationPairs int    `json:"overlay_relocation_pairs"`
	OverlayRelocationWords int    `json:"overlay_relocation_words"`
	OverlayCallsiteN6      int    `json:"overlay_callsite_words_n6"`
	OverlayCallsiteN6FP    int    `json:"overlay_callsite_words_n6fp"`
	OverlayCallsiteWords   int    `json:"overlay_callsite_words"`
	OverlayChangedWords    int    `json:"overlay_changed_words_total"`
	PayloadGuardBytes      int    `json:"payload_guard_bytes"`
	PayloadBodyBytes       int    `json:"payload_body_bytes"`
	PayloadRegions         int    `json:"payload_regions"`
	TotalEXEChangedWords   int    `json:"total_exe_changed_words"`
	LegacyEXEChangedWords  int    `json:"legacy_exe_changed_words"`
	LegacyLabel            string `json:"legacy_exe_changed_words_label"`
}

// N20IntegrityProof is the machine-checkable source/destination and pair
// coverage proof carried by the manifest.
type N20IntegrityProof struct {
	SourceEXESHA     string            `json:"source_exe_sha256"`
	SourceOverlays   map[string]string `json:"source_overlay_sha256"`
	DestEXESHA       string            `json:"dest_exe_sha256"`
	DestOverlays     map[string]string `json:"dest_overlay_sha256"`
	OverlayChecksums map[string]uint16 `json:"dest_overlay_checksum"`
	EXEPairs         int               `json:"exe_pairs"`
	EXEWords         int               `json:"exe_words"`
	OverlayPairs     int               `json:"overlay_pairs"`
	OverlayWords     int               `json:"overlay_words"`
	Gate             N20GateProof      `json:"gate"`
	FallbackTargets  map[string]string `json:"retail_fallback_targets"`
	VerifierFailJR   map[string]int    `json:"verifier_fail_jr_t4_count"`
	RomanizerCode    int               `json:"romanizer_code_bytes"`
	RomanizerTable   int               `json:"romanizer_table_bytes"`
	RomanizerProgram int               `json:"romanizer_program_bytes"`
	RomanizerSHA     string            `json:"romanizer_sha256"`
	RomanizerInBoth  bool              `json:"romanizer_in_both_bodies"`
	DeltaAuditPassed bool              `json:"delta_audit_passed"`
}

// N20RelocWriterRef is one static writer/initializer site relevant to the
// relocated destination.
type N20RelocWriterRef struct {
	Owner string `json:"owner"`
	PC    uint32 `json:"pc"`
	Field string `json:"field"`
	Kind  string `json:"kind"`
	Role  string `json:"role"`
}

// N20RelocReclearCall records one candidate bulk-clear call and whether its
// static destination range could be resolved.
type N20RelocReclearCall struct {
	Owner       string `json:"owner"`
	PC          uint32 `json:"pc"`
	A0          uint32 `json:"a0"`
	A1          uint32 `json:"a1"`
	End         uint32 `json:"end"`
	Known       bool   `json:"range_resolved"`
	A0Source    string `json:"address_source"`
	A1Source    string `json:"length_source"`
	InitialOnly bool   `json:"file_initial_state_only"`
	Hit         bool   `json:"overlaps_destination"`

	// Source-level resolution detail. Bounded means the static union of the
	// call's destinations is [RangeLo,RangeHi) even when a single invocation
	// clears A1 bytes. TableSlot records the authenticated file-backed
	// pointer word a stack/register argument was loaded from.
	Bounded      bool   `json:"bounded_range"`
	RangeLo      uint32 `json:"range_lo"`
	RangeHi      uint32 `json:"range_hi"`
	TableSlot    uint32 `json:"table_slot,omitempty"`
	Resolution   string `json:"resolution,omitempty"`
	StaticImmune bool   `json:"table_static_immutable,omitempty"`
}

// N20RelocOwnershipAudit is the destination-ownership re-audit required by the
// integration step. It enumerates what static bytes permit and explicitly
// rejects the claim that zero static references prove exclusive runtime
// ownership.
type N20RelocOwnershipAudit struct {
	FamilyAddr       uint32 `json:"family_addr"`
	GivenAddr        uint32 `json:"given_addr"`
	SlotBytes        int    `json:"slot_bytes"`
	BootBSSStart     uint32 `json:"boot_bss_start"`
	BootBSSEnd       uint32 `json:"boot_bss_end"`
	BootCleared      bool   `json:"boot_cleared"`
	OverlaySlotBase  uint32 `json:"overlay_slot_base"`
	BelowOverlaySlot bool   `json:"below_overlay_slot"`
	StackTop         uint32 `json:"stack_top"`
	HeapStart        uint32 `json:"heap_start"`
	StackDistance    uint32 `json:"stack_distance_bytes"`
	HeapDistance     uint32 `json:"heap_distance_bytes"`

	Writers              []N20RelocWriterRef `json:"writers"`
	WriterSites          int                 `json:"writer_sites"`
	ShimWriterCarriers   int                 `json:"shim_writer_carriers"`
	ShimWriterLoops      int                 `json:"shim_writer_copy_loops"`
	StaticDirectWriters  int                 `json:"static_direct_writers_to_destination"`
	ExplicitInitializers int                 `json:"explicit_initializers"`
	IndirectOnlyWriters  bool                `json:"only_indirect_shim_and_redirected_writers"`

	ReclearCalls         int                   `json:"bulk_clear_calls"`
	ReclearResolved      int                   `json:"bulk_clear_ranges_resolved"`
	ReclearUnresolved    int                   `json:"bulk_clear_ranges_unresolved"`
	ReclearOverlaps      int                   `json:"bulk_clear_overlaps"`
	NoPostFieldprepRec   bool                  `json:"no_post_fieldprep_reclear_found"`
	ReclearInitialOnly   int                   `json:"bulk_clear_file_initialized_pointers"`
	KnownPostbootOverlap int                   `json:"known_postboot_overlapping_clears"`
	UnknownRuntimeRanges int                   `json:"bulk_clear_runtime_ranges_not_proven"`
	ReclearDetail        []N20RelocReclearCall `json:"bulk_clear_calls_detail"`

	TTTableBase          uint32   `json:"tt_table_base"`
	TTTableEnd           uint32   `json:"tt_table_end"`
	TTTableStaticWriters int      `json:"tt_table_static_writers"`
	TTTableWriterPCs     []uint32 `json:"tt_table_writer_pcs"`
	TTTableVerdict       string   `json:"tt_table_verdict"`

	ExclusiveRuntimeOwnershipProven bool     `json:"exclusive_runtime_ownership_proven"`
	Blocker                         string   `json:"blocker"`
	Unknowns                        []string `json:"unknowns"`
}

// N20BuildManifest is the complete, machine-checkable integrated manifest.
type N20BuildManifest struct {
	Schema           int                    `json:"schema"`
	Verdict          string                 `json:"verdict"`
	SafeToPatch      bool                   `json:"safe_to_patch"`
	RuntimePass      bool                   `json:"runtime_pass"`
	Architecture     string                 `json:"architecture"`
	FamilyAddr       uint32                 `json:"family_addr"`
	GivenAddr        uint32                 `json:"given_addr"`
	SlotBytes        int                    `json:"slot_bytes"`
	GuardGapBytes    int                    `json:"guard_gap_bytes"`
	MaxInputKana     int                    `json:"max_input_kana"`
	SourceFieldBytes int                    `json:"source_field_bytes"`
	Carriers         int                    `json:"carriers"`
	UntouchedOverlay int                    `json:"untouched_overlays"`
	PatchedOverlays  []string               `json:"patched_overlays"`
	Accounting       N20ChangeAccounting    `json:"change_accounting"`
	Integrity        N20IntegrityProof      `json:"integrity"`
	Safety           N20RelocOwnershipAudit `json:"safety"`
	Words            []N20ManifestWord      `json:"words"`
	Regions          []N20ManifestRegion    `json:"payload_regions"`
	BlockedRoutes    []string               `json:"blocked_routes"`
	Missing          []string               `json:"missing"`
	RuntimeBlockers  []string               `json:"runtime_blockers"`
}

// N20IntegratedPlan is the single private in-memory build plan.
type N20IntegratedPlan struct {
	PatchedEXE      []byte            `json:"-"`
	PatchedOverlays map[string][]byte `json:"-"`

	N6        OverlayLocalPlan `json:"-"`
	FieldPrep N20RelocPlan     `json:"-"`

	Manifest    N20BuildManifest `json:"manifest"`
	Verdict     string           `json:"verdict"`
	SafeToPatch bool             `json:"safe_to_patch"`
	RuntimePass bool             `json:"runtime_pass"`
}

// PlanIntegratedN20Build composes every required N20 modification into one
// offline plan and verifies it before returning. Any missing overlay, any
// relocation mismatch, any missing pair, any checksum failure, any unplanned
// delta or a missing v0<12 gate is a hard error (fail closed).
func PlanIntegratedN20Build(exe []byte, overlays map[string][]byte) (N20IntegratedPlan, error) {
	var p N20IntegratedPlan
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return p, fmt.Errorf("unrecognised original EXE")
	}
	if len(overlays) != len(OverlaySHA) {
		return p, fmt.Errorf("need all %d original overlays, got %d", len(OverlaySHA), len(overlays))
	}
	for name, want := range OverlaySHA {
		d, ok := overlays[name]
		if !ok {
			return p, fmt.Errorf("missing overlay %s", name)
		}
		if len(d) != 196608 || sha(d) != want {
			return p, fmt.Errorf("overlay %s is not the authenticated original", name)
		}
	}

	n6Sites, err := ScanOverlayCallsites(overlays)
	if err != nil {
		return p, err
	}
	n6, err := PlanOverlayLocal(overlays, n6Sites)
	if err != nil {
		return p, err
	}
	fpSites, err := ScanOverlayFieldPrepCallsites(overlays)
	if err != nil {
		return p, err
	}
	fp, err := PlanN20Relocation(exe, overlays, fpSites)
	if err != nil {
		return p, err
	}

	// Compose one final image set. N6 and N6-FP carriers are proven disjoint
	// by PlanOverlayFieldPrep; refuse any overlap rather than pick a winner.
	patched := map[string][]byte{}
	for name, d := range overlays {
		patched[name] = d
	}
	for name, d := range n6.Patched {
		if _, ok := patched[name]; !ok {
			return p, fmt.Errorf("N6 patched unknown overlay %s", name)
		}
		patched[name] = d
	}
	for name, d := range fp.PatchedOverlay {
		if _, ok := n6.Patched[name]; ok {
			return p, fmt.Errorf("carrier %s carries both N6 and N6-FP", name)
		}
		if _, ok := patched[name]; !ok {
			return p, fmt.Errorf("N6-FP patched unknown overlay %s", name)
		}
		patched[name] = d
	}

	p.PatchedEXE = fp.PatchedEXE
	p.PatchedOverlays = patched
	p.N6 = n6
	p.FieldPrep = fp
	p.SafeToPatch = false
	p.RuntimePass = false
	p.Verdict = "INTEGRATED OFFLINE"

	m, err := buildN20BuildManifest(exe, overlays, n6, fp)
	if err != nil {
		return p, err
	}
	p.Manifest = m

	if err := verifyN20IntegratedBuild(exe, overlays, &p); err != nil {
		return p, err
	}
	return p, nil
}

func buildN20BuildManifest(exe []byte, overlays map[string][]byte,
	n6 OverlayLocalPlan, fp N20RelocPlan) (N20BuildManifest, error) {
	var m N20BuildManifest
	m.Schema = 2
	m.Verdict = "INTEGRATED OFFLINE"
	m.SafeToPatch = false
	m.RuntimePass = false
	m.Architecture = "N6 speaker guard+body plus N6-FP relocated 12-byte fieldprep guard+body, " +
		"same overlay-slot lifetime, 30 private EXE relocation words, zero EXE entry hooks"

	gate, err := n20RelocGateProof(fp.Module)
	if err != nil {
		return m, err
	}
	m.FamilyAddr, m.GivenAddr = N20RelocFamilyAddr, N20RelocGivenAddr
	m.SlotBytes, m.GuardGapBytes = N20RelocSlotBytes, N20RelocGuardGap
	m.MaxInputKana = 3
	m.SourceFieldBytes = 8

	romanizer, err := BuildN20PackedRomanizer(OLBodyBase)
	if err != nil {
		return m, err
	}
	m.Integrity.RomanizerCode = romanizer.CodeBytes
	m.Integrity.RomanizerTable = romanizer.TableBytes
	m.Integrity.RomanizerProgram = romanizer.ProgramBytes
	m.Integrity.RomanizerSHA = romanizer.TableSHA
	m.Integrity.RomanizerInBoth = bytes.HasPrefix(n6.Module.Body, romanizer.Binary) &&
		bytes.HasPrefix(fp.Module.Body, romanizer.Binary)
	if !m.Integrity.RomanizerInBoth {
		return m, fmt.Errorf("rebuilt romanizer is not the leading body bytes in both modules")
	}

	// Per-word manifest: 30 EXE relocation + 12 overlay relocation + 371
	// overlay callsite JAL retargets.
	for _, w := range fp.EXEWords {
		m.Words = append(m.Words, N20ManifestWord{
			Owner: "EXE", PC: w.PC, Old: w.Old, New: w.New, Kind: w.Kind,
			Role:   w.Role,
			Reason: "redirect the authenticated EXE materialisation to the relocated 12-byte field at 0x8012B500/0x8012B510",
		})
	}
	for _, w := range fp.OverlayWords {
		m.Words = append(m.Words, N20ManifestWord{
			Owner: w.Owner, PC: w.PC, Old: w.Old, New: w.New, Kind: w.Kind,
			Role:   w.Role,
			Reason: "redirect the authenticated overlay family materialisation to the same relocated field; retail write order preserved",
		})
	}

	n6Calls, fpCalls := 0, 0
	for _, name := range sortedKeys(n6.SitesByOverlay) {
		for _, cs := range n6.SitesByOverlay[name] {
			old := binary.LittleEndian.Uint32(overlays[name][cs.FileOff:])
			m.Words = append(m.Words, N20ManifestWord{
				Owner: name, PC: cs.PC, Old: old, New: jalWord(OLStubRAM), Kind: "jal",
				Role:   "N6 speaker surname callsite",
				Reason: "same-overlay JAL retarget from retail 0x80050dfc to guard 0x80160e10; delay slot preserved",
			})
			n6Calls++
		}
	}
	for _, name := range sortedKeys(fp.FieldPrep.SitesByOverlay) {
		for _, cs := range fp.FieldPrep.SitesByOverlay[name] {
			old := binary.LittleEndian.Uint32(overlays[name][cs.FileOff:])
			m.Words = append(m.Words, N20ManifestWord{
				Owner: name, PC: cs.PC, Old: old, New: jalWord(OLStubRAM), Kind: "jal",
				Role:   "N6-FP relocated fieldprep callsite",
				Reason: "same-overlay JAL retarget from retail 0x800847b8 to guard 0x80160e10; retail is called first by the shim; delay slot preserved",
			})
			fpCalls++
		}
	}
	sort.Slice(m.Words, func(i, j int) bool {
		if m.Words[i].Owner == m.Words[j].Owner {
			return m.Words[i].PC < m.Words[j].PC
		}
		return m.Words[i].Owner < m.Words[j].Owner
	})

	// Payload guard/body regions, accounted by length and SHA.
	for _, name := range sortedKeys(patchedModuleMap(n6, fp)) {
		mod, isN6 := patchedModuleFor(name, n6, fp)
		if mod == nil {
			continue
		}
		kind := "N6-FP relocated"
		if isN6 {
			kind = "N6"
		}
		m.Regions = append(m.Regions,
			N20ManifestRegion{
				Owner: name, RAMAddr: OLGuardBase, FileOff: OLPayloadFileOff,
				Bytes: len(mod.Guard), SHA256: sha(mod.Guard), Kind: "guard",
				Role:   kind + " guard",
				Reason: "magic/length/sum32/xor32 header, stub and verifier installed in the authenticated all-zero payload window",
			},
			N20ManifestRegion{
				Owner: name, RAMAddr: OLBodyBase, FileOff: OLBodyFileOff,
				Bytes: len(mod.Body), SHA256: sha(mod.Body), Kind: "body",
				Role:   kind + " body",
				Reason: "rebuilt packed romanizer plus the class shim; verified by the same guard before entry",
			})
	}

	guardBytes, bodyBytes := 0, 0
	for _, r := range m.Regions {
		if r.Kind == "guard" {
			guardBytes += r.Bytes
		} else {
			bodyBytes += r.Bytes
		}
	}

	m.PatchedOverlays = sortedKeys(patchedModuleMap(n6, fp))
	m.Carriers = len(m.PatchedOverlays)
	m.UntouchedOverlay = len(overlays) - m.Carriers

	m.Accounting = N20ChangeAccounting{
		EXEEntryHooks:          0,
		EXERelocationPairs:     len(n20RelocEXEPairs),
		EXERelocationWords:     len(fp.EXEWords),
		OverlayRelocationPairs: len(n20RelocOverlayPairs),
		OverlayRelocationWords: len(fp.OverlayWords),
		OverlayCallsiteN6:      n6Calls,
		OverlayCallsiteN6FP:    fpCalls,
		OverlayCallsiteWords:   n6Calls + fpCalls,
		OverlayChangedWords:    len(fp.OverlayWords) + n6Calls + fpCalls,
		PayloadGuardBytes:      guardBytes,
		PayloadBodyBytes:       bodyBytes,
		PayloadRegions:         len(m.Regions),
		TotalEXEChangedWords:   len(fp.EXEWords),
		LegacyEXEChangedWords:  0,
		LegacyLabel:            "legacy N6/N6-FP entry-hook count only; NOT total EXE changes (30 relocation words are applied)",
	}

	m.Integrity.SourceEXESHA = OriginalEXESHA
	m.Integrity.SourceOverlays = map[string]string{}
	m.Integrity.DestOverlays = map[string]string{}
	m.Integrity.OverlayChecksums = map[string]uint16{}
	for name := range overlays {
		m.Integrity.SourceOverlays[name] = OverlaySHA[name]
	}
	m.Integrity.EXEPairs = len(n20RelocEXEPairs)
	m.Integrity.EXEWords = len(fp.EXEWords)
	m.Integrity.OverlayPairs = len(n20RelocOverlayPairs)
	m.Integrity.OverlayWords = len(fp.OverlayWords)
	m.Integrity.Gate = gate
	m.Integrity.FallbackTargets = map[string]string{
		"N6":    fmt.Sprintf("0x%08x", OLOriginalSpeaker),
		"N6-FP": fmt.Sprintf("0x%08x", OLFieldPrepOriginal),
	}
	m.Integrity.VerifierFailJR = map[string]int{
		"N6":    n20CountJR12(n6.Module.Guard),
		"N6-FP": n20CountJR12(fp.Module.Guard),
	}

	m.BlockedRoutes = []string{
		"renderer P 0x800CA17C via EXE 0x80051508 (kanji name table, not dynamically kana-romanizable)",
		"renderer G 0x800CA190 via EXE 0x80051438 (kanji name table, not dynamically kana-romanizable)",
		"working string 0x800CA188 (suffix table)",
		"EXE-owned speaker callsites (16) still require an EXE entry hook, which this plan refuses",
		"formatter A-D, san, alternate parser and previous version #44/#53 remain retail",
		"honourifics are script-literal; generic queue 0x80081DC8 is never hooked",
	}
	m.Missing = []string{
		"no patched-image or emulator run",
		"no saved-game or whole-execution stack low-water measurement",
		"no proof that every fieldprep callsite reaches a rendered line in game",
	}
	m.RuntimeBlockers = []string{
		"dynamic pointer/DMA/IRQ/save-restore access to 0x8012B500..0x8012B52F is not disprovable offline",
		"loader atomicity is a 16-bit checksum filter, not an atomic DMA/cache barrier",
		"interrupt/cache/DMA concurrency is not modelled by Machine",
		"whole-game stack low-water with IRQs is unmeasured",
		"retail/N20 write order between duplicate overlay writers and the fieldprep shim is not runtime-proven",
	}
	return m, nil
}

// verifyN20IntegratedBuild independently re-derives every expected change and
// proves the returned bytes contain nothing else. It fails closed on a missing,
// duplicate or conflicting manifest record.
func verifyN20IntegratedBuild(exe []byte, overlays map[string][]byte, p *N20IntegratedPlan) error {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return fmt.Errorf("verify: unrecognised original EXE")
	}
	if len(overlays) != len(OverlaySHA) {
		return fmt.Errorf("verify: missing overlays")
	}
	if len(p.PatchedOverlays) != len(OverlaySHA) {
		return fmt.Errorf("verify: final overlay set has %d entries", len(p.PatchedOverlays))
	}

	// 1. Recompute expected instruction words from authenticated bytes.
	var expected []N20ManifestWord
	_, exeWords, err := PatchN20RelocEXE(exe)
	if err != nil {
		return fmt.Errorf("verify: EXE relocation source: %w", err)
	}
	if len(exeWords) != 30 {
		return fmt.Errorf("verify: EXE relocation produced %d words, want 30", len(exeWords))
	}
	for _, w := range exeWords {
		expected = append(expected, N20ManifestWord{Owner: "EXE", PC: w.PC, Old: w.Old,
			New: w.New, Kind: w.Kind, Role: w.Role,
			Reason: "redirect the authenticated EXE materialisation to the relocated 12-byte field at 0x8012B500/0x8012B510"})
	}
	ovSets, err := n20RelocOverlayWordSets(overlays)
	if err != nil {
		return fmt.Errorf("verify: overlay relocation source: %w", err)
	}
	totalOverlayReloc := 0
	for _, name := range sortedKeys(ovSets) {
		for _, w := range ovSets[name] {
			totalOverlayReloc++
			expected = append(expected, N20ManifestWord{Owner: name, PC: w.PC, Old: w.Old,
				New: w.New, Kind: w.Kind, Role: w.Role,
				Reason: "redirect the authenticated overlay family materialisation to the same relocated field; retail write order preserved"})
		}
	}
	if totalOverlayReloc != 12 {
		return fmt.Errorf("verify: overlay relocation produced %d words, want 12", totalOverlayReloc)
	}

	n6Sites, err := ScanOverlayCallsites(overlays)
	if err != nil {
		return fmt.Errorf("verify: N6 scan: %w", err)
	}
	n6Calls := 0
	for _, cs := range n6Sites {
		if !cs.NameRoute {
			continue
		}
		old := binary.LittleEndian.Uint32(overlays[cs.Overlay][cs.FileOff:])
		if old != jalWord(cs.Target) {
			return fmt.Errorf("verify: N6 callsite %s+0x%x is not the authenticated JAL", cs.Overlay, cs.FileOff)
		}
		expected = append(expected, N20ManifestWord{Owner: cs.Overlay, PC: cs.PC, Old: old,
			New: jalWord(OLStubRAM), Kind: "jal", Role: "N6 speaker surname callsite",
			Reason: "same-overlay JAL retarget from retail 0x80050dfc to guard 0x80160e10; delay slot preserved"})
		n6Calls++
	}
	fpSites, err := ScanOverlayFieldPrepCallsites(overlays)
	if err != nil {
		return fmt.Errorf("verify: N6-FP scan: %w", err)
	}
	fpCalls := 0
	for _, cs := range fpSites {
		old := binary.LittleEndian.Uint32(overlays[cs.Overlay][cs.FileOff:])
		if old != jalWord(OLFieldPrepOriginal) {
			return fmt.Errorf("verify: N6-FP callsite %s+0x%x is not the authenticated JAL", cs.Overlay, cs.FileOff)
		}
		expected = append(expected, N20ManifestWord{Owner: cs.Overlay, PC: cs.PC, Old: old,
			New: jalWord(OLStubRAM), Kind: "jal", Role: "N6-FP relocated fieldprep callsite",
			Reason: "same-overlay JAL retarget from retail 0x800847b8 to guard 0x80160e10; retail is called first by the shim; delay slot preserved"})
		fpCalls++
	}
	if n6Calls != 136 || fpCalls != 235 {
		return fmt.Errorf("verify: callsite coverage drifted: N6=%d N6-FP=%d, want 136/235", n6Calls, fpCalls)
	}

	// 2. Manifest must contain exactly this set: no missing, duplicate or
	// conflicting record. A duplicate PC with a different new word is a
	// conflict; a duplicate identical record is also refused because it
	// would double-count a patch.
	expKey := map[string]N20ManifestWord{}
	for _, w := range expected {
		key := fmt.Sprintf("%s|%08x", w.Owner, w.PC)
		if _, ok := expKey[key]; ok {
			return fmt.Errorf("verify: expected duplicate patch record %s", key)
		}
		expKey[key] = w
	}
	gotKey := map[string]N20ManifestWord{}
	for _, w := range p.Manifest.Words {
		key := fmt.Sprintf("%s|%08x", w.Owner, w.PC)
		if prev, ok := gotKey[key]; ok {
			if prev.New != w.New || prev.Old != w.Old {
				return fmt.Errorf("verify: conflicting patch records for %s", key)
			}
			return fmt.Errorf("verify: duplicate patch record %s", key)
		}
		gotKey[key] = w
		if _, ok := expKey[key]; !ok {
			return fmt.Errorf("verify: unplanned manifest word %s", key)
		}
	}
	if len(gotKey) != len(expKey) {
		for key := range expKey {
			if _, ok := gotKey[key]; !ok {
				return fmt.Errorf("verify: manifest is missing required patch record %s", key)
			}
		}
		return fmt.Errorf("verify: manifest word count %d want %d", len(gotKey), len(expKey))
	}
	for key, want := range expKey {
		got := gotKey[key]
		if got.Old != want.Old || got.New != want.New || got.Kind != want.Kind {
			return fmt.Errorf("verify: patch record %s is %08x->%08x kind %s, want %08x->%08x kind %s",
				key, got.Old, got.New, got.Kind, want.Old, want.New, want.Kind)
		}
	}

	// 3. Pair coverage: every LUI/ADDIU pair must be present and resolve to
	// the relocated field.
	exePairSeen := 0
	for _, pair := range n20RelocEXEPairs {
		target := N20RelocFamilyAddr
		if pair.Field == "given" {
			target = N20RelocGivenAddr
		}
		if err := n20VerifyManifestPair(gotKey, "EXE", pair, target); err != nil {
			return err
		}
		exePairSeen++
	}
	ovPairSeen := 0
	for _, pair := range n20RelocOverlayPairs {
		owner := n20RelocOverlayOwner(pair.ADDIU)
		if err := n20VerifyManifestPair(gotKey, owner, pair, N20RelocFamilyAddr); err != nil {
			return err
		}
		ovPairSeen++
	}
	if exePairSeen != 15 || ovPairSeen != 6 {
		return fmt.Errorf("verify: pair coverage %d/%d want 15/6", exePairSeen, ovPairSeen)
	}

	// 4. Gate proof must be present in the actual relocated shim.
	gate, err := n20RelocGateProof(p.FieldPrep.Module)
	if err != nil {
		return err
	}
	if gate.Count != 2 || gate.EightByteGates != 0 || gate.AcceptsV0 != 11 || gate.RejectsV0 != 12 {
		return fmt.Errorf("verify: gate proof %+v", gate)
	}
	if gate.SlotBytes != N20RelocSlotBytes {
		return fmt.Errorf("verify: gate slot %d", gate.SlotBytes)
	}
	p.Manifest.Integrity.Gate = gate
	if n20CountJR12(p.N6.Module.Guard) != 1 || n20CountJR12(p.FieldPrep.Module.Guard) != 1 {
		return fmt.Errorf("verify: retail fallback jr t4 missing from a module")
	}
	p.Manifest.Integrity.VerifierFailJR = map[string]int{
		"N6":    n20CountJR12(p.N6.Module.Guard),
		"N6-FP": n20CountJR12(p.FieldPrep.Module.Guard),
	}
	romanizer, err := BuildN20PackedRomanizer(OLBodyBase)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(p.N6.Module.Body, romanizer.Binary) ||
		!bytes.HasPrefix(p.FieldPrep.Module.Body, romanizer.Binary) {
		return fmt.Errorf("verify: rebuilt romanizer is not the leading body bytes in both modules")
	}
	p.Manifest.Integrity.RomanizerCode = romanizer.CodeBytes
	p.Manifest.Integrity.RomanizerTable = romanizer.TableBytes
	p.Manifest.Integrity.RomanizerProgram = romanizer.ProgramBytes
	p.Manifest.Integrity.RomanizerSHA = romanizer.TableSHA
	p.Manifest.Integrity.RomanizerInBoth = true
	p.Manifest.MaxInputKana = 3
	p.Manifest.SourceFieldBytes = 8

	// 5. Rebuild every final overlay from the authenticated original and the
	// verified word/region records, then require byte identity.
	n6Names := map[string]bool{}
	for n := range p.N6.Patched {
		n6Names[n] = true
	}
	fpNames := map[string]bool{}
	for n := range p.FieldPrep.PatchedOverlay {
		fpNames[n] = true
	}
	if len(n6Names) != 3 || len(fpNames) != 14 {
		return fmt.Errorf("verify: carrier families %d/%d want 3/14", len(n6Names), len(fpNames))
	}
	for n := range n6Names {
		if fpNames[n] {
			return fmt.Errorf("verify: carrier %s in both families", n)
		}
	}

	for _, name := range sortedKeys(overlays) {
		src := overlays[name]
		if len(src) != 196608 || sha(src) != OverlaySHA[name] {
			return fmt.Errorf("verify: overlay %s source drift", name)
		}
		d := bytes.Clone(src)
		changedWords := map[int]bool{}
		for _, w := range p.Manifest.Words {
			if w.Owner != name {
				continue
			}
			off := int(w.PC - OverlaySlotBase)
			if off < 0 || off+4 > len(d) {
				return fmt.Errorf("verify: %s word %08x outside image", name, w.PC)
			}
			if binary.LittleEndian.Uint32(d[off:]) != w.Old {
				return fmt.Errorf("verify: %s %08x old word drift", name, w.PC)
			}
			binary.LittleEndian.PutUint32(d[off:], w.New)
			changedWords[off] = true
		}
		hasModule := n6Names[name] || fpNames[name]
		var mod OverlayFieldPrepModule
		if n6Names[name] {
			// OverlayLocalModule and OverlayFieldPrepModule share the same
			// guard/body/verifier layout for the fields used here.
			mod.Guard, mod.Body, mod.Sum32, mod.XOR32 = p.N6.Module.Guard, p.N6.Module.Body, p.N6.Module.Sum32, p.N6.Module.XOR32
		} else if fpNames[name] {
			mod = p.FieldPrep.Module
		}
		for _, r := range p.Manifest.Regions {
			if r.Owner != name {
				continue
			}
			var b []byte
			switch r.Kind {
			case "guard":
				b = mod.Guard
			case "body":
				b = mod.Body
			default:
				return fmt.Errorf("verify: %s unknown region kind %s", name, r.Kind)
			}
			if len(b) != r.Bytes || sha(b) != r.SHA256 {
				return fmt.Errorf("verify: %s region %s geometry/SHA drift", name, r.Kind)
			}
			if r.FileOff < 0 || r.FileOff+len(b) > len(d) {
				return fmt.Errorf("verify: %s region %s outside image", name, r.Kind)
			}
			if !allZero(src[r.FileOff : r.FileOff+len(b)]) {
				return fmt.Errorf("verify: %s region %s was not zero in retail", name, r.Kind)
			}
			copy(d[r.FileOff:r.FileOff+len(b)], b)
		}
		if hasModule {
			ck := packedTableChecksum(d)
			d[0x2FFFC] = byte(ck >> 8)
			d[0x2FFFD] = byte(ck)
			if packedTableChecksum(d) != binary.BigEndian.Uint16(d[0x2FFFC:]) {
				return fmt.Errorf("verify: %s checksum does not validate", name)
			}
			// Guard integrity read back from the final bytes.
			if binary.LittleEndian.Uint32(d[OLPayloadFileOff:]) != binary.LittleEndian.Uint32(mod.Guard[:4]) {
				return fmt.Errorf("verify: %s guard magic not installed", name)
			}
			body := d[OLBodyFileOff : OLBodyFileOff+len(mod.Body)]
			if sha(body) != sha(mod.Body) {
				return fmt.Errorf("verify: %s body drift", name)
			}
		} else if !bytes.Equal(d, src) {
			return fmt.Errorf("verify: untouched overlay %s changed", name)
		}
		dest, ok := p.PatchedOverlays[name]
		if !ok || !bytes.Equal(dest, d) {
			return fmt.Errorf("verify: final bytes for %s differ from the verified reconstruction", name)
		}
		p.Manifest.Integrity.DestOverlays[name] = sha(dest)
		p.Manifest.Integrity.OverlayChecksums[name] = binary.BigEndian.Uint16(dest[0x2FFFC:])
	}
	p.Manifest.Integrity.DestEXESHA = sha(p.PatchedEXE)

	// 6. EXE reconstruction: exactly the 30 manifest words, nothing else.
	expectedEXE := bytes.Clone(exe)
	exeChanged := 0
	for _, w := range p.Manifest.Words {
		if w.Owner != "EXE" {
			continue
		}
		off := int(w.PC - 0x80040800)
		if off < 0 || off+4 > len(expectedEXE) {
			return fmt.Errorf("verify: EXE word %08x outside file", w.PC)
		}
		if binary.LittleEndian.Uint32(expectedEXE[off:]) != w.Old {
			return fmt.Errorf("verify: EXE %08x old word drift", w.PC)
		}
		binary.LittleEndian.PutUint32(expectedEXE[off:], w.New)
		exeChanged++
	}
	if exeChanged != 30 {
		return fmt.Errorf("verify: %d EXE manifest words, want 30", exeChanged)
	}
	if !bytes.Equal(expectedEXE, p.PatchedEXE) {
		return fmt.Errorf("verify: patched EXE differs from the verified reconstruction")
	}
	for i := 0; i < len(exe); i += 4 {
		if binary.LittleEndian.Uint32(expectedEXE[i:]) != binary.LittleEndian.Uint32(exe[i:]) {
			pc := uint32(i) + 0x80040800
			if _, ok := gotKey[fmt.Sprintf("EXE|%08x", pc)]; !ok {
				return fmt.Errorf("verify: unplanned EXE delta at %08x", pc)
			}
		}
	}

	// 7. Accounting and safety must match the verified records.
	acc := p.Manifest.Accounting
	if acc.EXEEntryHooks != 0 || acc.EXERelocationPairs != 15 || acc.EXERelocationWords != 30 ||
		acc.OverlayRelocationPairs != 6 || acc.OverlayRelocationWords != 12 ||
		acc.OverlayCallsiteN6 != 136 || acc.OverlayCallsiteN6FP != 235 ||
		acc.OverlayCallsiteWords != 371 || acc.TotalEXEChangedWords != 30 ||
		acc.LegacyEXEChangedWords != 0 {
		return fmt.Errorf("verify: change accounting %+v", acc)
	}
	if acc.PayloadRegions != len(p.Manifest.Regions) || acc.PayloadRegions != 34 {
		return fmt.Errorf("verify: payload region accounting %d", acc.PayloadRegions)
	}
	safety, err := AuditN20RelocOwnership(exe, overlays)
	if err != nil {
		return err
	}
	if !safety.BootCleared || !safety.BelowOverlaySlot ||
		safety.KnownPostbootOverlap != 0 || safety.ExclusiveRuntimeOwnershipProven {
		return fmt.Errorf("verify: destination ownership audit is not acceptable: %+v", safety)
	}
	p.Manifest.Safety = safety

	// 8. Manifest self-consistency. Steps 1-7 re-derive the bytes; this step
	// proves the manifest's own summary fields cannot be mutated, truncated or
	// left stale while the plan still returns success. It is the planner-bypass
	// gate: a caller cannot drop a carrier, a region, an accounting byte, a SHA
	// or a fallback target from the manifest and still get a valid plan.
	union := map[string]bool{}
	for n := range n6Names {
		union[n] = true
	}
	for n := range fpNames {
		union[n] = true
	}
	wantCarriers := sortedKeys(union)
	if !n20SameStrings(p.Manifest.PatchedOverlays, wantCarriers) {
		return fmt.Errorf("verify: manifest patched overlay set %v want %v", p.Manifest.PatchedOverlays, wantCarriers)
	}
	if p.Manifest.Carriers != len(wantCarriers) || p.Manifest.UntouchedOverlay != len(overlays)-len(wantCarriers) {
		return fmt.Errorf("verify: manifest carrier summary %d/%d want %d/%d",
			p.Manifest.Carriers, p.Manifest.UntouchedOverlay, len(wantCarriers), len(overlays)-len(wantCarriers))
	}
	if p.Manifest.Schema != 2 || p.Manifest.Verdict != "INTEGRATED OFFLINE" ||
		p.Manifest.SafeToPatch || p.Manifest.RuntimePass {
		return fmt.Errorf("verify: manifest header %+v", p.Manifest)
	}
	if p.Manifest.FamilyAddr != N20RelocFamilyAddr || p.Manifest.GivenAddr != N20RelocGivenAddr ||
		p.Manifest.SlotBytes != N20RelocSlotBytes || p.Manifest.GuardGapBytes != N20RelocGuardGap ||
		p.Manifest.MaxInputKana != 3 || p.Manifest.SourceFieldBytes != 8 {
		return fmt.Errorf("verify: manifest geometry/limit drift")
	}

	// Every carrier has exactly one guard and one body region; the 34 records
	// are unique and byte-identical to the built module bytes.
	type regionKey struct{ owner, kind string }
	wantRegions := map[regionKey]N20ManifestRegion{}
	guardBytes, bodyBytes := 0, 0
	for _, name := range wantCarriers {
		mod, _ := patchedModuleFor(name, p.N6, p.FieldPrep)
		if mod == nil {
			return fmt.Errorf("verify: carrier %s has no built module", name)
		}
		wantRegions[regionKey{name, "guard"}] = N20ManifestRegion{
			Owner: name, RAMAddr: OLGuardBase, FileOff: OLPayloadFileOff,
			Bytes: len(mod.Guard), SHA256: sha(mod.Guard), Kind: "guard",
		}
		wantRegions[regionKey{name, "body"}] = N20ManifestRegion{
			Owner: name, RAMAddr: OLBodyBase, FileOff: OLBodyFileOff,
			Bytes: len(mod.Body), SHA256: sha(mod.Body), Kind: "body",
		}
		guardBytes += len(mod.Guard)
		bodyBytes += len(mod.Body)
	}
	if len(p.Manifest.Regions) != len(wantRegions) || len(wantRegions) != 34 {
		return fmt.Errorf("verify: region records %d want %d", len(p.Manifest.Regions), len(wantRegions))
	}
	gotRegions := map[regionKey]N20ManifestRegion{}
	for _, r := range p.Manifest.Regions {
		k := regionKey{r.Owner, r.Kind}
		if _, ok := gotRegions[k]; ok {
			return fmt.Errorf("verify: duplicate region %s/%s", r.Owner, r.Kind)
		}
		gotRegions[k] = r
		if r.Role == "" || r.Reason == "" {
			return fmt.Errorf("verify: region %s/%s missing role/reason", r.Owner, r.Kind)
		}
	}
	for k, want := range wantRegions {
		got, ok := gotRegions[k]
		if !ok {
			return fmt.Errorf("verify: missing region %s/%s", k.owner, k.kind)
		}
		if got.RAMAddr != want.RAMAddr || got.FileOff != want.FileOff ||
			got.Bytes != want.Bytes || got.SHA256 != want.SHA256 {
			return fmt.Errorf("verify: region %s/%s geometry/SHA drift", k.owner, k.kind)
		}
	}
	for k := range gotRegions {
		if _, ok := wantRegions[k]; !ok {
			return fmt.Errorf("verify: unplanned region %s/%s", k.owner, k.kind)
		}
	}
	if acc.PayloadGuardBytes != guardBytes || acc.PayloadBodyBytes != bodyBytes ||
		acc.PayloadRegions != len(wantRegions) {
		return fmt.Errorf("verify: payload accounting %d/%d/%d want %d/%d/%d",
			acc.PayloadGuardBytes, acc.PayloadBodyBytes, acc.PayloadRegions,
			guardBytes, bodyBytes, len(wantRegions))
	}

	// Integrity maps must cover exactly the authenticated set; a missing key
	// would otherwise leave an overlay unaccounted.
	if len(p.Manifest.Integrity.SourceOverlays) != len(OverlaySHA) ||
		len(p.Manifest.Integrity.DestOverlays) != len(OverlaySHA) ||
		len(p.Manifest.Integrity.OverlayChecksums) != len(OverlaySHA) {
		return fmt.Errorf("verify: integrity map coverage %d/%d/%d want %d",
			len(p.Manifest.Integrity.SourceOverlays), len(p.Manifest.Integrity.DestOverlays),
			len(p.Manifest.Integrity.OverlayChecksums), len(OverlaySHA))
	}
	for name, want := range OverlaySHA {
		if got, ok := p.Manifest.Integrity.SourceOverlays[name]; !ok || got != want {
			return fmt.Errorf("verify: source SHA record %s", name)
		}
		if got, ok := p.Manifest.Integrity.DestOverlays[name]; !ok || got != sha(p.PatchedOverlays[name]) {
			return fmt.Errorf("verify: destination SHA record %s", name)
		}
		if got, ok := p.Manifest.Integrity.OverlayChecksums[name]; !ok ||
			got != binary.BigEndian.Uint16(p.PatchedOverlays[name][0x2FFFC:]) {
			return fmt.Errorf("verify: checksum record %s", name)
		}
	}
	for name := range p.Manifest.Integrity.SourceOverlays {
		if _, ok := OverlaySHA[name]; !ok {
			return fmt.Errorf("verify: unexpected source SHA key %s", name)
		}
	}
	if p.Manifest.Integrity.EXEPairs != 15 || p.Manifest.Integrity.EXEWords != 30 ||
		p.Manifest.Integrity.OverlayPairs != 6 || p.Manifest.Integrity.OverlayWords != 12 {
		return fmt.Errorf("verify: integrity pair counts %+v", p.Manifest.Integrity)
	}
	wantFallback := map[string]string{
		"N6":    fmt.Sprintf("0x%08x", OLOriginalSpeaker),
		"N6-FP": fmt.Sprintf("0x%08x", OLFieldPrepOriginal),
	}
	if len(p.Manifest.Integrity.FallbackTargets) != len(wantFallback) {
		return fmt.Errorf("verify: fallback target count %d", len(p.Manifest.Integrity.FallbackTargets))
	}
	for k, want := range wantFallback {
		if got := p.Manifest.Integrity.FallbackTargets[k]; got != want {
			return fmt.Errorf("verify: fallback target %s=%q want %q", k, got, want)
		}
	}
	if p.Manifest.Integrity.VerifierFailJR["N6"] != 1 ||
		p.Manifest.Integrity.VerifierFailJR["N6-FP"] != 1 {
		return fmt.Errorf("verify: verifier fallback counts %v", p.Manifest.Integrity.VerifierFailJR)
	}
	if len(p.Manifest.BlockedRoutes) == 0 || len(p.Manifest.Missing) == 0 ||
		len(p.Manifest.RuntimeBlockers) < 5 {
		return fmt.Errorf("verify: blocked/missing/runtime blocker lists are incomplete")
	}

	// The composed map must be exactly the two component plans, so a caller
	// cannot substitute a hand-built overlay after validation.
	for name, d := range p.N6.Patched {
		if !bytes.Equal(p.PatchedOverlays[name], d) {
			return fmt.Errorf("verify: N6 carrier %s differs from its component plan", name)
		}
	}
	for name, d := range p.FieldPrep.PatchedOverlay {
		if !bytes.Equal(p.PatchedOverlays[name], d) {
			return fmt.Errorf("verify: N6-FP carrier %s differs from its component plan", name)
		}
	}

	p.Manifest.Integrity.DeltaAuditPassed = true
	p.Manifest.Verdict = "INTEGRATED OFFLINE"
	p.Manifest.SafeToPatch = false
	p.Manifest.RuntimePass = false
	return nil
}

// n20SameStrings compares two string slices as sorted sets.
func n20SameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func n20VerifyManifestPair(got map[string]N20ManifestWord, owner string, pair n20RelocPair, target uint32) error {
	lui, ok := got[fmt.Sprintf("%s|%08x", owner, pair.LUI)]
	if !ok {
		return fmt.Errorf("verify: missing LUI record %s %08x", owner, pair.LUI)
	}
	add, ok := got[fmt.Sprintf("%s|%08x", owner, pair.ADDIU)]
	if !ok {
		return fmt.Errorf("verify: missing ADDIU record %s %08x", owner, pair.ADDIU)
	}
	if lui.New != n20RelocLUIWord(lui.Old, target) {
		return fmt.Errorf("verify: %s %08x LUI does not target %08x", owner, pair.LUI, target)
	}
	if add.New != n20RelocADDIUWord(add.Old, target) {
		return fmt.Errorf("verify: %s %08x ADDIU does not target %08x", owner, pair.ADDIU, target)
	}
	resolved := uint32(lui.New&0xFFFF)<<16 + uint32(int32(int16(add.New&0xFFFF)))
	if resolved != target {
		return fmt.Errorf("verify: %s %08x/%08x resolves %08x want %08x", owner, pair.LUI, pair.ADDIU, resolved, target)
	}
	return nil
}

func n20RelocGateProof(m OverlayFieldPrepModule) (N20GateProof, error) {
	var g N20GateProof
	g.SlotBytes = m.SlotBytes
	g.GateWord = 0x2C410000 | uint32(m.SlotBytes)
	g.AcceptsV0 = m.SlotBytes - 1
	g.RejectsV0 = m.SlotBytes
	g.AllOrNothing = true
	if m.ShimBodyRAM < OLBodyBase || int(m.ShimBodyRAM-OLBodyBase) >= len(m.Body) {
		return g, fmt.Errorf("gate: shim outside body")
	}
	shim := m.Body[int(m.ShimBodyRAM-OLBodyBase):]
	for i := 0; i+4 <= len(shim); i += 4 {
		w := binary.LittleEndian.Uint32(shim[i:])
		if w == g.GateWord {
			g.PCs = append(g.PCs, m.ShimBodyRAM+uint32(i))
		}
		if w == 0x2C410000|8 {
			g.EightByteGates++
		}
	}
	g.Count = len(g.PCs)
	if g.Count != 2 || g.EightByteGates != 0 {
		return g, fmt.Errorf("gate: found %d slot-%d gates and %d slot-8 gates, want 2/0",
			g.Count, m.SlotBytes, g.EightByteGates)
	}
	for _, a := range []uint32{N20RelocFamilyAddr, N20RelocGivenAddr} {
		pair := words(olLUI(10, a), olORI(10, 10, a&0xFFFF))
		if !bytes.Contains(shim, pair) {
			return g, fmt.Errorf("gate: destination LUI/ORI pair for %08x missing", a)
		}
		g.DestinationLUI = append(g.DestinationLUI, olLUI(10, a))
	}
	return g, nil
}

// AuditN20RelocOwnership re-audits the destination as far as static bytes
// permit. It enumerates the writers/initializers, the boot clear, candidate
// post-boot bulk clears, overlay-slot non-interference and stack/heap distance.
// It deliberately keeps exclusive runtime ownership UNPROVEN.
func AuditN20RelocOwnership(exe []byte, overlays map[string][]byte) (N20RelocOwnershipAudit, error) {
	var a N20RelocOwnershipAudit
	a.FamilyAddr, a.GivenAddr = N20RelocFamilyAddr, N20RelocGivenAddr
	a.SlotBytes = N20RelocSlotBytes
	a.BootBSSStart, a.BootBSSEnd = BootBSSStart, BootBSSEnd
	a.OverlaySlotBase, a.StackTop, a.HeapStart = OverlaySlotBase, StackTop, OriginalHeapStart
	a.BootCleared = N20RelocFamilyAddr >= BootBSSStart &&
		N20RelocGivenAddr+N20RelocSlotBytes <= BootBSSEnd
	a.BelowOverlaySlot = N20RelocGivenAddr+N20RelocSlotBytes <= OverlaySlotBase
	if StackTop > N20RelocGivenAddr+N20RelocSlotBytes {
		a.StackDistance = StackTop - (N20RelocGivenAddr + N20RelocSlotBytes)
	}
	if OriginalHeapStart > N20RelocGivenAddr+N20RelocSlotBytes {
		a.HeapDistance = OriginalHeapStart - (N20RelocGivenAddr + N20RelocSlotBytes)
	}

	// Writers: the retail fieldprep writer (2 sites, redirected to the new
	// fields), the N6-FP shim copy loops (one per carrier) and the four
	// authenticated overlay duplicate family writers. Each site is enumerated
	// from the authenticated pair table, not from prose.
	for _, pair := range n20RelocEXEPairs {
		switch pair.ADDIU {
		case 0x800847D4:
			a.Writers = append(a.Writers, N20RelocWriterRef{"EXE", pair.ADDIU, "family", "fieldprep_retail_writer", pair.Role})
		case 0x800847E8:
			a.Writers = append(a.Writers, N20RelocWriterRef{"EXE", pair.ADDIU, "given", "fieldprep_retail_writer", pair.Role})
		}
	}
	for _, pair := range n20RelocOverlayPairs {
		if pair.ADDIU == 0x80133B88 || pair.ADDIU == 0x80133BA0 {
			continue // consumers, not writers
		}
		a.Writers = append(a.Writers, N20RelocWriterRef{n20RelocOverlayOwner(pair.ADDIU), pair.ADDIU,
			"family", "overlay_duplicate_writer", pair.Role})
	}
	a.WriterSites = len(a.Writers)
	// The 14 carrier shim copy loops are indirect (pointer in registers), so
	// there is no direct static store instruction to the destination.
	fpSites, err := ScanOverlayFieldPrepCallsites(overlays)
	if err != nil {
		return a, err
	}
	carriers := map[string]bool{}
	for _, s := range fpSites {
		carriers[s.Overlay] = true
	}
	a.ShimWriterCarriers = len(carriers)
	a.ShimWriterLoops = 2 * len(carriers) // family and given copy loops per carrier
	a.StaticDirectWriters = 0
	a.ExplicitInitializers = 0
	a.IndirectOnlyWriters = true

	// TT.EXN keeps a file-backed pointer table at 0x80158A60..0x80158A80.
	// Enumerate decoded static stores into those 4-byte entries; the three
	// 16-bit writes to 0x80158A5C are a different field and are not counted.
	a.TTTableBase, a.TTTableEnd = n20TTTableBase, n20TTTableEnd
	a.TTTableWriterPCs = append(a.TTTableWriterPCs, n20TTTableStaticWriters(exe, 0x80040800)...)
	for _, name := range sortedKeys(overlays) {
		a.TTTableWriterPCs = append(a.TTTableWriterPCs, n20TTTableStaticWriters(overlays[name], OverlaySlotBase)...)
	}
	a.TTTableStaticWriters = len(a.TTTableWriterPCs)
	if a.TTTableStaticWriters == 0 {
		a.TTTableVerdict = "no decoded static store into 0x80158A60..0x80158AB8 (22 file-backed pointer words; 19 feed bzero calls); only 16-bit 0x80158A5C writes exist; DMA/IRQ/indirect writers remain unmodelled"
	} else {
		a.TTTableVerdict = "decoded static writers exist; table not statically immutable"
	}

	// Candidate bulk clears: every jal to the BIOS A0 wrapper used by the boot
	// clear. Resolve a0/a1 statically where possible and check overlap.
	check := func(owner string, d []byte, base uint32) error {
		for i := 0; i+4 <= len(d); i += 4 {
			w := binary.LittleEndian.Uint32(d[i:])
			if w>>26 != 0x03 || ((w&0x03FFFFFF)<<2|0x80000000) != 0x800AE080 {
				continue
			}
			pc := base + uint32(i)
			a.ReclearCalls++
			arg0, arg1 := n20BSSClearArguments(d, base, i)
			c := N20RelocReclearCall{Owner: owner, PC: pc, A0: arg0.Value, A1: arg1.Value,
				A0Source: arg0.Source, A1Source: arg1.Source}
			if t, ok := n20TargetedBSSClear(d, base, i); ok {
				c.A0, c.A1, c.A0Source, c.A1Source = t.A0, t.A1, t.AddrSource, "literal"
				c.RangeLo, c.RangeHi, c.Bounded = t.RangeLo, t.RangeHi, t.Bounded
				c.TableSlot, c.Resolution = t.TableSlot, t.Resolution
				if t.TableSlot != 0 {
					c.StaticImmune = a.TTTableStaticWriters == 0
				}
			}
			c.Known = c.A0Source == "literal" && c.A1Source == "literal"
			c.InitialOnly = c.A0Source == "file_initialized_pointer" && c.A1Source == "literal"
			if c.Known || c.InitialOnly {
				c.End = c.A0 + c.A1
				if c.Bounded {
					c.End = c.RangeHi
				}
				if c.End < c.A0 {
					return fmt.Errorf("bulk clear range overflow at %08x", pc)
				}
				if c.InitialOnly {
					a.ReclearInitialOnly++
				} else {
					a.ReclearResolved++
				}
				lo, hi := c.A0, c.End
				if c.Bounded {
					lo, hi = c.RangeLo, c.RangeHi
				}
				if lo < N20RelocGivenAddr+N20RelocSlotBytes && hi > N20RelocFamilyAddr {
					c.Hit = true
					a.ReclearOverlaps++
					if c.Known && c.PC != 0x80042108 {
						a.KnownPostbootOverlap++
					}
				}
			} else {
				a.ReclearUnresolved++
			}

			a.ReclearDetail = append(a.ReclearDetail, c)
		}
		return nil
	}
	if err := check("EXE", exe, 0x80040800); err != nil {
		return a, err
	}
	for _, name := range sortedKeys(overlays) {
		if err := check(name, overlays[name], OverlaySlotBase); err != nil {
			return a, err
		}
	}
	// Legacy boolean is now strictly PROOF-oriented: UNKNOWN != SAFE.
	// Even an initialized-pointer table is mutable at runtime, and any genuinely
	// unresolved destination/length prevents proving no later reclear.
	a.UnknownRuntimeRanges = a.ReclearUnresolved + a.ReclearInitialOnly
	a.NoPostFieldprepRec = a.KnownPostbootOverlap == 0 && a.UnknownRuntimeRanges == 0

	a.ExclusiveRuntimeOwnershipProven = false
	a.Blocker = "runtime BSS ownership NOT PROVEN: file-initialized pointer tables can change if an unmodelled runtime writer/DMA/ISR exists; indirect stores, save/restore and whole-game lifetime remain; absence of a known overlapping call is not proof of exclusivity"
	a.Unknowns = []string{
		"the four previously unresolved sites are now source-resolved (one bounded loop union, three stack slots loaded from the file-backed TT table), but table values remain initial-state evidence only",
		"TT 0x80158A60..0x80158A80 has no decoded static 32-bit writer (only 16-bit 0x80158A5C writes); DMA/IRQ/indirect writers are unmodelled",
		"dynamic pointer / DMA / IRQ / save-restore access to the relocated range is not disprovable offline",
		"the loader is checksum-gated, not atomic; torn CD load is unmodelled",
		"interrupt/cache/DMA concurrency is not modelled by Machine",
		"whole-game stack low-water with IRQs is unmeasured",
		"relative order of the four duplicate overlay writers and the fieldprep shim in a live scene is not runtime-proven",
	}
	return a, nil
}

// n20ResolveConst resolves a register constant before a call. The JAL delay
// slot executes before the callee, so it is checked first. Returns ok only when
// a full 32-bit base is found; a bare low half is reported unresolved rather
// than guessed.
func n20ResolveConst(d []byte, idx int, reg uint32) (uint32, bool) {
	lo := uint32(0)
	haveLo := false
	// Delay slot (idx+4) can write the argument register.
	if idx+8 <= len(d) {
		w := binary.LittleEndian.Uint32(d[idx+4:])
		op, rs, rt := w>>26, (w>>21)&31, (w>>16)&31
		if rt == reg {
			switch op {
			case 0x0D: // ori
				if rs != reg {
					return 0, false
				}
				lo, haveLo = w&0xFFFF, true
			case 0x09: // addiu
				if rs != reg {
					return 0, false
				}
				lo, haveLo = w&0xFFFF, true
			default:
				return 0, false
			}
		}
	}
	for k := 1; k <= 12; k++ {
		j := idx - 4*k
		if j < 0 {
			break
		}
		w := binary.LittleEndian.Uint32(d[j:])
		op, rs, rt := w>>26, (w>>21)&31, (w>>16)&31
		if rt != reg {
			continue
		}
		switch op {
		case 0x0F: // lui
			v := (w & 0xFFFF) << 16
			if haveLo {
				v += lo
			}
			return v, true
		case 0x0D, 0x09: // ori/addiu rt,rt,imm
			if rs != reg {
				return 0, false
			}
			if !haveLo {
				lo, haveLo = w&0xFFFF, true
			}
			continue
		case 0x00: // addu/ori? only accept move from zero
			if w&63 == 0x21 && rs == 0 && (w>>11)&31 == reg {
				continue
			}
			return 0, false
		default:
			return 0, false
		}
	}
	return 0, false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// n20CountJR12 counts jr t4 instructions in a guard. The verifier failure tail
// uses t4 (the untouched retail target), so exactly one is expected.
func n20CountJR12(guard []byte) int {
	n := 0
	for i := 0; i+4 <= len(guard); i += 4 {
		if binary.LittleEndian.Uint32(guard[i:]) == olJR(12) {
			n++
		}
	}
	return n
}

func patchedModuleMap(n6 OverlayLocalPlan, fp N20RelocPlan) map[string]bool {
	out := map[string]bool{}
	for n := range n6.Patched {
		out[n] = true
	}
	for n := range fp.PatchedOverlay {
		out[n] = true
	}
	return out
}

func patchedModuleFor(name string, n6 OverlayLocalPlan, fp N20RelocPlan) (*OverlayFieldPrepModule, bool) {
	if _, ok := n6.Patched[name]; ok {
		m := OverlayFieldPrepModule{
			Guard: n6.Module.Guard, Body: n6.Module.Body,
			BodyLen: n6.Module.BodyLen, Sum32: n6.Module.Sum32, XOR32: n6.Module.XOR32,
			RomanizerBytes: n6.Module.RomanizerBytes, VerifierBytes: n6.Module.VerifierBytes,
			BodyEndRAM: n6.Module.ModuleEnd(), SHA: n6.Module.SHA,
		}
		return &m, true
	}
	if _, ok := fp.PatchedOverlay[name]; ok {
		m := fp.Module
		return &m, false
	}
	return nil, false
}

// N20IntegratedReportFor exposes the integrated plan to the evidence generator.
func N20IntegratedReportFor(p N20IntegratedPlan) map[string]any {
	return map[string]any{
		"verdict":       p.Verdict,
		"safe_to_patch": p.SafeToPatch,
		"runtime_pass":  p.RuntimePass,
		"manifest":      p.Manifest,
		"exe_sha256":    sha(p.PatchedEXE),
		"overlay_count": len(p.PatchedOverlays),
	}
}
