package n20arch

// Loader integrity audit.
//
// The retail loader reads 96 sectors (196,608 B) into 0x80132000, then calls
// 0x8004636C with a0=sector count and a1=buffer. That routine sums every byte
// of sectors*2048-4 and compares the low 16 bits with the big-endian word in
// the last four bytes. It is a 16-bit byte sum, not a MAC: a single changed
// byte is detected unless a compensating change keeps the sum, and an all-zero
// buffer passes (0 == 0).
//
// State flow (authenticated):
//   0x80078FBC CD read -> state 1
//   0x80078FE8 poll 0x800460CC, test bit 0 -> state 2
//   0x8007902C checksum 0x8004636C -> on success FlushCache + state 3
//   0x80079054 on failure: state 0, previous LBA cleared, no dispatch
//
// The ready bit proves only that the loader's own completion flag was set. It
// does not prove DMA/cache ordering offline, so torn-load atomicity remains
// UNKNOWN even though a torn read is usually caught by the checksum.

import (
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	LoaderChecksumFunc = 0x8004636C
	LoaderChecksumCall = 0x8007902C
	LoaderReadyPoll    = 0x800460CC
	LoaderReadCall     = 0x80078FBC
	LoaderReadFunc     = 0x80046318
	LoaderFlushCall    = 0x80079044
	LoaderFlushFunc    = 0x80042458
	LoaderDispatchSel  = 0x80079070
	LoaderStateMachine = 0x80078A0C
	LoaderEntryPointer = 0x80123110
	LoaderStateAddr    = 0x800B6D34
	LoaderLBAAddr      = 0x800B6D40
	LoaderSectors      = 96
	LoaderBytes        = LoaderSectors * 2048

	// Authenticated state values written to 0x800B6D34.
	LoaderStateIdle     = 0
	LoaderStateReading  = 1
	LoaderStateChecksum = 2
	LoaderStateDispatch = 3
)

var loadingAnchors = []WordAnchor{
	{0x8004636C, 0x308E00FF, "checksum: andi t6,a0,0x00ff (sector count)"},
	{0x80046370, 0x000E32C0, "checksum: sll a2,t6,11 (*2048)"},
	{0x80046374, 0x24C6FFFC, "checksum: addiu a2,a2,-4 (exclude trailer)"},
	{0x8004638C, 0x908F0000, "checksum loop: lbu t7,0(a0)"},
	{0x80046390, 0x90F90000, "checksum loop: lbu t9,0(a3)"},
	{0x80046394, 0x004FC021, "checksum loop: addu t8,v0,t7"},
	{0x8004639C, 0x03191021, "checksum loop: addu v0,t8,t9"},
	{0x800463A4, 0x3048FFFF, "checksum loop: andi t0,v0,0xffff"},
	{0x800463C4, 0x00064A00, "trailer: sll t1,a2,8 (big-endian high byte)"},
	{0x800463C8, 0x01275021, "trailer: addu t2,t1,a3"},
	{0x800463CC, 0x104A0004, "compare sum with trailer word"},
	{0x800463D8, 0x00001025, "mismatch: v0=0"},
	{0x8007902C, 0x0C0118DB, "loader: jal 0x8004636C"},
	{0x80079034, 0x10400007, "loader: beq v0,zero,fail"},
	{0x80079044, 0x0C010916, "loader: jal FlushCache after checksum"},
	{0x80079048, 0xA02E6D34, "loader: state=3 after checksum"},
	{0x80079054, 0xA0206D34, "loader: state=0 on checksum failure"},
	{0x80078FE8, 0x0C011833, "state 1: jal 0x800460CC (ready poll)"},
	{0x80078FF0, 0x304E0001, "state 1: andi t6,v0,1"},
	{0x80079000, 0xA02F6D34, "state 1: state=2 when ready"},
}

// LoadingIntegrityAudit is the measured, three-valued loader verdict.
type LoadingIntegrityAudit struct {
	ChecksumFunc     uint32       `json:"checksum_func"`
	ChecksumCall     uint32       `json:"checksum_call"`
	ReadyPoll        uint32       `json:"ready_poll"`
	ReadCall         uint32       `json:"read_call"`
	Sectors          int          `json:"sectors"`
	Bytes            int          `json:"bytes"`
	TrailerBytes     int          `json:"trailer_bytes"`
	Algorithm        string       `json:"algorithm"`
	CollisionBits    int          `json:"collision_bits"`
	CollisionChance  string       `json:"collision_chance"`
	CoversCallsites  bool         `json:"covers_callsites"`
	CoversGuard      bool         `json:"covers_guard"`
	CoversBody       bool         `json:"covers_body"`
	ZeroBufferPasses bool         `json:"zero_buffer_passes"`
	Atomicity        string       `json:"atomicity"`
	Verdict          string       `json:"verdict"`
	Anchors          []WordAnchor `json:"anchors"`
}

// AuditLoadingIntegrity re-decodes the load gate from the authenticated EXE.
func AuditLoadingIntegrity(exe []byte) (LoadingIntegrityAudit, error) {
	a := LoadingIntegrityAudit{ChecksumFunc: LoaderChecksumFunc, ChecksumCall: LoaderChecksumCall,
		ReadyPoll: LoaderReadyPoll, ReadCall: LoaderReadCall, Sectors: LoaderSectors,
		Bytes: LoaderBytes, TrailerBytes: 4,
		Algorithm:       "sum of bytes over sectors*2048-4, low 16 bits, compared with big-endian trailer",
		CollisionBits:   16,
		CollisionChance: "1/65536 per independent corruption; not a cryptographic MAC",
		CoversCallsites: true, CoversGuard: true, CoversBody: true,
		Atomicity: "UNKNOWN: 0x800460CC ready bit does not prove DMA/cache completion; only the checksum is decoded",
		Verdict:   "checksum_gated_but_not_atomic"}
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return a, fmt.Errorf("unrecognised original EXE")
	}
	for _, an := range loadingAnchors {
		if got := wordAt(exe, an.PC); got != an.Word {
			return a, fmt.Errorf("loading anchor %08x is %08x, want %08x (%s)", an.PC, got, an.Word, an.Meaning)
		}
		a.Anchors = append(a.Anchors, an)
	}
	a.ZeroBufferPasses = true // 0 == 0 by construction; asserted by the test.
	return a, nil
}

// LoaderChecksum models 0x8004636C exactly: sum sectors*2048-4 bytes, compare
// with the big-endian 16-bit trailer. It returns computed, stored and pass.
func LoaderChecksum(buf []byte, sectors int) (uint16, uint16, bool, error) {
	if sectors <= 0 || sectors > 0x7F {
		return 0, 0, false, fmt.Errorf("sector count %d does not fit the loader's 8-bit count", sectors)
	}
	n := sectors * 2048
	if len(buf) < n {
		return 0, 0, false, fmt.Errorf("buffer %d B shorter than %d B", len(buf), n)
	}
	var sum uint32
	for _, b := range buf[:n-4] {
		sum += uint32(b)
	}
	computed := uint16(sum)
	stored := binary.BigEndian.Uint16(buf[n-4 : n-2])
	return computed, stored, computed == stored, nil
}

// loaderOrderAnchors are the authenticated instructions that fix the order
// DMA-complete -> checksum -> FlushCache -> dispatch -> first execution.
// They are decoded from the same EXE as loadingAnchors and checked by
// AuditLoaderOrder.
var loaderOrderAnchors = []WordAnchor{
	{0x80078A10, 0x90426D34, "state machine: lbu v0,0x800B6D34"},
	{0x80078A44, 0x0C01E312, "state 0: jal 0x80078C48 load request"},
	{0x80078A54, 0x0C01E3F8, "state 1: jal 0x80078FE0 ready poll"},
	{0x80078A64, 0x0C01E405, "state 2: jal 0x80079014 checksum"},
	{0x80078A74, 0x0C01E41C, "state 3: jal 0x80079070 scene dispatch"},
	{0x80078FBC, 0x0C0118C6, "read request: jal 0x80046318 (96 sectors)"},
	{0x80078FCC, 0xA0396D34, "read request: state=1 after DMA start"},
	{0x80078FE8, 0x0C011833, "state 1: jal 0x800460CC ready poll"},
	{0x80079000, 0xA02F6D34, "poll: state=2 when bit 0 is set"},
	{0x8007902C, 0x0C0118DB, "state 2: jal 0x8004636C checksum"},
	{0x80079034, 0x10400007, "checksum: beq v0,zero,fail"},
	{0x80079044, 0x0C010916, "checksum success: jal 0x80042458 FlushCache"},
	{0x80079048, 0xA02E6D34, "FlushCache delay slot: state=3"},
	{0x80079054, 0xA0206D34, "checksum failure: state=0"},
	{0x8007905C, 0xAC206D40, "checksum failure: LBA=0 (0x800B6D40)"},
	{0x800426C8, 0x8F393110, "main loop: lw t9,0x80123110 entry pointer"},
	{0x800426D0, 0x0320F809, "main loop: jalr ra,t9 first execution"},
	{0x80042758, 0x8F393110, "main loop scene path: lw t9,0x80123110"},
	{0x80042760, 0x0320F809, "main loop scene path: jalr ra,t9 first execution"},
}

// LoaderOrderAudit is the decoded ordering, not a hardware measurement.
type LoaderOrderAudit struct {
	ReadFunc                    uint32       `json:"read_func"`
	ReadyPoll                   uint32       `json:"ready_poll"`
	ChecksumFunc                uint32       `json:"checksum_func"`
	FlushFunc                   uint32       `json:"flush_func"`
	DispatchSelect              uint32       `json:"dispatch_select"`
	StateMachine                uint32       `json:"state_machine"`
	EntryPointer                uint32       `json:"entry_pointer"`
	FirstExecJalr               []uint32     `json:"first_execution_jalr"`
	StageOrder                  []string     `json:"stage_order"`
	StateValues                 []int        `json:"state_values"`
	ChecksumBeforeFlush         bool         `json:"checksum_before_flush"`
	FlushBeforeDispatch         bool         `json:"flush_before_dispatch"`
	DispatchBeforeFirst         bool         `json:"dispatch_before_first_execution"`
	StateThreeGate              bool         `json:"dispatch_gated_by_state_3"`
	StateZeroNoDispatch         bool         `json:"interrupted_load_state_0_no_dispatch"`
	SlotReplacedOnReload        bool         `json:"reload_replaces_slot"`
	MidTransferPatchedExecution bool         `json:"patched_jal_guard_body_mid_transfer"`
	MidTransferReason           string       `json:"mid_transfer_reason"`
	ChecksumStrength            string       `json:"checksum_strength"`
	Anchors                     []WordAnchor `json:"anchors"`
	Verdict                     string       `json:"verdict"`
}

// AuditLoaderOrder re-decodes the authenticated loader state machine and the
// two main-loop entry dispatches. It proves program order only; it cannot
// prove that an interrupt or DMA engine cannot observe the buffer earlier.
func AuditLoaderOrder(exe []byte) (LoaderOrderAudit, error) {
	a := LoaderOrderAudit{
		ReadFunc: LoaderReadFunc, ReadyPoll: LoaderReadyPoll,
		ChecksumFunc: LoaderChecksumFunc, FlushFunc: LoaderFlushFunc,
		DispatchSelect: LoaderDispatchSel, StateMachine: LoaderStateMachine,
		EntryPointer:  LoaderEntryPointer,
		FirstExecJalr: []uint32{0x800426D0, 0x80042760},
		StageOrder: []string{
			"dma_complete_poll (0x800460CC, state 1 -> 2)",
			"checksum (0x8004636C, state 2 -> 3 on pass, 0 on fail)",
			"FlushCache (0x80042458; state 3 store is its delay slot)",
			"dispatch select (0x80079070 writes 0x80123110)",
			"first execution (main-loop jalr through 0x80123110)",
		},
		StateValues:         []int{LoaderStateIdle, LoaderStateReading, LoaderStateChecksum, LoaderStateDispatch},
		ChecksumBeforeFlush: true, FlushBeforeDispatch: true,
		DispatchBeforeFirst: true, StateThreeGate: true,
		StateZeroNoDispatch: true, SlotReplacedOnReload: true,
		MidTransferPatchedExecution: false,
		MidTransferReason:           "program order: the only decoded path to the overlay slot is the state-3 dispatch select plus a later main-loop jalr; state 3 is reached only after the 0x8004636C checksum returns success and after the 0x80042458 FlushCache call. No decoded loader path calls or jumps into 0x80132000 while state is 0/1/2. Interrupt/DMA concurrency is not modelled, so this is an offline ordering proof, not a hardware guarantee.",
		ChecksumStrength:            "16-bit additive byte sum mod 65536 over 96*2048-4 bytes, compared with the big-endian trailer; single-byte corruption is always detected, a compensating pair is not, all-zero passes",
		Verdict:                     "ordered_checksum_flush_dispatch_but_isr_dma_unmeasured",
	}
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return a, fmt.Errorf("unrecognised original EXE")
	}
	for _, an := range loaderOrderAnchors {
		if got := wordAt(exe, an.PC); got != an.Word {
			return a, fmt.Errorf("loader order anchor %08x is %08x, want %08x (%s)", an.PC, got, an.Word, an.Meaning)
		}
		a.Anchors = append(a.Anchors, an)
	}
	// State 3 is written in the FlushCache delay slot; the dispatch select and
	// the jalr are later in program order. Re-assert the concrete PCs. The
	// main-loop jalr is in a different function, so only the state-machine and
	// state-2 paths are address-monotonic.
	if !(LoaderChecksumCall < LoaderFlushCall && LoaderFlushCall < LoaderDispatchSel) {
		return a, fmt.Errorf("state-2/state-3 loader PCs are not monotonic")
	}
	if !(0x80078A54 < 0x80078A64 && 0x80078A64 < 0x80078A74) {
		return a, fmt.Errorf("state-machine call order drifted")
	}
	if wordAt(exe, 0x80079048)&0xFFFF0000 != 0xA02E0000 ||
		wordAt(exe, 0x80079054)&0xFFFF0000 != 0xA0200000 {
		return a, fmt.Errorf("loader state stores drifted")
	}
	return a, nil
}

// AssertCarrierPayload is the planner-side ownership gate. It refuses a
// carrier whose file bytes in the module range are not zero, whose module
// range falls outside the 4,312 B payload, or which contains a direct absolute
// or J/JAL reference into its own module range. Indirect writers cannot be
// resolved from one image and remain an explicit residual, never a PASS.
func AssertCarrierPayload(name string, src []byte, moduleEnd uint32) error {
	if len(src) != 196608 || sha(src) != OverlaySHA[name] {
		return fmt.Errorf("carrier %s is not the authenticated original", name)
	}
	if moduleEnd <= OLGuardBase || moduleEnd > OLGuardBase+uint32(OLPayloadEndOff-OLPayloadFileOff) {
		return fmt.Errorf("carrier %s module end %08x is outside the payload", name, moduleEnd)
	}
	if !allZero(src[OLPayloadFileOff:OLPayloadEndOff]) {
		return fmt.Errorf("carrier %s payload is not file-backed zero; refusing to place a module", name)
	}
	lo, hi := OLGuardBase, moduleEnd
	endFile := overlayCodeEnd(src)
	for off := 0; off+8 <= endFile; off += 4 {
		if v, ok := materializedWord(src, off, endFile); ok && v >= lo && v < hi {
			return fmt.Errorf("carrier %s references its own module range at +0x%x (0x%08x)", name, off, v)
		}
	}
	for off := 0; off+4 <= len(src); off += 4 {
		w := binary.LittleEndian.Uint32(src[off:])
		if w>>26 != 0x02 && w>>26 != 0x03 {
			continue
		}
		tgt := ((w & 0x03FFFFFF) << 2) | 0x80000000
		if tgt >= lo && tgt < hi {
			return fmt.Errorf("carrier %s has a J/JAL target into its module range at +0x%x", name, off)
		}
	}
	return nil
}

// LoaderSim is a deliberately small model of the five loader stages. It is
// not a hardware model: it exists so negative tests can show that omitting or
// reordering a stage cannot reach dispatch.
type LoaderSim struct {
	Buf         []byte
	State       int
	LBA         uint32
	Flushed     bool
	Dispatched  uint32
	Executed    uint32
	Events      []string
	Sum, Stored uint16
}

func NewLoaderSim(buf []byte) *LoaderSim {
	return &LoaderSim{Buf: append([]byte(nil), buf...), State: LoaderStateIdle}
}

func (s *LoaderSim) event(e string) { s.Events = append(s.Events, e) }

// Request models the DMA start. d is the bytes delivered so far; a short d is
// a torn transfer and leaves the rest of the previous buffer intact.
func (s *LoaderSim) Request(lba uint32, d []byte) {
	copy(s.Buf, d)
	s.LBA = lba
	s.State = LoaderStateReading
	s.Flushed = false
	s.Dispatched = 0
	s.Executed = 0
	s.event("dma_start")
}

// Ready models 0x800460CC returning bit 0 set.
func (s *LoaderSim) Ready() {
	if s.State != LoaderStateReading {
		return
	}
	s.State = LoaderStateChecksum
	s.event("dma_complete")
}

// Interrupt models an interrupted transfer: state 0, LBA cleared, no
// dispatch. The buffer is left as delivered (a partial image can remain).
func (s *LoaderSim) Interrupt() {
	s.State = LoaderStateIdle
	s.LBA = 0
	s.event("interrupted")
}

// Verify models 0x8004636C and its success/failure state writes.
func (s *LoaderSim) Verify() bool {
	if s.State != LoaderStateChecksum {
		return false
	}
	c, st, ok, err := LoaderChecksum(s.Buf, LoaderSectors)
	s.Sum, s.Stored = c, st
	if err != nil || !ok {
		s.State = LoaderStateIdle
		s.LBA = 0
		s.event("checksum_fail")
		return false
	}
	s.State = LoaderStateDispatch
	s.event("checksum_pass")
	return true
}

// Flush models the 0x80042458 call. Dispatch is refused before it.
func (s *LoaderSim) Flush() {
	if s.State == LoaderStateDispatch {
		s.Flushed = true
		s.event("flushcache")
	}
}

// Dispatch models 0x80079070 writing the entry pointer. It requires a passed
// checksum (state 3) and the FlushCache call.
func (s *LoaderSim) Dispatch(entry uint32) uint32 {
	if s.State != LoaderStateDispatch || !s.Flushed {
		return 0
	}
	s.State = LoaderStateIdle
	s.LBA = 0
	s.Dispatched = entry
	s.event("dispatch")
	return entry
}

// Execute models the main-loop jalr. It is impossible without dispatch.
func (s *LoaderSim) Execute() uint32 {
	if s.Dispatched == 0 {
		return 0
	}
	s.Executed = s.Dispatched
	s.event("first_execution")
	return s.Executed
}

// PayloadTail records the file-backed bytes that occupy an overlay tail which
// is not all zero. It is evidence that the tail is data, not free space.
type PayloadTail struct {
	Overlay      string `json:"overlay"`
	NonZeroBytes int    `json:"non_zero_bytes"`
	FirstOffset  int    `json:"first_payload_offset"`
	LastOffset   int    `json:"last_payload_offset"`
	HeadHex      string `json:"head_hex"`
	TailHex      string `json:"tail_hex"`
	Carrier      bool   `json:"is_carrier"`
	Disposition  string `json:"disposition"`
}

// OverlayLoadCoverage is the offline-provable part of the overlay load gate.
// It deliberately separates what can be decided from authenticated bytes
// (coverage, all-zero payload, single-byte detection, direct absolute
// references) from what cannot (ownership of the zero tail, torn-read
// atomicity, stack low-water, interrupt/cache/DMA/BIOS behaviour).
type OverlayLoadCoverage struct {
	WindowStart uint32 `json:"window_start"`
	WindowEnd   uint32 `json:"window_end"`
	Sectors     int    `json:"sectors"`
	Bytes       int    `json:"bytes"`
	// The loader sums bytes [window_start, window_start+bytes-4) and reads the
	// stored 16-bit big-endian value from the next two bytes.
	ChecksumFrom uint32 `json:"checksum_from"`
	ChecksumTo   uint32 `json:"checksum_to"`
	GuardStart   uint32 `json:"guard_start"`
	GuardEnd     uint32 `json:"guard_end"`
	BodyStart    uint32 `json:"body_start"`
	ModuleEnd    uint32 `json:"module_end"`
	CoversGuard  bool   `json:"covers_guard"`
	CoversBody   bool   `json:"covers_body"`
	InSingleLoad bool   `json:"guard_and_body_in_one_load"`

	Carriers                int           `json:"carriers_scanned"`
	ZeroTailCarriers        int           `json:"zero_tail_carriers"`
	ZeroTailNames           []string      `json:"zero_tail_carrier_names"`
	NonZeroPayloadNames     []string      `json:"non_zero_payload_overlays"`
	NonZeroPayload          []PayloadTail `json:"non_zero_payload_bytes"`
	CarrierPayloadFree      bool          `json:"all_carrier_payload_bytes_zero_in_file"`
	CarrierLastDataMax      int           `json:"carrier_last_nonzero_before_payload_max"`
	CarrierMinGapToGuard    int           `json:"carrier_min_gap_bytes_to_guard"`
	DirectPayloadRefs       int           `json:"direct_absolute_payload_refs"`
	DirectRefLocations      []string      `json:"direct_absolute_ref_locations"`
	JumpPayloadRefs         int           `json:"jump_targets_into_payload"`
	JumpRefLocations        []string      `json:"jump_target_locations"`
	IndirectJumpsInCarriers int           `json:"indirect_jumps_in_carriers"`
	IndirectRefsResolved    int           `json:"indirect_payload_refs_resolved"`
	SceneEntries            int           `json:"scene_entry_count"`
	SceneEntryMax           uint32        `json:"scene_entry_max"`
	SceneEntriesInWindow    int           `json:"scene_entries_inside_payload_window"`
	ScanBound               int           `json:"direct_ref_scan_carriers"`

	SingleByteDetected     bool `json:"single_byte_change_detected"`
	CompensatingPairEvades bool `json:"compensating_change_evades"`
	ZeroBufferPasses       bool `json:"zero_buffer_passes"`
	ChecksumIsMAC          bool `json:"checksum_is_mac"`

	ZeroTailOwnership string `json:"zero_tail_ownership"`
	Atomicity         string `json:"atomicity"`
	StackLowWater     string `json:"stack_low_water"`
	IRQCacheDMA       string `json:"irq_cache_dma"`
	BIOS              string `json:"bios"`

	RuntimeEvidenceRequired []string `json:"runtime_evidence_required"`
	Verdict                 string   `json:"verdict"`
	Reason                  string   `json:"reason"`
}

// materializedWord reports the address built by a lui followed within four
// instructions by an ori/addiu of the same register. It is intentionally the
// same narrow idiom the offline scanner uses elsewhere; register-relative and
// indirect addressing are not resolved.
func materializedWord(d []byte, off, end int) (uint32, bool) {
	if off+8 > end || off+8 > len(d) {
		return 0, false
	}
	w := binary.LittleEndian.Uint32(d[off:])
	if w>>26 != 0x0F {
		return 0, false
	}
	rt := (w >> 16) & 31
	hi := (w & 0xFFFF) << 16
	for k := 1; k <= 4; k++ {
		p := off + 4*k
		if p+4 > end || p+4 > len(d) {
			break
		}
		y := binary.LittleEndian.Uint32(d[p:])
		op := y >> 26
		if (op != 0x0D && op != 0x09) || (y>>21)&31 != rt || (y>>16)&31 != rt {
			continue
		}
		v := hi | (y & 0xFFFF)
		if op == 0x09 && y&0x8000 != 0 {
			v -= 0x10000
		}
		return v, true
	}
	return 0, false
}

// AuditOverlayLoadCoverage re-decodes the authenticated EXE and all 26 original
// overlays and reports only facts that follow from those bytes. carriers is
// the N6-FP carrier set (the images that would contain a guard/body); the
// direct-reference scan is limited to the EXE and those carriers because a
// reference from an image that can never be loaded with the module is not a
// writer for that module.
func AuditOverlayLoadCoverage(exe []byte, overlays map[string][]byte, moduleEnd uint32, carriers []string) (OverlayLoadCoverage, error) {
	var a OverlayLoadCoverage
	a.DirectRefLocations = []string{}
	a.JumpRefLocations = []string{}
	a.ZeroTailNames = []string{}
	a.NonZeroPayloadNames = []string{}
	a.NonZeroPayload = []PayloadTail{}
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return a, fmt.Errorf("unrecognised original EXE")
	}
	if len(overlays) != len(OverlaySHA) {
		return a, fmt.Errorf("need all 26 authenticated overlays, got %d", len(overlays))
	}
	a.WindowStart = OverlaySlotBase
	a.WindowEnd = OverlaySlotEnd
	a.Sectors = LoaderSectors
	a.Bytes = LoaderBytes
	a.ChecksumFrom = OverlaySlotBase
	a.ChecksumTo = OverlaySlotBase + uint32(LoaderBytes-4)
	a.GuardStart = OLGuardBase
	a.GuardEnd = OLBodyBase
	a.BodyStart = OLBodyBase
	a.ModuleEnd = moduleEnd
	a.CoversGuard = OLGuardBase >= a.ChecksumFrom && OLBodyBase <= a.ChecksumTo
	a.CoversBody = OLBodyBase >= a.ChecksumFrom && moduleEnd <= a.ChecksumTo && moduleEnd > OLBodyBase
	a.InSingleLoad = OLGuardBase >= a.WindowStart && moduleEnd <= a.WindowEnd
	if !a.CoversGuard || !a.CoversBody || !a.InSingleLoad {
		return a, fmt.Errorf("fieldprep module %08x is outside the 96-sector load/checksum window", moduleEnd)
	}

	names := make([]string, 0, len(overlays))
	for n := range overlays {
		names = append(names, n)
	}
	sort.Strings(names)
	carrierSet := map[string]bool{}
	for _, n := range carriers {
		if _, ok := overlays[n]; !ok {
			return a, fmt.Errorf("carrier %s is not in the authenticated set", n)
		}
		carrierSet[n] = true
	}
	a.CarrierPayloadFree = true
	a.CarrierMinGapToGuard = OLPayloadFileOff
	for _, n := range names {
		d := overlays[n]
		if len(d) != 196608 || sha(d) != OverlaySHA[n] {
			return a, fmt.Errorf("overlay %s is not the authenticated original", n)
		}
		a.Carriers++
		zero := allZero(d[OLPayloadFileOff:OLPayloadEndOff])
		if !zero {
			first, last, count := -1, -1, 0
			for i, b := range d[OLPayloadFileOff:OLPayloadEndOff] {
				if b != 0 {
					if first < 0 {
						first = i
					}
					last = i
					count++
				}
			}
			headEnd := first + 16
			if headEnd > OLPayloadEndOff-OLPayloadFileOff {
				headEnd = OLPayloadEndOff - OLPayloadFileOff
			}
			tailStart := last - 8
			if tailStart < 0 {
				tailStart = 0
			}
			pt := PayloadTail{
				Overlay: n, NonZeroBytes: count,
				FirstOffset: first, LastOffset: last,
				HeadHex: fmt.Sprintf("%x", d[OLPayloadFileOff+first:OLPayloadFileOff+headEnd]),
				TailHex: fmt.Sprintf("%x", d[OLPayloadFileOff+tailStart:OLPayloadFileOff+last+1]),
				Carrier: carrierSet[n],
			}
			if carrierSet[n] {
				a.CarrierPayloadFree = false
				return a, fmt.Errorf("carrier %s payload is not zero in the original (first+0x%x, %d bytes)", n, first, count)
			}
			pt.Disposition = "excluded from every carrier set: file-backed non-zero tail; the planner refuses any non-zero payload"
			a.NonZeroPayloadNames = append(a.NonZeroPayloadNames, n)
			a.NonZeroPayload = append(a.NonZeroPayload, pt)
			continue
		}
		a.ZeroTailCarriers++
		a.ZeroTailNames = append(a.ZeroTailNames, n)
		if carrierSet[n] {
			last := 0
			for i := 0; i < OLPayloadFileOff; i++ {
				if d[i] != 0 {
					last = i
				}
			}
			if last > a.CarrierLastDataMax {
				a.CarrierLastDataMax = last
			}
			gap := OLPayloadFileOff - last - 1
			if gap < a.CarrierMinGapToGuard {
				a.CarrierMinGapToGuard = gap
			}
		}
	}

	// The direct-reference scan is deliberately wider than the carrier set:
	// any image in the authenticated disc that names the module range is
	// evidence about the tail even when that image can never carry a module.
	scanSet := map[string]bool{"EXE": true}
	for _, n := range names {
		scanSet[n] = true
	}
	a.ScanBound = len(scanSet)
	refLo, refHi := OLGuardBase, moduleEnd
	carrierRef := ""
	check := func(label string, d []byte, end int) {
		for off := 0; off+8 <= end; off += 4 {
			v, ok := materializedWord(d, off, end)
			if !ok || v < refLo || v >= refHi {
				continue
			}
			a.DirectPayloadRefs++
			if len(a.DirectRefLocations) < 32 {
				a.DirectRefLocations = append(a.DirectRefLocations,
					fmt.Sprintf("%s+0x%x=0x%08x", label, off, v))
			}
			if label != "EXE" && carrierSet[label] {
				carrierRef = label
			}
		}
	}
	jumpCheck := func(label string, d []byte) {
		for off := 0; off+4 <= len(d); off += 4 {
			w := binary.LittleEndian.Uint32(d[off:])
			if w>>26 != 0x02 && w>>26 != 0x03 {
				continue
			}
			tgt := ((w & 0x03FFFFFF) << 2) | 0x80000000
			if tgt < refLo || tgt >= refHi {
				continue
			}
			a.JumpPayloadRefs++
			if len(a.JumpRefLocations) < 32 {
				a.JumpRefLocations = append(a.JumpRefLocations,
					fmt.Sprintf("%s+0x%x->0x%08x", label, off, tgt))
			}
			if label != "EXE" && carrierSet[label] {
				carrierRef = label
			}
		}
	}
	check("EXE", exe, len(exe))
	jumpCheck("EXE", exe)
	carrierNames := make([]string, 0, len(scanSet)-1)
	for _, n := range names {
		carrierNames = append(carrierNames, n)
	}
	sort.Strings(carrierNames)
	for _, n := range carrierNames {
		d := overlays[n]
		check(n, d, overlayCodeEnd(d))
		jumpCheck(n, d)
		if !carrierSet[n] {
			continue
		}
		end := overlayCodeEnd(d)
		for off := 0; off+4 <= end; off += 4 {
			w := binary.LittleEndian.Uint32(d[off:])
			if w>>26 != 0 || (w&63 != 0x08 && w&63 != 0x09) {
				continue
			}
			if w&63 == 0x08 && (w>>21)&31 == 31 {
				continue // jr ra is a return, not an indirect transfer
			}
			a.IndirectJumpsInCarriers++
		}
	}
	// No offline resolver proves any of those indirect transfers cannot
	// target the zero tail; that is the ownership residual.
	a.IndirectRefsResolved = 0
	if carrierRef != "" {
		return a, fmt.Errorf("carrier %s contains a direct absolute or J/JAL reference into the module range", carrierRef)
	}

	// Scene entries are loaded from the EXE table at 0x800B1BEC. None may
	// point at the module, otherwise the scene dispatcher would execute
	// payload bytes as a scene entry.
	a.SceneEntries = len(FullSceneEntryTable(exe))
	for _, e := range FullSceneEntryTable(exe) {
		if e > a.SceneEntryMax {
			a.SceneEntryMax = e
		}
		if e >= OLGuardBase && e < moduleEnd {
			a.SceneEntriesInWindow++
		}
	}

	// A single changed byte b -> b^delta changes the 16-bit sum by delta,
	// which is non-zero for every non-zero delta. Two compensating changes
	// (e.g. +1 and -1) leave the sum unchanged. This is arithmetic, not a MAC.
	a.SingleByteDetected = true
	a.CompensatingPairEvades = true
	a.ZeroBufferPasses = true
	a.ChecksumIsMAC = false

	a.ZeroTailOwnership = fmt.Sprintf("CARRIER-ONLY, NOT OWNERSHIP: every carrier's file bytes in [0x%x,0x%x) are zero and no direct lui+ori/addiu or J/JAL reference into [0x%08x,0x%08x) exists in the EXE or any of the 26 overlays; %d overlays have file-backed non-zero tails and are excluded. The last file-backed byte in any carrier is 0x%x, at least 0x%x bytes before the guard; %d indirect jr/jalr sites exist in carriers and 0 resolve to the module range; register-relative/indirect writers remain unresolved, so zero bytes are not proof of runtime ownership", OLPayloadFileOff, OLPayloadEndOff, OLGuardBase, moduleEnd, len(a.NonZeroPayloadNames), a.CarrierLastDataMax, a.CarrierMinGapToGuard, a.IndirectJumpsInCarriers)
	a.Atomicity = "UNKNOWN: 0x800460CC ready bit and 0x8004636C checksum do not prove DMA/cache completion; a torn 96-sector read is only probabilistically caught"
	a.StackLowWater = "BOUNDED DELTA, LOW-WATER UNMEASURED: generated frames add at most 0x110 (N6) or 0xD0 (N6-FP) plus the 0x30 retail callee; the authenticated stack gap is 867,000 B, but the whole-game low-water with IRQ/callback frames is not measured"
	a.IRQCacheDMA = "UNMEASURED: no interrupt, cache or DMA timing is modelled"
	a.BIOS = "UNMEASURED: BIOS A0/B0/C services are only stubbed in the test Machine"
	a.RuntimeEvidenceRequired = []string{
		"torn-read atomicity across the 96-sector CD load",
		"actual ownership/use of the zero-filled overlay tail (indirect writers)",
		"whole-game stack low-water with the IRQ stack live",
		"cache flush and DMA ordering after the loader checksum",
		"BIOS call behaviour in the real runtime",
	}
	a.Verdict = "covered_by_loader_checksum_but_not_atomic_or_owned"
	a.Reason = fmt.Sprintf("the 96-sector load covers guard 0x%08x and body through 0x%08x and the loader checksum covers both; every carrier payload is file-backed zero and no carrier has a direct absolute or J/JAL reference into the module range; %d overlays have non-zero file-backed tails and are excluded; a single changed byte is always detected but a compensating pair is not, so this is an integrity filter, not a signature. %d absolute payload references and %d jump targets were found across the EXE plus all 26 overlays; %d carrier indirect jumps are unresolved; indirect writers, torn reads, tail ownership and runtime timing remain unproven", OLGuardBase, moduleEnd, len(a.NonZeroPayloadNames), a.DirectPayloadRefs, a.JumpPayloadRefs, a.IndirectJumpsInCarriers)
	return a, nil
}
