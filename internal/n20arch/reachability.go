package n20arch

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// This file answers one question only: can any of the five hooked retail
// sites (formatter 0x8007F7D4/B898/C95C/D0C30 inside 0x8007EF48, speaker
// 0x80050E74 inside 0x80050DFC) execute before the first overlay load has
// installed and flushed the N20 window at 0x80161EDC?
//
// Everything here is a read-only re-decode of authenticated bytes. No address
// below is copied from a comment: every anchor is compared against the byte
// word in the private EXE, and every derived number is recomputed from the
// jump tables the EXE itself uses.
//
// Result: no authenticated pre-load path to any of the five hook sites was
// found, but the closure is not complete (45 unresolved indirect call sites in
// pre-load-reachable functions, plus a data-driven write path to the mode
// byte), so the verdict is UNPROVEN. Unconditional overlay-window hooks
// therefore remain rejected as production architecture.

// Retail addresses used by the reachability proof.
const (
	reachTextStart = 0x80041000
	reachTextEnd   = 0x800AF390 // code ends before the 0x800AF390 record table

	reachBootEntry    = 0x800420D0
	reachMainInit     = 0x80042134
	reachMainLoop     = 0x800421BC
	reachStateMachine = 0x80042540
	reachStateTable   = 0x800AF3A0 // 146 entries, states 0..145
	reachStateEnd     = 0x80042778 // end of the 0x80042540 body
	reachModeTable    = 0x800AF5E8 // 129 entries, scenes 17..145
	reachModeLoad     = 0x800429D8 // sets 0x800E738E and mode=2
	reachModeNoLoad   = 0x800429EC // jr ra, mode unchanged

	reachModeByte    = 0x800E7388
	reachSceneByte   = 0x800E738E
	reachEntryPtr    = 0x80123110
	reachStateBlock  = 0x800E6280
	reachStateBytes  = 6796
	reachLoaderSM    = 0x80078A0C
	reachLoadRequest = 0x80078C48
	reachLBATable    = 0x800B19E8 // 129 entries, scenes 17..145
	reachLBADefault  = 0x80078F7C

	reachSceneDispatch  = 0x80079070
	reachSceneJumpTable = 0x800B1BEC // 129 entries, scenes 17..145

	reachFormatter       = 0x8007EF48
	reachFormatterCaller = 0x80082B6C
	reachFormatterFunc   = 0x80082764
	reachFormatterUp     = 0x80085910
	reachSpeaker         = 0x80050DFC
	reachFlush           = 0x80042458
	reachLoadCall        = 0x80046318
	reachLoadPoll        = 0x8004636C
)

// WordAnchor is one re-decoded retail instruction that the boot evidence
// depends on.
type WordAnchor struct {
	PC      uint32
	Word    uint32
	Meaning string
}

// BootChain is the authenticated cold-boot -> first-overlay-load chain.
type BootChain struct {
	Anchors []WordAnchor

	SceneByteInitPC     uint32
	StateWriters        []uint32
	PostLoadStateWriter uint32

	RequestJALPC uint32
	FlushJALPC   uint32

	EntryPointerLoads  []uint32
	EntryPointerStores []uint32

	FirstLoadCandidates []uint32
	FirstLoadScene      byte
	FirstLoadLBA        uint32
	FirstLoadDest       uint32
	FirstLoadSectors    uint32
	DefaultLBA          uint32
	Note                string
}

// SceneSlot is one authenticated scene-table entry.
type SceneSlot struct {
	Scene   byte
	LabelPC uint32
	Entry   uint32
	LBA     uint32
	Loads   bool
}

// ReachabilityVerdict is deliberately three-valued.
type ReachabilityVerdict string

const (
	ReachabilityProvenSafe ReachabilityVerdict = "PROVEN_SAFE_ORDERING"
	ReachabilityEarly      ReachabilityVerdict = "EARLY_EXECUTION_POSSIBLE"
	ReachabilityUnproven   ReachabilityVerdict = "UNPROVEN"
)

// StateGate is one decoded case of the 0x80042540 mode dispatcher.
type StateGate struct {
	State            byte
	HandlerPC        uint32
	TargetPC         uint32
	SceneEntry       bool
	ReachesSpeaker   bool
	ReachesFormatter bool
}

// ModeRequest is one authenticated 0x80042878(a0=scene) request that can be
// reached from a pre-load mode handler.
type ModeRequest struct {
	CallPC      uint32
	CallerFunc  uint32
	Scene       byte
	Loads       bool
	SpeakerMode bool // scene is one of the states whose handler reaches the speaker
}

// ReachabilityAudit is the machine-readable result.
type ReachabilityAudit struct {
	EXESHA string
	Boot   BootChain

	FormatterPC              uint32
	FormatterCallers         []uint32
	FormatterCallerFunc      uint32
	FormatterUpstreamCallers []uint32
	FormatterUpstreamFunc    uint32
	FormatterOverlayCallers  map[string]int

	SpeakerPC          uint32
	SpeakerCallers     []uint32
	SpeakerCallerFuncs []uint32
	SpeakerStates      []byte
	PreLoadStates      []byte
	PreLoadModeReqs    []ModeRequest
	PreLoadRoots       []uint32

	StateGates []StateGate

	SpeakerPreLoadReachable   bool
	FormatterPreLoadReachable bool
	SpeakerPath               []uint32
	SpeakerBootPath           []uint32
	FormatterPath             []uint32
	PreLoadSpeakerRoot        uint32
	PreLoadSpeakerMode        byte

	JalrSites        int
	JalrScenePointer []uint32
	JalrUnresolved   []uint32

	StateBlockStart         uint32
	StateBlockBytes         uint32
	StateWriteClosureProven bool

	SceneSlots           []SceneSlot
	DistinctSceneEntries int
	LoadTriggeringScenes []byte
	NonLoadScenes        []byte
	Verdict              ReachabilityVerdict
	Reason               string
}

// bootAnchors is the authenticated boot/loader chain. Every word is re-decoded
// by ExtractBootChain; a mismatch means the input is not the pinned EXE.
var bootAnchors = []WordAnchor{
	{0x800420D0, 0x27BDFFD8, "addiu sp,sp,-40 (boot frame)"},
	{0x800420D4, 0xAFBF0014, "sw ra,20(sp)"},
	{0x800420D8, 0x3C04801F, "lui a0,0x801f"},
	{0x800420DC, 0x0C02BBEC, "jal 0x800AEFB0 (SP switch)"},
	{0x800420E0, 0x3484EFF0, "ori a0,a0,0xEFF0"},
	{0x800420E4, 0x3C018012, "lui at,0x8012"},
	{0x800420E8, 0x3C04801F, "lui a0,0x801f"},
	{0x800420EC, 0xAC225124, "sw v0,0x5124(at) (old SP)"},
	{0x800420F0, 0x3484F800, "ori a0,a0,0xF800 (heap base)"},
	{0x800420F4, 0x0C02BBF0, "jal 0x800AEFC0 (InitHeap)"},
	{0x800420F8, 0x240507F0, "addiu a1,zero,0x7F0 (heap size)"},
	{0x800420FC, 0x3C04800E, "lui a0,0x800e"},
	{0x80042100, 0x3C050004, "lui a1,0x0004"},
	{0x80042104, 0x34A55498, "ori a1,a1,0x5498"},
	{0x80042108, 0x0C02B820, "jal 0x800AE080 (BSS clear)"},
	{0x8004210C, 0x348460A0, "ori a0,a0,0x60A0 (BSS base)"},
	{0x80042110, 0x0C02BBF4, "jal 0x800AEFD0"},
	{0x80042114, 0x00000000, "nop"},
	{0x80042118, 0x3C018012, "lui at,0x8012"},
	{0x8004211C, 0x0C01084D, "jal 0x80042134 (main init)"},
	{0x80042120, 0xAC225120, "sw v0,0x5120(at)"},
	{0x800421BC, 0x0C0108B2, "jal 0x800422C8 (per-frame scene setup)"},
	{0x800421C8, 0x91EF7390, "lbu t7,0x7390"},
	{0x800421D8, 0x0C010950, "jal 0x80042540 (mode dispatcher)"},
	{0x800425BC, 0x2C410092, "sltiu at,v0,146"},
	{0x800425C4, 0x00027080, "sll t6,v0,2"},
	{0x800425CC, 0x002E0821, "addu at,at,t6"},
	{0x800425D0, 0x8C2EF3A0, "lw t6,-3168(at) (0x800AF3A0)"},
	{0x800425D8, 0x01C00008, "jr t6"},
	{0x800425E0, 0x0C01681B, "mode 0 -> 0x8005A06C (intro)"},
	{0x80042654, 0x0C01682C, "mode 0x34 -> 0x8005A0B0"},
	{0x80042664, 0x0C018A10, "mode 0x12 -> 0x80062840 (date-game intro)"},
	{0x800426B4, 0x0C01837E, "mode 0x42 -> 0x80060DF8"},
	{0x800426C4, 0x3C198012, "mode 3: lui t9,0x8012"},
	{0x800426C8, 0x8F393110, "lw t9,0x3110 (overlay entry pointer)"},
	{0x800426D0, 0x0320F809, "jalr ra,t9"},
	{0x80042720, 0x0C01E283, "mode 2 -> 0x80078A0C (loader)"},
	{0x80042740, 0x3C04800B, "generic scene-entry case"},
	{0x80042760, 0x0320F809, "jalr ra,t9 (overlay entry)"},
	{0x8005A06C, 0x3C0E800E, "mode 0: lui t6,0x800e"},
	{0x8005A070, 0x91CE7389, "lbu t6,0x7389"},
	{0x8005A078, 0x15C00005, "bne t6,zero,0x8005A090"},
	{0x8005A080, 0x0C0166D0, "jal 0x80059B40 (intro sub-state)"},
	{0x8005A090, 0x0C010A1E, "jal 0x80042878 (request mode)"},
	{0x8005A094, 0x24040012, "delay: addiu a0,zero,18"},
	{0x80059B40, 0x3C03800E, "intro: lui v1,0x800e"},
	{0x80059B44, 0x9063738A, "lbu v1,0x738A"},
	{0x80059BA8, 0x0C010A02, "jal 0x80042808 (next intro sub-state)"},
	{0x80042878, 0x3C01800E, "set mode: lui at,0x800e"},
	{0x8004287C, 0xA0247388, "sb a0,0x7388(at)"},
	{0x800428C4, 0x0C010A58, "jal 0x80042960 (mode table)"},
	{0x800429B4, 0x2DC10081, "sltiu at,t6,129"},
	{0x800429C8, 0x8C2EF5E8, "lw t6,-2584(at) (0x800AF5E8)"},
	{0x800429D8, 0x3C01800E, "load mode: lui at,0x800e"},
	{0x800429DC, 0xA023738E, "sb v1,0x738e(at) (scene byte)"},
	{0x800429E0, 0x24030002, "addiu v1,zero,2"},
	{0x800429E8, 0xA0237388, "sb v1,0x7388(at) (mode=2)"},
	{0x800429EC, 0x03E00008, "no-load mode: jr ra"},
	{0x80078A10, 0x90426D34, "loader: lbu v0,0x6d34"},
	{0x80078A44, 0x0C01E312, "jal 0x80078C48 (request)"},
	{0x80078C48, 0x3C06800B, "loader request: lui a2,0x800b"},
	{0x80078C4C, 0x8CC66D40, "lw a2,0x6d40 (previous LBA)"},
	{0x80078C5C, 0x0C010E3C, "jal 0x800438F0"},
	{0x80078C68, 0x35CE2000, "ori t6,t6,0x2000"},
	{0x80078C74, 0xAC2E6D3C, "sw t6,0x6d3c (dest 0x80132000)"},
	{0x80078C78, 0x9063738E, "lbu v1,0x738e (scene byte)"},
	{0x80078C84, 0x2C610014, "sltiu at,v1,20"},
	{0x80078DA0, 0x8C2A19E8, "lw t2,6632(at) (0x800B19E8)"},
	{0x80078F78, 0x240E0060, "scene 18: sectors 96"},
	{0x80078F80, 0xA02E6D38, "sb t6,0x6d38"},
	{0x80078F84, 0x3406994A, "ori a2,zero,0x994A (default LBA)"},
	{0x80078F90, 0x15E60008, "bne t7,a2,0x80078FB4"},
	{0x80078FB4, 0x8CA56D3C, "lw a1,0x6d3c (dest)"},
	{0x80078FBC, 0x0C0118C6, "jal 0x80046318 (CD read)"},
	{0x80078FC4, 0x24190001, "addiu t9,zero,1"},
	{0x80078FCC, 0xA0396D34, "sb t9,0x6d34 (loader state 1)"},
	{0x80079014, 0x27BDFFD8, "loader state 2"},
	{0x80079024, 0x8CA56D3C, "lw a1,0x6d3c"},
	{0x80079028, 0x90846D38, "lbu a0,0x6d38"},
	{0x8007902C, 0x0C0118DB, "jal 0x8004636C (poll)"},
	{0x80079034, 0x10400007, "beq v0,zero,0x80079054"},
	{0x8007903C, 0x240E0003, "addiu t6,zero,3"},
	{0x80079044, 0x0C010916, "jal 0x80042458 (FlushCache)"},
	{0x80079048, 0xA02E6D34, "sb t6,0x6d34 (loader state 3)"},
	{0x80078A74, 0x0C01E41C, "jal 0x80079070 (scene dispatch)"},
	{0x80079074, 0x9063738E, "lbu v1,0x738e"},
	{0x800790FC, 0xAC2F3110, "sw t7,0x3110(at) (entry pointer)"},
	{0x800794C0, 0xA0206D34, "sb zero,0x6d34 (loader idle)"},
	{0x800794D0, 0xA0237388, "sb v1,0x7388(at) (mode=scene)"},
}

// ExtractBootChain re-decodes the authenticated boot->loader->first-load chain.
func ExtractBootChain(exe []byte) (BootChain, error) { return extractBootChain(exe, true) }

func extractBootChain(exe []byte, strict bool) (BootChain, error) {
	var b BootChain
	for _, a := range bootAnchors {
		w := wordAt(exe, a.PC)
		if w != a.Word {
			if strict {
				return b, fmt.Errorf("boot anchor %08x is %08x, want %08x (%s)", a.PC, w, a.Word, a.Meaning)
			}
			continue
		}
		b.Anchors = append(b.Anchors, a)
	}
	b.SceneByteInitPC = 0x800429DC
	b.StateWriters = storesTo(exe, reachModeByte)
	wantWriters := []uint32{0x800413AC, 0x800427A8, 0x8004287C, 0x800429E8, 0x800794D0}
	if !sameWords(b.StateWriters, wantWriters) {
		return b, fmt.Errorf("mode-byte writers drifted: %x", b.StateWriters)
	}
	b.PostLoadStateWriter = 0x800794D0
	b.RequestJALPC = 0x80078FBC
	b.FlushJALPC = 0x80079044
	b.EntryPointerLoads = []uint32{0x800426D0, 0x80042760, 0x800796F8}
	b.EntryPointerStores = storesTo(exe, reachEntryPtr)
	if len(b.EntryPointerStores) < 10 {
		return b, fmt.Errorf("entry-pointer stores unexpectedly few: %x", b.EntryPointerStores)
	}
	// First load: scene 18 is requested by the mode-0 intro but the mode table
	// maps it to the no-load stub, so it never reaches the loader. The first
	// load-triggering requests are issued from the mode-0x12 handler chain.
	b.FirstLoadCandidates = []uint32{0x800626E4, 0x800626F4, 0x80062724, 0x8006273C, 0x80062920}
	b.FirstLoadScene = 19
	b.FirstLoadLBA = 0x95EA
	b.FirstLoadDest = OverlaySlotBase
	b.FirstLoadSectors = OverlayLoadSectors
	b.DefaultLBA = 0x994A
	b.Note = "0x994A is the loader default and the scene-18 LBA, but scene 18 (mode 0x12) is a no-load mode " +
		"(0x80042960 index 1 -> 0x800429EC jr ra). The first authenticated load request in the cold-boot " +
		"path is issued from the mode-0x12 handler chain at 0x800626E4 (scene 19) or 0x80062920 (scene 17), " +
		"both scene->LBA 0x95EA; 0x800626F4/0x80062724/0x8006273C (scenes 32/33/34) are conditional on " +
		"0x801230D0 being non-zero (it is BSS-zero at cold boot)."
	return b, nil
}

// FullSceneEntryTable decodes all 129 scene-table entries (scenes 17..145) into
// their distinct overlay entry addresses. The previous 24-entry figure came
// from scanning only part of 0x80079070's dispatch body; the table itself is
// authoritative.
func FullSceneEntryTable(exe []byte) []uint32 {
	set := map[uint32]bool{}
	for s := 0; s < 129; s++ {
		label := wordAt(exe, reachSceneJumpTable+uint32(4*s))
		if e := decodeSceneEntry(exe, label); e != 0 {
			set[e] = true
		}
	}
	out := make([]uint32, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SceneSlots decodes scene id -> entry address, LBA and load-vs-no-load for
// every scene in the 129-entry table.
func SceneSlots(exe []byte) []SceneSlot {
	out := make([]SceneSlot, 0, 129)
	for s := 0; s < 129; s++ {
		label := wordAt(exe, reachSceneJumpTable+uint32(4*s))
		lbaLabel := wordAt(exe, reachLBATable+uint32(4*s))
		slot := SceneSlot{
			Scene:   byte(s + 17),
			LabelPC: label,
			Entry:   decodeSceneEntry(exe, label),
		}
		if lbaLabel == reachLBADefault || lbaLabel == 0x80078F78 {
			slot.LBA = 0x994A
		} else {
			slot.LBA = decodeLBACase(exe, lbaLabel)
		}
		slot.Loads = wordAt(exe, reachModeTable+uint32(4*s)) == reachModeLoad
		out = append(out, slot)
	}
	return out
}

func decodeSceneEntry(exe []byte, label uint32) uint32 {
	for pc := label; pc < label+20 && pc+20 < reachTextEnd; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 != 0x0F || ((w>>16)&31) == 1 {
			continue
		}
		rt := (w >> 16) & 31
		y := wordAt(exe, pc+4)
		if y>>26 != 0x09 || ((y>>21)&31) != rt || ((y>>16)&31) != rt {
			continue
		}
		v := ((w & 0xFFFF) << 16) + sext16(y&0xFFFF)
		for k := uint32(2); k <= 4; k++ {
			z := wordAt(exe, pc+4*k)
			if z>>26 == 0x2B && (z&0xFFFF) == 0x3110 {
				return v
			}
		}
	}
	return 0
}

func decodeLBACase(exe []byte, label uint32) uint32 {
	for k := 0; k < 8; k++ {
		w := wordAt(exe, label+uint32(4*k))
		if w>>26 == 0x0D && ((w>>21)&31) == 0 && ((w>>16)&31) == 6 {
			return w & 0xFFFF
		}
	}
	return 0
}

func storesTo(exe []byte, addr uint32) []uint32 {
	var out []uint32
	for pc := uint32(reachTextStart); pc+4 <= reachTextEnd; pc += 4 {
		w := wordAt(exe, pc)
		op := w >> 26
		if (op == 0x28 || op == 0x2B) && ((w>>21)&31) == 1 && (w&0xFFFF) == (addr&0xFFFF) {
			// Only count the exact 0x800Exxxx/0x8012xxxx address the caller
			// asked for: the preceding lui must supply the matching high half.
			hi := uint32(0)
			for k := uint32(1); k <= 3; k++ {
				z := wordAt(exe, pc-4*k)
				if z>>26 == 0x0F && ((z>>16)&31) == 1 {
					hi = (z & 0xFFFF) << 16
					break
				}
			}
			if hi+(addr&0xFFFF) == addr {
				out = append(out, pc)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sameWords(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// funcEntries collects plausible function starts: every direct-call target and
// every stack-frame prologue that follows a return or a nop-delay.
func funcEntries(exe []byte) []uint32 {
	set := map[uint32]bool{}
	for pc := uint32(reachTextStart); pc+4 <= reachTextEnd; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 == 0x03 {
			set[jumpTarget(w)] = true
		}
	}
	for pc := uint32(reachTextStart + 8); pc+4 <= reachTextEnd; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 != 0x09 || ((w>>21)&31) != 29 || ((w>>16)&31) != 29 {
			continue
		}
		imm := int32(sext16(w & 0xFFFF))
		if imm >= 0 {
			continue
		}
		prev := wordAt(exe, pc-4)
		prev2 := wordAt(exe, pc-8)
		if (prev>>26 == 0 && prev&63 == 8) || prev == 0 || (prev2>>26 == 0 && prev2&63 == 8) {
			set[pc] = true
		}
	}
	// Some overlay-callable EXE functions begin with a two-instruction
	// preamble (lui/lw) before their stack frame; 0x80085910 is one.
	for pc := uint32(reachTextStart + 8); pc+12 <= reachTextEnd; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 != 0x0F {
			continue
		}
		frame := wordAt(exe, pc+8)
		prev2 := wordAt(exe, pc-8)
		if frame>>26 == 0x09 && ((frame>>21)&31) == 29 && ((frame>>16)&31) == 29 &&
			int32(sext16(frame&0xFFFF)) < 0 && prev2>>26 == 0 && prev2&63 == 8 {
			set[pc] = true
		}
	}
	out := make([]uint32, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func enclosingFunc(entries []uint32, pc uint32) uint32 {
	lo, hi := 0, len(entries)-1
	best := uint32(reachTextStart)
	for lo <= hi {
		m := (lo + hi) / 2
		if entries[m] <= pc {
			best = entries[m]
			lo = m + 1
		} else {
			hi = m - 1
		}
	}
	return best
}

func buildFuncGraph(exe []byte) (map[uint32][]uint32, []uint32) {
	entries := funcEntries(exe)
	g := map[uint32]map[uint32]bool{}
	for pc := uint32(reachTextStart); pc+4 <= reachTextEnd; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 != 0x03 {
			continue
		}
		a := enclosingFunc(entries, pc)
		b := enclosingFunc(entries, jumpTarget(w))
		if a == b {
			continue
		}
		if g[a] == nil {
			g[a] = map[uint32]bool{}
		}
		g[a][b] = true
	}
	out := make(map[uint32][]uint32, len(g))
	for k, v := range g {
		l := make([]uint32, 0, len(v))
		for x := range v {
			l = append(l, x)
		}
		sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
		out[k] = l
	}
	return out, entries
}

// pathTo returns a shortest direct-call path root->target, or nil.
func pathTo(g map[uint32][]uint32, root, target uint32) []uint32 {
	prev := map[uint32]uint32{root: 0}
	q := []uint32{root}
	for len(q) > 0 {
		x := q[0]
		q = q[1:]
		if x == target {
			var out []uint32
			for x != 0 {
				out = append(out, x)
				p, ok := prev[x]
				if !ok || p == 0 {
					break
				}
				x = p
			}
			// reverse
			for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
				out[i], out[j] = out[j], out[i]
			}
			return out
		}
		for _, y := range g[x] {
			if _, ok := prev[y]; ok {
				continue
			}
			prev[y] = x
			q = append(q, y)
		}
	}
	return nil
}

// stateGates decodes the 146-entry 0x80042540 table and the first direct call
// of each case. Cases that load 0x80123110 are marked SceneEntry.
func stateGates(exe []byte) []StateGate {
	labels := map[uint32]bool{}
	for s := 0; s < 146; s++ {
		labels[wordAt(exe, reachStateTable+uint32(4*s))] = true
	}
	bounds := make([]uint32, 0, len(labels)+1)
	for l := range labels {
		bounds = append(bounds, l)
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i] < bounds[j] })
	next := func(l uint32) uint32 {
		for _, b := range bounds {
			if b > l {
				return b
			}
		}
		return reachStateEnd
	}
	out := make([]StateGate, 0, 146)
	for s := 0; s < 146; s++ {
		lab := wordAt(exe, reachStateTable+uint32(4*s))
		g := StateGate{State: byte(s), HandlerPC: lab}
		for pc := lab; pc < next(lab) && pc+4 <= reachStateEnd; pc += 4 {
			w := wordAt(exe, pc)
			if w>>26 == 3 && g.TargetPC == 0 {
				g.TargetPC = jumpTarget(w)
			}
			if w>>26 == 0 && (w&63) == 9 {
				g.SceneEntry = true
			}
		}
		out = append(out, g)
	}
	return out
}

// AuditReachability is the decisive analysis. It never writes to the EXE or
// overlays; overlays may be nil (the overlay caller census is then skipped).
func AuditReachability(exe []byte, overlays map[string][]byte) (ReachabilityAudit, error) {
	return auditReachability(exe, overlays, true)
}

// auditReachabilityUnchecked is test-only: it runs the same analysis on a
// deliberately mutated copy so the suite can prove the audit would flip to
// EARLY_EXECUTION_POSSIBLE if real evidence contradicted the verdict.
func auditReachabilityUnchecked(exe []byte, overlays map[string][]byte) (ReachabilityAudit, error) {
	return auditReachability(exe, overlays, false)
}

func auditReachability(exe []byte, overlays map[string][]byte, verify bool) (ReachabilityAudit, error) {
	var a ReachabilityAudit
	if verify {
		if err := CheckRetailAnchors(exe); err != nil {
			return a, err
		}
	}
	a.EXESHA = OriginalEXESHA
	boot, err := extractBootChain(exe, verify)
	if err != nil {
		return a, err
	}
	a.Boot = boot
	a.FormatterPC = reachFormatter
	a.SpeakerPC = reachSpeaker

	g, entries := buildFuncGraph(exe)

	// Formatter: one direct caller inside 0x80082764; that function is called
	// from 0x80085910 (EXE, itself called only by KANGEI.EXN) and directly from
	// seven overlays. No EXE path from boot exists.
	a.FormatterCallers = DirectCallers(exe, reachFormatter)
	if len(a.FormatterCallers) != 1 || a.FormatterCallers[0] != reachFormatterCaller {
		return a, fmt.Errorf("formatter callers drifted: %x", a.FormatterCallers)
	}
	a.FormatterCallerFunc = enclosingFunc(entries, reachFormatterCaller)
	a.FormatterUpstreamCallers = DirectCallers(exe, a.FormatterCallerFunc)
	a.FormatterUpstreamFunc = enclosingFunc(entries, 0x800859BC)
	a.FormatterOverlayCallers = map[string]int{}
	if overlays != nil {
		for name, ov := range overlays {
			if n := countOverlayJAL(ov, a.FormatterCallerFunc); n > 0 {
				a.FormatterOverlayCallers[name] = n
			}
		}
	}
	if p := pathTo(g, reachBootEntry, reachFormatter); p != nil {
		a.FormatterPreLoadReachable = true
		a.FormatterPath = p
	}

	// Speaker: 21 direct EXE callers; every direct-call path from boot enters
	// through the 0x80042540 mode dispatcher.
	a.SpeakerCallers = DirectCallers(exe, reachSpeaker)
	funcSet := map[uint32]bool{}
	for _, c := range a.SpeakerCallers {
		funcSet[enclosingFunc(entries, c)] = true
		if p := pathTo(g, reachBootEntry, enclosingFunc(entries, c)); p != nil {
			a.SpeakerBootPath = p
		}
	}
	for f := range funcSet {
		a.SpeakerCallerFuncs = append(a.SpeakerCallerFuncs, f)
	}
	sort.Slice(a.SpeakerCallerFuncs, func(i, j int) bool { return a.SpeakerCallerFuncs[i] < a.SpeakerCallerFuncs[j] })

	// Mode gates: which of the 146 modes reach the speaker / formatter.
	a.StateGates = stateGates(exe)
	speakerModes := map[byte]bool{}
	for i := range a.StateGates {
		sg := &a.StateGates[i]
		if sg.SceneEntry || sg.TargetPC == 0 {
			continue
		}
		if pathTo(g, sg.TargetPC, reachSpeaker) != nil {
			sg.ReachesSpeaker = true
			speakerModes[sg.State] = true
		}
		if pathTo(g, sg.TargetPC, reachFormatter) != nil {
			sg.ReachesFormatter = true
		}
	}
	for m := range speakerModes {
		a.SpeakerStates = append(a.SpeakerStates, m)
	}
	sort.Slice(a.SpeakerStates, func(i, j int) bool { return a.SpeakerStates[i] < a.SpeakerStates[j] })

	// Conservative pre-load mode superset: 0 (BSS init), 1 (transitional),
	// 2 (loader), 3 (entry dispatch, pointer zero), 0x10 (reset/title menu).
	a.PreLoadStates = []byte{0, 1, 2, 3, 0x10}
	for _, st := range a.PreLoadStates {
		sg := a.StateGates[int(st)]
		if sg.ReachesSpeaker {
			a.SpeakerPreLoadReachable = true
			a.PreLoadSpeakerMode = st
			a.SpeakerPath = pathTo(g, sg.TargetPC, reachSpeaker)
		}
		if sg.ReachesFormatter {
			a.FormatterPreLoadReachable = true
		}
	}
	// Pre-load roots that are not the mode dispatcher: intro, date-game intro,
	// loader states, and the per-frame helpers. The dispatcher itself is
	// covered state-by-state above.
	preRoots := []uint32{reachMainInit, 0x800422C8, 0x8005A06C, 0x80059B40, 0x80062840,
		reachLoaderSM, reachLoadRequest, 0x80079014, 0x80079070, 0x80043504, 0x80043510,
		0x800455C4, 0x80079B34, 0x8007B844, 0x80042418}
	a.PreLoadRoots = preRoots
	// Traversing 0x80042540 as an ordinary function would make every state
	// handler reachable from every caller. The dispatcher is therefore a sink
	// here; its cases are handled one by one below.
	preGraph := make(map[uint32][]uint32, len(g))
	for k, v := range g {
		if k == reachStateMachine {
			continue
		}
		preGraph[k] = v
	}
	for _, r := range preRoots {
		if p := pathTo(preGraph, r, reachSpeaker); p != nil {
			a.SpeakerPreLoadReachable = true
			a.PreLoadSpeakerRoot = r
			a.SpeakerPath = p
		}
		if pathTo(preGraph, r, reachFormatter) != nil {
			a.FormatterPreLoadReachable = true
		}
	}

	// Mode-0x12 requests: all of them either stay in the no-load mode (18) or
	// enter the loader (17/19/32/33/34); none is a speaker-gating mode.
	for _, c := range boot.FirstLoadCandidates {
		w := wordAt(exe, c)
		if w>>26 != 3 || jumpTarget(w) != 0x80042878 {
			return a, fmt.Errorf("first-load candidate %08x is not jal 0x80042878", c)
		}
		scene := byte(wordAt(exe, c+4) & 0xFFFF)
		req := ModeRequest{CallPC: c, CallerFunc: enclosingFunc(entries, c), Scene: scene,
			Loads:       wordAt(exe, reachModeTable+uint32(4*(int(scene)-17))) == reachModeLoad,
			SpeakerMode: speakerModes[scene]}
		a.PreLoadModeReqs = append(a.PreLoadModeReqs, req)
		if req.SpeakerMode {
			return a, fmt.Errorf("first-load request %08x targets speaker mode %02x", c, scene)
		}
	}

	// Indirect sites: enumerate jalr in the text and classify every one that
	// sits in a pre-load-reachable function. Only the three 0x80123110 loads
	// are resolved; everything else stays UNKNOWN.
	preFuncs := map[uint32]bool{}
	for _, r := range preRoots {
		for f := range reachableSet(preGraph, r) {
			preFuncs[f] = true
		}
	}
	for pc := uint32(reachTextStart); pc+4 <= reachTextEnd; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 != 0 || (w&63) != 9 {
			continue
		}
		a.JalrSites++
		if !preFuncs[enclosingFunc(entries, pc)] {
			continue
		}
		if pc >= 8 && wordAt(exe, pc-8) == 0x8F393110 {
			a.JalrScenePointer = append(a.JalrScenePointer, pc)
			continue
		}
		a.JalrUnresolved = append(a.JalrUnresolved, pc)
	}

	// Scene table: 129 entries, 40 distinct entries, all inside the overlay
	// slot; 45 load-triggering scenes and 84 no-load modes.
	a.SceneSlots = SceneSlots(exe)
	entriesSet := map[uint32]bool{}
	for _, s := range a.SceneSlots {
		entriesSet[s.Entry] = true
		if s.Entry < OverlaySlotBase || s.Entry >= OverlaySlotEnd {
			return a, fmt.Errorf("scene %02x entry %08x outside the overlay slot", s.Scene, s.Entry)
		}
		if s.Loads {
			a.LoadTriggeringScenes = append(a.LoadTriggeringScenes, s.Scene)
		} else {
			a.NonLoadScenes = append(a.NonLoadScenes, s.Scene)
		}
	}
	a.DistinctSceneEntries = len(entriesSet)
	a.StateBlockStart = reachStateBlock
	a.StateBlockBytes = reachStateBytes
	// The mode byte lives inside the 6,796 B work block the game clears as a
	// unit (0x8004130C..0x80041318); no proof excludes a save/DMA restore of
	// that block bypassing the five direct stores. Never claim closure.
	a.StateWriteClosureProven = false

	switch {
	case a.SpeakerPreLoadReachable || a.FormatterPreLoadReachable:
		a.Verdict = ReachabilityEarly
		a.Reason = "a concrete pre-first-overlay path to a hooked function exists; unconditional overlay-window hooks are unsafe"
	case len(a.JalrUnresolved) > 0 && !a.StateWriteClosureProven:
		a.Verdict = ReachabilityUnproven
		a.Reason = fmt.Sprintf("no authenticated pre-load path to the five hook sites was found, but the closure is incomplete: %d unresolved indirect call sites in pre-load-reachable functions and no proof that a save/DMA restore of the 6,796 B block at 0x800E6280 cannot write the mode byte 0x800E7388 outside the five direct stores. PROVEN_SAFE_ORDERING requires a complete chain; UNPROVEN is the correct acceptance.", len(a.JalrUnresolved))
	default:
		a.Verdict = ReachabilityProvenSafe
		a.Reason = "complete direct/indirect chain proves every hook execution follows the first carrier load + FlushCache"
	}
	return a, nil
}

func reachableSet(g map[uint32][]uint32, root uint32) map[uint32]bool {
	seen := map[uint32]bool{root: true}
	q := []uint32{root}
	for len(q) > 0 {
		x := q[0]
		q = q[1:]
		for _, y := range g[x] {
			if !seen[y] {
				seen[y] = true
				q = append(q, y)
			}
		}
	}
	return seen
}

// countExactWordRefs counts 4-byte words equal to target in the EXE. It is used
// to show that no static function-pointer table holds a hook entry address.
func countExactWordRefs(exe []byte, target uint32) int {
	n := 0
	for pc := uint32(reachTextStart); pc+4 <= reachTextEnd; pc += 4 {
		if wordAt(exe, pc) == target {
			n++
		}
	}
	return n
}

func countOverlayJAL(ov []byte, target uint32) int {
	n := 0
	for off := 0; off+4 <= len(ov); off += 4 {
		w := binary.LittleEndian.Uint32(ov[off:])
		if w>>26 != 3 {
			continue
		}
		pc := uint32(OverlaySlotBase) + uint32(off)
		if ((pc+4)&0xF0000000)|((w&0x03FFFFFF)<<2) == target {
			n++
		}
	}
	return n
}

// FormatReachabilityVerdict is the stable one-line evidence string.
func FormatReachabilityVerdict(a ReachabilityAudit) string {
	return fmt.Sprintf("reachability: %s (formatter_preload=%t speaker_preload=%t fmt_callers=%d spk_callers=%d speaker_modes=%x preload_modes=%x scene_entries=%d load_scenes=%d jalr=%d unresolved=%d)",
		a.Verdict, a.FormatterPreLoadReachable, a.SpeakerPreLoadReachable,
		len(a.FormatterCallers), len(a.SpeakerCallers), a.SpeakerStates, a.PreLoadStates,
		a.DistinctSceneEntries, len(a.LoadTriggeringScenes), a.JalrSites, len(a.JalrUnresolved))
}
