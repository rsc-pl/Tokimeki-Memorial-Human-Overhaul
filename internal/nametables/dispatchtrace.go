package nametables

// G40: strictly bounded, read-only original-disc EXE excerpts needed to trace
// the G39 overlay entry dispatcher. Lexical disassembly is NOT runtime or CFG
// evidence. In particular, RAM ownership/BSS/loader behavior remain unknown.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const N10OriginalEXESHA = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
const n10FileToRAM uint32 = 0x80040800

type N10TraceInstruction struct {
	FileOffset    int    `json:"file_offset"`
	RAM           string `json:"ram"`
	Word          string `json:"word"`
	LexicalDecode string `json:"lexical_decode"`
	ControlTarget string `json:"control_target,omitempty"`
}
type N10TraceWindow struct {
	Label                  string                `json:"label"`
	Reason                 string                `json:"reason"`
	StartFileOffset        int                   `json:"start_file_offset"`
	EndFileOffsetExclusive int                   `json:"end_file_offset_exclusive"`
	Instructions           []N10TraceInstruction `json:"instructions"`
}
type N10TraceControlSite struct {
	Window     string `json:"window"`
	FileOffset int    `json:"file_offset"`
	Decode     string `json:"decode"`
	Target     string `json:"target,omitempty"`
}
type N10DispatchTraceReport struct {
	Status                     string                `json:"status"`
	OwnerG38SHA256             string                `json:"owner_g38_sha256"`
	OriginalEXESHA256          string                `json:"original_exe_sha256"`
	OriginalSourceVerified     bool                  `json:"original_source_verified"`
	DispatcherPointerSlot      string                `json:"dispatcher_pointer_slot"`
	DispatcherJoin             string                `json:"dispatcher_join"`
	PointerReadFileOffset      int                   `json:"pointer_read_file_offset"`
	SourceWindowBytes          int                   `json:"source_window_bytes"`
	Windows                    []N10TraceWindow      `json:"windows"`
	LexicalControlSites        []N10TraceControlSite `json:"lexical_control_sites"`
	StaticFlow                 *N10TraceFlowReview   `json:"static_flow,omitempty"`
	RuntimeLoaderVerified      bool                  `json:"runtime_loader_verified"`
	BSSAndRAMOwnershipVerified bool                  `json:"bss_and_ram_ownership_verified"`
	SafeToPatch                bool                  `json:"safe_to_patch"`
	Limitations                []string              `json:"limitations"`
}

type n10TraceSpec struct {
	label, reason string
	from, to      int
}

// Named, finite windows only. No blanket EXE/ISO disassembly or ROM mutation.
func n10TraceSpecs() []n10TraceSpec {
	targetOffset := func(ram uint32) int { return int(ram - n10FileToRAM) }
	return []n10TraceSpec{
		{"dispatcher-and-indirect-call", "Around the G39 45-arm join 232604, entry pointer read 233200 and its consumers", 230400, 233984},
		{"callee-0x8009C674", "Direct JAL target seen immediately before G39's entry-pointer read", targetOffset(0x8009C674) - 64, targetOffset(0x8009C674) + 704},
		{"callee-0x8009C210", "Direct JAL target in adjacent original-disc G38 window", targetOffset(0x8009C210) - 64, targetOffset(0x8009C210) + 704},
		{"callee-0x800AF1A0", "Direct JAL target directly after a G39 entry-slot store", targetOffset(0x800AF1A0) - 64, targetOffset(0x800AF1A0) + 704},
	}
}

var n10Regs = []string{"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"}

func n10Reg(n uint32) string { return "$" + n10Regs[n&31] }

// MIPS R3000A instruction rendering of a word, NOT a CFG assertion.
// Unknown opcodes are deliberately left as literal words.
func decodeN10Word(w uint32, ram uint32) (string, string) {
	op, rs, rt, rd := w>>26, (w>>21)&31, (w>>16)&31, (w>>11)&31
	imm := int16(w & 0xffff)
	off := fmt.Sprintf("%d(%s)", imm, n10Reg(rs))
	if w == 0 {
		return "nop", ""
	}
	switch op {
	case 0:
		switch w & 63 {
		case 8:
			return fmt.Sprintf("jr %s", n10Reg(rs)), "indirect"
		case 9:
			return fmt.Sprintf("jalr %s,%s", n10Reg(rd), n10Reg(rs)), "indirect"
		case 33:
			return fmt.Sprintf("addu %s,%s,%s", n10Reg(rd), n10Reg(rs), n10Reg(rt)), ""
		case 35:
			return fmt.Sprintf("subu %s,%s,%s", n10Reg(rd), n10Reg(rs), n10Reg(rt)), ""
		case 37:
			return fmt.Sprintf("or %s,%s,%s", n10Reg(rd), n10Reg(rs), n10Reg(rt)), ""
		case 0:
			return fmt.Sprintf("sll %s,%s,%d", n10Reg(rd), n10Reg(rt), (w>>6)&31), ""
		case 2:
			return fmt.Sprintf("srl %s,%s,%d", n10Reg(rd), n10Reg(rt), (w>>6)&31), ""
		}
	case 2, 3:
		target := (ram+4)&0xF0000000 | ((w & 0x03ffffff) << 2)
		name := "j"
		if op == 3 {
			name = "jal"
		}
		return fmt.Sprintf("%s 0x%08X", name, target), fmt.Sprintf("0x%08X", target)
	case 4, 5, 6, 7:
		dest := uint32(int64(ram) + 4 + int64(imm)*4)
		name := []string{"beq", "bne", "blez", "bgtz"}[op-4]
		if op < 6 {
			return fmt.Sprintf("%s %s,%s,0x%08X", name, n10Reg(rs), n10Reg(rt), dest), fmt.Sprintf("0x%08X", dest)
		}
		return fmt.Sprintf("%s %s,0x%08X", name, n10Reg(rs), dest), fmt.Sprintf("0x%08X", dest)
	case 9:
		return fmt.Sprintf("addiu %s,%s,%d", n10Reg(rt), n10Reg(rs), imm), ""
	case 13:
		return fmt.Sprintf("ori %s,%s,0x%04X", n10Reg(rt), n10Reg(rs), w&0xffff), ""
	case 15:
		return fmt.Sprintf("lui %s,0x%04X", n10Reg(rt), w&0xffff), ""
	case 32:
		return fmt.Sprintf("lb %s,%s", n10Reg(rt), off), ""
	case 33:
		return fmt.Sprintf("lh %s,%s", n10Reg(rt), off), ""
	case 35:
		return fmt.Sprintf("lw %s,%s", n10Reg(rt), off), ""
	case 36:
		return fmt.Sprintf("lbu %s,%s", n10Reg(rt), off), ""
	case 37:
		return fmt.Sprintf("lhu %s,%s", n10Reg(rt), off), ""
	case 40:
		return fmt.Sprintf("sb %s,%s", n10Reg(rt), off), ""
	case 41:
		return fmt.Sprintf("sh %s,%s", n10Reg(rt), off), ""
	case 43:
		return fmt.Sprintf("sw %s,%s", n10Reg(rt), off), ""
	}
	return fmt.Sprintf("unclassified 0x%08X", w), ""
}

func n10TraceWindows(exe []byte) (N10DispatchTraceReport, error) {
	r := N10DispatchTraceReport{
		Status:                "G40_FOCUSED_ORIGINAL_EXE_DISPATCH_AND_CALLEES_LEXICAL_ONLY_DO_NOT_BOOT",
		DispatcherPointerSlot: "0x80123110", DispatcherJoin: "0x8007949C", PointerReadFileOffset: 233200,
		Windows: []N10TraceWindow{}, LexicalControlSites: []N10TraceControlSite{},
		Limitations: []string{
			"Lexical words are not proof of execution, control flow or reachable indirect jumps",
			"Only four targeted original-EXE windows are extracted; called functions may extend beyond the windows",
			"EXE declaration and static opcodes do not prove the overlay disc IO destination, BSS clearing or RAM liveness",
			"No writes to original game, translation, save state, Git or Go production builder",
			"N10 16 surnames HOLD / DO_NOT_BOOT; append bounds, aliases and UI fit remain unproven",
		},
	}
	if len(exe) != 667648 {
		return r, errors.New("not the expected original retail EXE size")
	}
	for _, spec := range n10TraceSpecs() {
		if spec.from < 2048 || spec.to > len(exe) || spec.from >= spec.to || spec.from%4 != 0 || spec.to%4 != 0 || spec.to-spec.from > 4096 {
			return r, fmt.Errorf("invalid bounded trace window %s", spec.label)
		}
		window := N10TraceWindow{Label: spec.label, Reason: spec.reason, StartFileOffset: spec.from, EndFileOffsetExclusive: spec.to, Instructions: []N10TraceInstruction{}}
		r.SourceWindowBytes += spec.to - spec.from
		for off := spec.from; off < spec.to; off += 4 {
			w := binary.LittleEndian.Uint32(exe[off : off+4])
			ram := n10FileToRAM + uint32(off)
			dec, target := decodeN10Word(w, ram)
			window.Instructions = append(window.Instructions, N10TraceInstruction{FileOffset: off, RAM: fmt.Sprintf("0x%08X", ram), Word: fmt.Sprintf("%08X", w), LexicalDecode: dec, ControlTarget: target})
			if target != "" {
				r.LexicalControlSites = append(r.LexicalControlSites, N10TraceControlSite{Window: spec.label, FileOffset: off, Decode: dec, Target: target})
			}
		}
		r.Windows = append(r.Windows, window)
	}
	if r.SourceWindowBytes > 8192 {
		return r, errors.New("too many bytes extracted")
	}
	// Make site ordering stable across tools/OS builds.
	sort.Slice(r.LexicalControlSites, func(i, j int) bool { return r.LexicalControlSites[i].FileOffset < r.LexicalControlSites[j].FileOffset })
	return r, nil
}

func BuildN10DispatchTrace(exe []byte, r N10LoaderFollowupReport, g38sha string) (N10DispatchTraceReport, error) {
	if len(g38sha) != 64 || r.Status != "G38_ORIGINAL_ODD_BIN_AND_MAIN_LOADER_ANCHORS_STATIC_ONLY_DO_NOT_BOOT" ||
		!r.OriginalSourcesVerified || r.FullControlFlowVerified || r.RuntimeLoaderVerified || r.BSSAndWritableMemoryVerified || r.SafeToPatch ||
		r.OwnerOriginalEXESHA256 != N10OriginalEXESHA || len(r.MainOverlayAddressPairs) != 48 || len(r.MainDirectOverlayJAL) != 2 ||
		len(exe) != 667648 || fmt.Sprintf("%x", sha256.Sum256(exe)) != N10OriginalEXESHA {
		return N10DispatchTraceReport{}, errors.New("original EXE / G38 provenance failed; refusing to generate trace")
	}
	// Recheck EVERY original captured context word, not only a report label.
	for _, site := range r.MainOverlayAddressPairs {
		for _, sample := range site.Words {
			if sample.Offset < 0 || sample.Offset+4 > len(exe) || sample.Offset%4 != 0 || fmt.Sprintf("%08X", binary.LittleEndian.Uint32(exe[sample.Offset:sample.Offset+4])) != sample.Hex {
				return N10DispatchTraceReport{}, fmt.Errorf("G38 source code differs at file offset %d", sample.Offset)
			}
		}
	}
	for _, site := range r.MainDirectOverlayJAL {
		for _, sample := range site.Words {
			if sample.Offset < 0 || sample.Offset+4 > len(exe) || sample.Offset%4 != 0 || fmt.Sprintf("%08X", binary.LittleEndian.Uint32(exe[sample.Offset:sample.Offset+4])) != sample.Hex {
				return N10DispatchTraceReport{}, fmt.Errorf("G38 prior JAL-like context differs at %d", sample.Offset)
			}
		}
	}
	if binary.LittleEndian.Uint32(exe[233196:]) != 0x3C198012 || binary.LittleEndian.Uint32(exe[233200:]) != 0x8F393110 {
		return N10DispatchTraceReport{}, errors.New("entry slot read differs from G39")
	}
	out, err := n10TraceWindows(exe)
	if err != nil {
		return out, err
	}
	out.OwnerG38SHA256 = g38sha
	out.OriginalEXESHA256 = N10OriginalEXESHA
	out.OriginalSourceVerified = true
	return out, nil
}
