package nametables

// G41: a conservative *bounded* lexical reachability model over the four
// original-EXE code windows collected in G40. This is not a true control-flow
// graph, not a runtime trace, and not evidence of writable-memory ownership.
// Instruction delay slots are included; unknown / out-of-window successors
// remain unresolved instead of being silently marked safe.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
)

type N10FlowSite struct {
	FileOffset  int    `json:"file_offset"`
	Word        string `json:"word"`
	Decode      string `json:"decode"`
	Destination string `json:"destination,omitempty"`
}

type N10FlowSeed struct {
	Label              string        `json:"label"`
	StartOffset        int           `json:"start_offset"`
	ReachableWords     int           `json:"reachable_words"`
	DirectCalls        []N10FlowSite `json:"direct_calls"`
	IndirectControl    []N10FlowSite `json:"indirect_control"`
	StoreWords         []N10FlowSite `json:"store_words"`
	UnresolvedEdges    []N10FlowSite `json:"unresolved_edges"`
	UnknownWords       int           `json:"unknown_words"`
	ReachedPointerRead bool          `json:"reached_pointer_read"`
	WorklistLimitHit   bool          `json:"worklist_limit_hit"`
}

type N10TraceFlowReview struct {
	Status                           string        `json:"status"`
	Seeds                            []N10FlowSeed `json:"seeds"`
	PointerReadOffset                int           `json:"pointer_read_offset"`
	PointerReadWordVerified          bool          `json:"pointer_read_word_verified"`
	SyntacticT9IndirectWithin64Bytes []N10FlowSite `json:"syntactic_t9_indirect_within_64_bytes"`
	RuntimeLoaderVerified            bool          `json:"runtime_loader_verified"`
	BSSOrHeapVerified                bool          `json:"bss_or_heap_verified"`
	SafeToPatch                      bool          `json:"safe_to_patch"`
	Limitations                      []string      `json:"limitations"`
}

func flowHex(word string) (uint32, error) {
	if len(word) != 8 {
		return 0, errors.New("expected eight hex digits")
	}
	n, err := strconv.ParseUint(word, 16, 32)
	return uint32(n), err
}

func flowSite(i N10TraceInstruction) N10FlowSite {
	return N10FlowSite{FileOffset: i.FileOffset, Word: i.Word, Decode: i.LexicalDecode, Destination: i.ControlTarget}
}

func flowTargetOffset(word uint32, off int) int {
	addr := n10FileToRAM + uint32(off)
	if word>>26 == 2 || word>>26 == 3 { // J/JAL
		dest := (addr+4)&0xF0000000 | ((word & 0x03ffffff) << 2)
		if dest < n10FileToRAM {
			return -1
		}
		return int(dest - n10FileToRAM)
	}
	return off + 4 + int(int16(word&0xffff))*4 // branch
}

func n10TraceFlow(trace N10DispatchTraceReport) (N10TraceFlowReview, error) {
	out := N10TraceFlowReview{
		Status:            "G41_BOUNDED_STATIC_FLOW_OVERAPPROXIMATION_NOT_RUNTIME_N10_HOLD_DO_NOT_BOOT",
		PointerReadOffset: 233200, Seeds: []N10FlowSeed{},
		SyntacticT9IndirectWithin64Bytes: []N10FlowSite{},
		Limitations: []string{
			"Reachability is a conservative lexical approximation only, not actual executed paths",
			"Unconditional JAL call targets are listed but not traversed unless they are explicit seeds",
			"Delay slots are included without dataflow/branch-likely modeling; unknown instructions and indirect jumps remain unresolved",
			"Individual instruction windows may truncate functions; edges outside those windows are not followed",
			"Nearby $t9 indirect syntax alone does not prove the loaded slot value reaches that jump",
			"No disc reads, overlay loader buffer destinations, writable RAM/BSS, worst-case string bounds or UI fit are certified",
		},
	}
	if !trace.OriginalSourceVerified || trace.SafeToPatch || trace.RuntimeLoaderVerified || trace.BSSAndRAMOwnershipVerified ||
		trace.OriginalEXESHA256 != N10OriginalEXESHA || trace.DispatcherPointerSlot != "0x80123110" ||
		trace.PointerReadFileOffset != 233200 || len(trace.Windows) != 4 || trace.SourceWindowBytes != 5888 {
		return out, errors.New("G40 trace missing original-disc source proof or safe HOLD status")
	}
	instructions := make(map[int]N10TraceInstruction)
	raw := make(map[int]uint32)
	for _, win := range trace.Windows {
		if win.StartFileOffset < 2048 || win.EndFileOffsetExclusive <= win.StartFileOffset ||
			(win.EndFileOffsetExclusive-win.StartFileOffset)/4 != len(win.Instructions) ||
			win.EndFileOffsetExclusive-win.StartFileOffset > 4096 {
			return out, errors.New("malformed window")
		}
		for j, inst := range win.Instructions {
			if inst.FileOffset != win.StartFileOffset+j*4 {
				return out, errors.New("missing or duplicate instructions")
			}
			w, err := flowHex(inst.Word)
			if err != nil {
				return out, err
			}
			dec, target := decodeN10Word(w, n10FileToRAM+uint32(inst.FileOffset))
			if inst.LexicalDecode != dec || inst.ControlTarget != target ||
				inst.RAM != fmt.Sprintf("0x%08X", n10FileToRAM+uint32(inst.FileOffset)) {
				return out, fmt.Errorf("mismatched original code decode at %d", inst.FileOffset)
			}
			if _, duplicated := instructions[inst.FileOffset]; duplicated {
				return out, errors.New("overlapping windows")
			}
			instructions[inst.FileOffset] = inst
			raw[inst.FileOffset] = w
		}
	}
	if raw[233196] != 0x3C198012 || raw[233200] != 0x8F393110 {
		return out, errors.New("G39 pointer read missing")
	}
	out.PointerReadWordVerified = true
	for off := 233204; off <= 233264; off += 4 {
		w, ok := raw[off]
		if !ok {
			break
		}
		if w>>26 == 0 && (w&63 == 8 || w&63 == 9) && ((w>>21)&31) == 25 {
			out.SyntacticT9IndirectWithin64Bytes = append(out.SyntacticT9IndirectWithin64Bytes, flowSite(instructions[off]))
		}
	}
	seeds := []struct {
		label string
		off   int
	}{
		{"dispatch-common-join", 232604}, {"isolated-entry-slot-writer", 233148},
		{"callee-0x8009C674", int(0x8009C674 - n10FileToRAM)},
		{"callee-0x8009C210", int(0x8009C210 - n10FileToRAM)},
		{"callee-0x800AF1A0", int(0x800AF1A0 - n10FileToRAM)},
	}
	for _, seed := range seeds {
		if _, ok := raw[seed.off]; !ok {
			return out, fmt.Errorf("seed missing %s", seed.label)
		}
		s := N10FlowSeed{Label: seed.label, StartOffset: seed.off, DirectCalls: []N10FlowSite{}, IndirectControl: []N10FlowSite{}, StoreWords: []N10FlowSite{}, UnresolvedEdges: []N10FlowSite{}}
		// Each queued instruction is either an ordinary control-flow position
		// or a delay slot. A delay slot does NOT fall through independently
		// after JR/J/branch; only the parent transfer selects successors.
		type node struct {
			off   int
			delay bool
		}
		seen := map[node]bool{}
		counted := map[int]bool{}
		q := []node{{seed.off, false}}
		push := func(off int, delay bool, origin N10TraceInstruction) {
			if _, exists := raw[off]; exists {
				key := node{off, delay}
				if !seen[key] {
					q = append(q, key)
				}
			} else if len(s.UnresolvedEdges) < 80 {
				s.UnresolvedEdges = append(s.UnresolvedEdges, N10FlowSite{FileOffset: origin.FileOffset, Word: origin.Word, Decode: origin.LexicalDecode, Destination: fmt.Sprintf("unresolved next offset %d", off)})
			}
		}
		for len(q) > 0 {
			if len(seen) >= 2048 {
				s.WorklistLimitHit = true
				break
			}
			n := q[0]
			q = q[1:]
			if seen[n] {
				continue
			}
			inst, ok := instructions[n.off]
			if !ok {
				continue
			}
			seen[n] = true
			w := raw[n.off]
			op := w >> 26
			if !counted[n.off] {
				counted[n.off] = true
				s.ReachableWords++
				if n.off == 233200 {
					s.ReachedPointerRead = true
				}
				if len(inst.LexicalDecode) >= 12 && inst.LexicalDecode[:12] == "unclassified" {
					s.UnknownWords++
				}
				if (op == 40 || op == 41 || op == 43) && len(s.StoreWords) < 80 {
					s.StoreWords = append(s.StoreWords, flowSite(inst))
				}
				if op == 3 {
					s.DirectCalls = append(s.DirectCalls, flowSite(inst))
				}
				if op == 0 && (w&63 == 8 || w&63 == 9) {
					s.IndirectControl = append(s.IndirectControl, flowSite(inst))
				}
			}
			if n.delay {
				continue
			}
			if op == 0 && (w&63 == 8 || w&63 == 9) {
				push(n.off+4, true, inst)
				if w&63 == 9 {
					push(n.off+8, false, inst)
				} // indirect call MAY return
				continue
			}
			isBranch := op == 4 || op == 5 || op == 6 || op == 7 || op == 1
			if op == 2 || op == 3 || isBranch {
				push(n.off+4, true, inst)
				target := flowTargetOffset(w, n.off)
				if op == 3 {
					push(n.off+8, false, inst)
					continue
				} // call only known fall-through
				if op == 2 {
					push(target, false, inst)
					continue
				}
				if op == 4 && ((w>>21)&31) == 0 && ((w>>16)&31) == 0 {
					push(target, false, inst)
					continue
				}
				if op == 5 && ((w>>21)&31) == 0 && ((w>>16)&31) == 0 {
					push(n.off+8, false, inst)
					continue
				}
				push(target, false, inst)
				push(n.off+8, false, inst)
				continue
			}
			push(n.off+4, false, inst)
		}
		sort.Slice(s.DirectCalls, func(i, j int) bool { return s.DirectCalls[i].FileOffset < s.DirectCalls[j].FileOffset })
		sort.Slice(s.IndirectControl, func(i, j int) bool { return s.IndirectControl[i].FileOffset < s.IndirectControl[j].FileOffset })
		sort.Slice(s.StoreWords, func(i, j int) bool { return s.StoreWords[i].FileOffset < s.StoreWords[j].FileOffset })
		out.Seeds = append(out.Seeds, s)
	}
	return out, nil
}

// BuildN10DispatchTraceG41 preserves the G40 original-disc SHA and contextual
// source gates, then annotates those SAME bounded bytes with a static graph.
func BuildN10DispatchTraceG41(exe []byte, previous N10LoaderFollowupReport, g38sha string) (N10DispatchTraceReport, error) {
	r, err := BuildN10DispatchTrace(exe, previous, g38sha)
	if err != nil {
		return r, err
	}
	flow, err := n10TraceFlow(r)
	if err != nil {
		return N10DispatchTraceReport{}, err
	}
	r.StaticFlow = &flow
	r.Status = "G41_FOCUSED_DISPATCH_TRACE_WITH_BOUNDED_STATIC_FLOW_N10_DO_NOT_BOOT"
	return r, nil
}
