package nametables

// G45: reconstruct the op-6 queue layout from SHA-verified original retail
// source reports, and capture only bounded downstream instructions. Nothing
// below executes on the game, observes DMA, or makes name patching safe.
import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
)

const N10OwnerG44RouteSHA = "68a4d6f6c25afe7d1d07630675e4813f4c4085b9ae482bf5ca40eef40dd380dc"

// The end address is EXCLUSIVE: adjacent state at 0x801255B0 is not spare memory.
type N10QueueLayoutG45 struct {
	QueueBase           string `json:"queue_base"`
	Capacity            int    `json:"capacity"`
	RecordStride        int    `json:"record_stride_bytes"`
	QueueEndExclusive   string `json:"queue_end_exclusive"`
	ProducerIndex       string `json:"producer_index"`
	OtherQueueCounter   string `json:"other_queue_counter"`
	OpcodeOffset        int    `json:"opcode_offset"`
	ArgumentOffset      int    `json:"argument_offset"`
	DescriptorOffset    int    `json:"descriptor_offset"`
	DescriptorCopyBytes int    `json:"descriptor_copy_bytes_when_pointer_nonzero"`
	LastByteFlagOffset  int    `json:"last_byte_flag_offset"`
	FullQueueComparison string `json:"full_queue_comparison"`
}

type N10QueueFollowupG45 struct {
	Status                        string            `json:"status"`
	OriginalEXESHA256             string            `json:"original_exe_sha256"`
	OwnerG44SHA256                string            `json:"owner_g44_sha256"`
	OwnerG43SHA256                string            `json:"owner_g43_sha256"`
	G44SourceVerified             bool              `json:"g44_source_verified"`
	G43QueueTailVerified          bool              `json:"g43_queue_tail_verified"`
	OriginalEXEVerified           bool              `json:"original_exe_verified"`
	Operation6Target              string            `json:"operation_6_target"`
	Queue                         N10QueueLayoutG45 `json:"queue"`
	ExtraCodeWindows              []N10TraceWindow  `json:"extra_code_windows"`
	QueueExecutionRuntimeVerified bool              `json:"queue_execution_runtime_verified"`
	DeviceTransferVerified        bool              `json:"device_transfer_verified"`
	DMAAndDestinationVerified     bool              `json:"dma_and_destination_verified"`
	BufferOwnershipVerified       bool              `json:"buffer_ownership_verified"`
	SafeToPatch                   bool              `json:"safe_to_patch"`
	Limitations                   []string          `json:"limitations"`
}

func queueG45WordMap(wins []N10TraceWindow) (map[uint32]uint32, error) {
	out := make(map[uint32]uint32)
	for _, w := range wins {
		if w.StartFileOffset < 2048 || w.EndFileOffsetExclusive > w.StartFileOffset+2048 ||
			(w.EndFileOffsetExclusive-w.StartFileOffset)/4 != len(w.Instructions) ||
			w.StartFileOffset%4 != 0 || w.EndFileOffsetExclusive%4 != 0 {
			return nil, fmt.Errorf("G45 source window geometry rejected")
		}
		for i, v := range w.Instructions {
			off := w.StartFileOffset + i*4
			at := n10FileToRAM + uint32(off)
			if v.FileOffset != off || v.RAM != fmt.Sprintf("0x%08X", at) || len(v.Word) != 8 {
				return nil, fmt.Errorf("G45 source continuity rejected")
			}
			x, e := strconv.ParseUint(v.Word, 16, 32)
			if e != nil {
				return nil, e
			}
			if _, found := out[at]; found {
				return nil, fmt.Errorf("G45 duplicate source opcode")
			}
			out[at] = uint32(x)
		}
	}
	return out, nil
}

func ReviewN10QueueG45(rawG44 []byte, rawG43 []byte) (N10QueueFollowupG45, error) {
	r := N10QueueFollowupG45{
		Status:         "G45_STATIC_RING_QUEUE_DOWNSTREAM_CAPTURE_N10_HOLD",
		OwnerG44SHA256: N10OwnerG44RouteSHA, OwnerG43SHA256: N10OwnerG43TransferSHA,
		OriginalEXESHA256: N10OriginalEXESHA, Operation6Target: "0x80045494",
		Queue: N10QueueLayoutG45{
			QueueBase: "0x80125130", Capacity: 48, RecordStride: 24, QueueEndExclusive: "0x801255B0",
			ProducerIndex: "0x80125129", OtherQueueCounter: "0x80125128", OpcodeOffset: 0,
			ArgumentOffset: 4, DescriptorOffset: 8, DescriptorCopyBytes: 16, LastByteFlagOffset: 23,
			FullQueueComparison: "modulo-48 counter comparison; static only",
		},
		ExtraCodeWindows: []N10TraceWindow{},
		Limitations: []string{
			"The 48 x 24-byte RAM queue and op-6 handler are derived from original static code; executed-PC evidence missing",
			"0x801255B0 is immediately adjacent state and is NOT proven free memory",
			"The descriptor copy at offset +8 is a bounded function call; its exact implementation remains to be classified",
			"The packed word 0x60132000 must not be interpreted directly as a RAM pointer",
			"No CD transfer/DMA completion, target RAM ownership, writable lifetime, heap/BSS alias or renderer buffer capacity verified",
			"N10 all 16 surname edits HOLD / DO_NOT_BOOT; no game, translation, Git or builder writes",
		},
	}
	if len(rawG44) > 256<<10 || fmt.Sprintf("%x", sha256.Sum256(rawG44)) != N10OwnerG44RouteSHA ||
		len(rawG43) > 256<<10 || fmt.Sprintf("%x", sha256.Sum256(rawG43)) != N10OwnerG43TransferSHA {
		return r, fmt.Errorf("G45 original owner reports SHA mismatch")
	}
	var owner N10RequestRouteReviewG44
	var prev N10DescriptorReviewG43
	if e := json.Unmarshal(rawG44, &owner); e != nil {
		return r, e
	}
	if e := json.Unmarshal(rawG43, &prev); e != nil {
		return r, e
	}
	if owner.Status != "G44_STATIC_REQUEST_DISPATCH_TABLE_EXE_ONLY_N10_HOLD" || owner.OwnerG43SHA256 != N10OwnerG43TransferSHA || owner.OriginalEXESHA256 != N10OriginalEXESHA ||
		!owner.OwnerSourceVerified || !owner.OriginalEXEVerified || owner.RequestedOperation != 6 || owner.DispatchTableBase != "0x800AF810" || owner.DispatchTableLength != 28 || owner.Operation6EntryAddress != "0x800AF828" || owner.Operation6Target != "0x80045494" ||
		!owner.Operation6TargetInMainEXECode || !owner.Operation6IsCandidate45494 || owner.Operation6BranchRuntimeVerified || owner.SafeToPatch || owner.SectorTransferVerified || owner.OverlayRAMBoundsVerified ||
		len(owner.Entries) != 28 || len(owner.NewCodeWindows) != 4 ||
		prev.Status != "G43_ORIGINAL_MIPS_PACKED_REQUEST_STATIC_ONLY_DO_NOT_BOOT" || prev.OriginalEXESHA != N10OriginalEXESHA || !prev.SourceVerified || prev.SafeToPatch {
		return r, fmt.Errorf("G45 evidence status/header inconsistent")
	}
	for i, v := range owner.Entries {
		if v.Operation != i || v.TableAddress != fmt.Sprintf("0x%08X", uint32(0x800AF810+i*4)) || v.FileOffset != int(uint32(0x800AF810+i*4)-n10FileToRAM) || !v.Aligned || !v.InMainEXECodeRange {
			return r, fmt.Errorf("G45 table entry %d inconsistent", i)
		}
	}
	if owner.Entries[6].WordLittleEndian != "0x80045494" {
		return r, fmt.Errorf("G45 operation 6 table word differs")
	}
	code, e := queueG45WordMap(owner.NewCodeWindows)
	if e != nil {
		return r, e
	}
	tail, e := queueG45WordMap(prev.NewCodeWindows)
	if e != nil {
		return r, e
	}
	anchor := map[uint32]uint32{
		// producer and cyclic modulo-48 buffer indexing
		0x80045318: 0x3C0F8012, 0x8004531C: 0x91EF5128, 0x80045320: 0x24020030,
		0x80045324: 0x01E2001B, 0x8004532C: 0x91085129,
		0x80045338: 0x00084880, 0x8004533C: 0x01284823, 0x80045348: 0x000948C0,
		0x8004534C: 0x254A5130, 0x80045378: 0x0062001B,
		0x80045388: 0x012A1021, 0x80045390: 0x17190003,
		// packet fields and 16 byte payload copy
		0x800453A0: 0xA0440000, 0x800453A4: 0xAC450004,
		0x800453A8: 0x14E10004, 0x800453AC: 0xA0400017,
		0x800453BC: 0x10E00008, 0x800453C0: 0x24440008,
		0x800453C4: 0x00E02825, 0x800453C8: 0x0C02B828,
		0x800453CC: 0x24060010,
	}
	for at, w := range anchor {
		if got, ok := code[at]; !ok || got != w {
			return r, fmt.Errorf("G45 retail enqueue opcode mismatch at %08X", at)
		}
	}
	tailAnchors := map[uint32]uint32{
		0x80045494: 0x3C01800B, 0x80045498: 0xAC273D6C,
		0x8004549C: 0x24040006, 0x800454A0: 0x0C0114C6,
		0x800454A4: 0x00E02825,
		0x800453D0: 0x3C088012, 0x800453D4: 0x91085129,
		0x800453DC: 0x25030001, 0x800453E0: 0x306800FF,
		0x800453E4: 0x2D010030, 0x800453E8: 0x10200004,
		0x800453F0: 0xA0285129, 0x800453FC: 0x3C018012,
		0x80045400: 0xA0205129, 0x8004540C: 0x03E00008,
		0x800455C4: 0x3C0E8012, 0x800455CC: 0x91EF5129,
		0x800455D0: 0x91CE5128, 0x800455E0: 0x0C0118FA,
	}
	for at, w := range tailAnchors {
		if got, ok := tail[at]; !ok || got != w {
			return r, fmt.Errorf("G45 queue tail/consumer mismatch at %08X", at)
		}
	}
	r.G44SourceVerified = true
	r.G43QueueTailVerified = true
	return r, nil
}

type n10Queue45Window struct {
	label      string
	start, end uint32
}

func queueG45Windows() []n10Queue45Window {
	return []n10Queue45Window{
		{"request-queue-consumer-continuation", 0x800458A0, 0x80046070},
		{"request-descriptor-copy-helper", 0x800AE080, 0x800AE140},
		{"request-queue-consumer-helper", 0x800463D0, 0x800464A0},
	}
}

func CaptureN10QueueG45(exe []byte, r N10QueueFollowupG45) (N10QueueFollowupG45, error) {
	if !r.G44SourceVerified || !r.G43QueueTailVerified || r.SafeToPatch || r.QueueExecutionRuntimeVerified || r.DeviceTransferVerified || r.DMAAndDestinationVerified || r.BufferOwnershipVerified ||
		len(exe) != 667648 || fmt.Sprintf("%x", sha256.Sum256(exe)) != N10OriginalEXESHA {
		return r, fmt.Errorf("G45 requires original retail EXE SHA and verified G44/G43 source")
	}
	return captureG45VerifiedEXE(exe, r)
}
func captureG45VerifiedEXE(exe []byte, r N10QueueFollowupG45) (N10QueueFollowupG45, error) {
	if !r.G44SourceVerified || !r.G43QueueTailVerified || len(r.ExtraCodeWindows) > 0 || r.SafeToPatch || r.OriginalEXEVerified {
		return r, fmt.Errorf("G45 rejected unsafe/repeated capture")
	}
	for _, spec := range queueG45Windows() {
		if spec.start < n10FileToRAM+2048 || spec.end <= spec.start || spec.end > n10FileToRAM+uint32(len(exe)) || spec.end-spec.start > 2048 {
			return r, fmt.Errorf("G45 invalid bounded code window")
		}
		start := int(spec.start - n10FileToRAM)
		end := int(spec.end - n10FileToRAM)
		w := N10TraceWindow{Label: spec.label, Reason: "Original EXE static MIPS; no executed PC or DMA proof", StartFileOffset: start, EndFileOffsetExclusive: end, Instructions: []N10TraceInstruction{}}
		for off := start; off < end; off += 4 {
			word := uint32(exe[off]) | uint32(exe[off+1])<<8 | uint32(exe[off+2])<<16 | uint32(exe[off+3])<<24
			addr := n10FileToRAM + uint32(off)
			dec, target := decodeN10Word(word, addr)
			w.Instructions = append(w.Instructions, N10TraceInstruction{FileOffset: off, RAM: fmt.Sprintf("0x%08X", addr), Word: fmt.Sprintf("%08X", word), LexicalDecode: dec, ControlTarget: target})
		}
		r.ExtraCodeWindows = append(r.ExtraCodeWindows, w)
	}
	r.OriginalEXEVerified = true
	return r, nil
}
