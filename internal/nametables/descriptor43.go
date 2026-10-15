package nametables

// G43 examines owner-supplied, SHA-gated original MIPS words. A packed request
// descriptor is not an observed DMA transfer or proof of writable overlay RAM.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const N10OwnerG42IOSHA = "ffd9954c91a751ab9c76708033bd8f633d483d99f06f4ec6c942894b07723d5d"

type N10DescriptorReviewG43 struct {
	Status                                 string           `json:"status"`
	OwnerG42SHA                            string           `json:"owner_g42_sha256"`
	OriginalEXESHA                         string           `json:"original_exe_sha256"`
	SourceVerified                         bool             `json:"original_source_verified"`
	AddressBeforePacking                   string           `json:"address_before_packing"`
	Sectors                                int              `json:"sector_count"`
	PackedDescriptor                       string           `json:"packed_descriptor_word_little_endian"`
	PackedBytePattern                      string           `json:"packed_descriptor_bytes_low_to_high"`
	DescriptorStackOffset                  int              `json:"descriptor_stack_offset"`
	DescriptorBuilder                      string           `json:"descriptor_builder"`
	RequestConsumer                        string           `json:"request_consumer_not_proven"`
	RequestOperation                       int              `json:"request_operation_argument"`
	ExampleLBA                             int64            `json:"example_tt_exn_lba"`
	SectorTransferVerified                 bool             `json:"sector_transfer_verified"`
	CalleeDescriptorInterpretationVerified bool             `json:"callee_descriptor_interpretation_verified"`
	OverlayRAMBoundsVerified               bool             `json:"overlay_ram_bounds_verified"`
	SafeToPatch                            bool             `json:"safe_to_patch"`
	NewCodeWindows                         []N10TraceWindow `json:"new_code_windows"`
	Limitations                            []string         `json:"limitations"`
}

type n10G43WindowSpec struct {
	label      string
	start, end uint32
}

func n10G43WindowSpecs() []n10G43WindowSpec {
	return []n10G43WindowSpec{
		{"packed-request-consumer-0x80045414", 0x800453D0, 0x800458A0},
		{"request-setup-0x80044750", 0x80044700, 0x800448D0},
		{"device-request-helper-0x80087C64", 0x80087C20, 0x80087E80},
		{"pre-transition-0x8009EC80", 0x8009EC40, 0x8009EDD0},
	}
}

func ReviewN10DescriptorG43(r N10IOLoaderReview) (N10DescriptorReviewG43, error) {
	out := N10DescriptorReviewG43{
		Status:      "G43_ORIGINAL_MIPS_PACKED_REQUEST_STATIC_ONLY_DO_NOT_BOOT",
		OwnerG42SHA: N10OwnerG42IOSHA, OriginalEXESHA: N10OriginalEXESHA,
		AddressBeforePacking: "0x80132000 (G41/G42 static selector hypothesis)",
		Sectors:              96, DescriptorStackOffset: 40, DescriptorBuilder: "0x800462BC",
		RequestConsumer: "0x80045414", RequestOperation: 6, ExampleLBA: 39530,
		NewCodeWindows: []N10TraceWindow{},
		Limitations: []string{
			"Packed four-byte request descriptor is statically proven, but receiver semantics have not been decoded",
			"Replacing the most significant byte of 0x80132000 is NOT proof that 0x60132000 is a virtual RAM pointer",
			"No live CD read, DMA destination, RAM lifetime, BSS clearing, heap alias or name-buffer size verified",
			"Prior G42 report has G40 lexical source schema; no G41 dynamic/static_flow data can be invented",
			"No translation, original ROM/CUE, Git or production builder writes; all 16 surname edits HOLD / DO_NOT_BOOT",
		},
	}
	if r.Status != "G42_STATIC_IO_SELECTOR_NOT_RUNTIME_N10_DO_NOT_BOOT" ||
		!r.SourceWordsVerified || r.OriginalEXESHA != N10OriginalEXESHA ||
		r.IOCallTarget != "0x80046318" || r.IOCallFileOffset != 233016 ||
		r.SelectedSectorCount != 96 || r.DestinationFromOriginalSelector != "0x80132000 via [0x800B6D3C] (static)" ||
		len(r.Windows) != 4 || len(r.SelectorMatches) != 24 ||
		r.IOFunctionImplementationVerified || r.RuntimeIOVerified || r.RAMWriteOwnershipVerified || r.SafeToPatch {
		return out, fmt.Errorf("G42 owner report identity/status mismatch or unsafe claim")
	}
	ttFound := false
	for _, s := range r.SelectorMatches {
		if strings.HasSuffix(s.Path, "/TT.EXN") && s.LBA == 39530 && s.SectorCount == 96 {
			ttFound = true
		}
	}
	if !ttFound {
		return out, fmt.Errorf("missing TT.EXN LBA geometry anchor")
	}
	words := map[uint32]uint32{}
	for _, win := range r.Windows {
		if win.StartFileOffset < 2048 || win.EndFileOffsetExclusive > 667648 || len(win.Instructions) != (win.EndFileOffsetExclusive-win.StartFileOffset)/4 {
			return out, fmt.Errorf("G42 source window malformed")
		}
		for k, ins := range win.Instructions {
			expected := win.StartFileOffset + 4*k
			if ins.FileOffset != expected || ins.RAM != fmt.Sprintf("0x%08X", n10FileToRAM+uint32(expected)) {
				return out, fmt.Errorf("noncontiguous G42 original instruction")
			}
			v, e := strconv.ParseUint(ins.Word, 16, 32)
			if e != nil || len(ins.Word) != 8 {
				return out, fmt.Errorf("invalid original opcode")
			}
			ram := n10FileToRAM + uint32(expected)
			if _, dupe := words[ram]; dupe {
				return out, fmt.Errorf("duplicate original RAM word")
			}
			words[ram] = uint32(v)
		}
	}
	// Anchor every register handoff, its delay slot, and both opaque callee
	// targets against the *actual owner-distributed G42 source bytes*.
	anchors := map[uint32]uint32{
		0x800462BC: 0xACC50000, // sw a1,0(a2)
		0x800462C0: 0x03E00008, // jr ra
		0x800462C4: 0xA0C40003, // sb a0,3(a2): return delay slot
		0x80046320: 0xAFA40048, // save sector count
		0x80046324: 0xAFA5004C, // save original pointer
		0x80046328: 0xAFA60050, // save LBA
		0x8004632C: 0x0C0111D4, // setup caller at 0x80044750
		0x80046330: 0x24040006, // operation 6, setup
		0x80046334: 0x93A40048, // reload sector count
		0x80046338: 0x8FA5004C, // reload pointer
		0x8004633C: 0x0C0118AF, // jal builder 0x800462BC
		0x80046340: 0x27A60028, // a2 -> stack descriptor
		0x80046344: 0x8FA50050, // reload LBA
		0x80046348: 0x24040006, // a0 operation 6
		0x8004634C: 0x0C011505, // jal 0x80045414
		0x80046350: 0x27A60028, // a2 -> same descriptor in delay slot
	}
	for addr, want := range anchors {
		if got, ok := words[addr]; !ok || got != want {
			return out, fmt.Errorf("original MIPS anchor %08X mismatch", addr)
		}
	}
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], 0x80132000)
	bytes[3] = 96 // sb $a0,3($a2) executes as the return delay slot
	out.PackedDescriptor = fmt.Sprintf("0x%08X", binary.LittleEndian.Uint32(bytes[:]))
	out.PackedBytePattern = fmt.Sprintf("%02X %02X %02X %02X", bytes[0], bytes[1], bytes[2], bytes[3])
	if out.PackedDescriptor != "0x60132000" {
		return out, fmt.Errorf("descriptor regression")
	}
	out.SourceVerified = true
	return out, nil
}

func CaptureN10DescriptorG43(exe []byte, r N10DescriptorReviewG43) (N10DescriptorReviewG43, error) {
	if !r.SourceVerified || r.SafeToPatch || r.SectorTransferVerified || r.CalleeDescriptorInterpretationVerified || r.OverlayRAMBoundsVerified {
		return r, fmt.Errorf("G43 source proof/status missing")
	}
	if len(exe) != 667648 || fmt.Sprintf("%x", sha256.Sum256(exe)) != N10OriginalEXESHA {
		return r, fmt.Errorf("G43 original EXE SHA/length mismatch")
	}
	return captureG43Windows(exe, r)
}
func captureG43Windows(exe []byte, r N10DescriptorReviewG43) (N10DescriptorReviewG43, error) {
	for _, spec := range n10G43WindowSpecs() {
		if spec.start < n10FileToRAM+2048 || spec.end <= spec.start || spec.end > n10FileToRAM+uint32(len(exe)) ||
			(spec.start-n10FileToRAM)%4 != 0 || (spec.end-n10FileToRAM)%4 != 0 || spec.end-spec.start > 2048 {
			return r, fmt.Errorf("invalid G43 window")
		}
		start := int(spec.start - n10FileToRAM)
		end := int(spec.end - n10FileToRAM)
		win := N10TraceWindow{Label: spec.label, Reason: "static original EXE bytes; no runtime/DMA observation", StartFileOffset: start, EndFileOffsetExclusive: end, Instructions: []N10TraceInstruction{}}
		for off := start; off < end; off += 4 {
			raw := binary.LittleEndian.Uint32(exe[off : off+4])
			ram := n10FileToRAM + uint32(off)
			dec, target := decodeN10Word(raw, ram)
			win.Instructions = append(win.Instructions, N10TraceInstruction{FileOffset: off, RAM: fmt.Sprintf("0x%08X", ram), Word: fmt.Sprintf("%08X", raw), LexicalDecode: dec, ControlTarget: target})
		}
		r.NewCodeWindows = append(r.NewCodeWindows, win)
	}
	return r, nil
}
