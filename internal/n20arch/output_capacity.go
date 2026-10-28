package n20arch

// N20 output-capacity audit (read-only, offline).
//
// The question is whether a longer romanized name could be consumed without
// enlarging the two shared retail working fields 0x800CA16C/0x800CA174. The
// answer is no: the fields are 8 bytes each and the next retail field starts
// at exactly +8 (0x800CA17C), so there is zero slack. The downstream formatter,
// renderer and queue buffers do have enough room for a three-kana name, but
// they are only reachable through those two fields. A shim-local buffer cannot
// be substituted because every authorised consumer reads the retail fields;
// the only bypass would be the generic renderer queue 0x80081DC8, which is
// explicitly forbidden. Nothing is implemented or expanded here.

import (
	"fmt"
)

const (
	N20FormatterEntry        uint32 = 0x8007EF48
	N20FormatterFrameBytes          = 0x290
	N20FormatterBufferOff           = 0x68
	N20FormatterNextLocalOff        = 0x27C
	N20RendererEntry         uint32 = 0x80081190
	N20RendererFrameBytes           = 0x2F8
	N20RendererLineOff              = 0x2A4
	N20RendererLineCap              = 0x40
	N20RendererFTempOff             = 0x28C
	N20QueueEntry            uint32 = 0x8004E788
	N20QueueMaxEntries              = 52
	N20QueueEntryStride             = 8
	N20QueueLengthOff               = 5
	N20WorkingFieldBytes            = 8
	N20WorkingNextField      uint32 = 0x800CA17C
)

// N20ConsumerCapacity is one decoded output path row.
type N20ConsumerCapacity struct {
	Consumer      string `json:"consumer"`
	Site          string `json:"site"`
	Buffer        string `json:"buffer"`
	CapacityBytes int    `json:"capacity_bytes"`
	RequiredBytes int    `json:"required_bytes_for_three_kana"`
	Fits          bool   `json:"fits"`
	Note          string `json:"note"`
}

// N20OutputCapacityAudit is the exact consumer-capacity verdict.
type N20OutputCapacityAudit struct {
	WorkingFamily   uint32                `json:"working_family"`
	WorkingGiven    uint32                `json:"working_given"`
	BlockedNext     uint32                `json:"blocked_next_field"`
	WorkingSlot     int                   `json:"working_slot_bytes_including_nul"`
	MaxRomanBytes   int                   `json:"max_three_kana_roman_bytes"`
	ExactSlotBytes  int                   `json:"required_exact_slot_bytes"`
	PaddedSlotBytes int                   `json:"required_padded_slot_bytes"`
	AlignedSlot     int                   `json:"aligned_slot_bytes"`
	Consumers       []N20ConsumerCapacity `json:"consumers"`
	DownstreamFits  bool                  `json:"downstream_fits_three_kana"`
	SafeLongerPath  bool                  `json:"safe_longer_path"`
	Verdict         string                `json:"verdict"`
	Reason          string                `json:"reason"`
}

func capRow(consumer, site, buffer string, capacity, required int, note string) N20ConsumerCapacity {
	return N20ConsumerCapacity{
		Consumer: consumer, Site: site, Buffer: buffer,
		CapacityBytes: capacity, RequiredBytes: required,
		Fits: capacity >= required, Note: note,
	}
}

// AuditN20OutputCapacity re-decodes the authenticated consumer instructions
// and returns a byte-level capacity table. It does not execute or patch.
func AuditN20OutputCapacity(exe []byte) (N20OutputCapacityAudit, error) {
	var a N20OutputCapacityAudit
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return a, fmt.Errorf("unrecognised original EXE")
	}
	for _, an := range []struct {
		pc   uint32
		want uint32
		name string
	}{
		{N20FormatterEntry, 0x27BDFD70, "formatter entry frame -0x290"},
		{0x8007F868, 0x27A40068, "formatter_b sprintf dest sp+0x68"},
		{0x8007F898, 0x0C0139E2, "formatter_b queue"},
		{0x80080C00, 0x27A40068, "formatter_d sprintf dest sp+0x68"},
		{0x80080C30, 0x0C0139E2, "formatter_d queue"},
		{N20RendererEntry, 0x27BDFD08, "renderer entry frame -0x2F8"},
		{0x80081420, 0x27B2028C, "renderer F temp s2=sp+0x28C"},
		{0x80081560, 0x27B902A4, "renderer line buffer sp+0x2A4"},
		{0x80081D7C, 0x27A702A4, "generic queue a3=sp+0x2A4"},
		{0x800817D0, 0x24C60040, "renderer p line clamp 64"},
		{0x8008194C, 0x24C60040, "renderer F line clamp 64"},
		{0x80081A04, 0x24C60040, "renderer m line clamp 64"},
		{0x800818DC, 0x02402025, "renderer F sprintf dest s2"},
		{0x800818E8, 0x24E7A174, "renderer F given argument"},
		{0x800818F0, 0x02C03025, "renderer F family argument"},
		{0x800819A0, 0x02402025, "renderer m strcpy dest s2"},
		{0x800819A8, 0x24A5A174, "renderer m given source"},
		{0x80081784, 0x02C02025, "renderer p family source"},
		{0x8004E79C, 0x29010034, "queue max 52 entries"},
		{0x8004E7C0, 0x0008C8C0, "queue entry stride 8"},
		{0x8004E854, 0xA0620005, "queue length byte at +5"},
		{0x800847D4, 0x2484A16C, "working family writer"},
		{0x800847E8, 0x2484A174, "working given writer"},
		{0x800847FC, 0x2484A17C, "blocked next field"},
	} {
		if got := wordAt(exe, an.pc); got != an.want {
			return a, fmt.Errorf("%s drifted at %08x: %08x", an.name, an.pc, got)
		}
	}

	a.WorkingFamily = OLFieldPrepWorkFam
	a.WorkingGiven = OLFieldPrepWorkGiv
	a.BlockedNext = N20WorkingNextField
	a.WorkingSlot = N20WorkingFieldBytes
	if OLFieldPrepWorkGiv-OLFieldPrepWorkFam != N20WorkingFieldBytes ||
		N20WorkingNextField-OLFieldPrepWorkGiv != N20WorkingFieldBytes {
		return a, fmt.Errorf("working-field geometry drifted")
	}
	a.MaxRomanBytes = 9
	a.ExactSlotBytes = a.MaxRomanBytes + 1
	a.PaddedSlotBytes = FieldPrepWireBytes(a.MaxRomanBytes) + 1
	a.AlignedSlot = (a.PaddedSlotBytes + 3) &^ 3

	// Three-kana worst case after the guest odd-length pad: each field is 10
	// wire bytes (9 letters + one high-bit space); the name join is 20 + NUL.
	maxFieldWire := FieldPrepWireBytes(a.MaxRomanBytes)
	joinBytes := 2*maxFieldWire + 1
	formatterBytes := maxFieldWire + 1 /* space */ + 1
	a.Consumers = []N20ConsumerCapacity{
		capRow("working family", "0x800CA16C", "shared retail field", a.WorkingSlot,
			a.PaddedSlotBytes, "8 bytes including NUL; next field starts at +8, zero slack"),
		capRow("working given", "0x800CA174", "shared retail field", a.WorkingSlot,
			a.PaddedSlotBytes, "8 bytes including NUL; blocked field 0x800CA17C starts at +8"),
		capRow("formatter_b/d sprintf", "0x8007F868 / 0x80080C00", "sp+0x68", N20FormatterNextLocalOff-N20FormatterBufferOff,
			formatterBytes, "next recorded local at sp+0x27C; only the name+space+NUL is written"),
		capRow("renderer p", "0x80081780", "line buffer sp+0x2A4", N20RendererLineCap,
			maxFieldWire, "authenticated copy loop; line clamp is 64 bytes"),
		capRow("renderer m", "0x800819A4", "F temp sp+0x28C", N20RendererLineOff-N20RendererFTempOff,
			maxFieldWire, "strcpy given into the 24-byte temp below the line buffer"),
		capRow("renderer F", "0x800818DC", "F temp sp+0x28C", N20RendererLineOff-N20RendererFTempOff,
			joinBytes, "sprintf(\"%s%s\") temp overlaps line buffer after 24 bytes"),
		capRow("renderer line", "0x80081D7C", "line buffer sp+0x2A4", N20RendererLineCap,
			joinBytes, "a3 for the generic queue; 64-byte clamp in p/m/F"),
		capRow("generic queue", "0x8004E788", "entry table 0x800B3DC0", N20QueueMaxEntries*N20QueueEntryStride,
			N20QueueEntryStride, "52 entries x 8 bytes; length byte at +5; every rendered line uses it"),
	}
	a.DownstreamFits = true
	// The first two rows are the shared working fields; "downstream" is every
	// consumer that reads them.
	for _, c := range a.Consumers[2:] {
		if !c.Fits {
			a.DownstreamFits = false
		}
	}
	a.SafeLongerPath = false
	a.Verdict = "blocked_shared_working_field_8_bytes"
	a.Reason = fmt.Sprintf(
		"the two working fields are 8 bytes including NUL and the next field starts at 0x%08x, so a three-kana name needing %d exact / %d padded bytes cannot be stored without relocating shared retail fields. The downstream formatter (%d bytes), p/m (%d), F temp (%d) and 64-byte renderer line all have room for the %d-byte join, and the generic queue has %d entries. A shim-local buffer is not consumed by any authorised callsite, and bypassing the fields through the generic queue 0x80081DC8 is forbidden. No buffer is expanded and no longer-name path is implemented.",
		N20WorkingNextField, a.ExactSlotBytes, a.PaddedSlotBytes,
		N20FormatterNextLocalOff-N20FormatterBufferOff, maxFieldWire,
		N20RendererLineOff-N20RendererFTempOff, joinBytes, N20QueueMaxEntries)
	return a, nil
}
