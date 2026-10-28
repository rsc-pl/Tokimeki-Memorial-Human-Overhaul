package playername

// Caller-scoped MIPS-I speaker-label bridge; code placement is unverified.
// It never mutates the player's saved surname. Code placement and actual
// stack headroom MUST be proven before an ISO hook is permitted.
import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PS1SpeakerQueueDependencies describes HYPOTHETICAL relocation targets.
// CallerReturn is the return address immediately after the original JAL.
// The original JAL delay-slot instruction must be preserved by any future
// installer; this function DOES NOT alter the callsite.
type PS1SpeakerQueueDependencies struct {
	Romanizer, OriginalQueue, SurnameField, CallerReturn uint32
}

type PS1SpeakerQueueWrapper struct {
	Entry                                  uint32   `json:"hypothetical_entry"`
	CodeBytes                              int      `json:"code_bytes"`
	ExtraStackBytes                        int      `json:"hypothetical_extra_stack_bytes"`
	OwnedScratchBytes                      int      `json:"owned_temporary_output_bytes"`
	ExactCallerGate                        bool     `json:"requires_exact_caller_return"`
	ExactSourcePointerGate                 bool     `json:"requires_actual_surname_field_pointer"`
	OriginalSurnameUnchanged               bool     `json:"does_not_write_game_surname"`
	PreservesQueueABI                      bool     `json:"preserves_five_queue_arguments_and_return"`
	OriginalQueueConsumesTextSynchronously bool     `json:"queue_text_consumed_before_return"`
	CodePlacementProven                    bool     `json:"code_placement_proven"`
	StackHeadroomProven                    bool     `json:"stack_headroom_proven"`
	RuntimeSourcePointerProven             bool     `json:"runtime_a3_pointer_proven"`
	Installed                              bool     `json:"installed"`
	SafeToPatch                            bool     `json:"safe_to_patch"`
	Words                                  []uint32 `json:"-"`
	Binary                                 []byte   `json:"-"`
}

// BuildPS1SpeakerQueueWrapper builds the MIPS speaker-path stub. The wrapper
// calls the existing safe CP932 romanizer with suffix=none and maxKana=3.
// Its 64-byte output is independent of the saved surname and only lives until
// the synchronous original queue returns. Any gate/conversion failure passes
// the original pointer and complete O32 argument set through unchanged.
func BuildPS1SpeakerQueueWrapper(origin uint32, d PS1SpeakerQueueDependencies) (PS1SpeakerQueueWrapper, error) {
	r := PS1SpeakerQueueWrapper{Entry: origin, ExtraStackBytes: 0xb0, OwnedScratchBytes: 64, ExactCallerGate: true, ExactSourcePointerGate: true, OriginalSurnameUnchanged: true, PreservesQueueABI: true, OriginalQueueConsumesTextSynchronously: true}
	for _, a := range []uint32{origin, d.Romanizer, d.OriginalQueue, d.CallerReturn} {
		if a < 0x80010000 || a >= 0x80200000 || a&3 != 0 {
			return r, errors.New("unaligned or out-of-range executable/return address")
		}
	}
	if d.SurnameField < 0x80010000 || d.SurnameField >= 0x801ffff8 {
		return r, errors.New("invalid surname pointer")
	}
	if origin == d.Romanizer || origin == d.OriginalQueue || d.Romanizer == d.OriginalQueue || d.SurnameField == origin {
		return r, errors.New("address alias")
	}
	b := mipsBuf{labels: map[string]int{}}
	e := func(w uint32) { b.emit(w) }
	mov := func(dst, src uint32) { e(iType(9, src, dst, 0)) }
	lw := func(dst, base uint32, offset int16) { e(iType(35, base, dst, offset)); e(0) } // R3000A load-delay
	sw := func(src, base uint32, offset int16) { e(iType(43, base, src, offset)) }
	li := func(dst, addr uint32) { e(iType(15, 0, dst, int16(addr>>16))); e(iType(13, dst, dst, int16(addr))) }
	branchNe := func(a, c uint32, label string) { b.branch(5, a, c, label); e(0) }
	branchEq := func(a, c uint32, label string) { b.branch(4, a, c, label); e(0) }
	jal := func(addr uint32) { e(0x0c000000 | ((addr >> 2) & 0x03ffffff)); e(0) }
	// old sp=sp+0xb0. 0x10=outgoing fifth; 0x20..0x5f scratch,
	// 0x70..0x80 saved s0..s4, 0x84 saved ra. Nothing above old sp touched.
	e(iType(9, 29, 29, -0xb0))
	for s := uint32(16); s <= 20; s++ {
		sw(s, 29, int16(0x70+(s-16)*4))
	}
	sw(31, 29, 0x84)
	mov(16, 4)
	mov(17, 5)
	mov(18, 6)
	mov(19, 7)
	lw(20, 29, 0xc0) // original caller stack arg 5, after allocating frame
	li(8, d.CallerReturn)
	branchNe(31, 8, "passthrough")
	li(8, d.SurnameField)
	branchNe(19, 8, "passthrough")
	mov(4, 19)
	e(iType(9, 29, 5, 0x20)) // a1=owned scratch
	e(iType(9, 0, 6, 64))
	e(iType(9, 0, 7, 3)) // suffix=none, max three kana
	jal(d.Romanizer)
	branchEq(2, 0, "passthrough")
	e(iType(9, 29, 19, 0x20)) // successful conversion: only replace a3
	b.label("passthrough")
	mov(4, 16)
	mov(5, 17)
	mov(6, 18)
	mov(7, 19)
	sw(20, 29, 0x10)
	jal(d.OriginalQueue)
	for s := uint32(16); s <= 20; s++ {
		lw(s, 29, int16(0x70+(s-16)*4))
	}
	lw(31, 29, 0x84)
	e(0x03e00008)             // jr ra
	e(iType(9, 29, 29, 0xb0)) // delay slot: restore stack
	if err := b.resolve(); err != nil {
		return r, err
	}
	r.CodeBytes = len(b.words) * 4
	if uint64(origin)+uint64(r.CodeBytes) > 0x80200000 {
		return r, fmt.Errorf("wrapper crosses end of RAM")
	}
	r.Words = b.words
	r.Binary = make([]byte, r.CodeBytes)
	for i, w := range b.words {
		binary.LittleEndian.PutUint32(r.Binary[i*4:], w)
	}
	return r, nil
}
