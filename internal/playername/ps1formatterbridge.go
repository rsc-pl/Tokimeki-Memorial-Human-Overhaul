package playername

// formatter bridge executes the bounded surname formatting formatter rule as MIPS-I source-side code.
// It is an OFFLINE candidate. No executable placement, stack-headroom or
// narrator-screen identity follows from producing correct queue bytes.
import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	PS1FormatterSource = uint32(0x800e6354)
	PS1FormatterGlobal = uint32(0x800ca16c)
)

type PS1FormatterBridge struct {
	Entry                              uint32   `json:"hypothetical_entry"`
	CodeBytes                          int      `json:"code_bytes"`
	FrameBytes                         int      `json:"generated_local_frame_bytes"`
	BoundedPrivatePairBytes            int      `json:"bounded_private_pair_bytes"`
	SourceSourceAndGlobalMatchRequired bool     `json:"saved_global_and_formatted_bytes_match_required"`
	BothExactReturnsRequired           bool     `json:"requires_either_exact_formatter_return"`
	OriginalQueueSynchronousAssumed    bool     `json:"queue_consumes_pointer_synchronously_assumed"`
	GuestStackHeadroomProven           bool     `json:"guest_stack_headroom_proven"`
	RendererNarrationProven            bool     `json:"renderer_narration_proven"`
	LinkedIn8KiBWith                   bool     `json:"linked_with_extended_name_table"`
	Installed                          bool     `json:"installed"`
	SafeToPatch                        bool     `json:"safe_to_patch"`
	Words                              []uint32 `json:"-"`
	Binary                             []byte   `json:"-"`
}

// BuildPS1FormatterBridge accepts only exact retail formatter returns A/B.
// Source must be precisely saved kana surname, copied identically to global,
// then followed by ASCII 0x20 and NUL in the caller's a3 buffer. The outgoing
// original a0..a3 and fifth argument are passed to the original enqueue once.
// The generated frame owns the replacement through the synchronous JAL.
// A matching return address alone is never sufficient to alter a message.
func BuildPS1FormatterBridge(origin, safeSingleRomanizer uint32) (PS1FormatterBridge, error) {
	return buildPS1FormatterBridge(origin, safeSingleRomanizer, false)
}

// BuildPS1FormatterBridgeFourRoutes extends the exact original formatter
// return allowlist from the two witnessed previous version sites to all FOUR original
// surname-global %s-space branches, authenticated against the owner's
// original EXE. No extra code region, game memory writes or patch approval.
func BuildPS1FormatterBridgeFourRoutes(origin, safeSingleRomanizer uint32) (PS1FormatterBridge, error) {
	return buildPS1FormatterBridge(origin, safeSingleRomanizer, true)
}

func buildPS1FormatterBridge(origin, safeSingleRomanizer uint32, fourRoutes bool) (PS1FormatterBridge, error) {
	r := PS1FormatterBridge{Entry: origin, FrameBytes: 0xc0, BoundedPrivatePairBytes: 64,
		SourceSourceAndGlobalMatchRequired: true, BothExactReturnsRequired: true, OriginalQueueSynchronousAssumed: true}
	for _, a := range []uint32{origin, safeSingleRomanizer} {
		if a < 0x80010000 || a >= 0x80200000 || a&3 != 0 {
			return r, errors.New("unverified or unaligned executable address")
		}
	}
	if origin == safeSingleRomanizer {
		return r, errors.New("bridge/core alias")
	}
	b := mipsBuf{labels: map[string]int{}}
	e := func(w uint32) { b.emit(w) }
	add := func(t, s uint32, n int16) { e(iType(9, s, t, n)) }
	mov := func(t, s uint32) { add(t, s, 0) }
	lw := func(t, s uint32, n int16) { e(iType(35, s, t, n)) }
	lbu := func(t, s uint32, n int16) { e(iType(36, s, t, n)); e(0) }
	sw := func(t, s uint32, n int16) { e(iType(43, s, t, n)) }
	sb := func(t, s uint32, n int16) { e(iType(40, s, t, n)) }
	sltiu := func(t, s uint32, n int16) { e(iType(11, s, t, n)) }
	andi := func(t, s uint32, n int16) { e(iType(12, s, t, n)) }
	addu := func(t, s1, s2 uint32) { e(rType(s1, s2, t, 0, 0x21)) }
	beq := func(a, c uint32, l string) { b.branch(4, a, c, l); e(0) }
	bne := func(a, c uint32, l string) { b.branch(5, a, c, l); e(0) }
	jump := func(l string) { beq(0, 0, l) }
	address := func(t, v uint32) { e(iType(15, 0, t, int16(v>>16))); e(iType(13, t, t, int16(v&0xffff))) }
	jal := func(t uint32) { e(0x0c000000 | ((t >> 2) & 0x03ffffff)); e(0) }
	// Stack old arg5 at old_sp+0x10 -> current +0xd0. Output [0x20,0x60).
	// s0..s5 at 0x80..0x94, RA at 0xa0, clean outgoing arg5 at 0x10.
	add(29, 29, -0xc0)
	for i := uint32(16); i <= 21; i++ {
		sw(i, 29, int16(0x80+4*(i-16)))
	}
	sw(31, 29, 0xa0)
	mov(16, 4)
	mov(17, 5)
	mov(18, 6)
	mov(19, 7)
	lw(20, 29, 0xd0)
	beq(19, 0, "queue")
	if fourRoutes {
		// Four exact returns in one address window; three branch delay
		// slots prepare the following candidate. No `ORI` accumulation.
		high := uint16(0x8008)
		e(iType(15, 0, 24, int16(high)))
		add(8, 24, int16(-2084)) // 0x8007f7dc
		b.branch(4, 31, 8, "allowed")
		add(8, 24, int16(-1888)) // branch delay: 0x8007f8a0
		b.branch(4, 31, 8, "allowed")
		add(8, 24, int16(-1692)) // branch delay: 0x8007f964
		b.branch(4, 31, 8, "allowed")
		add(8, 24, int16(3128)) // branch delay: 0x80080c38
		bne(31, 8, "queue")
	} else {
		address(8, PS1FormatterSurnameReturnA)
		beq(31, 8, "allowed")
		address(8, PS1FormatterSurnameReturnB)
		bne(31, 8, "queue")
	}
	b.label("allowed")
	add(21, 0, 0) // source CP932 byte index, max 6 incl bounded NUL at 2/4/6
	address(14, PS1FormatterSource)
	address(15, PS1FormatterGlobal)
	b.label("verify")
	sltiu(8, 21, 7)
	beq(8, 0, "queue")
	addu(9, 14, 21)
	e(iType(36, 9, 10, 0)) // saved field; next addu fills R3000A delay
	addu(9, 15, 21)
	lbu(11, 9, 0) // global copy
	bne(10, 11, "queue")
	beq(10, 0, "end_name")
	addu(9, 19, 21)
	lbu(12, 9, 0) // formatted input
	bne(10, 12, "queue")
	add(21, 21, 1)
	jump("verify")
	b.label("end_name")
	beq(21, 0, "queue")
	andi(8, 21, 1)
	bne(8, 0, "queue")
	// Verify exact original '%s ' formatting, including NUL; no suffix.
	addu(9, 19, 21)
	e(iType(36, 9, 10, 0)) // independent addiu fills load delay
	add(8, 0, 0x20)
	bne(10, 8, "queue")
	lbu(10, 9, 1)
	bne(10, 0, "queue")
	address(4, PS1FormatterSource)
	add(5, 29, 0x20)
	add(6, 0, 60)
	add(7, 0, 3) // 1..3 kana, suffix selector=none
	jal(safeSingleRomanizer)
	// Result is the complete pair-font string plus NUL. For odd Latin
	// lengths the existing pair's final padding already represents the
	// retail space; for even lengths append an entire (space,space) pair.
	sltiu(8, 2, 3)
	bne(8, 0, "queue")
	sltiu(8, 2, 62) // allows 2 extra spaces + NUL inside 64B
	beq(8, 0, "queue")
	add(9, 2, -2)
	addu(10, 29, 9)
	e(iType(36, 10, 11, 0x20)) // addiu fills load delay
	add(8, 0, 0xa0)
	beq(11, 8, "converted")
	add(9, 2, -1) // previous terminator slot
	addu(10, 29, 9)
	add(12, 0, 0x81)
	sb(12, 10, 0x20) // existing pairfont blank glyph 0x8140
	add(12, 0, 0x40)
	sb(12, 10, 0x21)
	sb(0, 10, 0x22)
	b.label("converted")
	if fourRoutes {
		// Original formatter queue x = -104 - 4*strlen(raw CP932).
		// Rebase that x to the romanized PAIR-FONT surname byte count
		// (v0 includes NUL). The separately appended trailing space is
		// NOT part of the width, as in the original sprintf %s-space.
		add(8, 21, 1)
		e(rType(8, 2, 8, 0, 0x23)) // subu t0,t0,v0
		e(rType(0, 8, 8, 2, 0))    // sll t0,t0,2
		addu(16, 16, 8)            // adjusted original x, preserved in s0
	}
	add(19, 29, 0x20)
	b.label("queue")
	mov(4, 16)
	mov(5, 17)
	mov(6, 18)
	mov(7, 19)
	sw(20, 29, 0x10)
	jal(0x8004e788)
	// Restore RA before independent callee-saved loads (R3000A).
	lw(31, 29, 0xa0)
	for i := uint32(16); i <= 21; i++ {
		lw(i, 29, int16(0x80+4*(i-16)))
	}
	e(0x03e00008)
	add(29, 29, 0xc0)
	if err := b.resolve(); err != nil {
		return r, err
	}
	r.Words = b.words
	r.CodeBytes = 4 * len(b.words)
	if origin+uint32(r.CodeBytes) > 0x80200000 {
		return r, fmt.Errorf("bridge outside guest RAM")
	}
	r.Binary = make([]byte, r.CodeBytes)
	for i, w := range r.Words {
		binary.LittleEndian.PutUint32(r.Binary[i*4:], w)
	}
	return r, nil
}
