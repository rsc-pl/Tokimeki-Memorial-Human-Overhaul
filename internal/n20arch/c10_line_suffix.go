package n20arch

// Bounded C10 full-message formatter for F2-P and F3.
// a0=complete CP932 queue message, a1=output (caller-owned), a2=capacity,
// t6=1 saved given+君, 2 saved surname+さん OR saved surname+君. v0=length including NUL or 0.
// Only one exact dynamic name+suffix occurrence at a CP932 character boundary is accepted.
// After an exact match, a single source ASCII blank before comma/full stop
// is omitted. An odd pair-font 0xA0 pad is replaced by that punctuation
// (0xAC/0xAE), rather than left visibly before it.
// The source and destination stay untouched on failure. This is NOT an EXE
// queue hook: the caller must authenticate buffer ownership and synchronously
// enqueue the returned scratch buffer with the original queue arguments.
import "fmt"

func buildC10LineSuffix(sharedRAM, romanizer uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	add := func(d, s uint32, i int16) { w(olADDIU(d, s, i)) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	addu := func(d, x, y uint32) { w(olAddu(d, x, y)) }
	sw := func(d, b uint32, o int16) { w(olSW(d, b, o)) }
	lw := func(d, b uint32, o int16) { w(olLW(d, b, o)); w(0) }
	lbu := func(d, b uint32, o int16) { w(olLBU(d, b, o)); w(0) }
	sb := func(d, b uint32, o int16) { w(olSB(d, b, o)) }
	beq := func(x, y uint32, l string) { a.b(4, x, y, l); w(0) }
	bne := func(x, y uint32, l string) { a.b(5, x, y, l); w(0) }
	j := func(l string) { beq(0, 0, l) }
	sltu := func(d, x, y uint32) { w(olRType(x, y, d, 0x2b)) }
	// 0x20..0x8f 112B staged message; 0xa0..0xbf s registers;
	// 0xc0 saved RA, 0xd0 suffix byte count. 0x120 aligned frame.
	add(29, 29, -0x120)
	for i, r := range []uint32{16, 17, 18, 19, 20, 21, 22, 23} {
		sw(r, 29, int16(0xa0+i*4))
	}
	sw(31, 29, 0xc0)
	mov(16, 4)
	mov(17, 5)
	mov(18, 6)
	mov(23, 14)
	beq(16, 0, "fail")
	beq(17, 0, "fail")
	w(olSLTIU(8, 18, 32))
	bne(8, 0, "fail")
	add(8, 0, 1)
	beq(23, 8, "given")
	add(8, 0, 2)
	bne(23, 8, "fail")
	w(olLUI(19, OLA0SurnameField))
	w(olORI(19, 19, OLA0SurnameField&0xffff))
	j("role")
	a.label("given")
	w(olLUI(19, OLFieldPrepSavedGiv))
	w(olORI(19, 19, OLFieldPrepSavedGiv&0xffff))
	a.label("role")
	add(13, 0, 2)
	sw(13, 29, 0xd0) // initial min token length for scanning; exact length overwrites on match.
	// Bounded NUL-terminated saved name (2/4/6 bytes).
	add(21, 0, 0)
	a.label("name_len")
	w(olSLTIU(8, 21, 7))
	a.b(4, 8, 0, "fail")
	addu(9, 19, 21) // safe also on failure: read-only address calculation
	lbu(10, 9, 0)
	beq(10, 0, "name_done")
	a.b(4, 0, 0, "name_len")
	add(21, 21, 2) // branch delay slot (R3000A)
	a.label("name_done")
	beq(21, 0, "fail")
	// Complete source line must terminate within 64 B; mixed ASCII/CP932 may have odd byte length.
	add(20, 0, 0)
	a.label("source_len")
	w(olSLTIU(8, 20, 64))
	a.b(4, 8, 0, "fail")
	addu(9, 16, 20) // safe also on failure: read-only address calculation
	lbu(10, 9, 0)
	beq(10, 0, "source_done")
	a.b(4, 0, 0, "source_len")
	add(20, 20, 1) // branch delay slot (R3000A)
	a.label("source_done")
	beq(20, 0, "fail")
	lw(13, 29, 0xd0)
	addu(12, 21, 13) // token length
	sltu(8, 20, 12)
	bne(8, 0, "fail")
	add(22, 0, -1) // one match offset, -1 = none
	add(11, 0, 0)  // CP932 character-boundary candidate offset
	a.label("find")
	addu(9, 11, 12)
	sltu(8, 20, 9)
	a.b(5, 8, 0, "found_end")
	add(8, 0, 0) // initialize byte counter in branch delay slot
	a.label("match_name")
	a.b(4, 8, 21, "match_suffix")
	addu(9, 19, 8) // harmless on match: match_suffix overwrites t1
	lbu(10, 9, 0)
	addu(9, 11, 8)
	addu(9, 16, 9)
	lbu(15, 9, 0)
	bne(10, 15, "advance")
	a.b(4, 0, 0, "match_name")
	add(8, 8, 1) // branch delay slot (R3000A)
	a.label("match_suffix")
	addu(9, 11, 21)
	addu(9, 16, 9)
	add(8, 0, 1)
	a.b(4, 23, 8, "kun")
	addu(8, 11, 21) // BEQ delay: harmless on given+君 path
	// Both accepted surname suffixes are scanned at an exact CP932 boundary.
	// A two-byte surname+君 may end at NUL, so never inspect four bytes
	// of さん unless the complete four-byte suffix is inside source_len.
	add(8, 8, 4)
	sltu(8, 20, 8)
	bne(8, 0, "kun")
	for i, v := range []int16{0x82, 0xb3, 0x82, 0xf1} {
		w(olLBU(10, 9, int16(i)))
		add(15, 0, v) // R3000A load-delay filler
		bne(10, 15, "kun")
	}
	a.b(4, 0, 0, "record")
	add(13, 0, 4) // branch-delay: four-byte さん
	a.label("kun")
	for i, v := range []int16{0x8c, 0x4e} {
		w(olLBU(10, 9, int16(i)))
		add(15, 0, v) // R3000A load-delay filler
		bne(10, 15, "advance")
	}
	a.b(4, 0, 0, "record")
	add(13, 0, 2) // branch-delay: two-byte 君
	a.label("record")
	add(8, 0, -1)
	a.b(5, 22, 8, "fail") // multiple occurrences are ambiguous
	sw(13, 29, 0xd0)      // delay slot: count is private stack even on failure
	mov(22, 11)
	a.label("advance")
	// Skip one ASCII/halfwidth byte or one complete Shift-JIS code unit.
	// Lead byte ranges are 0x81..0x9f and 0xe0..0xfc.
	addu(9, 16, 11)
	lbu(10, 9, 0)
	w(olSLTIU(8, 10, 0x81))
	bne(8, 0, "step_one")
	w(olSLTIU(8, 10, 0xa0))
	bne(8, 0, "step_two")
	w(olSLTIU(8, 10, 0xe0))
	bne(8, 0, "step_one")
	w(olSLTIU(8, 10, 0xfd))
	bne(8, 0, "step_two")
	a.label("step_one")
	a.b(4, 0, 0, "find")
	add(11, 11, 1) // branch delay slot (R3000A)
	a.label("step_two")
	a.b(4, 0, 0, "find")
	add(11, 11, 2) // branch delay slot (R3000A)
	a.label("found_end")
	add(8, 0, -1)
	a.b(4, 22, 8, "fail")
	add(8, 0, 0) // branch delay: private staging counter
	// Copy prefix into a private staged buffer. Output is written only on success.
	a.label("copy_prefix")
	a.b(4, 8, 22, "romanize")
	addu(9, 16, 8) // on completion: t1 unused by romanizer setup
	lbu(10, 9, 0)
	addu(9, 29, 8)
	sb(10, 9, 0x20)
	a.b(4, 0, 0, "copy_prefix")
	add(8, 8, 1) // branch delay slot (R3000A)
	a.label("romanize")
	mov(4, 19)
	addu(5, 29, 22)
	add(5, 5, 0x20)
	add(6, 0, 32)
	add(7, 0, 3)
	add(8, 0, 2)
	beq(13, 8, "given_selector")
	add(7, 0, 0x203)
	j("call_roman")
	a.label("given_selector")
	add(7, 0, 0x103)
	a.label("call_roman")
	w(jalWord(romanizer))
	w(0)
	beq(2, 0, "fail")
	w(olSLTIU(8, 2, 33))
	beq(8, 0, "fail")
	// New count includes the suffix after the matched original token.
	lw(13, 29, 0xd0)
	addu(12, 21, 13)
	addu(10, 22, 12) // source after original name+suffix
	sltu(8, 20, 10)
	bne(8, 0, "fail")
	// Pair-aware punctuation after an authenticated dynamic name and suffix.
	// The existing romanizer pads odd high-bit Latin output with 0xA0.
	// If the source next contains (optional ONE ASCII blank) followed by
	// ASCII comma/full stop, replace ONLY that last high-bit padding glyph
	// with the high-bit punctuation and consume the original punctuation.
	// This preserves the 2-glyph pairing. For even-length output, only trim
	// one original ASCII blank without changing other separators.
	// All work remains private until capacity and source checks pass.
	add(9, 2, -1)
	addu(9, 9, 22)  // position just after the romanizer bytes in staging
	addu(8, 16, 10) // source cursor after original token
	w(olLBU(15, 8, 0))
	add(13, 0, 0) // MIPS-I load-delay filler; optional-blank count
	add(12, 0, 0x20)
	bne(15, 12, "encoded_punctuation_check")
	w(olLBU(15, 8, 1)) // only executed when one blank was present
	add(13, 0, 1)      // MIPS-I load-delay filler; one source blank
	a.label("encoded_punctuation_check")
	// Accept both raw ASCII and high-bit font-encoded punctuation.
	w(olIType(0x0c, 15, 15, 0x7f)) // andi t7,t7,0x7f, only after detecting optional ASCII space
	add(12, 0, 0x2c)
	a.b(4, 15, 12, "encoded_punctuation_copy")
	add(12, 0, 0x2e) // branch-delay: prepare full stop comparator
	bne(15, 12, "tail_ready")
	a.label("encoded_punctuation_copy")
	addu(10, 10, 13) // trim optional single ASCII blank
	addu(8, 29, 9)
	w(olLBU(12, 8, 0x1f))     // last romanized byte in staged buffer
	add(11, 0, 0xa0)          // load-delay filler, exactly the padding byte
	bne(12, 11, "tail_ready") // even roman output: ordinary comma copied
	add(15, 15, 0x80)         // 0x2c/0x2e -> pair-glyph 0xac/0xae
	sb(15, 8, 0x1f)
	add(10, 10, 1) // consume punctuation already inserted into pad
	a.label("tail_ready")
	// Romanized cursor (9) already includes output before original tail.
	// The tail after optional trimming/punctuation folding begins at 10.
	w(olRType(20, 10, 11, 0x23)) // remaining bytes
	addu(14, 9, 11)
	add(14, 14, 1) // output total with NUL
	sltu(8, 18, 14)
	bne(8, 0, "fail")
	w(olSLTIU(8, 14, 113))
	beq(8, 0, "fail")
	// Copy suffix including original NUL to the private staging area.
	a.label("copy_tail")
	addu(8, 16, 10)
	lbu(15, 8, 0)
	addu(8, 29, 9)
	sb(15, 8, 0x20)
	add(10, 10, 1)
	add(9, 9, 1)
	sltu(8, 20, 10)
	beq(8, 0, "copy_tail")
	// Success is now proven. Commit exactly the staged bytes.
	add(8, 0, 0)
	a.label("commit")
	a.b(4, 8, 14, "success")
	addu(9, 29, 8) // harmless on success; no writes
	lbu(10, 9, 0x20)
	addu(9, 17, 8)
	sb(10, 9, 0)
	a.b(4, 0, 0, "commit")
	add(8, 8, 1) // branch delay slot (R3000A)
	a.label("success")
	mov(2, 14)
	j("exit")
	a.label("fail")
	mov(2, 0)
	// Reuse the authenticated failure-path no-op for encoded punctuation; preserve the dispatcher offset.
	a.label("exit")
	// R3000A permits back-to-back loads into different saved registers.
	// None is consumed until after the final RA load and its delay slot.
	for i, r := range []uint32{16, 17, 18, 19, 20, 21, 22, 23} {
		w(olLW(r, 29, int16(0xa0+i*4)))
	}
	lw(31, 29, 0xc0)
	w(olJR(31))
	add(29, 29, 0x120)
	a.resolve()
	b := words(a.words...)
	if len(b) > 1040 {
		return nil, fmt.Errorf("full-line C10 token helper %d bytes exceeds 1040-byte suffix+spare budget", len(b))
	}
	_ = sharedRAM
	return b, nil
}
