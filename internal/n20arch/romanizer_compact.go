package n20arch

// romanization: compact, width-aware F1 speaker shim for a single resident image shared
// with the telephone TEL dispatcher. This changes no ABI, validation contract, RAM
// window or gameplay safety status. The branch/jump delay slots are deliberate.
import "fmt"

func BuildCompactSpeakerShim(romanizer uint32) ([]byte, error) {
	if romanizer&3 != 0 {
		return nil, fmt.Errorf("unaligned romanizer %08x", romanizer)
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	add := func(d, s uint32, imm int16) { w(olADDIU(d, s, imm)) }
	lw := func(d, b uint32, off int16) { w(olLW(d, b, off)) }
	sw := func(d, b uint32, off int16) { w(olSW(d, b, off)) }
	lbu := func(d, b uint32, off int16) { w(olLBU(d, b, off)) }
	bne := func(x, y uint32, label string) { a.b(5, x, y, label) }
	beq := func(x, y uint32, label string) { a.b(4, x, y, label) }
	sub := func(d, x, y uint32) { w(olRType(x, y, d, 0x23)) }
	srl := func(d, s, sh uint32) { w(olRType(0, s, d, 0x02) | sh<<6) }
	sll := func(d, s, sh uint32) { w(olRType(0, s, d, 0x00) | sh<<6) }
	sltiu := func(d, s uint32, n int16) { w(olSLTIU(d, s, n)) }

	// Preserve original caller's a0 for the retail fallback, ra for returning.
	// The frame is never exposed outside the synchronous retail queue call.
	add(29, 29, -speakerGeometryFrameBytes)
	sw(31, 29, 0x7c)
	sw(4, 29, 0x60)
	w(olLUI(8, OLA0SurnameField))
	add(8, 8, int16(OLA0SurnameField&0xffff))
	bne(4, 8, "retail")
	w(olLUI(9, speakerGeometryAdvanceRAM)) // branch delay: safe on either outcome
	lbu(10, 9, int16(speakerGeometryAdvanceRAM&0xffff))
	w(0) // load delay
	add(11, 0, speakerGeometryAdvanceCell)
	bne(10, 11, "retail")
	w(0)

	// a0 is unchanged, so do not redundantly save an s-register.
	add(5, 29, speakerGeometryNameBufOff)
	add(6, 0, speakerGeometryNameBufBytes)
	w(jalWord(romanizer))
	add(7, 0, 3) // JAL delay slot: suffix=none, maximum three kana

	// v0 includes NUL.  v0=0 and v0=1 are both rejected by the range check;
	// unsigned underflow is intentional and checked before scanning bytes.
	add(8, 2, -1)
	w(olIType(0x0c, 8, 9, 1))
	bne(9, 0, "retail")
	add(9, 8, -2)
	sltiu(9, 9, speakerGeometrySurnameMax-1)
	beq(9, 0, "retail")
	add(10, 29, speakerGeometryNameBufOff)

	// Reject any output outside the authenticated installed 0xA0..0xFA
	// pair-font glyph alphabet; the wave-dash is deliberately rejected.
	a.label("pairs")
	lbu(11, 10, 0)
	add(10, 10, 1) // MIPS-I load-delay filler
	add(11, 11, -0xa0)
	sltiu(11, 11, 0x5b)
	beq(11, 0, "retail")
	add(8, 8, -1) // harmless on invalid-byte fallback
	bne(8, 0, "pairs")
	srl(12, 2, 1) // branch delay: recomputable, v0 is unchanged

	// Native speaker centring x=-107-7*cells, with no 2/4/6-byte table cap.
	sll(13, 12, 3)
	sub(13, 13, 12)
	add(4, 0, -107)
	sub(4, 4, 13)
	add(5, 0, 50)
	add(6, 0, 0)
	add(7, 29, speakerGeometryNameBufOff)
	w(jalWord(speakerGeometryQueueEntry))
	sw(0, 29, 0x10) // delay slot: original O32 fifth argument
	lw(31, 29, 0x7c)
	w(0) // R3000A load-use hazard: JR must see the restored ra
	w(olJR(31))
	add(29, 29, speakerGeometryFrameBytes)

	// Tail-call original speaker on any unexpected value. Restore the exact
	// original a0, ra and sp; original speaker itself returns to our caller.
	a.label("retail")
	lw(4, 29, 0x60)
	lw(31, 29, 0x7c)
	w(jWord(OLOriginalSpeaker))
	add(29, 29, speakerGeometryFrameBytes)
	a.resolve()
	b := words(a.words...)
	if len(b) > 192 {
		return nil, fmt.Errorf("romanization compact shim %d > 192 bytes", len(b))
	}
	return b, nil
}

func PlanC10GyoziSourceCompact(original []byte) (C10SourceCandidate, error) {
	return planC10GyoziSource(original, BuildCompactSpeakerShim)
}
