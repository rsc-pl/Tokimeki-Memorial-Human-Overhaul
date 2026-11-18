package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	pQuestionStart = uint32(0x80081578)
	pQuestionEnd   = uint32(0x80081614)
	pQuestionJoin  = uint32(0x8008169c)
)

// The P expansion has two consecutive copies into the renderer's 64-byte
// line buffer. Replace its byte-at-a-time name copy with a bounded exact
// length copy, then retain the guarded literal copy. This frees instructions
// inside the existing P branch; neither the guard nor any overlay grows.
func buildPTerminalQuestion(guard parserGuardProgram) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	w(jalWord(guard.entries["checkedstrlen"]))
	mov(4, 23)
	mov(16, 2)
	mov(6, 2)
	mov(5, 23)
	w(jalWord(guard.entries["dynamic_strncpy"]))
	mov(4, 17)
	// s1 is sp+0x2a4+s3; derive the same remaining capacity as retail.
	w(olLW(5, 29, 0x60))
	w(olAddu(4, 17, 16))
	w(olADDIU(6, 29, 0x2e4))
	w(olAddu(5, 5, 20))
	w(olRType(6, 4, 6, 0x23))
	w(jalWord(guard.entries["dynamic_strncpy"]))
	w(olADDIU(5, 5, 1))
	// v0 is the original strncpy destination, including the n==0 case.
	// Only inspect two literal bytes if both are inside the guarded buffer.
	w(olADDIU(9, 29, 0x2e2))
	w(olRType(9, 2, 9, 0x2b))
	a.b(5, 9, 0, "done")
	w(olLBU(10, 23, 0))
	w(olADDIU(11, 0, 0xa0))
	w(olADDIU(10, 10, -0xc1))
	w(olSLTIU(10, 10, 26)) // packed capital Latin initial, not a fullwidth kana lead
	a.b(4, 10, 0, "done")
	w(olADDIU(12, 0, 0x3f))
	w(olLBU(9, 2, 1))
	w(olLBU(10, 2, 0))
	a.b(5, 9, 0, "done")
	w(olLBU(13, 2, -1)) // nonempty P guaranteed by initial glyph gate
	a.b(5, 10, 12, "done")
	w(olORI(10, 10, 0x80))
	a.b(5, 13, 11, "done")
	w(0)
	w(olSB(10, 2, -1))
	w(olSB(0, 2, 0))
	a.label("done")
	// Preserve the original signed-16 parser indices. The S branch's
	// unchanged common suffix calculates s3/s4 from v0=len(P).
	w(olAddu(21, 21, 16))
	w(olADDIU(21, 21, -1))
	w(21<<16 | 25<<11 | 16<<6)
	mov(2, 16)
	w(25<<16 | 21<<11 | 16<<6 | 3)
	// The following, unchanged S comparator is the final jump's delay
	// instruction. Its write to at is dead in the common index suffix.
	w(jWord(pQuestionJoin))
	a.resolve()
	return words(a.words...)
}

// PlanPTerminalQuestion applies the bounded P-expansion adjustment only when
// authenticated parser instructions match. It preserves saved name fields and
// padding outside the eligible terminal punctuation pair.
func PlanPTerminalQuestion(retail, current []byte) ([]byte, error) {
	if len(retail) != 667648 || len(current) != len(retail) || sha(retail) != OriginalEXESHA {
		return nil, fmt.Errorf("P terminal question: executable identity mismatch")
	}
	guard, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return nil, err
	}
	at := func(pc uint32) int { return int(pc - Base) }
	if !bytes.Equal(current[at(parserGuardParserGuardRAM):at(parserGuardParserGuardRAM)+len(guard.code)], guard.code) {
		return nil, fmt.Errorf("P terminal question: bounded copy routine mismatch")
	}
	start, end := at(pQuestionStart), at(pQuestionEnd)
	want := bytes.Clone(retail[start:end])
	binary.LittleEndian.PutUint32(want, jalWord(guard.entries["checkedstrlen"]))
	binary.LittleEndian.PutUint32(want[0x800815cc-pQuestionStart:], jalWord(guard.entries["dynamic_strncpy"]))
	if !bytes.Equal(current[start:end], want) ||
		!bytes.Equal(current[at(0x80081560):start], retail[at(0x80081560):start]) ||
		!bytes.Equal(current[end:end+4], retail[end:end+4]) ||
		!bytes.Equal(current[at(pQuestionJoin):at(0x800816bc)], retail[at(pQuestionJoin):at(0x800816bc)]) ||
		!bytes.Equal(current[at(0x80081d2c):at(0x80081d4c)], retail[at(0x80081d2c):at(0x80081d4c)]) {
		return nil, fmt.Errorf("P terminal question: parser instruction preimage mismatch")
	}
	// The existing P relocation has an independently authenticated reader.
	for _, pc := range []uint32{0x800813f8, 0x8008140c} {
		old := binary.LittleEndian.Uint32(retail[at(pc):])
		want := n20RelocADDIUWord(old, givenKunExtended)
		if pc == 0x800813f8 {
			want = n20RelocLUIWord(old, givenKunExtended)
		}
		if binary.LittleEndian.Uint32(current[at(pc):]) != want {
			return nil, fmt.Errorf("P terminal question: relocated field reader mismatch")
		}
	}
	code := buildPTerminalQuestion(guard)
	if len(code) != end-start {
		return nil, fmt.Errorf("P terminal question: instruction extent mismatch")
	}
	out := bytes.Clone(current)
	copy(out[start:end], code)
	return out, nil
}
