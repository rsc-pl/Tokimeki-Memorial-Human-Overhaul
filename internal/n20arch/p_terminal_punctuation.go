package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type pPunctuationSite struct{ start, end, tail, join uint32 }

var pPunctuationSites = [...]pPunctuationSite{
	{0x80081578, 0x80081614, 0x800815cc, 0x8008169c},
	{0x80081eb0, 0x80081f4c, 0x80081f04, 0x80081fd4},
}

const pPunctuationBodyWords = 21

// Both P branches copy the prepared field and the literal tail into the same
// bounded parser scratch. The shared leaf uses only words freed by those
// two compact copy loops. It does not modify the saved or prepared name.
func pPunctuationLeaf(first bool, here, next uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	if first {
		branch := func(op, rs, rt, target uint32) {
			pc := here + uint32(len(a.words))*4
			w(olIType(op, rs, rt, uint16(int16((int64(target)-int64(pc)-4)/4))))
		}
		ret := next + 17*4
		w(olADDIU(9, 29, 0x2e2))
		w(olRType(9, 2, 9, 0x2b))
		branch(5, 9, 0, ret)
		w(olLBU(10, 17, 0)) // the copied name starts at s1 in either parser
		w(olADDIU(11, 0, 0xa0))
		w(olADDIU(10, 10, -0xc1))
		w(olSLTIU(10, 10, 26))
		branch(4, 10, 0, ret)
		w(olLBU(9, 2, -1))
		w(olLBU(10, 2, 0))
		branch(5, 9, 11, ret)
		w(olLBU(12, 2, 1))
		w(olORI(10, 10, 0x80))
		w(olADDIU(13, 0, 0xbf))
		branch(4, 10, 13, next+2*4)
		w(olIType(12, 10, 13, 0xfd)) // comma and period differ only by bit 1
		w(jWord(next))
		w(olADDIU(14, 0, 0xac))
	} else {
		a.b(5, 13, 14, "ret")
		w(0)
		a.label("matched")
		a.b(4, 12, 0, "raw")
		w(olADDIU(9, 29, 0x2e1))
		a.b(5, 12, 11, "ret")
		w(olRType(9, 2, 9, 0x2b))
		a.b(5, 9, 0, "ret")
		w(0)
		w(olLBU(9, 2, 2))
		w(0)
		// Only NUL or the native line-break control (0x20) can follow.
		// For a line break, leave a blank pair in the old punctuation
		// cell, preserving every subsequent control and parser index.
		w(olIType(12, 9, 13, 0xdf))
		a.b(5, 13, 0, "ret")
		w(9<<16 | 13<<11 | 2<<6) // sll t5,t1,2
		w(olAddu(12, 9, 13))     // 0 -> 0, 0x20 -> 0xA0
		w(olSB(12, 2, 1))
		a.label("raw")
		w(olSB(10, 2, -1))
		w(olSB(12, 2, 0))
		a.label("ret")
		w(olJR(31))
		// The untouched following S comparator supplies the delay slot.
		// Its write to at is dead before the common parser continuation.
	}
	a.resolve()
	return words(a.words...)
}

func buildPTerminalPunctuation(g parserGuardProgram, leaf uint32, site pPunctuationSite) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	w(jalWord(g.entries["checkedstrlen"]))
	mov(4, 23)
	mov(16, 2)
	mov(6, 2)
	mov(5, 23)
	w(jalWord(g.entries["dynamic_strncpy"]))
	mov(4, 17)
	w(olLW(5, 29, 0x60))
	w(olAddu(4, 17, 16))
	w(olADDIU(6, 29, 0x2e4))
	w(olAddu(5, 5, 20))
	w(olSUBU(6, 6, 4))
	w(jalWord(g.entries["dynamic_strncpy"]))
	w(olADDIU(5, 5, 1))
	w(jalWord(leaf))
	w(olAddu(21, 21, 16))
	w(olADDIU(21, 21, -1))
	w(21<<16 | 21<<11 | 16<<6)
	w(21<<16 | 21<<11 | 16<<6 | 3)
	w(jWord(site.join))
	mov(2, 16)
	a.resolve()
	return words(a.words...)
}

// PlanPTerminalPunctuation extends the existing exact terminal question
// handling to both native P copy paths and terminal comma/period/question
// forms, including a packed punctuation cell ending a non-final line.
// Other nonterminal literals and non-Latin prepared fields remain untouched.
func PlanPTerminalPunctuation(retail, current []byte) ([]byte, error) {
	// Authenticate the original first branch and prepared-field relocation.
	if _, err := PlanPTerminalQuestion(retail, current); err != nil {
		return nil, err
	}
	g, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return nil, err
	}
	at := func(pc uint32) int { return int(pc - Base) }
	out := bytes.Clone(current)
	leaf := pPunctuationSites[0].start + 4*pPunctuationBodyWords
	next := pPunctuationSites[1].start + 4*pPunctuationBodyWords
	for i, s := range pPunctuationSites {
		want := bytes.Clone(retail[at(s.start):at(s.end)])
		binary.LittleEndian.PutUint32(want, jalWord(g.entries["checkedstrlen"]))
		binary.LittleEndian.PutUint32(want[s.tail-s.start:], jalWord(g.entries["dynamic_strncpy"]))
		if !bytes.Equal(current[at(s.start):at(s.end)], want) || !bytes.Equal(current[at(s.start)-24:at(s.start)], retail[at(s.start)-24:at(s.start)]) || !bytes.Equal(current[at(s.join):at(s.join)+32], retail[at(s.join):at(s.join)+32]) || binary.LittleEndian.Uint32(current[at(s.end):]) != 0x24010053 {
			return nil, fmt.Errorf("P terminal punctuation: source drift at %#x", s.start)
		}
		body := buildPTerminalPunctuation(g, leaf, s)
		if len(body) != 4*pPunctuationBodyWords {
			return nil, fmt.Errorf("P terminal punctuation: unexpected body size %d", len(body))
		}
		body = append(body, pPunctuationLeaf(i == 0, s.start+4*pPunctuationBodyWords, next)...)
		if len(body) != int(s.end-s.start) {
			return nil, fmt.Errorf("P terminal punctuation: extent mismatch at %#x", s.start)
		}
		copy(out[at(s.start):at(s.end)], body)
	}
	return out, nil
}
