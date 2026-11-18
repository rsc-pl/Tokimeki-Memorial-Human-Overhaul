package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type gSuffixSite struct {
	start, end, tail, join uint32
	pairs                  [][2]uint32
}

var gSuffixSites = [...]gSuffixSite{
	{0x800816c8, 0x80081774, 0x80081724, 0x8008169c, [][2]uint32{{0x800816c8, 0x800816d0}, {0x800816d8, 0x800816dc}, {0x8008172c, 0x80081734}, {0x80081744, 0x80081750}}},
	{0x80082000, 0x800820b0, 0x80082060, 0x80081fd4, [][2]uint32{{0x80082000, 0x80082008}, {0x80082010, 0x8008201c}, {0x80082028, 0x8008202c}, {0x80082068, 0x80082070}, {0x80082080, 0x8008208c}}},
}

const gSuffixSource = uint32(0x800b35b4)
const gSuffixBodyWords = 24

// Normalize only a complete, even-sized packed Latin name ending in the
// separate encoded -san suffix. Its original alignment pad moves behind
// the suffix. The shared source, parser indices and following text are
// untouched. Both halves fit in the compacted original G copy loops.
func gSuffixLeaf(first bool, here, next uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	pLeaf := pPunctuationSites[0].start + 4*pPunctuationBodyWords
	ret := pPunctuationSites[1].start + 4*pPunctuationBodyWords + 17*4
	bret := func(op, rs, rt uint32) {
		pc := here + uint32(len(a.words))*4
		w(olIType(op, rs, rt, uint16(int16((int64(ret)-int64(pc)-4)/4))))
	}
	if first {
		w(olADDIU(9, 16, -6))
		w(olSLTIU(9, 9, 26)) // length 6..31, constrained to the 32-byte field
		bret(4, 9, 0)
		w(olIType(12, 16, 9, 1))
		bret(5, 9, 0)
		w(olLBU(11, 8, -5))
		w(olADDIU(12, 0, 0xa0))
		bret(5, 11, 12)
		w(olLBU(11, 8, -4))
		w(olADDIU(13, 0, 0xad))
		bret(5, 11, 13)
		w(olLBU(11, 8, -3))
		w(olADDIU(13, 0, 0xf3))
		bret(5, 11, 13)
		w(olLBU(11, 8, -2))
		w(olADDIU(13, 0, 0xe1))
		bret(5, 11, 13)
		w(olLBU(11, 8, -1))
		w(jWord(next)) // unchanged following comparator is the delay slot
	} else {
		w(olADDIU(13, 0, 0xee))
		bret(5, 11, 13)
		w(olAddu(14, 17, 0))
		a.label("prefix")
		w(olLBU(11, 14, 0))
		w(olADDIU(14, 14, 1))
		w(olIType(12, 11, 11, 0xdf)) // packed ASCII case fold
		w(olADDIU(11, 11, -0xc1))
		w(olSLTIU(11, 11, 26))
		bret(4, 11, 0)
		w(olADDIU(10, 8, -5))
		a.b(5, 14, 10, "prefix")
		w(olADDIU(11, 0, 0xad))
		w(olSB(11, 8, -5))
		w(olADDIU(11, 0, 0xf3))
		w(olSB(11, 8, -4))
		w(olADDIU(11, 0, 0xe1))
		w(olSB(11, 8, -3))
		w(olSB(13, 8, -2))
		w(jWord(pLeaf)) // consume the new trailing pad before punctuation
		w(olSB(12, 8, -1))
	}
	a.resolve()
	return words(a.words...)
}

func buildGSuffixBody(g parserGuardProgram, leaf uint32, site gSuffixSite) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	w(olLUI(4, gSuffixSource))
	w(jalWord(g.entries["checkedstrlen"]))
	w(olADDIU(4, 4, int16(gSuffixSource&0xffff)))
	mov(16, 2)
	mov(6, 2)
	w(olLUI(5, gSuffixSource))
	w(olADDIU(5, 5, int16(gSuffixSource&0xffff)))
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
	w(olAddu(8, 17, 16))
	w(olAddu(21, 21, 16))
	w(olADDIU(21, 21, -1))
	w(21<<16 | 21<<11 | 16<<6)
	w(21<<16 | 21<<11 | 16<<6 | 3)
	w(jWord(site.join))
	mov(2, 16)
	a.resolve()
	return words(a.words...)
}

// PlanGSuffixJoin authenticates both relocated G source paths and rewrites
// only their existing copy-loop extents; no additional memory is reserved.
func PlanGSuffixJoin(retail, current []byte) ([]byte, error) {
	if len(retail) != 667648 || len(current) != len(retail) || sha(retail) != OriginalEXESHA {
		return nil, fmt.Errorf("G suffix: executable identity mismatch")
	}
	g, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return nil, err
	}
	at := func(pc uint32) int { return int(pc - Base) }
	if !bytes.Equal(current[at(parserGuardParserGuardRAM):at(parserGuardParserGuardRAM)+len(g.code)], g.code) {
		return nil, fmt.Errorf("G suffix: guarded parser mismatch")
	}
	for i, s := range pPunctuationSites {
		p := s.start + 4*pPunctuationBodyWords
		want := pPunctuationLeaf(i == 0, p, pPunctuationSites[1].start+4*pPunctuationBodyWords)
		if !bytes.Equal(current[at(p):at(s.end)], want) || binary.LittleEndian.Uint32(current[at(s.end):]) != 0x24010053 {
			return nil, fmt.Errorf("G suffix: punctuation leaf mismatch at %#x", p)
		}
	}
	leaf := gSuffixSites[0].start + 4*gSuffixBodyWords
	next := gSuffixSites[1].start + 4*gSuffixBodyWords
	out := bytes.Clone(current)
	for i, s := range gSuffixSites {
		want := bytes.Clone(retail[at(s.start):at(s.end)])
		for _, pair := range s.pairs {
			hi, lo := pair[0]-s.start, pair[1]-s.start
			binary.LittleEndian.PutUint32(want[hi:], n20RelocLUIWord(binary.LittleEndian.Uint32(want[hi:]), gSuffixSource))
			binary.LittleEndian.PutUint32(want[lo:], binary.LittleEndian.Uint32(want[lo:])&0xffff0000|gSuffixSource&0xffff)
		}
		binary.LittleEndian.PutUint32(want[4:], jalWord(g.entries["checkedstrlen"]))
		binary.LittleEndian.PutUint32(want[s.tail-s.start:], jalWord(g.entries["dynamic_strncpy"]))
		if !bytes.Equal(current[at(s.start):at(s.end)], want) || !bytes.Equal(current[at(s.start)-12:at(s.start)], retail[at(s.start)-12:at(s.start)]) || !bytes.Equal(current[at(s.join):at(s.join)+32], retail[at(s.join):at(s.join)+32]) || binary.LittleEndian.Uint32(current[at(s.end):]) != 0x24010070 {
			return nil, fmt.Errorf("G suffix: relocated copy preimage mismatch at %#x", s.start)
		}
		body := buildGSuffixBody(g, leaf, s)
		body = append(body, gSuffixLeaf(i == 0, s.start+4*gSuffixBodyWords, next)...)
		if len(body) != int(s.end-s.start) {
			return nil, fmt.Errorf("G suffix: extent mismatch at %#x: %d", s.start, len(body))
		}
		copy(out[at(s.start):at(s.end)], body)
	}
	return out, nil
}
