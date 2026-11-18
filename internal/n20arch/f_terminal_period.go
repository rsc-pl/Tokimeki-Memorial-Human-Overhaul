package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type fPeriodSite struct{ start, end, tail, join uint32 }

var fPeriodSites = []fPeriodSite{
	{0x800818fc, 0x80081998, 0x80081950, 0x8008169c},
	{0x80082238, 0x800822d4, 0x8008228c, 0x80081fd4},
}

const fPeriodBodyWords = 23

// The two original F loops each free 16 instruction words. The shared leaf
// uses those words, leaving the renderer reservation and the date gate intact.
func fPeriodLeafPart(first bool, next uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	if first {
		base := fPeriodSites[0].start + 4*fPeriodBodyWords
		ret := next + 11*4
		bret := func(op, rs, rt uint32) {
			pc := base + uint32(len(a.words))*4
			w(olIType(op, rs, rt, uint16((int32(ret)-int32(pc)-4)/4)))
		}
		w(olADDIU(9, 29, 0x2e1))
		w(olRType(9, 2, 9, 0x2b))
		bret(5, 9, 0)
		w(olLBU(10, 18, 0))
		w(olADDIU(12, 0, 0xa0)) // load delay before reading the initial glyph
		w(olADDIU(10, 10, -0xc1))
		w(olSLTIU(10, 10, 26))
		bret(4, 10, 0)
		w(0)
		w(olLBU(9, 2, -1))
		w(olLBU(11, 2, 0))
		bret(5, 9, 12)
		w(olADDIU(12, 0, 0xae))
		w(jWord(next))
		w(0)
	} else {
		w(olLBU(9, 2, 1))
		w(olLBU(10, 2, 2))
		w(olADDIU(9, 9, -0xa0))
		w(olADDIU(11, 11, -0xae))
		w(olRType(9, 10, 9, 0x25))
		w(olRType(9, 11, 9, 0x25))
		a.b(5, 9, 0, "done")
		w(0)
		w(olSB(12, 2, -1))
		w(olSB(0, 2, 0))
		w(olSB(0, 2, 1))
		a.label("done")
		w(0x03e00008)
		w(0)
	}
	a.resolve()
	for len(a.words) < 16 {
		w(0)
	}
	return words(a.words...)
}

func buildFTerminalPeriod(g parserGuardProgram, leaf uint32, site fPeriodSite) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	w(jalWord(g.entries["checkedstrlen"]))
	mov(4, 18)
	mov(16, 2)
	mov(6, 2)
	mov(5, 18)
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
	w(0)
	w(olAddu(21, 21, 16))
	w(olADDIU(21, 21, -1))
	w(21<<16 | 21<<11 | 16<<6)
	w(21<<16 | 21<<11 | 16<<6 | 3)
	mov(2, 16)
	w(jWord(site.join))
	w(0)
	a.resolve()
	return words(a.words...)
}

// PlanFTerminalPeriod replaces the two original F copy loops without growing
// their instruction extents; the shared leaf occupies only the freed words
// within those same two loops. No other control token is changed.
func PlanFTerminalPeriod(retail, current []byte) ([]byte, error) {
	if len(retail) != 667648 || len(current) != len(retail) || sha(retail) != OriginalEXESHA {
		return nil, fmt.Errorf("F terminal period: executable identity mismatch")
	}
	g, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return nil, err
	}
	at := func(pc uint32) int { return int(pc - Base) }
	if !bytes.Equal(current[at(parserGuardParserGuardRAM):at(parserGuardParserGuardRAM)+len(g.code)], g.code) {
		return nil, fmt.Errorf("F terminal period: parser reservation mismatch")
	}
	out := bytes.Clone(current)
	leaf := fPeriodSites[0].start + 4*fPeriodBodyWords
	next := fPeriodSites[1].start + 4*fPeriodBodyWords
	for i, s := range fPeriodSites {
		want := bytes.Clone(retail[at(s.start):at(s.end)])
		binary.LittleEndian.PutUint32(want, jalWord(g.entries["checkedstrlen"]))
		binary.LittleEndian.PutUint32(want[s.tail-s.start:], jalWord(g.entries["dynamic_strncpy"]))
		if !bytes.Equal(current[at(s.start):at(s.end)], want) ||
			!bytes.Equal(current[at(s.join):at(s.join)+32], retail[at(s.join):at(s.join)+32]) {
			return nil, fmt.Errorf("F terminal period: instruction preimage mismatch at %#x", s.start)
		}
		body := buildFTerminalPeriod(g, leaf, s)
		if len(body) != 4*fPeriodBodyWords {
			return nil, fmt.Errorf("F terminal period: unexpected body length %d", len(body))
		}
		body = append(body, fPeriodLeafPart(i == 0, next)...)
		if len(body) != int(s.end-s.start) {
			return nil, fmt.Errorf("F terminal period: instruction extent %d != %d", len(body), s.end-s.start)
		}
		copy(out[at(s.start):at(s.end)], body)
	}
	return out, nil
}
