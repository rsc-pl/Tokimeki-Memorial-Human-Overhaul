package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// The four native G/P expansions share their exact guarded copy contract.
// Tag the aligned source pointer in s0 (which the original loops overwrite
// with strlen), then keep the two dispatch bits above the bounded length
// across the copy calls. Restore the native length and signed indices before
// entering the original parser continuation. No extra stack or RAM slot.
func gpSharedCopy(g parserGuardProgram, common, dispatch, inner uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	w(olIType(12, 16, 8, 3))
	w(jalWord(g.entries["checkedstrlen"]))
	w(olSUBU(4, 16, 8))
	w(olIType(12, 16, 8, 3))
	w(olSUBU(5, 16, 8))
	w(8<<16 | 8<<11 | 16<<6)
	w(olRType(2, 8, 16, 0x25))
	mov(6, 2)
	w(jalWord(g.entries["dynamic_strncpy"]))
	mov(4, 17)
	w(olLW(5, 29, 0x60))
	w(olIType(12, 16, 8, 0xffff))
	w(olAddu(4, 17, 8))
	w(olADDIU(6, 29, 0x2e4))
	w(olAddu(5, 5, 20))
	w(olSUBU(6, 6, 4))
	w(jalWord(g.entries["dynamic_strncpy"]))
	w(olADDIU(5, 5, 1))
	w(16<<16 | 24<<11 | 16<<6 | 2)
	w(olIType(12, 16, 16, 0xffff))
	w(olIType(12, 24, 15, 2))
	w(jalWord(dispatch))
	mov(8, 2)
	w(jalWord(inner))
	w(olAddu(21, 21, 16))
	w(olADDIU(21, 21, -1))
	w(21<<16 | 21<<11 | 16<<6)
	w(21<<16 | 21<<11 | 16<<6 | 3)
	w(olIType(12, 24, 24, 1))
	pc := common + uint32(len(a.words))*4
	w(olIType(5, 24, 0, uint16(int16((int64(pPunctuationSites[1].join)-int64(pc)-4)/4))))
	mov(2, 16)
	w(jWord(pPunctuationSites[0].join))
	w(0)
	return words(a.words...)
}

// The installed narrow-pair renderer selects packed glyphs at first byte
// >= A0. Only move a complete run of bytes within its bounded alphabet;
// reject mixed fullwidth pairs, other controls and an unterminated run.
// A0 is moved from before the punctuation to the last byte of this SAME
// run. The delimiter offset, run length and all subsequent bytes stay put.
func gpInnerWords() *miniAsm {
	a := &miniAsm{labels: map[string]int{}}
	w := a.w
	a.b(4, 16, 0, "ret")
	w(olIType(12, 16, 9, 1))
	a.b(5, 9, 0, "ret")
	w(olADDIU(11, 29, 0x2e4))
	w(olRType(2, 11, 9, 0x2b))
	a.b(4, 9, 0, "ret")
	w(olLBU(9, 2, -2))
	w(olADDIU(12, 0, 0xa0))
	a.b(4, 9, 12, "ret") // two trailing spaces are not a single alignment pad
	w(olLBU(10, 2, -1))
	const mask uint32 = 1<<1 | 1<<7 | 1<<12 | 1<<14 | 1<<31 // ! ' , . ?
	w(olLUI(13, mask))
	a.b(5, 10, 12, "ret")
	w(olLBU(10, 2, 0))
	w(olORI(13, 13, mask&0xffff))
	w(olSLTIU(8, 10, 0xc0))
	a.b(4, 8, 0, "ret")
	w(olRType(10, 13, 13, 6)) // srlv: low five bits select the punctuation
	w(olIType(12, 13, 13, 1))
	a.b(4, 13, 0, "ret")
	w(olAddu(8, 17, 0))
	a.label("scan")
	w(olLBU(10, 8, 0))
	w(olADDIU(8, 8, 1))
	w(olADDIU(9, 10, -0xa0))
	w(olSLTIU(9, 9, 0x5b))
	a.b(4, 9, 0, "delimiter")
	w(olIType(12, 10, 13, 0xdf))
	// The scan starts within the checked scratch and advances by one,
	// so equality at the end suffices and no byte beyond it is loaded.
	a.b(5, 8, 11, "scan")
	w(0)
	a.label("ret")
	w(olJR(31))
	w(0)
	a.label("delimiter")
	a.b(5, 13, 0, "ret")
	w(olSUBU(9, 8, 17))
	w(olIType(12, 9, 9, 1))
	a.b(4, 9, 0, "ret") // complete pair run, not an odd/truncated literal
	w(olADDIU(8, 8, -1))
	w(olRType(2, 8, 9, 0x2b))
	a.b(4, 9, 0, "ret")
	w(0)
	a.label("shift")
	w(olLBU(10, 2, 0))
	w(olADDIU(2, 2, 1))
	a.b(5, 2, 8, "shift")
	w(olSB(10, 2, -2))
	w(olJR(31))
	w(olSB(12, 8, -1))
	return a
}

// Move the existing G suffix leaf to a single native extent. Its exact
// validation and fallback stay identical; the already-validated four
// suffix bytes can be rotated with a bounded byte loop instead of literals.
func gpLegacyG(here, pLeaf, pRet uint32) []byte {
	oldA := gSuffixSites[0].start + 4*gSuffixBodyWords
	oldB := gSuffixSites[1].start + 4*gSuffixBodyWords
	oldRet := pPunctuationSites[1].start + 4*pPunctuationBodyWords + 17*4
	a := gSuffixLeaf(true, oldA, oldB)
	b := gSuffixLeaf(false, oldB, oldB)
	var out []uint32
	add := func(raw []byte, old uint32, count int) {
		for i := 0; i < count; i++ {
			v := binary.LittleEndian.Uint32(raw[i*4:])
			if v>>26 == 4 || v>>26 == 5 {
				target := uint32(int64(old) + int64(i*4+4) + int64(int16(v))*4)
				pc := here + uint32(len(out))*4
				if target == oldRet {
					target = pRet
				} else {
					target = pc + 4 + uint32(int32(int16(v))*4)
				}
				v = v&0xffff0000 | uint32(uint16(int16((int64(target)-int64(pc)-4)/4)))
			}
			out = append(out, v)
		}
	}
	add(a, oldA, 18) // fall directly through to the second validator
	add(b, oldB, 11) // keep the prefix loop, replace its delay slot
	out = append(out, olADDIU(13, 8, -1))
	out = append(out, olLBU(11, 14, 1), olADDIU(14, 14, 1),
		olIType(5, 14, 13, uint16(0xfffd)), olSB(11, 14, -1),
		jWord(pLeaf), olSB(12, 8, -1))
	return words(out...)
}

// PlanGPInnerPunctuation is staged after the existing terminal and suffix
// planners, whose emitted instruction preimages are authenticated again.
// It owns only their four existing native extents; unrelated code and all
// overlay bytes are unchanged.
func PlanGPInnerPunctuation(retail, current []byte) ([]byte, error) {
	if len(retail) != 667648 || len(current) != len(retail) || sha(retail) != OriginalEXESHA || givenKunExtended&3 != 0 || gSuffixSource&3 != 0 {
		return nil, fmt.Errorf("dynamic punctuation: source identity or alignment")
	}
	g, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return nil, err
	}
	at := func(pc uint32) int { return int(pc - Base) }
	if !bytes.Equal(current[at(parserGuardParserGuardRAM):at(parserGuardParserGuardRAM)+len(g.code)], g.code) {
		return nil, fmt.Errorf("dynamic punctuation: guarded copy preimage")
	}
	p0, p1 := pPunctuationSites[0], pPunctuationSites[1]
	g0, g1 := gSuffixSites[0], gSuffixSites[1]
	for i, p := range pPunctuationSites {
		want := append(buildPTerminalPunctuation(g, p0.start+4*pPunctuationBodyWords, p), pPunctuationLeaf(i == 0, p.start+4*pPunctuationBodyWords, p1.start+4*pPunctuationBodyWords)...)
		if !bytes.Equal(current[at(p.start):at(p.end)], want) || binary.LittleEndian.Uint32(current[at(p.end):]) != 0x24010053 || !bytes.Equal(current[at(p.join):at(p.join)+32], retail[at(p.join):at(p.join)+32]) {
			return nil, fmt.Errorf("dynamic punctuation: P preimage %#x", p.start)
		}
	}
	for i, s := range gSuffixSites {
		want := append(buildGSuffixBody(g, g0.start+4*gSuffixBodyWords, s), gSuffixLeaf(i == 0, s.start+4*gSuffixBodyWords, g1.start+4*gSuffixBodyWords)...)
		if !bytes.Equal(current[at(s.start):at(s.end)], want) || binary.LittleEndian.Uint32(current[at(s.end):]) != 0x24010070 {
			return nil, fmt.Errorf("dynamic punctuation: G preimage %#x", s.start)
		}
	}
	common := p0.start + 4
	pLeaf := p1.start + 8
	pNext := pLeaf + 18*4
	pRet := pNext + 17*4
	gLeaf := g1.start + 12
	legacyG := gpLegacyG(gLeaf, pLeaf, pRet)
	inner := gLeaf + uint32(len(legacyG))
	dispatch := common + 33*4
	body := gpSharedCopy(g, common, dispatch, inner)
	if len(body) != 33*4 {
		return nil, fmt.Errorf("dynamic punctuation: shared copy size %d", len(body))
	}
	out := bytes.Clone(current)
	install := func(start, end uint32, raw []byte) error {
		if len(raw) > int(end-start) {
			return fmt.Errorf("dynamic punctuation: extent %#x needs %d of %d bytes", start, len(raw), end-start)
		}
		clear(out[at(start):at(end)])
		copy(out[at(start):at(end)], raw)
		return nil
	}
	// The leaf calls use only t0..t7; t8 carries the parser instance bit.
	pc := dispatch
	disp := words(olIType(4, 15, 0, uint16(int16((int64(pLeaf)-int64(pc)-4)/4))), 0, jWord(gLeaf), 0)
	first := append(words(olAddu(16, 23, 0)), body...)
	first = append(first, disp...)
	if err = install(p0.start, p0.end, first); err != nil {
		return nil, err
	}
	second := words(jWord(common), olORI(16, 23, 1))
	second = append(second, pPunctuationLeaf(true, pLeaf, pNext)...)
	second = append(second, pPunctuationLeaf(false, pNext, pNext)...)
	second = append(second, words(0)...)
	if err = install(p1.start, p1.end, second); err != nil {
		return nil, err
	}
	entry := func(tag uint32) []byte {
		return words(olLUI(16, gSuffixSource), jWord(common), olORI(16, 16, (gSuffixSource&0xffff)|tag))
	}
	// Split at the complete initial guard, with a delay-slot comparator
	// that is already authenticated and has no live output here.
	leaf := gpInnerWords()
	const split = 4
	tailPC := g0.start + 12
	pcFor := func(i int) uint32 {
		if i < split {
			return inner + uint32(i*4)
		}
		return tailPC + uint32((i-split)*4)
	}
	for _, f := range leaf.fix {
		off := int64(pcFor(leaf.labels[f.label])) - int64(pcFor(f.idx)) - 4
		leaf.words[f.idx] |= uint32(uint16(int16(off / 4)))
	}
	left := append(entry(3), legacyG...)
	left = append(left, words(leaf.words[:split]...)...)
	left = append(left, words(jWord(tailPC))...)
	if uint32(len(left)) != g1.end-g1.start {
		return nil, fmt.Errorf("dynamic punctuation: guard split %d vs %d", len(left), g1.end-g1.start)
	}
	if err = install(g1.start, g1.end, left); err != nil {
		return nil, err
	}
	right := append(entry(2), words(leaf.words[split:]...)...)
	if err = install(g0.start, g0.end, right); err != nil {
		return nil, err
	}
	return out, nil
}
