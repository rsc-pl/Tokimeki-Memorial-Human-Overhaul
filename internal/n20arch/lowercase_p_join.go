package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PlanLowercasePJoin routes both authenticated lowercase-p renderer branches
// through the existing bounded name-copy/terminal-punctuation implementation.
// The source pointer remains the native s6 field-prepared by the game; no
// source-name or save changes, extra storage or new executable region exist.
func PlanLowercasePJoin(retail, current []byte) ([]byte, error) {
	if len(retail) != 667648 || len(current) != len(retail) || sha(retail) != OriginalEXESHA {
		return nil, fmt.Errorf("lowercase p: original executable identity")
	}
	at := func(pc uint32) int { return int(pc - Base) }
	const common uint32 = 0x8008157c
	// The existing shared guarded-copy program must already be fully present.
	g, err := parserCopyGuardCompactParserProgram()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(current[at(parserGuardParserGuardRAM):at(parserGuardParserGuardRAM)+len(g.code)], g.code) {
		return nil, fmt.Errorf("lowercase p: guarded copy missing")
	}
	if binary.LittleEndian.Uint32(current[at(pPunctuationSites[0].start):]) != olAddu(16, 23, 0) ||
		binary.LittleEndian.Uint32(current[at(0x80081608):]) != jWord(gSuffixSites[1].start+12) ||
		binary.LittleEndian.Uint32(current[at(pPunctuationSites[1].start):]) != jWord(common) {
		return nil, fmt.Errorf("lowercase p: shared copy entry not installed")
	}
	// The parser's original s6 must point at the relocated, pair-aligned working
	// family field. Validate the exact LUI/ADDIU producer, not a guessed pointer.
	for _, pc := range []uint32{0x800813fc, 0x80081408} {
		old := binary.LittleEndian.Uint32(retail[at(pc):])
		want := n20RelocADDIUWord(old, N20RelocFamilyAddr)
		if pc == 0x800813fc {
			want = n20RelocLUIWord(old, N20RelocFamilyAddr)
		}
		if binary.LittleEndian.Uint32(current[at(pc):]) != want {
			return nil, fmt.Errorf("lowercase p: field source drift at %#x", pc)
		}
	}
	if N20RelocFamilyAddr&3 != 0 {
		return nil, fmt.Errorf("lowercase p: unaligned source")
	}
	out := bytes.Clone(current)
	// Only the three-instruction entry of each native lowercase-p body is
	// changed. The p/other-marker comparators, native fallthrough, later parser
	// cases, source buffers and existing P/G correction bytes remain unmodified.
	for i, s := range []struct{ marker, entry, end uint32 }{
		{0x80081774, 0x80081780, 0x8008181c},
		{0x800820b0, 0x800820bc, 0x80082158},
	} {
		// The existing guarded manual-loop pass already owns the first strlen JAL of each
		// lowercase-p loop: require its exact guarded replacement, not
		// retail's unguarded strlen. The shared copy retains both
		// checked-length and bounded-copy guarantees.
		want := bytes.Clone(retail[at(s.marker) : at(s.end)+4])
		binary.LittleEndian.PutUint32(want[at(s.entry)-at(s.marker):], jalWord(g.entries["checkedstrlen"]))
		// The authenticated manual-loop copy stage also guards the native
		// second length/copy operation (the original call +0x54).
		binary.LittleEndian.PutUint32(want[at(s.entry+0x54)-at(s.marker):], jalWord(g.entries["dynamic_strncpy"]))
		if !bytes.Equal(current[at(s.marker):at(s.end)+4], want) {
			for pc := s.marker; pc <= s.end; pc += 4 {
				prev, got := binary.LittleEndian.Uint32(want[at(pc)-at(s.marker):]), binary.LittleEndian.Uint32(current[at(pc):])
				if prev != got {
					return nil, fmt.Errorf("lowercase p: native branch %d preimage mismatch at %#x: retail %#08x current %#08x", i, pc, prev, got)
				}
			}
			return nil, fmt.Errorf("lowercase p: native branch %d preimage mismatch", i)
		}
		// Low bit tags the second parser. The common guarded copy selects the
		// corresponding native continuation and the same P punctuation validator.
		entry := []uint32{olAddu(16, 22, 0), jWord(common), 0}
		if i != 0 {
			entry[0] = olORI(16, 22, 1)
		}
		for j, w := range entry {
			binary.LittleEndian.PutUint32(out[at(s.entry)+j*4:], w)
		}
	}
	return out, nil
}
