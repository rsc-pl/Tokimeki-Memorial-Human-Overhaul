package n20arch

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

// PlanNPCModerateBalancePrivate is a source-owned and preimage-guarded
// compromise for the SIX NPC-A EXE paths only. NPC spacing stays responsible for the
// prefix/parser synchronization; NPC spacing moves the label RIGHT 3 native X units
// and their paired quote+body LEFT 1 unit. This sacrifices NPC spacing's conservative
// four-pixel inter-element reserve but never accepts overlapping glyph ink in
// the model for the exact current 16 names in both 14/16 stride modes.
// The phone, other 8 formatters, overlay consumers, UI and N20 are untouched.
// One owner private runtime test is still essential; NOT safe for public use.
func PlanNPCModerateBalancePrivate(retail, npcSpacingStage []byte, names []string) ([]byte, error) {
	const base uint32 = 0x80040800
	const digest = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	if len(retail) != 667648 || len(npcSpacingStage) != len(retail) || fmt.Sprintf("%x", sha256.Sum256(retail)) != digest {
		return nil, fmt.Errorf("NPC spacing authentic retail EXE mismatch")
	}
	if len(names) != 16 {
		return nil, fmt.Errorf("NPC spacing incomplete source-owned name table")
	}
	enc := &script.PairEncoder{}
	for i, name := range names {
		if name == "" || len(name) > speakerScratchMaxFormattedSourceBytes {
			return nil, fmt.Errorf("NPC spacing unsupported length name %d", i)
		}
		for _, c := range name {
			if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
				return nil, fmt.Errorf("NPC spacing unsupported non-ASCII letter name %d", i)
			}
		}
		pairs, err := enc.Encode(name)
		if err != nil || len(pairs) < len(name) || len(pairs) > len(name)+1 || len(pairs) < 2 || len(pairs)%2 != 0 {
			return nil, fmt.Errorf("NPC spacing invalid pair layout name %d", i)
		}
		n := len(pairs)
		last, err := graphics.RenderPair(pairs[n-2]&0x7f, pairs[n-1]&0x7f)
		if err != nil {
			return nil, fmt.Errorf("NPC spacing invalid last glyph name %d: %w", i, err)
		}
		inkWidth := 0
		for y := 0; y < 12; y++ {
			for x := 0; x < 12; x++ {
				if last[(y*12+x)/8]&(0x80>>uint((y*12+x)%8)) != 0 && x+1 > inkWidth {
					inkWidth = x + 1
				}
			}
		}
		speakerX := -101 - 4*n // NPC spacing speaker -104-4n, +3
		prefixX := -105 + 4*n  // NPC spacing prefix -104+4n, -1
		for _, stride := range []int{14, 16} {
			lastInkEnd := speakerX + (n/2-1)*stride + inkWidth
			if prefixX < lastInkEnd {
				return nil, fmt.Errorf("NPC spacing name %d would overlap with prefix at stride %d by %d", i, stride, lastInkEnd-prefixX)
			}
		}
	}
	if err := VerifyNPCLabelGeometryBaseline(retail, npcSpacingStage); err != nil {
		return nil, fmt.Errorf("NPC spacing speaker geometry rollback missing: %w", err)
	}
	get := func(b []byte, pc uint32) uint32 { return binary.LittleEndian.Uint32(b[pc-base:]) }
	out := append([]byte(nil), npcSpacingStage...)
	for i, r := range npcNameQueueNPCNameQueues {
		// Original speaker is the immediate addiu at NameBasePC. The prefix
		// sits at NameQueuePC+0x20 after NPC spacing. The parser X reloads that exact
		// prefix from stack, so both elements stay coordinated automatically.
		old := get(retail, r.NameBasePC)
		if old&0xffff != 0xff98 || old>>26 != 9 || get(npcSpacingStage, r.NameBasePC) != old {
			return nil, fmt.Errorf("NPC spacing speaker preimage drift in route %d", i)
		}
		pc := r.NameQueuePC + 0x20
		if get(retail, pc) != 0x2404ffaa || get(npcSpacingStage, pc) != 0x2484ff98 {
			return nil, fmt.Errorf("NPC spacing NPC spacing quote preimage drift in route %d", i)
		}
		binary.LittleEndian.PutUint32(out[r.NameBasePC-base:], (old&0xffff0000)|0xff9b)
		binary.LittleEndian.PutUint32(out[pc-base:], 0x2484ff97)
	}
	return out, nil
}
