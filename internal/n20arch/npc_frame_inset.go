package n20arch

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

// PlanNPCFrameInsetPrivate applies the owner's one-time, jointly shifted
// visual compromise AFTER NPC spacing on the SIX authenticated NPC-A EXE routes.
// Both surname and its quote move RIGHT 3 native X units; the NPC coordinates parser
// reads that same quote position and therefore also moves RIGHT 3.
// The ink-to-quote separation is EXACTLY the same as owner-tested NPC spacing.
// Telephone, title activity, exams, seasonal overlays and N20 are untouched.
// This is a PRIVATE test-only candidate, NOT a runtime or production PASS.
func PlanNPCFrameInsetPrivate(retail, npcFrameStage []byte, names []string) ([]byte, error) {
	const base uint32 = 0x80040800
	if len(npcFrameStage) != len(retail) || len(names) != 16 {
		return nil, fmt.Errorf("NPC frame wrong EXE/name-table dimensions")
	}
	const digest = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	if len(retail) != 667648 || fmt.Sprintf("%x", sha256.Sum256(retail)) != digest {
		return nil, fmt.Errorf("NPC frame authentic retail EXE mismatch")
	}
	// All twelve speaker/quote preimages below MUST be the exact NPC spacing opcodes;
	// layout restoration's unmodified baseline guard is not applicable after NPC spacing.
	enc := &script.PairEncoder{}
	for i, name := range names {
		if name == "" || len(name) > speakerScratchMaxFormattedSourceBytes {
			return nil, fmt.Errorf("NPC frame source-owned name %d has invalid size", i)
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
				return nil, fmt.Errorf("NPC frame source-owned name %d is not supported ASCII", i)
			}
		}
		pairs, err := enc.Encode(name)
		if err != nil || len(pairs) < len(name) || len(pairs) > len(name)+1 || len(pairs) < 2 || len(pairs)%2 != 0 {
			return nil, fmt.Errorf("NPC frame invalid encoded name %d", i)
		}
		n := len(pairs)
		last, err := graphics.RenderPair(pairs[n-2]&0x7f, pairs[n-1]&0x7f)
		if err != nil {
			return nil, fmt.Errorf("NPC frame bad pair glyph %d: %w", i, err)
		}
		inkWidth := 0
		for y := 0; y < 12; y++ {
			for x := 0; x < 12; x++ {
				if last[(y*12+x)/8]&(0x80>>uint((y*12+x)%8)) != 0 && x+1 > inkWidth {
					inkWidth = x + 1
				}
			}
		}
		// NPC spacing name=-101-4*n; quote=-105+4*n. Both shift +3.
		speakerX := -98 - 4*n
		quoteX := -102 + 4*n
		for _, stride := range []int{14, 16} {
			inkEnd := speakerX + (n/2-1)*stride + inkWidth
			if quoteX < inkEnd {
				return nil, fmt.Errorf("NPC frame name %d overlaps quote at stride %d", i, stride)
			}
		}
	}
	get := func(b []byte, pc uint32) uint32 { return binary.LittleEndian.Uint32(b[pc-base:]) }
	out := append([]byte(nil), npcFrameStage...)
	for i, r := range npcNameQueueNPCNameQueues {
		// Exact NPC spacing installed words, not an approximate instruction pattern.
		oldName := get(npcFrameStage, r.NameBasePC)
		oldQuote := get(npcFrameStage, r.NameQueuePC+0x20)
		original := get(retail, r.NameBasePC)
		wantName := (original & 0xffff0000) | 0xff9b
		if original&0xffff != 0xff98 || original>>26 != 9 || oldName != wantName || oldQuote != 0x2484ff97 {
			return nil, fmt.Errorf("NPC frame unexpected NPC spacing preimage at route %d", i)
		}
		binary.LittleEndian.PutUint32(out[r.NameBasePC-base:], (original&0xffff0000)|0xff9e)
		binary.LittleEndian.PutUint32(out[r.NameQueuePC+0x20-base:], 0x2484ff9a)
	}
	return out, nil
}
