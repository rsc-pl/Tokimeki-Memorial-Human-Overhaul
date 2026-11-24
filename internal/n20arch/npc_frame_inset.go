package n20arch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

// PlanNPCFrameInset applies a coordinated geometry adjustment
// after NPC spacing on six authenticated NPC-A executable routes.
// Both surname and its quote move RIGHT 3 native X units; the NPC coordinates parser
// reads that same quote position and therefore also moves RIGHT 3.
// The ink-to-quote separation is unchanged from the input NPC layout.
// Telephone, title activity, exams, seasonal overlays and N20 are untouched.
// This geometry variant is evaluated offline; no in-game runtime safety is established.
func PlanNPCFrameInset(retail, npcFrameStage []byte, names []string) ([]byte, error) {
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

// PlanLiteralSpeakerGeometry coordinates the two selector-11 fixed-source
// speaker branches without changing the shared queue or ordinary NPC routes.
func PlanLiteralSpeakerGeometry(retail, stage []byte, name string) ([]byte, error) {
	const digest = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	if len(retail) != 667648 || len(stage) != len(retail) || fmt.Sprintf("%x", sha256.Sum256(retail)) != digest {
		return nil, fmt.Errorf("literal speaker retail EXE mismatch")
	}
	get := func(b []byte, pc uint32) uint32 { return binary.LittleEndian.Uint32(b[pc-Base:]) }
	if get(retail, 0x800b22d4) != 0x80080634 || get(stage, 0x800b22d4) != 0x80080634 {
		return nil, fmt.Errorf("literal speaker dispatch mismatch")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
			return nil, fmt.Errorf("literal speaker unsupported source glyph")
		}
	}
	encoded, err := (&script.PairEncoder{}).Encode(name)
	n := len(encoded)
	if err != nil || n < 2 || n > 10 || n%2 != 0 {
		return nil, fmt.Errorf("literal speaker invalid source width")
	}
	alias := stage[ShortHookSpareRAM-Base:]
	if !bytes.Equal(alias[:n], encoded) || alias[n] != 0 {
		return nil, fmt.Errorf("literal speaker relocated source mismatch")
	}
	changedPairs := map[uint32]bool{}
	for _, pair := range [][2]uint32{{0x800807b4, 0x800807bc}, {0x800807e4, 0x800807e8}, {0x80080794, 0x80080868}, {0x80080888, 0x8008088c}} {
		hi, lo := get(stage, pair[0]), get(stage, pair[1])
		if hi>>26 != 15 || lo>>26 != 9 || (hi>>16)&31 != (lo>>16)&31 || (lo>>21)&31 != (lo>>16)&31 ||
			hi&0xffff0000 != get(retail, pair[0])&0xffff0000 || lo&0xffff0000 != get(retail, pair[1])&0xffff0000 ||
			uint32(int64(hi&0xffff)<<16+int64(int16(lo))) != ShortHookSpareRAM {
			return nil, fmt.Errorf("literal speaker address preimage mismatch at %#x", pair[0])
		}
		changedPairs[pair[0]], changedPairs[pair[1]] = true, true
	}
	for pc := uint32(0x80080634); pc < 0x800808f4; pc += 4 {
		if !changedPairs[pc] && get(stage, pc) != get(retail, pc) {
			return nil, fmt.Errorf("literal speaker instruction preimage mismatch at %#x", pc)
		}
	}
	last, err := graphics.RenderPair(encoded[n-2]&0x7f, encoded[n-1]&0x7f)
	if err != nil {
		return nil, err
	}
	inkWidth := 0
	for y := 0; y < 12; y++ {
		for x := 0; x < 12; x++ {
			if last[(y*12+x)/8]&(0x80>>uint((y*12+x)%8)) != 0 && x+1 > inkWidth {
				inkWidth = x + 1
			}
		}
	}
	speakerX, quoteX := -98-4*n, -102+4*n
	bodyX := quoteX + 16
	for _, stride := range []int{14, 16} {
		if quoteX < speakerX+(n/2-1)*stride+inkWidth || bodyX+12*stride+12 > 160 {
			return nil, fmt.Errorf("literal speaker geometry exceeds verified bounds at stride %d", stride)
		}
	}
	out := append([]byte(nil), stage...)
	patch := func(pc, original uint32, x int) error {
		if get(stage, pc) != original {
			return fmt.Errorf("literal speaker coordinate preimage mismatch at %#x", pc)
		}
		binary.LittleEndian.PutUint32(out[pc-Base:], original&0xffff0000|uint32(uint16(int16(x))))
		return nil
	}
	for _, pcs := range [][3]uint32{{0x800807cc, 0x80080814, 0x8008083c}, {0x80080870, 0x800808b8, 0x800808e0}} {
		if err := patch(pcs[0], 0x240eff98, -98); err != nil {
			return nil, err
		}
		if err := patch(pcs[1], 0x2404ffaa, quoteX); err != nil {
			return nil, err
		}
		if err := patch(pcs[2], 0x2404ffb8, bodyX); err != nil {
			return nil, err
		}
	}
	return out, nil
}
