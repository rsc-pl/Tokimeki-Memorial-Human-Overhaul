package n20arch

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

// PlanCoordinatedNPCAFirstLinePrivate is a narrowly-scoped PRIVATE geometry
// candidate for the six owner-observed NPC-A formatter routes. It preserves
// the native speaker-X, N10 name bytes and glyph/font setup. It moves the
// quote-prefix and the dialogue parser's initial X TOGETHER, to the right of
// the formatted speaker's conservative pair-glyph right edge.
//
// This is NOT a runtime fit proof: actual glyph preparation, wrapping, GPU
// bounding boxes, per-window right edges, C10 ownership and overlays remain
// unverified. Do not ship through any public builder; safe_to_patch is false.
//
// n is the exact formatted source byte count (less the space) from formatted length and is
// read from the existing sp+0x286 halfword. Retail NPC X=-104-4*n. For 1-byte
// English letters, ceil((n+1)/2) pairs each with at most 16px advance imply:
//
//	right_edge <= -104-4*n + 16*floor((n+1)/2)
//
// The new prefix X = -96+4*n is >= this bound (0px margin for odd n; 8px
// for even n). The body starts prefix+16 (retail's prefix+14 assumes 14px).
// Dynamic screen fit is NOT established by this algebra.
//
// An inline-only implementation uses the post-name-queue former NPC scratch buffer scratch
// word sp+0x50 to carry the prefix X into the parser call. The name was fully
// consumed synchronously by 0x8004E788, whose eight-byte queued record holds
// no source text pointer. Original sp+0x10 fifth-argument zero is established
// immediately before the name call and untouched by intervening instructions
// and the queue callee (the old redundant zero stores are reclaimed).
// No new executable code, BSS, overlay hook, or independent RAM allocation.
func PlanCoordinatedNPCAFirstLinePrivate(retail, npcGeometryStage []byte, englishNames []string) ([]byte, error) {
	const base = uint32(0x80040800)
	const digest = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	if len(retail) != 667648 || len(npcGeometryStage) != len(retail) || fmt.Sprintf("%x", sha256.Sum256(retail)) != digest {
		return nil, fmt.Errorf("NPC coordinates authenticated EXE preimage missing")
	}
	if len(englishNames) != 16 {
		return nil, fmt.Errorf("NPC coordinates requires all 16 source-owned current NPC names")
	}
	encoder := &script.PairEncoder{}
	for i, name := range englishNames {
		if len(name) == 0 || len(name) > speakerScratchMaxFormattedSourceBytes {
			return nil, fmt.Errorf("NPC coordinates invalid source name length at %d", i)
		}
		for j := 0; j < len(name); j++ {
			if !(name[j] >= 'A' && name[j] <= 'Z') && !(name[j] >= 'a' && name[j] <= 'z') {
				return nil, fmt.Errorf("NPC coordinates unsupported non-ASCII-letter name at %d (no lossy name rewrite permitted)", i)
			}
		}
		encoded, e := encoder.Encode(name)
		if e != nil || len(encoded) > speakerScratchMaxFormattedSourceBytes || len(encoded) < len(name) || len(encoded) > len(name)+1 {
			return nil, fmt.Errorf("NPC coordinates name encoding differs from padded English pair-font contract at %d", i)
		}
		// NPC spacing precise ink bound. The source is PairEncoder encoded (even bytes).
		// sprintf appends one ASCII space, ignored by the pair-counting queue.
		// Check the actual bundled English glyph atlas, not merely the stride.
		n := len(encoded)
		if n < 2 || n%2 != 0 {
			return nil, fmt.Errorf("NPC spacing non-paired name source at %d", i)
		}
		last, ge := graphics.RenderPair(encoded[n-2]&0x7f, encoded[n-1]&0x7f)
		if ge != nil {
			return nil, fmt.Errorf("NPC spacing cannot render final pair %d: %w", i, ge)
		}
		lastInkRight := 0
		for y := 0; y < 12; y++ {
			for x := 0; x < 12; x++ {
				if last[(y*12+x)/8]&(0x80>>uint((y*12+x)%8)) != 0 && x+1 > lastInkRight {
					lastInkRight = x + 1
				}
			}
		}
		prefixX := -104 + 4*n
		for _, advance := range []int{14, 16} {
			nameRightInk := -104 - 4*n + (n/2-1)*advance + lastInkRight
			if prefixX-nameRightInk < 4 || prefixX < -32768 || prefixX+16 > 32767 {
				return nil, fmt.Errorf("NPC spacing glyph ink/quote separation fails name[%d] stride=%d", i, advance)
			}
		}
	}
	if err := VerifyNPCLabelGeometryBaseline(retail, npcGeometryStage); err != nil {
		return nil, fmt.Errorf("NPC coordinates rejected prior speaker geometry or foreign name geometry: %w", err)
	}
	get := func(buf []byte, pc uint32) uint32 { return binary.LittleEndian.Uint32(buf[pc-base:]) }
	patches := map[uint32]uint32{}
	assign := func(pc, expected, replacement uint32) error {
		if get(retail, pc) != expected || get(npcGeometryStage, pc) != expected {
			return fmt.Errorf("NPC coordinates owner conflict at %08x (expected %08x; retail %08x / stage %08x)", pc, expected, get(retail, pc), get(npcGeometryStage, pc))
		}
		if _, duplicate := patches[pc]; duplicate {
			return fmt.Errorf("NPC coordinates overlapping instruction at %08x", pc)
		}
		patches[pc] = replacement
		return nil
	}
	for i, route := range npcNameQueueNPCNameQueues {
		n := route.NameQueuePC
		p := route.TextQueuePC // quote prefix queue, NOT body parser
		if p != n+0x24 || route.TextXPC != p-4 || get(retail, p+0x34) != 0x0c020464 || get(npcGeometryStage, p+0x34) != 0x0c020464 {
			return nil, fmt.Errorf("NPC coordinates inconsistent named prefix/parser ownership in route %d", i)
		}
		// formatted length count is derived from the actual sprintf-produced name.
		countWord := get(npcGeometryStage, route.FormatPC+8)
		if countWord>>26 != 9 || (countWord>>21)&31 != 2 || uint16(countWord) != 0xffff {
			return nil, fmt.Errorf("NPC coordinates missing formatted length source count in route %d", i)
		}
		countReg := (countWord >> 16) & 31
		if countReg == 0 || countReg == 2 {
			return nil, fmt.Errorf("NPC coordinates invalid formatted length count destination at route %d", i)
		}
		// Name queue must be synchronous, with fifth argument zero.
		if get(retail, n) != 0x0c0139e2 || get(npcGeometryStage, n) != 0x0c0139e2 || get(retail, n+4) != 0xafa00010 || get(npcGeometryStage, n+4) != 0xafa00010 {
			return nil, fmt.Errorf("NPC coordinates name queue/fifth-argument drift at route %d", i)
		}
		if get(retail, p) != 0x0c0139e2 || get(npcGeometryStage, p) != 0x0c0139e2 || get(retail, p+4) != 0xafa00010 || get(retail, p+0x30) != 0xafa00010 {
			return nil, fmt.Errorf("NPC coordinates quote/parser fifth-argument boundary drift in route %d", i)
		}
		// NPC scratch buffer rehomed the formatted name away from sp+0x68.
		if get(npcGeometryStage, route.FormatPC+4) != 0x27a40030 || get(npcGeometryStage, n-4) != 0x27a70030 {
			return nil, fmt.Errorf("NPC coordinates missing NPC scratch buffer synchronous name scratch ownership at route %d", i)
		}
		// formatted length changed the original stack load to addiu rCount,v0,-1; the
		// previous stack slot sp+0x286 is stale. Preserve the CORRECT count
		// there before the synchronous name queue, otherwise NPC coordinates could
		// reproduce speaker geometry's n=0 bug despite passing static X arithmetic.
		// The retail name-call y used sll/sra/move to sign-extend s1; s1 is
		// already directly used for parser Y later. Reclaim these instructions
		// while passing the exact same y through move a1,s1.
		if err := assign(n-0x1c, 0x00112c00, (0x29<<26)|(29<<21)|(countReg<<16)|0x0286); err != nil {
			return nil, err
		} // sh rCount,0x286(sp)
		oldYSign := get(retail, n-0x18)
		if oldYSign>>26 != 0 || oldYSign&63 != 3 || (oldYSign>>16)&31 != 5 || (oldYSign>>6)&31 != 16 {
			return nil, fmt.Errorf("NPC coordinates original signed Y preparation drift route %d", i)
		}
		if err := assign(n-0x18, oldYSign, 0); err != nil {
			return nil, err
		} // nop after removed sign extension
		oldYMove := get(retail, n-8)
		if oldYMove>>26 != 0 || oldYMove&63 != 0x25 || (oldYMove>>11)&31 != 5 || (oldYMove>>21)&31 != (oldYSign>>11)&31 {
			return nil, fmt.Errorf("NPC coordinates original Y move inconsistent with sra route %d", i)
		}
		if err := assign(n-8, oldYMove, 0x02202825); err != nil {
			return nil, err
		} // move a1,s1
		// Old n+8: sll a1,s1,16. Old n+12: sra t*,a1,16.
		// R3000A load delay: a loaded register is NOT readable by the immediately
		// following instruction. Set quote Y first; schedule the load at n+12
		// and the dependent shift at n+0x1c, with intervening source setup.
		if err := assign(n+8, 0x00112c00, 0x02202825); err != nil {
			return nil, err
		} // move a1,s1
		oldSRA := get(retail, n+12)
		if oldSRA>>26 != 0 || oldSRA&0x3f != 3 || (oldSRA>>21)&31 != 0 || (oldSRA>>16)&31 != 5 || (oldSRA>>6)&31 != 16 {
			return nil, fmt.Errorf("NPC coordinates unexpected n+12 sra at route %d", i)
		}
		if err := assign(n+12, oldSRA, 0x87a40286); err != nil {
			return nil, err
		} // lh a0,0x286(sp), at least two unrelated operations before use
		oldMove := get(retail, n+0x1c)
		if oldMove>>26 != 0 || oldMove&0x3f != 0x25 || (oldMove>>11)&31 != 5 {
			return nil, fmt.Errorf("NPC coordinates name-prefix y coordinate source drift at route %d", i)
		}
		if err := assign(n+0x1c, oldMove, 0x00042080); err != nil {
			return nil, err
		} // sll a0,a0,2 (after the load delay)
		if err := assign(n+0x20, 0x2404ffaa, 0x2484ff98); err != nil {
			return nil, err
		} // NPC spacing compact prefix_x = -104+4n, preserves glyph ink gap >=4px
		if err := assign(p+4, 0xafa00010, 0xafa40050); err != nil {
			return nil, err
		} // save prefix X after label consumption
		if i == len(npcNameQueueNPCNameQueues)-1 {
			// The final route obtains parser a3 from sp+0x27c, not s0.
			// Reclaim one redundant literal-pointer materialisation:
			// 0x800b2220 is exactly four bytes below the other 0x800b2224.
			if get(retail, p+0x0c) != 0x3c0e800b || get(retail, p+0x10) != 0x25ce2224 || get(retail, p+0x1c) != 0x8fa7027c {
				return nil, fmt.Errorf("NPC coordinates final route parser source pointer drift")
			}
			if err := assign(p+8, 0x3c18800b, 0x87a40050); err != nil {
				return nil, err
			} // lh a0,0x50(sp)
			if err := assign(p+0x14, 0x27182220, 0x25d8fffc); err != nil {
				return nil, err
			} // addiu t8,t6,-4
			if err := assign(p+0x28, 0x2404ffb8, 0x24840010); err != nil {
				return nil, err
			} // addiu a0,a0,16
		} else {
			if err := assign(p+0x24, 0x2404ffb8, 0x87a40050); err != nil {
				return nil, err
			} // reload prefix X
			if err := assign(p+0x28, 0x02202825, 0x02202825); err != nil {
				return nil, err
			} // move a1,s1 separates lh from dependent addiu
			if err := assign(p+0x2c, 0x02003825, 0x24840010); err != nil {
				return nil, err
			} // body X = prefix X+16, after the load delay
			if err := assign(p+0x30, 0xafa00010, 0x02003825); err != nil {
				return nil, err
			} // move a3,s0 (fifth arg is still zero)
		}

	}
	out := append([]byte(nil), npcGeometryStage...)
	for pc, newWord := range patches {
		binary.LittleEndian.PutUint32(out[pc-base:], newWord)
	}
	return out, nil
}
