package n20arch

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// PlanNPCFormattedLengthPrivate is a *private, unverified-at-runtime* N10
// consistency correction. Six legacy NPC-A routes obtain the label's X count
// from the result of a separate strlen BEFORE formatting. With N10 Phase-2
// source relocation, that length may refer to a different buffer than the
// sprintf("%s ", N10-A) that is actually enqueued. Immediately after sprintf
// returns, its v0 is the number of formatted bytes excluding NUL. Because
// the SHA-pinned format is exactly "%s " we use (v0-1), i.e. length of the
// very string formatted, instead of the earlier potentially stale strlen.
// This does NOT adjust X, quote/body starts, line-wrap, fonts or GPU clipping.
// It is not a demonstrated fix for the existing owner-visible overlap.
func PlanNPCFormattedLengthPrivate(retail, speakerScratchStage []byte) ([]byte, error) {
	const base = uint32(0x80040800)
	const digest = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	if len(retail) != 667648 || len(speakerScratchStage) != len(retail) || fmt.Sprintf("%x", sha256.Sum256(retail)) != digest {
		return nil, fmt.Errorf("formatted length retail/source EXE authentication refused")
	}
	// Original sprintf: initialize its length counter to zero, return it in
	// v0. This is a bounded source contract, not a general C-library claim.
	word := func(buf []byte, pc uint32) uint32 { return binary.LittleEndian.Uint32(buf[pc-base:]) }
	if word(retail, 0x800AE154) != 0xAFA00248 || word(retail, 0x800AEE9C) != 0x8FA20248 || word(retail, 0x800AEEA0) != 0x03E00008 {
		return nil, fmt.Errorf("formatted length sprintf return-count ABI drift")
	}
	if err := VerifyNPCLabelGeometryBaseline(retail, speakerScratchStage); err != nil {
		return nil, fmt.Errorf("formatted length rejected geometry/ownership: %w", err)
	}
	out := append([]byte(nil), speakerScratchStage...)
	for i, route := range npcNameQueueNPCNameQueues {
		// NPC scratch buffer's relocated output buffer and its queue input MUST match.
		if word(speakerScratchStage, route.FormatPC+4) != 0x27A40030 || word(speakerScratchStage, route.NameQueuePC-4) != 0x27A70030 {
			return nil, fmt.Errorf("formatted length missing NPC scratch buffer paired formatter buffer at route %d", i)
		}
		if word(retail, route.FormatPC) != 0x0C02B84C || word(speakerScratchStage, route.FormatPC) != 0x0C02B84C {
			return nil, fmt.Errorf("formatted length unexpected sprintf caller at route %d", i)
		}
		// The six source-A materialisations were already redirected to the
		// exact Phase-2 A buffer by N10. No historic fixtures or name swaps.
		if word(retail, route.FormatPC-16) != 0x3C06800D || word(retail, route.FormatPC-8) != 0x24C6A188 ||
			word(speakerScratchStage, route.FormatPC-16) != 0x3C06800B || word(speakerScratchStage, route.FormatPC-8) != 0x24C635A4 {
			return nil, fmt.Errorf("formatted length current N10-A source ownership mismatch at route %d", i)
		}
		// Every format literal is verified as original "%s \x00".
		formatHi := word(retail, route.FormatPC-20)
		formatLo := word(retail, route.FormatPC-4)
		if formatHi != 0x3C05800B || formatLo>>26 != 9 || (formatLo>>21)&31 != 5 || (formatLo>>16)&31 != 5 {
			return nil, fmt.Errorf("formatted length unexpected format argument at route %d", i)
		}
		formatPtr := uint32(0x800B0000) + uint32(int16(formatLo))
		if int(formatPtr-base)+4 > len(retail) || word(retail, formatPtr) != 0x00207325 { // little-endian "%s \x00"
			return nil, fmt.Errorf("formatted length unexpected format bytes at route %d (%08x)", i, formatPtr)
		}
		countPC := route.FormatPC + 8
		original := word(retail, countPC)
		if word(speakerScratchStage, countPC) != original || original>>26 != 0x21 || (original>>21)&31 != 29 || uint16(original) != 0x0286 {
			return nil, fmt.Errorf("formatted length unexpected original strlen-count read at %08x", countPC)
		}
		dest := (original >> 16) & 31
		if dest == 0 || dest == 2 {
			return nil, fmt.Errorf("formatted length invalid original count register at route %d", i)
		}
		// addiu original-dest, v0, -1. sprintf outputs "<name><space>".
		// Preserve caller count register; no additional RAM or hooks.
		revised := (uint32(9) << 26) | (uint32(2) << 21) | (dest << 16) | 0xffff
		binary.LittleEndian.PutUint32(out[countPC-base:], revised)
	}
	return out, nil
}
