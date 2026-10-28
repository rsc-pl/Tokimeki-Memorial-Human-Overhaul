package n20arch

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/script"
)

// NPCScratchCandidate is a bounded candidate, not a validated renderer or layout fix.
//
// Original 0x8007ef48 frame: saved RA at sp+44 (0x2c); the first
// separately initialized local is the 16-byte object sp+88..103
// (0x58..0x67). The 40-byte interval [sp+0x30,sp+0x58) is not directly
// accessed or addressed by any original instruction in this function.
// Source-authenticated six NPC-A sprintf("%s ") producers previously wrote
// at sp+0x68; their synchronous queue consumer read the same bytes.
// Repoint BOTH producer and queue caller to the candidate 40-byte scratch.
// Do not change name X, prefix, parser start, source names or public code.
//
// Direct instruction-reference inventory is NOT an exhaustive dynamic alias
// proof; this must never authorize production patching or RAM safety claims.
const (
	speakerScratchScratchOffset           uint16 = 0x30
	speakerScratchScratchEnd              uint16 = 0x58
	speakerScratchMaxFormattedSourceBytes        = int(speakerScratchScratchEnd-speakerScratchScratchOffset) - 2 // space + NUL
)

func PlanPrivateNPCScratch(retail, merged []byte, sourceNPCNames []string) ([]byte, error) {
	const expected = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	const base = uint32(0x80040800)
	if len(retail) != 667648 || len(merged) != len(retail) || fmt.Sprintf("%x", sha256.Sum256(retail)) != expected {
		return nil, fmt.Errorf("NPC scratch buffer retail source authentication failed")
	}
	if len(sourceNPCNames) != 16 {
		return nil, fmt.Errorf("NPC scratch buffer requires all 16 live source-owned names")
	}
	encoder := &script.PairEncoder{}
	for i, s := range sourceNPCNames {
		raw, err := encoder.Encode(s)
		if err != nil {
			return nil, fmt.Errorf("NPC scratch buffer NPC %d encoding: %w", i, err)
		}
		if len(raw) == 0 || len(raw) > speakerScratchMaxFormattedSourceBytes {
			return nil, fmt.Errorf("NPC scratch buffer NPC source %d encoded length %d exceeds 38-byte formatted buffer limit", i, len(raw))
		}
		for j := 0; j < len(s); j++ {
			if s[j] == 0 {
				return nil, fmt.Errorf("NPC scratch buffer NPC source %d has embedded NUL", i)
			}
		}
	}
	// Prove the original function has the expected frame boundary and gap.
	get := func(b []byte, p uint32) uint32 { return binary.LittleEndian.Uint32(b[p-base:]) }
	if get(retail, 0x8007ef48) != 0x27bdfd70 || get(retail, 0x8007ef50) != 0xafbf002c || get(retail, 0x8007ef6c) != 0x27aa0058 || get(retail, 0x80081124) != 0x27bd0290 {
		return nil, fmt.Errorf("NPC scratch buffer stack-frame layout drift")
	}
	// Fail closed if any retail instruction refers to the proposed scratch
	// directly as a SP-relative load/store or computes a pointer inside it.
	// Authenticated source ensures this exact negative proof cannot be reused on
	// a different binary. This does not prove all register-indirect consumers.
	for p := uint32(0x8007ef4c); p < 0x80081120; p += 4 {
		w := get(retail, p)
		op := w >> 26
		rs := (w >> 21) & 31
		imm := uint16(w)
		if rs != 29 || imm < speakerScratchScratchOffset || imm >= speakerScratchScratchEnd {
			continue
		}
		if op == 9 || op == 8 || (op >= 0x20 && op <= 0x2e) {
			return nil, fmt.Errorf("NPC scratch buffer proposed stack gap is referenced at %08x", p)
		}
	}
	out := append([]byte(nil), merged...)
	for i, s := range npcNameQueueNPCNameQueues {
		fmtDest := s.FormatPC + 4
		queueSrc := s.NameQueuePC - 4
		if get(retail, fmtDest) != 0x27a40068 || get(retail, queueSrc) != 0x27a70068 {
			return nil, fmt.Errorf("NPC scratch buffer original NPC scratch ABI drift route %d", i)
		}
		if get(merged, fmtDest) != get(retail, fmtDest) || get(merged, queueSrc) != get(retail, queueSrc) {
			return nil, fmt.Errorf("NPC scratch buffer real English/N10/N20 ownership collision at %08x or %08x", fmtDest, queueSrc)
		}
		binary.LittleEndian.PutUint32(out[fmtDest-base:], 0x27a40000|uint32(speakerScratchScratchOffset))
		binary.LittleEndian.PutUint32(out[queueSrc-base:], 0x27a70000|uint32(speakerScratchScratchOffset))
	}
	return out, nil
}
