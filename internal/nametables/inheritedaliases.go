package nametables

import (
	"encoding/binary"
	"fmt"
)

// inheritedFujisakiCode describes the *reviewed* branch island of the retail
// SLPM_86.053. Both conditional branches enter the same JAL at 0x40064, whose
// delay slot uses a0's inherited high half to form the Fujisaki source.
// The fall-through reloads a0 at 0x3ffb4, before it can use it. This is a
// local control-flow proof only; it does not prove complete consumer coverage.
var inheritedFujisakiCode = []struct {
	offset int
	word   uint32
}{
	{0x3ff94, 0x3c04800b}, // lui a0,0x800b
	{0x3ff98, 0x14f80032}, // bne a3,t8 -> 0x40064
	{0x3ff9c, 0x00000000}, // delay slot
	{0x3ffa0, 0x9059fffe}, // lbu t9,-2(v0)
	{0x3ffa4, 0x3c0e8012}, // lui t6,0x8012
	{0x3ffa8, 0x14f9002e}, // bne a3,t9 -> 0x40064
	{0x3ffac, 0x00000000}, // delay slot
	{0x3ffb0, 0x8dce2cdc}, // lw t6,0x2cdc(t6)
	// 0x3ffb4 reloads a0; its immediate changes during G23 direct stage.
	{0x40064, 0x0c02b838}, // jal strcpy-equivalent
	{0x40068, 0x2484219c}, // addiu a0,a0,0x219c -- JAL delay slot
}

// RewriteGuardedInheritedFujisaki independently redirects the fourth fixed
// Fujisaki source. Only the existing LUI at 0x3ff94 and ADDIU at 0x40068 may
// change. Its branch-provenance proof is tied to the byte-exact known retail
// instructions. The input must already be the G23 direct-source candidate.
// Result is a research-only EXE COPY, not safe to boot.
func RewriteGuardedInheritedFujisaki(source []byte, target uint32) ([]byte, error) {
	if target == 0 || len(source) < 0x4006c {
		return nil, fmt.Errorf("invalid Fujisaki candidate geometry")
	}
	for _, v := range inheritedFujisakiCode {
		if v.offset+4 > len(source) || binary.LittleEndian.Uint32(source[v.offset:]) != v.word {
			return nil, fmt.Errorf("Fujisaki inherited path mismatch at %#x", v.offset)
		}
	}
	// The incoming a0 is overwritten unconditionally in the fall-through
	// path after the second conditional branch. G23's first direct rewrite
	// changes its immediate; here only register/opcode and verified low-half
	// are required. Changing THIS LUI would otherwise corrupt that caller.
	reload := binary.LittleEndian.Uint32(source[0x3ffb4:])
	if reload>>16 != 0x3c04 || reload&0xffff != 0x8005 {
		return nil, fmt.Errorf("Fujisaki fall-through does not reload staged a0")
	}
	// Verify branch targets by decoding signed PC-relative displacement.
	for _, at := range []int{0x3ff98, 0x3ffa8} {
		w := binary.LittleEndian.Uint32(source[at:])
		destination := int64(at+4) + int64(int16(w&0xffff))*4
		if destination != 0x40064 {
			return nil, fmt.Errorf("Fujisaki branch at %#x targets %#x", at, destination)
		}
	}
	// ADDIU sign-extends its low immediate. The adjusted LUI half is therefore
	// (address + 0x8000) >> 16, rather than address >> 16.
	hi := ((target + 0x8000) >> 16) & 0xffff
	lo := target & 0xffff
	if (hi<<16)+uint32(int32(int16(lo))) != target {
		return nil, fmt.Errorf("inherited Fujisaki MIPS address cannot be represented")
	}
	out := append([]byte(nil), source...)
	binary.LittleEndian.PutUint32(out[0x3ff94:], 0x3c040000|hi)
	binary.LittleEndian.PutUint32(out[0x40068:], 0x24840000|lo)
	// The G23 direct source at 0x3ffb4 is deliberately untouched.
	if binary.LittleEndian.Uint32(out[0x3ffb4:]) != reload {
		return nil, fmt.Errorf("indirect rewrite clobbered direct source")
	}
	return out, nil
}
