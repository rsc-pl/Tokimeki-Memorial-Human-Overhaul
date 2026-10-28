// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"encoding/binary"
	"fmt"
)

var inheritedFujisakiCode = []struct {
	offset int
	word   uint32
}{
	{0x3ff94, 0x3c04800b},
	{0x3ff98, 0x14f80032},
	{0x3ff9c, 0x00000000},
	{0x3ffa0, 0x9059fffe},
	{0x3ffa4, 0x3c0e8012},
	{0x3ffa8, 0x14f9002e},
	{0x3ffac, 0x00000000},
	{0x3ffb0, 0x8dce2cdc},

	{0x40064, 0x0c02b838},
	{0x40068, 0x2484219c},
}

func RewriteGuardedInheritedFujisaki(source []byte, target uint32) ([]byte, error) {
	if target == 0 || len(source) < 0x4006c {
		return nil, fmt.Errorf("invalid Fujisaki candidate geometry")
	}
	for _, v := range inheritedFujisakiCode {
		if v.offset+4 > len(source) || binary.LittleEndian.Uint32(source[v.offset:]) != v.word {
			return nil, fmt.Errorf("Fujisaki inherited path mismatch at %#x", v.offset)
		}
	}

	reload := binary.LittleEndian.Uint32(source[0x3ffb4:])
	if reload>>16 != 0x3c04 || reload&0xffff != 0x8005 {
		return nil, fmt.Errorf("Fujisaki fall-through does not reload staged a0")
	}

	for _, at := range []int{0x3ff98, 0x3ffa8} {
		w := binary.LittleEndian.Uint32(source[at:])
		destination := int64(at+4) + int64(int16(w&0xffff))*4
		if destination != 0x40064 {
			return nil, fmt.Errorf("Fujisaki branch at %#x targets %#x", at, destination)
		}
	}

	hi := ((target + 0x8000) >> 16) & 0xffff
	lo := target & 0xffff
	if (hi<<16)+uint32(int32(int16(lo))) != target {
		return nil, fmt.Errorf("inherited Fujisaki MIPS address cannot be represented")
	}
	out := append([]byte(nil), source...)
	binary.LittleEndian.PutUint32(out[0x3ff94:], 0x3c040000|hi)
	binary.LittleEndian.PutUint32(out[0x40068:], 0x24840000|lo)

	if binary.LittleEndian.Uint32(out[0x3ffb4:]) != reload {
		return nil, fmt.Errorf("indirect rewrite clobbered direct source")
	}
	return out, nil
}
