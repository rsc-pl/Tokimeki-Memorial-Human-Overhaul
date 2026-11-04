package playername

// Shared assembler primitives used by the source-gated name display adapters.
// These helpers do not select callers, place code or authorize a runtime patch.
import (
	"errors"
	"fmt"
)

type mipsBranch struct {
	at    int
	label string
}
type mipsBuf struct {
	words    []uint32
	labels   map[string]int
	branches []mipsBranch
}

func (b *mipsBuf) emit(w uint32)  { b.words = append(b.words, w) }
func (b *mipsBuf) label(s string) { b.labels[s] = len(b.words) }
func (b *mipsBuf) branch(op, rs, rt uint32, label string) {
	b.branches = append(b.branches, mipsBranch{len(b.words), label})
	b.emit((op << 26) | (rs << 21) | (rt << 16))
}
func iType(op, rs, rt uint32, imm int16) uint32 {
	return (op << 26) | (rs << 21) | (rt << 16) | uint32(uint16(imm))
}
func (b *mipsBuf) resolve() error {
	for _, v := range b.branches {
		to, ok := b.labels[v.label]
		if !ok {
			return fmt.Errorf("undefined MIPS label %s", v.label)
		}
		disp := to - v.at - 1
		if disp < -32768 || disp > 32767 {
			return errors.New("MIPS branch range")
		}
		b.words[v.at] |= uint32(uint16(int16(disp)))
	}
	return nil
}
